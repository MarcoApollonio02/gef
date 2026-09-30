"""GEF kernel commands (category 06-k) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Other: kernel code-pointer search, SMM
status/dump/info, qemu-device-info and UEFI OVMF info. Auto-discovered by
gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import os
import subprocess

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
    read_memory,
    u32,
    u64,
)
from gef.core.process import (
    Pid,
    get_pagesize,
    is_in_smm,
    scan_smm_token_in_monitor,
)
from gef.core.qemu import QemuMonitor, disable_phys, enable_phys, read_physmem
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
class SmmStatusCommand(GenericCommand):
    """Tell whether the CPU is currently in System Management Mode (SMM).

    Detection heuristic: in SMM the CPU executes from a code window inside the
    SMRAM physical region (SMBASE + 0x8000 in the legacy DOS layout, an
    arbitrary address inside TSEG on modern Q35). ``$pc in SMRAM`` is therefore
    a reliable in-SMM indicator on QEMU. The command also scans
    ``monitor info registers`` for an SMM token as a secondary cross-check and
    reports whichever signals fire.
    """

    _cmdline_ = "smm-status"
    _category_ = "06-k. Qemu-system/KGDB Cooperation - SMM"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="print only `in_smm` or `not_in_smm` (scriptable).")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}        # show in-SMM verdict with rationale",
        "{0:s} --quiet # script-friendly single-token output",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = ("Only meaningful when debugging qemu-system-x86[_64]. "
              "SMM has no dedicated architectural flag exposed via the gdb "
              "stub, so detection relies on $pc lying within the SMRAM "
              "physical range resolved from `monitor info mtree -f`.")

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        smram = QemuMonitor.get_smram_map(verbose=not args.quiet)
        if smram is None:
            if not args.quiet:
                err("Could not resolve SMRAM map")
            return
        smram_base, smram_size = smram
        smram_end = smram_base + smram_size
        pc = get_register("$pc")
        if pc is None:
            if not args.quiet:
                err("Could not read $pc")
            return

        in_smm_pc = smram_base <= pc < smram_end
        in_smm_mon, smm_token = scan_smm_token_in_monitor()
        in_smm = in_smm_pc or in_smm_mon

        if args.quiet:
            gef_print("in_smm" if in_smm else "not_in_smm")
            return

        if in_smm:
            verdict = Color.colorify("CURRENTLY IN SMM", "bold red")
        else:
            verdict = Color.colorify("NOT in SMM", "bold green")
        gef_print("{}: $pc={:#x}, SMRAM=[{:#x}-{:#x}) ({} bytes)".format(
            verdict, pc, smram_base, smram_end, GefUtil.get_size_str(smram_size)))

        reasons = []
        if in_smm_pc:
            reasons.append("$pc within SMRAM range")
        if in_smm_mon:
            reasons.append("`monitor info registers` mentions '{}'".format(smm_token))
        if reasons:
            gef_print("  rationale: {}".format("; ".join(reasons)))
        else:
            gef_print("  rationale: no SMM indicators found")
        return


@register_command
class SmmDumpCommand(GenericCommand):
    """Dump SMRAM to disk when the CPU is in System Management Mode.

    By default dumps only when :func:`is_in_smm` is True (i.e. ``$pc`` lies
    inside the SMRAM physical range) -- otherwise prints a warning and exits.
    Pass ``--force`` to dump regardless of the in-SMM verdict (useful for
    inspecting SMRAM contents without first driving the guest into SMM) and
    ``--commit`` to actually write bytes (without it the command is a dry run,
    mirroring :class:`SmartMemoryDumpCommand`).
    """

    _cmdline_ = "smm-dump"
    _category_ = "06-k. Qemu-system/KGDB Cooperation - SMM"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--force", action="store_true",
                        help="dump even if the CPU is not currently in SMM.")
    parser.add_argument("-c", "--commit", action="store_true",
                        help="actually write the dump file (without this flag, dry run only).")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                   # dry run; prints where the dump would go",
        "{0:s} --commit          # dump SMRAM only if in SMM",
        "{0:s} --commit --force  # dump SMRAM regardless of in-SMM status",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = ("When `is_in_smm()` is True, SMRAM is read via virtmode "
              ":func:`read_memory` (GDB's `m` packet routes through the CPU's "
              "current AS, which during SMM is the per-CPU SMM AS); falls back "
              "to :func:`read_physmem` only if the virtmode read is empty. "
              "Physmode/`monitor xp`/`monitor gpa2hva` paths use the system AS, "
              "where the chipset's SMRAM overlay is masked by D_OPEN and reads "
              "return `0xff` or `pc.ram` zero-fill, never real SMM bytes.")

    @staticmethod
    def read_smram_in_smm(smram_base, smram_size):
        """Read SMRAM via the per-CPU SMM AS (virtmode).

        Physmode, `monitor xp`, and `monitor gpa2hva`/`/proc/<pid>/mem` all use
        the system AS, where the chipset's SMRAM overlay is masked by D_OPEN
        when not in SMM -- returning `\xff` or `pc.ram` zero-fill. In virtmode
        the GDB stub routes through the current CPU's AS (`cpu->as`), which in
        SMM is the SMM AS. Since SMM enters in flat real mode (`CR0.PG=0`),
        GVA==GPA and `read_memory(smram_base, smram_size)` lands inside SMRAM.
        """
        cur_mode = QemuMonitor.get_current_mmu_mode()
        switched_to_virt = False
        if cur_mode == "phys":
            if not disable_phys():
                return None
            switched_to_virt = True
        try:
            try:
                return read_memory(smram_base, smram_size)
            except gdb.MemoryError:
                return None
        finally:
            if switched_to_virt:
                enable_phys()

    @staticmethod
    def dump_smram(smram_base, smram_size, commit):
        size_str = GefUtil.get_size_str(smram_size)
        dirpath = os.path.join(GEF_TEMP_DIR, "mem-dump-" + GefUtil.now_str())
        fname = "{:08x}-{:08x}_smram.raw".format(smram_base, smram_base + smram_size - 1)
        filepath = os.path.join(dirpath, fname)
        if commit:
            data = None
            if is_in_smm():
                data = SmmDumpCommand.read_smram_in_smm(smram_base, smram_size)
                if not data:
                    warn("virtmode+SMM-AS read empty; falling back to read_physmem.")
            if not data:
                try:
                    data = read_physmem(smram_base, smram_size)
                except Exception as e:
                    err("SMRAM read failed at {:#x}/{:#x}: {}".format(smram_base, smram_size, e))
                    return None
            if not data:
                err("SMRAM read returned no data at {:#x}/{:#x}".format(smram_base, smram_size))
                return None
            if data.count(0) == len(data):
                warn("SMRAM dump is all zero bytes -- TSEG may be masked from the "
                     "system AS (D_OPEN closed) or SMRAM was never written by firmware.")
            try:
                os.makedirs(dirpath, exist_ok=True)
            except OSError as e:
                err("Could not create dump directory {}: {}".format(dirpath, e))
                return None
            try:
                with open(filepath, "wb") as fd:
                    fd.write(data)
            except OSError as e:
                err("Could not write dump file {}: {}".format(filepath, e))
                return None
            info("Saved SMRAM to {:s} ({:s})".format(filepath, GefUtil.get_size_str(len(data))))
            return filepath
        info("Dry run: would dump SMRAM [{:#x}-{:#x}) ({}) to {:s}".format(
            smram_base, smram_base + smram_size, size_str, filepath))
        warn('Add "--commit" to actually write the file.')
        return filepath

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        smram = QemuMonitor.get_smram_map(verbose=True)
        if smram is None:
            err("Could not resolve SMRAM map")
            return
        smram_base, smram_size = smram

        in_smm = is_in_smm()
        if in_smm:
            ok("CPU is currently in SMM - proceeding with SMRAM dump.")
        elif args.force:
            warn("Not in SMM, but --force given; proceeding with SMRAM dump.")
        else:
            warn("Not in SMM and --force not given; skipping SMRAM dump.")
            warn("Hint: pass --force to dump regardless of in-SMM status.")
            return

        SmmDumpCommand.dump_smram(smram_base, smram_size, args.commit)
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
    _category_ = "06-k. Qemu-system/KGDB Cooperation - SMM"

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

    def smm_banner(self, smram, pc, in_smm_pc, in_smm_mon, smm_token):
        smram_base, smram_size = smram
        smram_end = smram_base + smram_size
        self.out.append(titlify("SMM Status"))
        verdict = (Color.colorify("CURRENTLY IN SMM", "bold red")
                   if in_smm_pc or in_smm_mon
                   else Color.colorify("NOT in SMM", "bold green"))
        self.out.append("{}: $pc={:#x}, SMRAM=[{:#x}-{:#x}) ({} bytes)".format(
            verdict, pc, smram_base, smram_end, GefUtil.get_size_str(smram_size)))
        reasons = []
        if in_smm_pc:
            reasons.append("$pc within SMRAM range")
        if in_smm_mon:
            reasons.append("`monitor info registers` mentions '{}'".format(smm_token))
        self.out.append("  rationale: {}".format(
            "; ".join(reasons) if reasons else "no SMM indicators found"))
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

    def smm_save_state_preview(self, smram_base):
        self.out.append(titlify("Save-state preview (256 bytes at SMRAM base)"))
        try:
            data = read_physmem(smram_base, 0x100)
        except Exception as e:
            data = None
            self.out.append("(SMRAM read at {:#x} failed: {})".format(smram_base, e))
        if data:
            self.out.append(hexdump(data, base=smram_base, show_symbol=False))
        elif data is not None:
            self.out.append("(SMRAM read at {:#x} returned no data)".format(smram_base))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        from gef.commands.kernel.register import QemuRegistersCommand
        smram = QemuMonitor.get_smram_map(verbose=args.verbose)
        if smram is None:
            err("Could not resolve SMRAM map")
            return
        smram_base, smram_size = smram
        pc = get_register("$pc")
        if pc is None:
            err("Could not read $pc")
            return

        in_smm_pc = smram_base <= pc < smram_base + smram_size
        in_smm_mon, smm_token = scan_smm_token_in_monitor()

        self.out = []
        self.smm_banner(smram, pc, in_smm_pc, in_smm_mon, smm_token)
        # `qregisters_x86_x64` only touches `self.out` (no other instance
        # state), so it can be called as an unbound method on a SmmInfoCommand
        # instance. Instantiating QemuRegistersCommand() would try to re-register
        # the `qreg` gdb command, which gdb rejects.
        QemuRegistersCommand.qregisters_x86_x64(self)
        self.smm_smbase()
        if args.verbose:
            self.smm_save_state_preview(smram_base)
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

