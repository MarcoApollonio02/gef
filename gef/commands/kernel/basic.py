"""GEF kernel commands (category 06-c) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Linux Basic: kernel checksec, magic, base,
version, cmdline and current-state commands. Auto-discovered by
gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import collections
import itertools
import re
import struct
import traceback

import gdb

from gef.commands.base import (
    BufferingOutput,
    ContextManager,
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
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.kernel import AddrMap, Kernel, KernelPerCpu, KernelSysctl, KernelVersion, Ksym
from gef.core.memory import (
    hexdump,
    is_valid_addr,
    read_cstring_from_memory,
    read_int8_from_memory,
    read_int32_from_memory,
    read_int64_from_memory,
    read_int_from_memory,
    read_memory,
    u32,
)
from gef.core.pagewalk import (
    KernelAddressHeuristicFinder,
    KernelAddressHeuristicFinderUtil,
    PageMap,
)
from gef.core.process import (
    is_arm32,
    is_arm64,
    is_in_kernel,
    is_kgdb,
    is_kvm_enabled,
    is_riscv32,
    is_riscv64,
    is_support_secure_world,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import get_register, to_unsigned_long
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil, align


@register_command
class KernelChecksecCommand(GenericCommand):
    """Check the security properties of the current kernel."""

    _cmdline_ = "kchecksec"
    _category_ = "06-c. Qemu-system/KGDB Cooperation - Linux Basic"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def get_kconfig(self):
        self.kconfig = None
        self.kconfig_where = None
        # Over KGDB, scanning .rodata and the configs module for IKCFG_ST is too slow.
        if is_kgdb() and Ksym.get_addr("kernel_config_data") is None:
            return
        try:
            ret = gdb.execute("kconfig --quiet --no-pager", to_string=True)
        except gdb.error:
            return
        ret = Color.remove_color(ret)
        kconfig = {}
        for line in ret.splitlines():
            r = re.match(r"^(CONFIG_\w+)=(.*)$", line)
            if r:
                kconfig[r.group(1)] = r.group(2)
                continue
            r = re.match(r"^# (CONFIG_\w+) is not set$", line)
            if r:
                kconfig[r.group(1)] = "n"
        if not kconfig:
            return
        self.kconfig = kconfig
        r1 = re.search(r"configs module: (0x[0-9a-f]+)", ret)
        r2 = re.search(r"IKCFG_ST: (0x[0-9a-f]+)", ret)
        if r1:
            self.kconfig_where = "configs module: {:s}".format(r1.group(1))
        elif r2:
            self.kconfig_where = "IKCFG_ST: {:s}".format(r2.group(1))
        return

    def get_config(self, *names):
        # Returns the first given name that the embedded kernel config has, and its value.
        # The value is None if the kernel config is unavailable, or "n" if it is not set.
        if self.kconfig is None:
            return names[0], None
        for name in names:
            if name in self.kconfig:
                return name, self.kconfig[name]
        return names[0], "n"

    @staticmethod
    def config_str(name, value):
        if value == "n":
            return "kconfig: {:s} is not set".format(name)
        return "kconfig: {:s}={:s}".format(name, value)

    def print_kconfig_state(self, cfg, names=None, secure_if_enabled=True):
        # Prints the build-time state decided by the embedded kernel config, and returns True.
        # If the kernel config is unavailable, prints nothing and returns False.
        name, value = self.get_config(*(names or [cfg]))
        if value is None:
            return False
        if secure_if_enabled:
            good, bad = ("bold green", "bold red")
        else:
            good, bad = ("bold red", "bold green")
        if value == "n":
            state = Color.colorify("Disabled", bad)
        elif value == "m":
            state = Color.colorify("Module", good)
        else:
            state = Color.colorify("Enabled", good)
        gef_print("{:<40s}: {:s} ({:s})".format(cfg, state, self.config_str(name, value)))
        return True

    def get_loaded_modules(self):
        # Returns [[name, base, size], ...] (a module has multiple regions since v6.4), or None if it failed.
        if self.loaded_modules is not False:
            return self.loaded_modules
        modules = Kernel.modules().get_loaded()
        if modules is None:
            self.loaded_modules = None
        else:
            self.loaded_modules = [[name, base, size] for _module, name, regions in modules for _type, base, size in regions]
        return self.loaded_modules

    @staticmethod
    def get_sysctl_addr(name, symbol):
        # A sysctl tree walk reads too much memory over KGDB, so only the symbol of the variable is used.
        if is_kgdb():
            return Ksym.get_addr(symbol)
        return KernelSysctl.get(name)

    def is_modules_supported(self):
        if KernelAddressHeuristicFinder.get_modules() is not None:
            return True
        return self.get_sysctl_addr("kernel.modules_disabled", "modules_disabled") is not None

    def check_loadable_modules(self):
        modules_symbol = KernelAddressHeuristicFinder.get_modules()
        modules_disabled_addr = self.get_sysctl_addr("kernel.modules_disabled", "modules_disabled")
        modules_supported = modules_symbol is not None or modules_disabled_addr is not None
        modules_disabled = None
        if modules_disabled_addr is not None:
            value = read_int32_from_memory(modules_disabled_addr, safe=True)
            if value is not None:
                modules_disabled = bool(value)
            else:
                modules_disabled = None

        if modules_supported is False:
            state = Color.colorify("Unsupported", "bold green")
        elif modules_disabled is True:
            state = Color.colorify("Loading disabled", "bold green")
        elif modules_disabled is False and modules_supported is True:
            state = Color.colorify("Loading allowed", "bold red")
        else:
            state = Color.grayify("Unknown")
        evidence = []
        if modules_symbol is not None:
            evidence.append("modules={:#x}".format(modules_symbol))
        if modules_disabled is not None:
            evidence.append("kernel.modules_disabled={:d}".format(int(modules_disabled)))
        if evidence:
            additional = ", ".join(evidence)
        else:
            additional = "runtime evidence not found"
        gef_print("{:<40s}: {:s} ({:s})".format("Loadable modules", state, additional))
        return

    def check_io_uring_access(self):
        supported = None
        kversion = Kernel.version()
        if kversion is not None and kversion < "5.1":
            supported = False
        else:
            try:
                output = gdb.execute("ksyscalls -f io_uring_setup --quiet --no-pager", to_string=True)
                clean_output = Color.remove_color(output)
                if re.search(r"\]\s+valid\s+io_uring_setup\s", clean_output):
                    supported = True
                elif re.search(r"\]\s+invalid\s+io_uring_setup\s", clean_output):
                    supported = False
            except gdb.error:
                pass

        disabled_addr = self.get_sysctl_addr("kernel.io_uring_disabled", "sysctl_io_uring_disabled")
        if disabled_addr is not None:
            supported = True
        if supported is False:
            state = Color.colorify("Unsupported", "bold green")
            gef_print("{:<40s}: {:s}".format("io_uring access", state))
            return

        if disabled_addr is None:
            if supported is True:
                state = Color.colorify("Unrestricted", "bold red")
                additional = "kernel.io_uring_disabled: not available"
                gef_print("{:<40s}: {:s} ({:s})".format("io_uring access", state, additional))
            else:
                gef_print("{:<40s}: {:s}".format("io_uring access", Color.grayify("Unknown")))
            return
        disabled = read_int32_from_memory(disabled_addr, safe=True)
        if disabled is None:
            gef_print("{:<40s}: {:s}".format("io_uring access", Color.grayify("Unknown")))
            return

        if disabled == 0:
            state = Color.colorify("Unrestricted", "bold red")
            additional = "kernel.io_uring_disabled=0"
        elif disabled == 1:
            state = Color.colorify("Privileged or group only", "bold yellow")
            group_addr = self.get_sysctl_addr("kernel.io_uring_group", "sysctl_io_uring_group")
            group = None
            if group_addr is not None:
                group = read_int32_from_memory(group_addr, safe=True)
            additional = "kernel.io_uring_disabled=1"
            if group is not None:
                additional += ", kernel.io_uring_group={:d}".format(group)
        elif disabled == 2:
            state = Color.colorify("Disabled", "bold green")
            additional = "kernel.io_uring_disabled=2"
        else:
            state = Color.grayify("Unknown")
            additional = "kernel.io_uring_disabled={:d}".format(disabled)
        gef_print("{:<40s}: {:s} ({:s})".format("io_uring access", state, additional))
        return

    def check_basic_information(self):
        kcmdline = Kernel.cmdline()
        if kcmdline is None or kcmdline.cmdline is None:
            gef_print("{:<40s}: {:s}".format("Kernel cmdline", "Not found"))
        else:
            gef_print("{:<40s}: {:s}".format("Kernel cmdline", kcmdline.cmdline.strip()))

        text_base = Kernel.layout().text_base
        if text_base is None:
            gef_print("{:<40s}: {:s}".format("Kernel base (heuristic)", "Not found"))
        else:
            gef_print("{:<40s}: {:#x}".format("Kernel base (heuristic)", text_base))

        stext = Ksym.get_addr("_stext")
        if stext is None:
            gef_print("{:<40s}: {:s}".format("Kernel base (_stext from kallsyms)", "Not found"))
        else:
            gef_print("{:<40s}: {:#x}".format("Kernel base (_stext from kallsyms)", stext))

        self.get_kconfig()
        if self.kconfig is None:
            additional = "CONFIG_* settings are inferred"
            gef_print("{:<40s}: {:s} ({:s})".format("Kernel config", "Not found", additional))
        else:
            additional = "CONFIG_* settings are taken from it"
            if self.kconfig_where:
                additional = "{:s}, {:s}".format(self.kconfig_where, additional)
            gef_print("{:<40s}: {:s} ({:s})".format("Kernel config", "Found", additional))
        return

    def x86_specific(self):
        if not is_x86():
            return

        cr0 = get_register("cr0", use_mbed_exec=True, use_monitor=True)
        cr4 = get_register("cr4", use_mbed_exec=True, use_monitor=True)
        efer = get_register("efer", use_monitor=True)

        bits = [
            ["Write Protection (CR0 bit 16)", cr0, "CR0", 16],
            ["PAE (CR4 bit 5)", cr4, "CR4", 5],
            ["SMEP (CR4 bit 20)", cr4, "CR4", 20],
            ["SMAP (CR4 bit 21)", cr4, "CR4", 21],
            ["CET (CR4 bit 23)", cr4, "CR4", 23],
        ]
        for name, reg, regname, bit in bits:
            if reg is None:
                additional = "{:s}: Not available".format(regname)
                gef_print("{:<40s}: {:s} ({:s})".format(name, Color.grayify("Unknown"), additional))
            elif (reg >> bit) & 1:
                gef_print("{:<40s}: {:s}".format(name, Color.colorify("Enabled", "bold green")))
            else:
                gef_print("{:<40s}: {:s}".format(name, Color.colorify("Disabled", "bold red")))

        if (cr4 is not None and not cr4 & (1 << 5)) or (efer is not None and not efer & (1 << 11)):
            state = Color.colorify("Disabled", "bold red")
        elif cr4 is None or efer is None:
            state = Color.grayify("Unknown")
        else:
            state = Color.colorify("Enabled", "bold green")
        gef_print("{:<40s}: {:s}".format("NX (CR4.PAE + EFER.NXE)", state))

        # CET MSR
        if cr4 is not None and (cr4 >> 23) & 1:
            MSR_IA32_S_CET = None
            if is_kvm_enabled():
                additional = "for more precisely, use `msr MSR_IA32_S_CET` without `-enable-kvm`"
            else:
                additional = "MSR_IA32_S_CET: Not available"
                try:
                    ret = gdb.execute("msr --quiet MSR_IA32_S_CET", to_string=True)
                    MSR_IA32_S_CET = int(ret, 16)
                except (gdb.error, ValueError):
                    pass
            if MSR_IA32_S_CET is None:
                gef_print("{:<40s}: {:s} ({:s})".format("CET SHSTK (MSR_IA32_S_CET bit 0)", Color.grayify("Unknown"), additional))
                gef_print("{:<40s}: {:s} ({:s})".format("CET IBT (MSR_IA32_S_CET bit 2)", Color.grayify("Unknown"), additional))
            else:
                if MSR_IA32_S_CET & 1:
                    gef_print("{:<40s}: {:s}".format("CET SHSTK (MSR_IA32_S_CET bit 0)", Color.colorify("Enabled", "bold green")))
                else:
                    gef_print("{:<40s}: {:s}".format("CET SHSTK (MSR_IA32_S_CET bit 0)", Color.colorify("Disabled", "bold red")))
                if (MSR_IA32_S_CET >> 2) & 1:
                    gef_print("{:<40s}: {:s}".format("CET IBT (MSR_IA32_S_CET bit 2)", Color.colorify("Enabled", "bold green")))
                else:
                    gef_print("{:<40s}: {:s}".format("CET IBT (MSR_IA32_S_CET bit 2)", Color.colorify("Disabled", "bold red")))
        return

    def arm32_specific(self):
        if not is_arm32():
            return

        # PXN
        ID_MMFR0 = get_register("$ID_MMFR0")
        ID_MMFR0_S = get_register("$ID_MMFR0_S")
        if ID_MMFR0 is not None and (ID_MMFR0 >> 2) & 1:
            gef_print("{:<40s}: {:s}".format("PXN (ID_MMFR0 bit 2)", Color.colorify("Enabled", "bold green")))
        elif ID_MMFR0_S is not None and (ID_MMFR0_S >> 2) & 1:
            gef_print("{:<40s}: {:s}".format("PXN (ID_MMFR0 bit 2)", Color.colorify("Enabled", "bold green")))
        elif is_kgdb() and ID_MMFR0 is None and ID_MMFR0_S is None:
            additional = "ID_MMFR0: Not available in KGDB mode"
            gef_print("{:<40s}: {:s} ({:s})".format("PXN (ID_MMFR0 bit 2)", Color.grayify("Unknown"), additional))
        else:
            gef_print("{:<40s}: {:s}".format("PXN (ID_MMFR0 bit 2)", Color.colorify("Disabled", "bold red")))

        # PAN
        gef_print("{:<40s}: {:s} (all ARMv7 is unsupported)".format("PAN", Color.colorify("Disabled", "bold red")))
        return

    def arm64_specific(self):
        if not is_arm64():
            return

        # PXN
        gef_print("{:<40s}: {:s} (all ARMv8~ is supported)".format("PXN", Color.colorify("Enabled", "bold green")))

        # PAN
        ID_AA64MMFR1_EL1 = get_register("$ID_AA64MMFR1_EL1", use_mbed_exec=True)
        if ID_AA64MMFR1_EL1 is not None and ((ID_AA64MMFR1_EL1 >> 20) & 0b1111) != 0b0000:
            gef_print("{:<40s}: {:s}".format("PAN (ID_AA64MMFR1_EL1 bit 23-20)", Color.colorify("Enabled", "bold green")))
        else:
            gef_print("{:<40s}: {:s}".format("PAN (ID_AA64MMFR1_EL1 bit 23-20)", Color.colorify("Disabled", "bold red")))
        return

    def get_x86_link_address(self):
        _, physical_start = self.get_config("CONFIG_PHYSICAL_START")
        _, physical_align = self.get_config("CONFIG_PHYSICAL_ALIGN")
        _, page_offset = self.get_config("CONFIG_PAGE_OFFSET")
        try:
            physical_start = int(physical_start, 16)
            physical_align = int(physical_align, 16)
        except (TypeError, ValueError):
            physical_start, physical_align = 0x100_0000, 0x20_0000
        load_physical_addr = align(physical_start, physical_align)
        if is_x86_64():
            return 0xffff_ffff_8000_0000 + load_physical_addr # __START_KERNEL_map
        try:
            return int(page_offset, 16) + load_physical_addr
        except (TypeError, ValueError):
            return 0xc000_0000 + load_physical_addr

    def check_kaslr(self):
        cfg = "CONFIG_RANDOMIZE_BASE (KASLR)"
        kcmdline = Kernel.cmdline()
        kversion = Kernel.version()

        # build-time
        name, value = self.get_config("CONFIG_RANDOMIZE_BASE")
        if value is not None:
            build = value == "y"
            build_str = self.config_str(name, value)
        else:
            # Some `*kaslr*` exist regardless of CONFIG_RANDOMIZE_BASE (e.g. kaslr_requires_kpti of ARM64),
            # so use only the symbols of the code that is built with it.
            kaslr_only_symbols = [
                "kaslr_get_random_long", "init_trampoline_kaslr", "kernel_randomize_memory", # x86 4.8~
                "kaslr_early_init", "__pi_kaslr_early_init", "kaslr_init", # ARM64 4.6~
            ]
            found = [sym for sym in kaslr_only_symbols if Ksym.get_addr(sym) is not None]
            if found:
                build = True
                build_str = "{:s}: Found".format(found[0])
            else:
                others = sorted({Ksym.get_name(addr) or "?" for addr in Ksym.get_addrs("kaslr", match="in")})
                others = [x for x in others if not x.startswith(("__setup", "__initcall", "__pfx_", "__cfi_"))]
                build_str = "KASLR specific symbols: Not found"
                if others:
                    build_str += " ({:s}: Found, but not specific)".format(", ".join(others[:3]))
                # x86 3.14~4.7 has no such symbols in vmlinux, so leave it to the runtime check
                if is_x86() and "3.14" <= kversion < "4.8":
                    build = None
                else:
                    build = False

        # runtime
        randomized = None
        definite = False
        runtime_str = None
        if build is not False:
            if kcmdline and "nokaslr" in kcmdline.cmdline:
                randomized, definite = False, True
                runtime_str = "nokaslr is in cmdline"
            elif is_arm64() and Ksym.get_addr("__kaslr_is_enabled") is not None:
                v = read_int8_from_memory(Ksym.get_addr("__kaslr_is_enabled"), safe=True)
                if v is not None:
                    randomized, definite = bool(v), True
                    runtime_str = "__kaslr_is_enabled: {:d}".format(v)
            elif is_x86():
                text = Ksym.get_addr("_text") or Kernel.layout().text_base
                if text is not None:
                    link = self.get_x86_link_address()
                    randomized = text != link
                    runtime_str = "_text {:s} link address {:#x}".format("!=" if randomized else "==", link)
                    if self.kconfig is None:
                        runtime_str += " (assuming CONFIG_PHYSICAL_START=0x1000000)"
            if runtime_str is None and kcmdline:
                runtime_str = "nokaslr is not in cmdline"

        additional = build_str
        if runtime_str:
            additional += ", runtime: " + runtime_str
        if build is False:
            state = Color.colorify("Unsupported", "bold red")
        elif randomized is False:
            state = Color.colorify("Disabled" if definite else "Disabled (maybe)", "bold red")
        elif randomized is True:
            state = Color.colorify("Enabled" if build else "Enabled (maybe)", "bold green")
        elif build:
            state = Color.colorify("Enabled", "bold green")
        else:
            state = Color.grayify("Unknown")
        gef_print("{:<40s}: {:s} ({:s})".format(cfg, state, additional))
        return

    def check_fgkaslr(self):
        if not is_x86_64():
            return

        # https://github.com/alobakin/linux/pull/3
        cfg = "CONFIG_FG_KASLR (FGKASLR)"

        name, value = self.get_config("CONFIG_FG_KASLR")
        if value is not None:
            additional = self.config_str(name, value)
            if value != "y":
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            else:
                kcmdline = Kernel.cmdline()
                for opt in ["nokaslr", "nofgkaslr", "fgkaslr=off"]:
                    if kcmdline and opt in kcmdline.cmdline:
                        additional += ", runtime: {:s} is in cmdline".format(opt)
                        gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
                        break
                else:
                    gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            self.print_kconfig_state("CONFIG_MODULE_FG_KASLR (FGKASLR)", names=["CONFIG_MODULE_FG_KASLR"])
            return

        kversion = Kernel.version()
        if kversion < "5.5":
            # https://lore.kernel.org/kernel-hardening/20200205223950.1212394-1-kristen@linux.intel.com/
            additional = "FGKASLR was first proposed in 5.5.0-rc7"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            cfg = "CONFIG_MODULE_FG_KASLR (FGKASLR)"
            gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("Unsupported", "bold red")))
            return

        if "6.14" <= kversion:
            # As of 6.14, the following detection logic is no longer available.
            # It has not yet been incorporated into the mainline, and no samples are available.
            # Therefore, this check is disabled.
            gef_print("{:<40s}: {:s}".format(cfg, Color.grayify("Unknown")))
            cfg = "CONFIG_MODULE_FG_KASLR (FGKASLR)"
            gef_print("{:<40s}: {:s}".format(cfg, Color.grayify("Unknown")))
            return

        swapgs_restore_regs_and_return_to_usermode = Ksym.get_addr("swapgs_restore_regs_and_return_to_usermode")
        commit_creds = Ksym.get_addr("commit_creds")

        # something is wrong
        if not swapgs_restore_regs_and_return_to_usermode or not commit_creds:
            gef_print("{:<40s}: {:s}".format(cfg, Color.grayify("Unknown")))
            cfg = "CONFIG_MODULE_FG_KASLR (FGKASLR)"
            gef_print("{:<40s}: {:s}".format(cfg, Color.grayify("Unknown")))
            return

        # swapgs_restore_regs_and_return_to_usermode is in a fixed location.
        # commit_creds are placed dynamically.
        if swapgs_restore_regs_and_return_to_usermode < commit_creds: # For some reason this works fine
            kcmdline = Kernel.cmdline()
            if kcmdline and "nokaslr" in kcmdline.cmdline:
                additional = "nokaslr is in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            elif kcmdline and "nofgkaslr" in kcmdline.cmdline:
                additional = "nofgkaslr is in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            elif kcmdline and "fgkaslr=off" in kcmdline.cmdline:
                additional = "fgkaslr=off is in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            else:
                additional = "swapgs_restore_regs_and_return_to_usermode < commit_creds"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            # Could not build detection logic for CONFIG_MODULE_FG_KASLR.
            # But there is no way to disable it except at build time.
            # It's included in the patch that introduces FGKASLR, so it is assumed to be always enabled.
            cfg = "CONFIG_MODULE_FG_KASLR (FGKASLR)"
            gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("Enabled (maybe)", "bold green")))
        else:
            additional = "swapgs_restore_regs_and_return_to_usermode > commit_creds"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            cfg = "CONFIG_MODULE_FG_KASLR (FGKASLR)"
            gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("Unsupported", "bold red")))
        return

    def check_kpti(self):
        kversion = Kernel.version()
        if is_arm64():
            cfg = "CONFIG_UNMAP_KERNEL_AT_EL0 (KPTI)"
        elif "6.9" <= kversion:
            cfg = "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION (KPTI)"
        else:
            cfg = "CONFIG_PAGE_TABLE_ISOLATION (KPTI)"
        kcmdline = Kernel.cmdline()

        if is_arm32():
            gef_print("{:<40s}: {:s} (ARMv7 is unsupported)".format(cfg, Color.colorify("Unsupported", "bold red")))
            return

        # build-time
        if is_arm64():
            name, value = self.get_config("CONFIG_UNMAP_KERNEL_AT_EL0")
            symbols = ["map_entry_trampoline", "idmap_kpti_install_ng_mappings"]
        else:
            name, value = self.get_config("CONFIG_MITIGATION_PAGE_TABLE_ISOLATION", "CONFIG_PAGE_TABLE_ISOLATION")
            symbols = ["pti_init", "kaiser_init"] # kaiser_init: KAISER backported to 4.4.y and 4.9.y
        if value is not None:
            build_str = self.config_str(name, value)
            if value != "y":
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), build_str))
                return
        else:
            found = [sym for sym in symbols if Ksym.get_addr(sym) is not None]
            if not found:
                build_str = "{:s}: Not found".format(symbols[0])
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), build_str))
                return
            build_str = "{:s}: Found".format(found[0])

        # runtime
        state = None
        runtime_str = None
        if is_x86():
            if kcmdline and "nopti" in kcmdline.cmdline:
                state, runtime_str = "Disabled", "nopti is in cmdline"
            elif kcmdline and "pti=off" in kcmdline.cmdline:
                state, runtime_str = "Disabled", "pti=off is in cmdline"
            elif kcmdline and "mitigations=off" in kcmdline.cmdline:
                state, runtime_str = "Disabled", "mitigations=off is in cmdline"
            elif kcmdline and "pti=on" in kcmdline.cmdline:
                state, runtime_str = "Enabled", "pti=on is in cmdline"
            elif is_kgdb():
                # A whole pagewalk reads too much memory over KGDB.
                runtime_str = "pagewalk is skipped in KGDB mode"
            elif is_in_kernel():
                maps = AddrMap.get_maps(command="pagewalk --quiet --no-pager --simple --disable-color")
                if not maps:
                    runtime_str = "pagewalk gave no memory map"
                else:
                    for entry in maps:
                        if "USER" in entry.flags and entry.is_executable():
                            # If the qemu startup option does not include `-cpu kvm64`,
                            # isolation will not occur even if KPTI is enabled.
                            state, runtime_str = "Disabled", "USER memory has R-X permission in kernel context"
                            break
                    else:
                        state, runtime_str = "Enabled (maybe)", "USER memory has no R-X permission in kernel context"

        elif is_arm64():
            use_ng_mappings = Ksym.get_addr("arm64_use_ng_mappings")
            if use_ng_mappings is not None:
                use_ng_mappings = read_int8_from_memory(use_ng_mappings, safe=True)
            text_flags = None
            if use_ng_mappings is None and not is_kgdb():
                # KPTI maps the kernel with nG, so it is the runtime state itself
                try:
                    ret = gdb.execute("pagewalk --quiet --no-pager --disable-color --trace {:#x}".format(Ksym.get_addr("_stext")), to_string=True)
                except gdb.error:
                    ret = ""
                r = re.findall(r"^0x[0-9a-f]+-0x[0-9a-f]+\s+.*\[(EL0/.*)\]$", ret, re.M)
                if r:
                    text_flags = r[-1].split()
            if use_ng_mappings is not None:
                if use_ng_mappings:
                    state = "Enabled"
                else:
                    state = "Disabled"
                runtime_str = "arm64_use_ng_mappings: {:d}".format(use_ng_mappings)
            elif text_flags is not None:
                if "GLOBAL" in text_flags:
                    state, runtime_str = "Disabled", "kernel text is mapped as GLOBAL"
                else:
                    state, runtime_str = "Enabled", "kernel text is mapped as non-GLOBAL (nG)"
            elif kcmdline and "kpti=0" in kcmdline.cmdline:
                state, runtime_str = "Disabled", "kpti=0 is in cmdline"
            elif kcmdline and "mitigations=off" in kcmdline.cmdline and "nokaslr" in kcmdline.cmdline:
                state, runtime_str = "Disabled", "mitigations=off and nokaslr are in cmdline"
            elif kcmdline and "mitigations=off" in kcmdline.cmdline and "nokaslr" not in kcmdline.cmdline:
                state, runtime_str = "Enabled", "mitigations=off is in cmdline, nokaslr is not in cmdline"
            elif kcmdline and "kpti=1" in kcmdline.cmdline:
                state, runtime_str = "Enabled", "kpti=1 is in cmdline"
            else:
                state = "Enabled (maybe)"

        additional = build_str
        if runtime_str:
            additional += ", runtime: " + runtime_str
        if state is None:
            state = Color.grayify("Unknown")
        elif state.startswith("Enabled"):
            state = Color.colorify(state, "bold green")
        else:
            state = Color.colorify(state, "bold red")
        gef_print("{:<40s}: {:s} ({:s})".format(cfg, state, additional))
        return

    def get_module_ranges(self):
        ranges = []
        for name, start, size in self.get_loaded_modules() or []:
            if size:
                ranges.append((start, start + size, name))
        return ranges

    def check_rwx_page(self):
        klayout = Kernel.layout()
        if not klayout.maps:
            for name in ["Kernel image W^X", "Module W^X", "Other vmalloc/JIT W^X"]:
                gef_print("{:<40s}: {:s}".format(name, Color.grayify("Unknown")))
            return

        module_ranges = self.get_module_ranges()
        module_area = None
        try:
            constants = KernelAddressHeuristicFinder.consts()
            if constants.MODULES_VADDR is not None and constants.MODULES_END is not None:
                module_area = tuple(sorted((constants.MODULES_VADDR, constants.MODULES_END)))
        except (AttributeError, TypeError):
            pass

        kernel_bounds = [
            value for value in [
                klayout.text_base, klayout.text_end, klayout.ro_base, klayout.ro_end, klayout.rw_base, klayout.rw_end,
            ] if value not in (None, 0)
        ]
        if kernel_bounds:
            kernel_area = (min(kernel_bounds), max(kernel_bounds))
        else:
            kernel_area = None
        categories = {"kernel": [], "module": [], "other": []}

        for entry in klayout.maps:
            if not entry.is_writable() or not entry.is_executable():
                continue
            start, end = entry.vstart, entry.vend
            label = ""
            for module_start, module_end, module_name in module_ranges:
                if start < module_end and module_start < end:
                    label = module_name
                    categories["module"].append((start, end, label))
                    break
            else:
                if kernel_area and start < kernel_area[1] and kernel_area[0] < end:
                    label = Symbol.format(start)
                    categories["kernel"].append((start, end, label))
                elif module_area and start < module_area[1] and module_area[0] < end:
                    categories["other"].append((start, end, "module allocation area (unresolved/JIT)"))
                else:
                    label = Symbol.format(start)
                    categories["other"].append((start, end, label))

        def print_category(name, entries):
            additional = []
            if entries:
                for start, end, label in entries[:4]:
                    if label:
                        suffix = " {:s}".format(label)
                    else:
                        suffix = ""
                    additional.append("{:#x}-{:#x}{:s}".format(start, end, suffix))
                if len(entries) > 4:
                    additional.append("... +{:d} more".format(len(entries) - 4))
                state = Color.colorify("Found", "bold red")
                additional.insert(0, "{:d} observed mapping(s)".format(len(entries)))
            else:
                state = Color.colorify("Not found", "bold green")
                additional.append("observed page tables")
            gef_print("{:<40s}: {:s} ({:s})".format(name, state, ", ".join(additional)))
            return

        print_category("Kernel image W^X", categories["kernel"])
        print_category("Module W^X", categories["module"])
        print_category("Other vmalloc/JIT W^X", categories["other"])
        return

    def check_secure_world(self):
        if not is_arm32() and not is_arm64():
            return

        # The secure memory is found from the memory tree of QEMU.
        if is_kgdb():
            gef_print("{:<40s}: {:s}".format("Secure world", Color.grayify("Unknown")))
        elif is_support_secure_world():
            gef_print("{:<40s}: {:s}".format("Secure world", "Found"))
        else:
            gef_print("{:<40s}: {:s}".format("Secure world", "Not found"))
        return

    def check_CONFIG_SLAB_FREELIST_HARDENED(self):
        cfg = "CONFIG_SLAB_FREELIST_HARDENED"
        if self.print_kconfig_state(cfg):
            return

        # Dumping the freelists reads too much memory over KGDB, so use the debug information.
        if is_kgdb():
            offset = GefUtil.offsetof("kmem_cache", "random")
            if GefUtil.sizeof("kmem_cache") is None:
                additional = "struct kmem_cache: Not found in debug information"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            elif offset is None:
                additional = "offsetof(kmem_cache, random): Not found"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            else:
                additional = "offsetof(kmem_cache, random): {:#x}".format(offset)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            return

        slab_cache_names = " ".join("kmalloc-{:d}".format(n) for n in [8, 16, 32, 64, 96, 128, 192, 256, 512])
        slub_dump_ret = gdb.execute("slub-dump --quiet --no-pager {:s}".format(slab_cache_names), to_string=True)
        if slub_dump_ret.count("Corrupted") >= 2: # Destruction of up to one SLUB freelist is allowed.
            gef_print("{:<40s}: {:s}".format(cfg, Color.grayify("Unknown")))
            return

        slub_dump_ret = gdb.execute("slub-dump --meta", to_string=True)
        r = re.search(r"offsetof\(kmem_cache, random\): (0x\S+)", slub_dump_ret)
        if r:
            additional = "offsetof(kmem_cache, random): {:s}".format(r.group(1))
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        else:
            additional = "offsetof(kmem_cache, random): Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_CONFIG_SLAB_FREELIST_RANDOM(self):
        cfg = "CONFIG_SLAB_FREELIST_RANDOM"
        if self.print_kconfig_state(cfg):
            return

        # Walking the caches reads too much memory over KGDB, so use the debug information.
        if is_kgdb():
            offset = GefUtil.offsetof("kmem_cache", "random_seq")
            if GefUtil.sizeof("kmem_cache") is None:
                additional = "struct kmem_cache: Not found in debug information"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            elif offset is None:
                additional = "offsetof(kmem_cache, random_seq): Not found"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            else:
                additional = "offsetof(kmem_cache, random_seq): {:#x}".format(offset)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            return

        try:
            if Kernel.get_slab_type() == "SLUB":
                slub = Kernel.slub()
            else:
                slub = None
            if slub is not None:
                slub.warmup_page2virt()
            initialized = slub is not None and slub.initialize()
            if initialized:
                offset = slub.kmem_cache_offset_random_seq
            else:
                offset = None
        except gdb.error:
            offset = None
            initialized = False
        if not initialized:
            gef_print("{:<40s}: {:s}".format(cfg, Color.grayify("Unknown")))
            return
        if offset is None:
            additional = "offsetof(kmem_cache, random_seq): Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            return

        selected = []
        try:
            for list_entry in slub.parse_kmem_caches_for_initialize():
                cache = list_entry - slub.kmem_cache_offset_list
                name_ptr = read_int_from_memory(cache + slub.kmem_cache_offset_name)
                name = read_cstring_from_memory(name_ptr)
                if re.match(r"^kmalloc-(?:8|16|32|64|96|128|192|256|512)$", name):
                    selected.append(cache)
        except gdb.MemoryError:
            selected = []

        enabled = 0
        checked = 0
        for cache in selected:
            random_seq = read_int_from_memory(cache + offset, safe=True)
            if random_seq is None:
                continue
            checked += 1
            if random_seq and is_valid_addr(random_seq):
                enabled += 1

        additional = "random_seq at {:#x} offset, {:d}/{:d} representative caches".format(offset, enabled, checked)
        if checked == 0:
            state = Color.grayify("Unknown")
        elif enabled == checked:
            state = Color.colorify("Enabled", "bold green")
        elif enabled == 0:
            state = Color.colorify("Disabled", "bold red")
        else:
            state = Color.colorify("Partial", "bold yellow")
        gef_print("{:<40s}: {:s} ({:s})".format(cfg, state, additional))
        return

    def check_CONFIG_SLAB_VIRTUAL(self):
        cfg = "CONFIG_SLAB_VIRTUAL"
        # https://patchwork.kernel.org/project/linux-mm/patch/20230915105933.495735-12-matteorizzo@google.com/#25548022
        stw = "slub_tlbflush_worker"
        name, value = self.get_config(cfg)
        if value is not None:
            build = value == "y"
            build_str = self.config_str(name, value)
        else:
            build = Ksym.get_addr(stw) is not None
            build_str = "{:s}: {:s}".format(stw, "Found" if build else "Not found")
        if not build:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), build_str))
            return

        kversion = Kernel.version()
        if kversion < "6.6":
            additional = "{:s} (kernel version < 6.6)".format(build_str)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        else:
            # If version is >= 6.6, vmlinux can switch `slab_virtual` status with boot-parameter
            kcmdline = Kernel.cmdline()
            if kcmdline:
                r = re.search(r"slab_virtual=(\d+)", kcmdline.cmdline)
            else:
                r = None
            if kcmdline is None:
                additional = "{:s}, runtime: cmdline: Not found".format(build_str)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            elif r:
                additional = "{:s}, runtime: {:s} is in cmdline".format(build_str, r.group(0))
                if r.group(1) == "0":
                    gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
                else:
                    gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            else:
                additional = "{:s}, runtime: slab_virtual is NOT in cmdline".format(build_str)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_selinux(self):
        cfg = "SELinux"
        # SELinux does not support being built as a kernel module.
        # Therefore, only symbols in the kernel can be used to determine whether SELinux is supported or not.
        selinux_init = Ksym.get_addr("selinux_init")
        if selinux_init is None:
            additional = "selinux_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        kversion = Kernel.version()
        if kversion < "4.17":
            selinux_enabled_addr = Ksym.get_addr("selinux_enabled")
            selinux_enforcing_addr = Ksym.get_addr("selinux_enforcing")
            if selinux_enabled_addr is None:
                additional = "selinux_init: Found, selinux_enabled: Not detected"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
                return

            if selinux_enforcing_addr is None:
                additional = "selinux_init: Found, seliux_enforcing: Not detected"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
                return

            selinux_enabled = read_int32_from_memory(selinux_enabled_addr)
            selinux_enforcing = read_int32_from_memory(selinux_enforcing_addr)
            additional = "selinux_init: Found, selinux_enabled: {:d}, selinux_enforcing: {:d}".format(
                selinux_enabled, selinux_enforcing,
            )
            if selinux_enabled == 0:
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            elif selinux_enforcing == 0:
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Permissive", "bold red"), additional))
            else:
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enforcing", "bold green"), additional))
            return

        # 4.17 <= kernel
        """
        struct selinux_state {
        #ifdef CONFIG_SECURITY_SELINUX_DISABLE
            abool disabled;
        #endif
        #ifdef CONFIG_SECURITY_SELINUX_DEVELOP
            abool enforcing;
        #endif
            abool checkreqprot;
            abool initialized;
            abool policycap[__POLICYDB_CAP_MAX]; # __POLICYDB_CAP_MAX:6 ~ 8 bytes
            astruct page *status_page;
            astruct mutex status_lock;
            astruct selinux_avc *avc;
            astruct selinux_policy __rcu *policy;
            astruct mutex policy_mutex;
        } __randomize_layout;

        x64 sample
        gef> x/16xg 0xffffffff8ba20740
        0xffffffff8ba20740:     0x0100010101010001      0x0000000000000001
        0xffffffff8ba20750:     0xffffe3bc00215140      0x0000000000000000
        0xffffffff8ba20760:     0x0000000000000000      0xffffffff8ba20768
        0xffffffff8ba20770:     0xffffffff8ba20768      0xffffffff8ba1ef20
        0xffffffff8ba20780:     0xffff8ecc7fe62800      0x0000000000000000
        """

        selinux_state = KernelAddressHeuristicFinder.get_selinux_state()

        if selinux_state is None:
            additional = "selinux_init: Found, selinux_state: Not detected"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        if read_int64_from_memory(selinux_state) == 0:
            additional = "selinux_init: Found, selinux_state: Not initialized"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            return

        selinux_disable = Ksym.get_addr("selinux_disable")
        CONFIG_SECURITY_SELINUX_DISABLE = selinux_disable is not None
        enforcing_setup = Ksym.get_addr("enforcing_setup")
        CONFIG_SECURITY_SELINUX_DEVELOP = enforcing_setup is not None

        # selinux_state.disabled
        if CONFIG_SECURITY_SELINUX_DISABLE:
            selinux_disabled = read_int8_from_memory(selinux_state)
            additional = "selinux_init: Found, selinux_state.disable: {:d}".format(selinux_disabled)
        else:
            selinux_disabled = None
            additional = "selinux_init: Found, selinux_state.disable: Not found"

        # selinux_state.enforcing
        if CONFIG_SECURITY_SELINUX_DEVELOP and CONFIG_SECURITY_SELINUX_DISABLE:
            selinux_enforcing = read_int8_from_memory(selinux_state + 1)
            additional += ", selinux_state.enforcing: {:d}".format(selinux_enforcing)
        elif CONFIG_SECURITY_SELINUX_DEVELOP and not CONFIG_SECURITY_SELINUX_DISABLE:
            selinux_enforcing = read_int8_from_memory(selinux_state)
            additional += ", selinux_state.enforcing: {:d}".format(selinux_enforcing)
        else:
            selinux_enforcing = True
            additional += ", selinux_state.enforcing: Not found"

        if selinux_disabled:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        elif not selinux_enforcing:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Permissive", "bold red"), additional))
        elif selinux_enforcing:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enforcing", "bold green"), additional))
        return

    def check_smack(self):
        cfg = "SMACK"
        smack_init = Ksym.get_addr("smack_init")
        if smack_init is None:
            additional = "smack_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        kfilesystems_ret = gdb.execute("kfilesystems --quiet --no-pager --skip-mount-path", to_string=True)
        if not kfilesystems_ret:
            additional = "smack_init: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        if "smackfs" in kfilesystems_ret:
            additional = "smack_init: Found, smackfs: Mounted"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        else:
            additional = "smack_init: Found, smackfs: Not mounted"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_apparmor(self):
        cfg = "AppArmor"
        apparmor_init = Ksym.get_addr("apparmor_init")
        if apparmor_init is None:
            additional = "apparmor_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        apparmor_enabled_addr = KernelAddressHeuristicFinder.get_apparmor_enabled()
        apparmor_initialized_addr = KernelAddressHeuristicFinder.get_apparmor_initialized()
        if apparmor_enabled_addr is None:
            additional = "apparmor_init: Found, apparmor_enabled: Not detected"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        kversion = Kernel.version()
        if kversion < "5.1":
            apparmor_enabled = read_int8_from_memory(apparmor_enabled_addr) # bool
        else:
            apparmor_enabled = read_int32_from_memory(apparmor_enabled_addr) # int

        if apparmor_enabled not in [0, 1]:
            additional = "apparmor_init: Found, apparmor_enabled: {:#x}".format(apparmor_enabled)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        # `apparmor_initialized` is __initdata and freed after boot before v4.12, so trust it
        # only when the finder actually located it. Otherwise the verdict rests on apparmor_enabled.
        apparmor_initialized = None
        if apparmor_initialized_addr is not None:
            apparmor_initialized = read_int32_from_memory(apparmor_initialized_addr)
            if apparmor_initialized not in [0, 1]:
                additional = "apparmor_init: Found, apparmor_initialized: {:#x}".format(apparmor_initialized)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
                return

        additional = "apparmor_init: Found"
        if apparmor_initialized is not None:
            additional += ", apparmor_initialized: {:d}".format(apparmor_initialized)
        additional += ", apparmor_enabled: {:d}".format(apparmor_enabled)
        if apparmor_enabled == 0:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        elif apparmor_initialized == 0:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def check_tomoyo(self):
        cfg = "TOMOYO"
        tomoyo_init = Ksym.get_addr("tomoyo_init")
        if tomoyo_init is None:
            additional = "tomoyo_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        tomoyo_enabled_addr = KernelAddressHeuristicFinder.get_tomoyo_enabled()
        if tomoyo_enabled_addr is None:
            additional = "tomoyo_init: Found, tomoyo_enabled: Not detected"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        tomoyo_enabled = read_int32_from_memory(tomoyo_enabled_addr)
        additional = "tomoyo_init: Found, tomoyo_enabled: {:d}".format(tomoyo_enabled)
        if tomoyo_enabled == 0:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def is_yama_initialized(self):
        # Returns True, False or None (unknown), and the reason if False.
        # Until v4.1, yama_init() returns early unless Yama is the major LSM or CONFIG_SECURITY_YAMA_STACKED=y.
        # Since v5.1, yama_init() is not called unless Yama is in the LSM order (CONFIG_LSM or lsm=).
        # Then Yama restricts nothing, though `ptrace_scope` keeps its initial value 1.

        # v4.2 - v5.0 always register Yama
        if Ksym.get_addr("yama_add_hooks") is not None:
            return True, None

        # v4.1 or earlier
        security_ops = Ksym.get_addr("security_ops")
        if security_ops is not None:
            # CONFIG_SECURITY_YAMA_STACKED=y has no yama_ops, and the hooks of Yama are called directly
            yama_ops = Ksym.get_addr("yama_ops")
            if yama_ops is None:
                return True, None
            ops = read_int_from_memory(security_ops)
            if ops == yama_ops:
                return True, None
            name = read_cstring_from_memory(ops, 16, safe=True) or "???"
            return False, "security_ops: {:s}".format(name)

        # v4.15 - v6.18
        lsm_names = Ksym.get_addr("lsm_names")
        if lsm_names is not None:
            names = read_cstring_from_memory(read_int_from_memory(lsm_names), 256, safe=True)
            if names is not None:
                if "yama" in names.split(","):
                    return True, None
                return False, "lsm_names: {:s}".format(names)

        # v6.19 or later
        lsm_idlist = Ksym.get_addr("lsm_idlist")
        lsm_active_cnt = Ksym.get_addr("lsm_active_cnt")
        if lsm_idlist is not None and lsm_active_cnt is not None:
            names = []
            for i in range(read_int32_from_memory(lsm_active_cnt)):
                lsmid = read_int_from_memory(lsm_idlist + runtime.current_arch.ptrsize * i)
                names.append(read_cstring_from_memory(read_int_from_memory(lsmid), 32, safe=True) or "???")
            if "yama" in names:
                return True, None
            return False, "lsm_idlist: {:s}".format(",".join(names))

        # A sysctl tree walk reads too much memory over KGDB.
        if is_kgdb() or not Kernel.sysctl().initialize():
            return None, None
        if KernelSysctl.get("kernel.yama.ptrace_scope") is None:
            return False, "kernel.yama.ptrace_scope: Not registered"
        return True, None

    def check_yama(self):
        cfg = "Yama (ptrace_scope)"
        # v4.2 - v5.0 have yama_add_hooks() instead
        yama_init_name = "yama_init"
        if Ksym.get_addr("yama_add_hooks") is not None:
            yama_init_name = "yama_add_hooks"
        yama_init = Ksym.get_addr(yama_init_name)
        if yama_init is None:
            additional = "yama_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        initialized, reason = self.is_yama_initialized()
        if initialized is False:
            additional = "{:s}: Found, {:s}".format(yama_init_name, reason)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            return

        ptrace_scope_addr = KernelAddressHeuristicFinder.get_ptrace_scope()
        if initialized is None or ptrace_scope_addr is None:
            additional = "{:s}: Found, kernel.yama.ptrace_scope: Not found".format(yama_init_name)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        ptrace_scope = read_int32_from_memory(ptrace_scope_addr)
        additional = "{:s}: Found, kernel.yama.ptrace_scope: {:d}".format(yama_init_name, ptrace_scope)
        if ptrace_scope == 0:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def check_integrity(self):
        cfg = "Integrity (IMA/EVM)"
        # integrity_iintcache_init only means CONFIG_INTEGRITY=y and it is removed from linux 6.9,
        # so use the initializer of each feature instead.
        ima_init = Ksym.get_addr("ima_init")
        init_evm = Ksym.get_addr("init_evm")
        found = "ima_init: {:s}, init_evm: {:s}".format(
            "Found" if ima_init is not None else "Not found",
            "Found" if init_evm is not None else "Not found",
        )
        if ima_init is None and init_evm is None:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), found))
            return

        # ima_appraise= is meaningless if IMA itself is not compiled in.
        if ima_init is not None:
            kcmdline = Kernel.cmdline()
        else:
            kcmdline = None
        if kcmdline and "ima_appraise=enforce" in kcmdline.cmdline:
            additional = found + ", ima_appraise=enforce is in cmdline"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        elif kcmdline and "ima_appraise=off" in kcmdline.cmdline:
            additional = found + ", ima_appraise=off is in cmdline"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        elif kcmdline and "ima_appraise=log" in kcmdline.cmdline:
            additional = found + ", ima_appraise=log is in cmdline"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Permissive", "bold red"), additional))
        elif kcmdline and "ima_appraise=fix" in kcmdline.cmdline:
            additional = found + ", ima_appraise=fix is in cmdline"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Permissive", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", found))
        return

    def check_loadpin(self):
        cfg = "LoadPin"
        loadpin_init = Ksym.get_addr("loadpin_init")
        if loadpin_init is None:
            additional = "loadpin_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        kversion = Kernel.version()
        if kversion < "4.20":
            loadpin_cfg_name = "kernel.loadpin.enabled"
            loadpin_cfg_addr = KernelAddressHeuristicFinder.get_loadpin_enabled()
        else:
            loadpin_cfg_name = "kernel.loadpin.enforce"
            loadpin_cfg_addr = KernelAddressHeuristicFinder.get_loadpin_enforce()

        if loadpin_cfg_addr is None:
            additional = "loadpin_init: Found, {:s}: Not found".format(loadpin_cfg_name)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        loadpin_status = read_int32_from_memory(loadpin_cfg_addr)
        additional = "loadpin_init: Found, {:s}: {:d}".format(loadpin_cfg_name, loadpin_status)
        if loadpin_status == 0:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def check_safe_setid(self):
        cfg = "SafeSetID"
        safesetid_security_init = Ksym.get_addr("safesetid_security_init")
        if safesetid_security_init is None:
            additional = "safesetid_security_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        additional = "safesetid_security_init: Found"
        gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
        return

    def check_lockdown(self):
        cfg = "Lockdown"

        kversion = Kernel.version()
        if kversion < "5.4":
            additional = "{:s}: implemented from linux 5.4".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unimplemented", "bold red"), additional))
            return

        lockdown_lsm_init = Ksym.get_addr("lockdown_lsm_init")
        if lockdown_lsm_init is None:
            additional = "lockdown_lsm_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        kernel_locked_down = KernelAddressHeuristicFinder.get_kernel_locked_down()
        if kernel_locked_down is None:
            additional = "lockdown_lsm_init: Found, kernel_locked_down: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        val = read_int32_from_memory(kernel_locked_down, safe=True)
        if val is None:
            additional = "lockdown_lsm_init: Found, kernel_locked_down: Memory read error"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        if val == 0:
            additional = "lockdown_lsm_init: Found, kernel_locked_down: 0 (none)"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            if val == 1:
                additional = "lockdown_lsm_init: Found, kernel_locked_down: 1 (integrity)"
            elif val == 2:
                additional = "lockdown_lsm_init: Found, kernel_locked_down: 2 (confidentiality)"
            else:
                additional = "lockdown_lsm_init: Found, kernel_locked_down: {:d}".format(val)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def check_bpf(self):
        cfg = "BPF"
        bpf_lsm_init = Ksym.get_addr("bpf_lsm_init")
        if bpf_lsm_init is None:
            additional = "bpf_lsm_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        additional = "bpf_lsm_init: Found"
        gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
        return

    def check_landlock(self):
        cfg = "Landlock"
        landlock_init = Ksym.get_addr("landlock_init")
        if landlock_init is None:
            additional = "landlock_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        additional = "landlock_init: Found"
        gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
        return

    def check_lkrg(self):
        cfg = "Linux Kernel Runtime Guard (LKRG)"
        modules = self.get_loaded_modules()
        if modules is None and not self.is_modules_supported():
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), "CONFIG_MODULES=n"))
            return
        if modules is None:
            additional = "kmod is failed"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        if "lkrg" in [name for name, _start, _size in modules]:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), "Loaded"))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), "Not loaded"))
        return

    def check_unprivileged_userfaultfd(self):
        cfg = "vm.unprivileged_userfaultfd"

        stv_uff_ret = gdb.execute("ksyscalls -f userfaultfd --quiet --no-pager", to_string=True)
        if "userfaultfd" not in stv_uff_ret:
            additional = "userfaultfd syscall: Unimplemented"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Syscall unsupported", "bold green"), additional))
            return

        if "invalid userfaultfd" in stv_uff_ret:
            additional = "userfaultfd syscall: Disabled"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Syscall unsupported", "bold green"), additional))
            return

        kversion = Kernel.version()
        if kversion < "5.2":
            additional = "userfaultfd syscall: Enabled; sysctl unavailable before Linux 5.2"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unrestricted", "bold red"), additional))
            return

        sysctl_unprivileged_userfaultfd = KernelAddressHeuristicFinder.get_sysctl_unprivileged_userfaultfd()
        if sysctl_unprivileged_userfaultfd is None:
            additional = "{:s}: Not found".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        v = read_int32_from_memory(sysctl_unprivileged_userfaultfd)
        additional = "{:s}: {:d}".format(cfg, v)
        if v == 0:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
        return

    def check_unprivileged_bpf_disabled(self):
        cfg = "kernel.unprivileged_bpf_disabled"

        stv_bpf_ret = gdb.execute("ksyscalls -f bpf --quiet --no-pager", to_string=True)
        if "bpf" not in stv_bpf_ret:
            additional = "bpf syscall: Unimplemented"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Syscall unsupported", "bold green"), additional))
            return

        if "invalid bpf" in stv_bpf_ret:
            additional = "bpf syscall: Disabled"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Syscall unsupported", "bold green"), additional))
            return

        kversion = Kernel.version()
        if kversion < "4.4":
            additional = "bpf syscall: Enabled; CAP_SYS_ADMIN required; sysctl unavailable before Linux 4.4"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Privileged only", "bold green"), additional))
            return

        sysctl_unprivileged_bpf_disabled = KernelAddressHeuristicFinder.get_sysctl_unprivileged_bpf_disabled()
        if sysctl_unprivileged_bpf_disabled is None:
            additional = "{:s}: Not found".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        v = read_int32_from_memory(sysctl_unprivileged_bpf_disabled)
        additional = "{:s}: {:d}".format(cfg, v)
        if v == 0:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def check_kexec_load_disabled(self):
        cfg = "kernel.kexec_load_disabled"
        kversion = Kernel.version()
        if kversion < "3.14":
            additional = "{:s}: implemented from linux 3.14".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unimplemented", "bold red"), additional))
            return

        r1 = gdb.execute("ksyscalls -f kexec_load --quiet --no-pager", to_string=True)
        r2 = gdb.execute("ksyscalls -f kexec_file_load --quiet --no-pager", to_string=True)
        if ("kexec_load" not in r1 or "invalid kexec_load" in r1) and \
           ("kexec_file_load" not in r2 or "invalid kexec_file_load" in r2):
            additional = ""
            if "kexec_load" not in r1:
                additional = "kexec_load syscall: Unimplemented"
            elif "invalid kexec_load" in r1:
                additional = "kexec_load syscall: Disabled"
            if "kexec_file_load" not in r2:
                additional += ", " + "kexec_file_load syscall: Unimplemented"
            elif "invalid kexec_file_load" in r2:
                additional += ", " + "kexec_file_load syscall: Disabled"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Syscall unsupported", "bold green"), additional))
            return

        kexec_load_disabled = KernelAddressHeuristicFinder.get_kexec_load_disabled()
        if kexec_load_disabled is None:
            additional = "{:s}: Not found".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        v1 = read_int32_from_memory(kexec_load_disabled)
        additional = "{:s}: {:d}".format(cfg, v1)
        if v1 == 0:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def check_namespaces(self):
        kversion = Kernel.version()
        cfgs = [
            ["4.9", "user.max_user_namespaces"],
            ["4.9", "user.max_pid_namespaces"],
            ["4.9", "user.max_uts_namespaces"],
            ["4.9", "user.max_ipc_namespaces"],
            ["4.9", "user.max_net_namespaces"],
            ["4.9", "user.max_mnt_namespaces"],
            ["4.9", "user.max_cgroup_namespaces"],
            ["5.6", "user.max_time_namespaces"],
        ]
        supported_cfgs = [cfg for kv, cfg in cfgs if not kversion < kv]
        addrs = {}
        if supported_cfgs and is_kgdb():
            # A ksysctl tree walk reads too much memory over KGDB, so use init_user_ns.ucount_max[] from the debug information.
            user_ns = GefUtil.typed_struct(Ksym.get_addr("init_user_ns"), "struct user_namespace")
            ucount_max = GefUtil.field(user_ns, "ucount_max")
            for cfg in supported_cfgs:
                try:
                    index = int(gdb.parse_and_eval("UCOUNT_{:s}_NAMESPACES".format(cfg.split("_")[1].upper())))
                    value = ucount_max[index]
                    addrs[cfg] = (to_unsigned_long(value.address), value.type.sizeof)
                except (gdb.error, TypeError):
                    pass
        elif supported_cfgs:
            # A ksysctl tree walk is slow, so resolve all namespace limits in one pass.
            filters = " ".join("-f {:s}".format(cfg) for cfg in supported_cfgs)
            try:
                ret = gdb.execute("ksysctl --quiet --no-pager {:s}".format(filters), to_string=True)
            except gdb.error:
                ret = ""
            for line in Color.remove_color(ret).splitlines():
                fields = line.split()
                if len(fields) < 3 or fields[0] not in supported_cfgs:
                    continue
                try:
                    # ~5.13: int with proc_dointvec_minmax, 5.14~: long with proc_doulongvec_minmax
                    addrs[fields[0]] = (int(fields[1], 16), int(fields[2], 16))
                except ValueError:
                    pass

        for kv, cfg in cfgs:
            if kversion < kv:
                additional = "{:s}: implemented from linux {:s}".format(cfg, kv)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unimplemented", "bold red"), additional))
                continue

            if cfg not in addrs:
                additional = "{:s}: Not found".format(cfg)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
                continue

            addr, maxlen = addrs[cfg]
            if maxlen == 8:
                val = read_int64_from_memory(addr, safe=True)
            else:
                val = read_int32_from_memory(addr, safe=True)
            if val is None:
                additional = "{:s}: Memory read error at {:#x}".format(cfg, addr)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            elif val:
                gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("{:d}".format(val), "bold red")))
            else:
                gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("{:d}".format(val), "bold green")))
        return

    def check_unprivileged_userns_clone(self):
        cfg = "kernel.unprivileged_userns_clone"
        addr = self.get_sysctl_addr(cfg, "unprivileged_userns_clone")
        if addr is None:
            additional = "{:s}: Not found, Only present in debian-based environments".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        val = read_int32_from_memory(addr)
        additional = "{:s}: {:d}, Only present in debian-based environments".format(cfg, val)
        if val:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        return

    def check_userns_restrict(self):
        cfg = "kernel.userns_restrict"
        addr = self.get_sysctl_addr(cfg, "sysctl_userns_restrict")
        if addr is None:
            additional = "{:s}: Not found, Only present in ALT-linux-based environments".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        val = read_int32_from_memory(addr)
        additional = "{:s}: {:d}, Only present in ALT-linux-based environments".format(cfg, val)
        if val:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_CONFIG_KALLSYMS_ALL(self):
        cfg = "CONFIG_KALLSYMS_ALL"
        if self.print_kconfig_state(cfg, secure_if_enabled=False):
            return

        # Scanning the runtime kallsyms reads too much memory over KGDB.
        if is_kgdb():
            kallsyms = None
        else:
            kallsyms = Ksym.get_runtime_kallsyms(quiet=True)
        if kallsyms is None:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), "runtime kallsyms unavailable"))
        elif "modprobe_path" in kallsyms[1]:
            additional = "modprobe_path: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
        elif self.is_modules_supported():
            additional = "modprobe_path: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), "module support not confirmed"))
        return

    def check_CONFIG_IKCONFIG(self):
        cfg = "CONFIG_IKCONFIG"
        name, value = self.get_config(cfg)
        if value in ("y", "m"):
            additional = self.config_str(name, value)
            if self.kconfig_where:
                additional += ", " + self.kconfig_where
            if value == "y":
                state = "Enabled"
            else:
                state = "Module"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify(state, "bold red"), additional))
            return

        if Ksym.get_addr("ikconfig_init"):
            # CONFIG_IKCONFIG_PROC=y needs CONFIG_IKCONFIG, but the config could not be extracted
            additional = "ikconfig_init: Found, IKCFG_ST: Not extracted"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
        elif self.is_modules_supported():
            additional = "IKCFG_ST: Not found in the kernel and the loaded modules (CONFIG_IKCONFIG=n, or =m and not loaded)"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
        else:
            additional = "IKCFG_ST: Not found, CONFIG_MODULES=n"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        return

    def check_CONFIG_IKCONFIG_PROC(self):
        cfg = "CONFIG_IKCONFIG_PROC"
        name, value = self.get_config(cfg)
        if value is not None:
            additional = self.config_str(name, value)
            if value == "y" and self.get_config("CONFIG_IKCONFIG")[1] == "m":
                additional += ", /proc/config.gz appears while the configs module is loaded"
            if value == "y":
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
            else:
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
            return

        # ikconfig_init is built only with CONFIG_IKCONFIG_PROC
        if Ksym.get_addr("ikconfig_init"):
            additional = "ikconfig_init: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
        elif self.is_modules_supported():
            additional = "ikconfig_init: Not found, it may be in the configs module"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
        else:
            additional = "ikconfig_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        return

    def check_CONFIG_DEBUG_INFO_BTF(self):
        from gef.commands.kernel.symbol_type import KtypesCommand
        cfg = "CONFIG_DEBUG_INFO_BTF"
        if self.print_kconfig_state(cfg, secure_if_enabled=False):
            return

        start_btf = Ksym.get_addr("__start_BTF")
        if start_btf:
            additional = "__start_BTF: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
            return

        # Over KGDB, scanning memory for the BTF header is too slow, and the symbols of vmlinux keep __start_BTF.
        if is_kgdb() and not Ksym.kernel_img:
            additional = "__start_BTF: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
            return

        btf_range = KtypesCommand.get_btf_addr()
        if btf_range is not None:
            additional = "BTF header: Found at {:#x} (__start_BTF hidden)".format(btf_range[0])
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
            return

        if Ksym.kernel_img:
            additional = "BTF header: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
            return

        additional = "__start_BTF: Not found"
        if Ksym.get_addr("modprobe_path") is None and KernelAddressHeuristicFinder.get_modules() is not None:
            gef_print("{:<40s}: {:s} ({:s}, CONFIG_KALLSYMS_ALL=n)".format(cfg, Color.grayify("Unknown"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        return

    def check_CONFIG_RANDSTRUCT(self):
        cfg = "CONFIG_RANDSTRUCT"
        kversion = Kernel.version()
        if kversion is not None and kversion < "4.13":
            additional = "implemented from Linux 4.13"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        # ~5.18: CONFIG_GCC_PLUGIN_RANDSTRUCT
        if self.print_kconfig_state(cfg, names=[cfg, "CONFIG_GCC_PLUGIN_RANDSTRUCT"]):
            return

        members = ("procname", "data", "maxlen", "mode", "proc_handler", "extra1", "extra2")
        offsets = [GefUtil.offsetof("ctl_table", member) for member in members]
        if None not in offsets:
            randomized = offsets != sorted(offsets)
            if randomized:
                state = Color.colorify("Enabled", "bold green")
            else:
                state = Color.colorify("Disabled", "bold red")
            gef_print("{:<40s}: {:s} (ctl_table layout from debug information)".format(cfg, state))
            return

        # A sysctl tree walk reads too much memory over KGDB.
        if is_kgdb():
            additional = "ctl_table layout: Not found in debug information"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        # If kallsyms can be resolved but ksysctl cannot, the structure layout may be unusual.
        # The structures parsed by ksysctl are stable across kernel versions, except for
        # `struct ctl_dir.inodes`. Also, the first member of `struct ctl_table` is a
        # `const char *procname`, which will almost certainly point to readable data.
        # Therefore, a ksysctl failure is a useful RANDSTRUCT signal, but it is not sufficient
        # positive evidence by itself because unrelated finder failures can produce the same result.
        if KernelSysctl.get("kernel.version") is None:
            gef_print("{:<40s}: {:s}".format(cfg, Color.grayify("Unknown")))
        else:
            gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("Disabled", "bold red")))
        return

    @staticmethod
    def is_first_arg_used(res):
        # Returns True if the first argument register is read before it is overwritten,
        # False if it is overwritten first, or None if it cannot be decided.
        if is_x86_64():
            reg_re = r"\b(?:rdi|edi|di|dil)\b"
        elif is_x86_32():
            reg_re = r"\b(?:eax|ax|al|ah)\b"
        elif is_arm64():
            reg_re = r"\b[xw]0\b"
        elif is_arm32():
            reg_re = r"\br0\b"
        else:
            return None

        for line in res.splitlines():
            m = re.search(r"^\s*(?:=>\s*)?0x[0-9a-f]+(?:\s+<[^>]*>)?:\s*(\S+)\s*(.*)", line)
            if not m:
                continue
            mnemonic = m.group(1)
            operands = re.sub(r"\s+(?://|@|;|# ).*$", "", m.group(2))
            if re.fullmatch(r"call\w*|jmp\w*|ret\w*|bl|blx|blr|br|b|bx", mnemonic):
                return None
            if re.match(r"pop|ldm", mnemonic) and re.search(r"\bpc\b", operands) or operands.split(",")[0].strip() == "pc":
                return None
            if not re.search(reg_re, operands):
                continue
            ops = re.split(r",\s*(?![^\[]*\]|[^{]*})", operands)
            dst, srcs = ops[0], ops[1:]
            if is_x86():
                if mnemonic in ("xor", "sub") and len(ops) == 2 and dst == srcs[0]:
                    return False
                if mnemonic in ("mov", "movzx", "movsx", "movsxd", "movabs", "lea", "pop"):
                    return not (re.fullmatch(reg_re, dst) and not any(re.search(reg_re, x) for x in srcs))
                return True
            # ARM: the destination is also read by stores, comparisons and partial writes
            if re.fullmatch(r"(?:str|stur|stp|stl|stx|stm|push|cmp|cmn|tst|teq|cbn?z|tbn?z|movk|movt|bfi|bfxil|ccmp)\w*", mnemonic):
                return True
            if is_arm32() and re.search(r"(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)$", mnemonic):
                return None
            if mnemonic.startswith("ldp"):
                dsts = ops[:2]
            else:
                dsts = ops[:1]
            srcs = ops[len(dsts):]
            return not (any(re.fullmatch(reg_re, x) for x in dsts) and not any(re.search(reg_re, x) for x in srcs))
        return None

    @staticmethod
    def get_usermodehelper_path_source(res):
        # Follows the stores of call_usermodehelper_setup() to find what is written to `sub_info->path`.
        # `path` is just before `argv` in `struct subprocess_info`, and `argv` is the second argument.
        # Returns ["arg", 0] if it is the first argument, ["const", addr] if it is a constant, or None.
        if is_x86_64():
            arg_regs = ["rdi", "rsi"]
            clobbered = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"]
        elif is_x86_32():
            arg_regs = ["eax", "edx"]
            clobbered = ["eax", "ecx", "edx"]
        elif is_arm64():
            arg_regs = ["x0", "x1"]
            clobbered = ["x{:d}".format(i) for i in range(19)]
        elif is_arm32():
            arg_regs = ["r0", "r1"]
            clobbered = ["r0", "r1", "r2", "r3", "r12", "ip", "lr"]
        else:
            return None

        regs = {reg: ["arg", i] for i, reg in enumerate(arg_regs)}
        stores = {} # (base register, offset): value
        for line in res.splitlines():
            m = re.search(r"^\s*(?:=>\s*)?(0x[0-9a-f]+)(?:\s+<[^>]*>)?:\s*(\S+)\s*(.*)", line)
            if not m:
                continue
            pos, mnemonic, operands = int(m.group(1), 16), m.group(2), m.group(3)
            # gdb appends `<symbol>` to an address if vmlinux is loaded (always in KGDB mode)
            comment = re.search(r"(?:# |@ |; |// #)(0x[0-9a-f]+|-?\d+)(?:\s+<[^>]*>)?\s*$", operands)
            operands = re.sub(r"\s+(?://|@|;|# ).*$", "", operands).strip()
            ops = re.split(r",\s*(?![^\[]*\]|[^{]*})", operands)

            if re.fullmatch(r"call\w*|bl|blx|blr", mnemonic):
                for reg in clobbered:
                    regs.pop(reg, None)
                continue

            # stores
            if is_x86():
                if mnemonic == "mov" and len(ops) == 2:
                    r = re.fullmatch(r"(?:QWORD|DWORD) PTR \[(\w+)(?:\+(0x[0-9a-f]+))?\]", ops[0])
                    if r:
                        if re.fullmatch(r"0x[0-9a-f]+", ops[1]):
                            value = ["const", AddressUtil.normalize_address(int(ops[1], 16))]
                        else:
                            value = regs.get(ops[1])
                        stores[(r.group(1), int(r.group(2) or "0", 16))] = value
                        continue
            else:
                if mnemonic in ("stp", "str", "stur") and len(ops) >= 2:
                    if mnemonic == "stp":
                        srcs = ops[:2]
                    else:
                        srcs = ops[:1]
                    addr_op = ops[len(srcs)]
                    r = re.fullmatch(r"\[(\w+)(?:,\s*#(-?(?:0x[0-9a-f]+|\d+)))?\](!?)", addr_op)
                    if r:
                        base, off = r.group(1), int(r.group(2) or "0", 0)
                        for i, src in enumerate(srcs):
                            stores[(base, off + runtime.current_arch.ptrsize * i)] = regs.get(src)
                        if r.group(3) or len(ops) > len(srcs) + 1: # write-back
                            regs.pop(base, None)
                    continue

            # register writes
            dst = ops[0]
            if is_x86_64() and re.fullmatch(r"e(?:ax|bx|cx|dx|si|di|bp|sp)|r\d+d", dst):
                # a 32-bit write clears the upper bits, so it is no longer a pointer
                regs.pop("r" + dst[1:] if dst.startswith("e") else dst[:-1], None)
                continue
            if mnemonic in ("mov", "movabs") and len(ops) == 2:
                if ops[1] in regs:
                    regs[dst] = regs[ops[1]]
                elif re.fullmatch(r"#?(0x[0-9a-f]+|\d+)", ops[1]):
                    regs[dst] = ["const", int(ops[1].lstrip("#"), 0)]
                else:
                    regs.pop(dst, None)
            elif mnemonic == "lea" and comment:
                regs[dst] = ["const", int(comment.group(1), 16)]
            elif mnemonic in ("adrp", "adr") and len(ops) == 2:
                regs[dst] = ["const", int(ops[1].split()[0], 16)]
            elif mnemonic == "add" and len(ops) == 3 and regs.get(ops[1], [None])[0] == "const" and ops[2].startswith("#"):
                regs[dst] = ["const", regs[ops[1]][1] + int(ops[2].lstrip("#"), 0)]
            elif mnemonic == "movw" and comment:
                regs[dst] = ["const", int(comment.group(1), 0)]
            elif mnemonic == "movt" and comment and regs.get(dst, [None])[0] == "const":
                regs[dst] = ["const", (regs[dst][1] & 0xffff) | (int(comment.group(1), 0) << 16)]
            elif mnemonic == "ldr" and re.fullmatch(r"\[pc(?:,\s*#(-?\d+))?\]", ops[-1]) and len(ops) == 2:
                v = read_int_from_memory(pos + 8 + int(re.search(r"#(-?\d+)|$", ops[-1]).group(1) or 0), safe=True)
                if v is None:
                    regs.pop(dst, None)
                else:
                    regs[dst] = ["const", v]
            elif mnemonic.startswith(("push", "cmp", "test", "tst", "cmn", "teq", "nop", "endbr", "pac", "aut", "b.", "j", "cb", "tb")):
                pass
            elif mnemonic.startswith(("ldp", "pop", "ldm")):
                if re.search(r"\bpc\b", operands): # a return like `popeq {r4, pc}`, the state is kept if not taken
                    continue
                for reg in re.findall(r"\b\w+\b", " ".join(ops[:2] if mnemonic.startswith("ldp") else ops)):
                    regs.pop(reg, None)
            else:
                regs.pop(dst, None)

        for (base, off), value in stores.items():
            if value == ["arg", 1]:
                path = stores.get((base, off - runtime.current_arch.ptrsize))
                if path == ["arg", 0] or path and path[0] == "const":
                    return path
        return None

    def check_CONFIG_STATIC_USERMODEHELPER(self):
        cfg = "CONFIG_STATIC_USERMODEHELPER"
        kversion = Kernel.version()
        if kversion < "4.11":
            additional = "{:s}: implemented from linux 4.11".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unimplemented", "bold red"), additional))
            return

        name, value = self.get_config(cfg)
        if value is not None:
            additional = self.config_str(name, value)
            if value == "n":
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
                return
            path_name, path = self.get_config("CONFIG_STATIC_USERMODEHELPER_PATH")
            if path != "n":
                additional += ", {:s}={:s}".format(path_name, path)
            if path == '""':
                additional += " (all usermode helpers are blocked)"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            return

        call_usermodehelper_setup = Ksym.get_addr("call_usermodehelper_setup")
        if call_usermodehelper_setup is None:
            additional = "call_usermodehelper_setup: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        # CONFIG_STATIC_USERMODEHELPER=y: `sub_info->path = CONFIG_STATIC_USERMODEHELPER_PATH;`
        # CONFIG_STATIC_USERMODEHELPER=n: `sub_info->path = path;` (the first argument)
        res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(call_usermodehelper_setup, 50)
        source = self.get_usermodehelper_path_source(res)
        if source == ["arg", 0]:
            additional = "call_usermodehelper_setup stores the argument to sub_info->path"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            return
        if source is not None:
            path = read_cstring_from_memory(source[1], max_length=0x100, safe=True)
            if path is not None:
                additional = "call_usermodehelper_setup stores \"{:s}\" to sub_info->path".format(path)
                if path == "":
                    additional += " (all usermode helpers are blocked)"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
                return

        # fallback: the path constant, or the use of the first argument
        if is_x86():
            g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
        elif is_arm64():
            g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
        elif is_arm32():
            g = itertools.chain(
                KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
            )
        else:
            g = []
        klayout = Kernel.layout()
        for x in g:
            if not is_valid_addr(x):
                continue
            if klayout.ro_base is not None and klayout.ro_end is not None and not klayout.ro_base <= x < klayout.ro_end:
                continue
            path = read_cstring_from_memory(x, max_length=0x100, safe=True)
            # the default value of CONFIG_STATIC_USERMODEHELPER_PATH is "/sbin/usermode-helper".
            if path and path.startswith("/"):
                additional = "call_usermodehelper_setup uses static path \"{:s}\"".format(path)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
                return
        if self.is_first_arg_used(res):
            additional = "call_usermodehelper_setup uses the argument"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            additional = "call_usermodehelper_setup uses neither a path constant nor the argument"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
        return

    def check_CONFIG_STACKPROTECTOR(self):
        cfg = "CONFIG_STACKPROTECTOR"
        # ~4.17: CONFIG_CC_STACKPROTECTOR
        if self.print_kconfig_state(cfg, names=[cfg, "CONFIG_CC_STACKPROTECTOR"]):
            return

        # __stack_chk_fail is built only with it. ktask cannot find task_struct.stack_canary with CONFIG_RANDSTRUCT,
        # and walks the task list, which is slow over KGDB.
        if Ksym.get_addr("__stack_chk_fail") is not None:
            additional = "__stack_chk_fail: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            return
        if is_kgdb():
            additional = "__stack_chk_fail: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            return

        ktask_ret = gdb.execute("ktask --meta", to_string=True)
        r = re.search(r"offsetof\(task_struct, stack_canary\): (0x\S+)", ktask_ret)
        if r:
            additional = "offsetof(task_struct, stack_canary): {:s}".format(r.group(1))
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            return

        if "stack_canary" in ktask_ret:
            additional = "offsetof(task_struct, stack_canary): Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            additional = "ktask was failed"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
        return

    def check_CONFIG_SHADOW_CALL_STACK(self):
        if not is_arm64():
            return

        cfg = "CONFIG_SHADOW_CALL_STACK (Clang ARM64)"
        if self.print_kconfig_state(cfg, names=["CONFIG_SHADOW_CALL_STACK"]):
            return

        scs_alloc = Ksym.get_addr("scs_alloc")
        if scs_alloc:
            additional = "scs_alloc: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        else:
            additional = "scs_alloc: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_CONFIG_HARDENED_USERCOPY(self):
        cfg = "CONFIG_HARDENED_USERCOPY"
        if self.print_kconfig_state(cfg):
            return

        __check_heap_object = Ksym.get_addr("__check_heap_object")
        if __check_heap_object:
            additional = "__check_heap_object: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        else:
            additional = "__check_heap_object: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_CONFIG_FUSE_FS(self):
        cfg = "CONFIG_FUSE_FS"
        name, value = self.get_config(cfg)
        if value == "y" or value is None and Ksym.get_addr("fuse_do_open"):
            if value:
                additional = self.config_str(name, value)
            else:
                additional = "fuse_do_open: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
            return
        if value == "n":
            additional = self.config_str(name, value)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
            return

        # CONFIG_FUSE_FS=m or unknown
        modules = self.get_loaded_modules()
        if modules is None:
            loaded = None
        else:
            loaded = "fuse" in [name for name, _start, _size in modules]
        if value:
            additional = self.config_str(cfg, value)
        else:
            additional = "fuse_do_open: Not found"
        if loaded is True:
            additional += ", runtime: fuse module: Loaded"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Module", "bold red"), additional))
        elif value == "m":
            additional += ", runtime: fuse module: {:s}".format("Not loaded" if loaded is False else "Unknown (kmod is failed)")
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Module", "bold red"), additional))
        elif not self.is_modules_supported():
            additional += ", CONFIG_MODULES=n"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        elif loaded is False:
            additional += ", fuse module: Not loaded (CONFIG_FUSE_FS=n, or =m and not loaded)"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
        else:
            additional += ", kmod is failed"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
        return

    def check_kadr_kallsyms(self):
        cfg = "KADR (kallsyms)"
        kversion = Kernel.version()
        if kversion < "4.15":
            kptr_restrict = KernelAddressHeuristicFinder.get_kptr_restrict()
            if kptr_restrict is None:
                additional = "kernel.kptr_restrict: Not found"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
                return

            v1 = read_int32_from_memory(kptr_restrict)
            additional = "kernel.kptr_restrict: {:d}".format(v1)
            if v1 == 0:
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            else:
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            return

        kptr_restrict = KernelAddressHeuristicFinder.get_kptr_restrict()
        sysctl_perf_event_paranoid = KernelAddressHeuristicFinder.get_sysctl_perf_event_paranoid()
        if kptr_restrict is None:
            additional = "kernel.kptr_restrict: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        if sysctl_perf_event_paranoid is None:
            additional = "kernel.perf_event_paranoid: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        v1 = read_int32_from_memory(kptr_restrict)
        v2 = read_int32_from_memory(sysctl_perf_event_paranoid, signed=True)
        additional = "kernel.kptr_restrict: {:d}, kernel.perf_event_paranoid: {:d}".format(v1, v2)
        if v1 == 0 and v2 <= 1:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def check_kadr_dmesg(self):
        dmesg_restrict = KernelAddressHeuristicFinder.get_dmesg_restrict()
        cfg = "KADR (dmesg)"
        if dmesg_restrict is None:
            additional = "kernel.dmesg_restrict: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        v1 = read_int32_from_memory(dmesg_restrict)
        additional = "kernel.dmesg_restrict: {:d}".format(v1)
        if v1 == 0:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def check_mmap_min_addr(self):
        cfg = "vm.mmap_min_addr"
        mmap_min_addr = KernelAddressHeuristicFinder.get_mmap_min_addr()
        if mmap_min_addr is None:
            mmap_min_addr = KernelAddressHeuristicFinder.get_dac_mmap_min_addr()
        if mmap_min_addr is None:
            additional = "{:s}: Not found".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        val = read_int_from_memory(mmap_min_addr)
        if val:
            gef_print("{:<40s}: {:s}".format(cfg, Color.colorify_hex(val, "bold green")))
        else:
            gef_print("{:<40s}: {:s}".format(cfg, Color.colorify_hex(val, "bold red")))
        return

    def check_supported_syscall(self):
        cfg = "Supported system call"
        supported_syscall = []
        if is_x86_32():
            if KernelAddressHeuristicFinder.get_sys_call_table_x86():
                supported_syscall.append("x86(native)")
        elif is_x86_64():
            if KernelAddressHeuristicFinder.get_sys_call_table_x64():
                supported_syscall.append("x64")
            if KernelAddressHeuristicFinder.get_sys_call_table_x86():
                supported_syscall.append("x86(compat)")
            elif Ksym.get_addr("ia32_sys_call"): # 6.6.26~
                supported_syscall.append("x86(compat)")
            if KernelAddressHeuristicFinder.get_sys_call_table_x32():
                supported_syscall.append("x32")
            elif Ksym.get_addr("x32_sys_call"): # 6.6.26~
                supported_syscall.append("x32")
        elif is_arm32():
            if KernelAddressHeuristicFinder.get_sys_call_table_arm32():
                supported_syscall.append("arm32(native)")
        elif is_arm64():
            if KernelAddressHeuristicFinder.get_sys_call_table_arm64():
                supported_syscall.append("arm64")
            if KernelAddressHeuristicFinder.get_sys_call_table_arm64_compat():
                supported_syscall.append("arm32(compat)")

        if supported_syscall:
            gef_print("{:<40s}: {:s}".format(cfg, ", ".join(supported_syscall)))
        else:
            gef_print("{:<40s}: {:s}".format(cfg, "???"))
        return

    def run_checks(self, *checks):
        for check in checks:
            try:
                check()
            except (gdb.error, ValueError, TypeError, AttributeError, KeyError, IndexError, struct.error) as e:
                # A failure of one check should not hide the others
                name = check.__name__.replace("check_", "")
                lineno = traceback.extract_tb(e.__traceback__)[-1].lineno
                additional = "{:s} at line {:d}: {:s}".format(type(e).__name__, lineno, str(e).strip().split("\n")[0])
                gef_print("{:<40s}: {:s} ({:s})".format(name, Color.grayify("Unknown"), additional))
        return

    def print_security_properties_qemu_system(self):
        self.kconfig = None
        self.kconfig_where = None
        self.loaded_modules = False

        gef_print(titlify("Kernel information"))
        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        gef_print("{:<40s}: {:d}.{:d}.{:d}".format("Kernel version", *kversion.version_tuple))
        self.run_checks(self.check_basic_information)

        gef_print(titlify("Register settings"))
        self.run_checks(self.x86_specific, self.arm32_specific, self.arm64_specific)

        if Ksym.get_addr("_stext") is None:
            err("ksymaddr-remote is failed")
            return

        gef_print(titlify("Memory settings"))
        self.run_checks(
            self.check_kaslr,
            self.check_fgkaslr,
            self.check_kpti,
            self.check_rwx_page,
            self.check_secure_world,
        )

        gef_print(titlify("Allocator"))
        allocator = Kernel.get_slab_type()
        gef_print("{:<40s}: {:s}".format("Allocator", allocator))
        if allocator == "SLUB":
            self.run_checks(
                self.check_CONFIG_SLAB_FREELIST_HARDENED,
                self.check_CONFIG_SLAB_FREELIST_RANDOM,
                self.check_CONFIG_SLAB_VIRTUAL,
            )
        gef_print(titlify("Kernel module"))
        self.run_checks(self.check_loadable_modules)

        gef_print(titlify("Security Module"))
        self.run_checks(
            self.check_selinux,
            self.check_smack,
            self.check_apparmor,
            self.check_tomoyo,
            self.check_yama,
            self.check_integrity,
            self.check_loadpin,
            self.check_safe_setid,
            self.check_lockdown,
            self.check_bpf,
            self.check_landlock,
            self.check_lkrg,
        )

        gef_print(titlify("Dangerous system call"))
        self.run_checks(
            self.check_unprivileged_userfaultfd,
            self.check_unprivileged_bpf_disabled,
            self.check_kexec_load_disabled,
            self.check_io_uring_access,
        )

        gef_print(titlify("namespaces"))
        self.run_checks(
            self.check_namespaces,
            self.check_unprivileged_userns_clone,
            self.check_userns_restrict,
        )

        gef_print(titlify("Other"))
        self.run_checks(
            self.check_CONFIG_KALLSYMS_ALL,
            self.check_CONFIG_IKCONFIG,
            self.check_CONFIG_IKCONFIG_PROC,
            self.check_CONFIG_DEBUG_INFO_BTF,
            self.check_CONFIG_RANDSTRUCT,
            self.check_CONFIG_STATIC_USERMODEHELPER,
            self.check_CONFIG_STACKPROTECTOR,
            self.check_CONFIG_SHADOW_CALL_STACK,
            self.check_CONFIG_HARDENED_USERCOPY,
            self.check_CONFIG_FUSE_FS,
            self.check_kadr_kallsyms,
            self.check_kadr_dmesg,
            self.check_mmap_min_addr,
            self.check_supported_syscall,
        )
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        # Over KGDB, scanning memory for kallsyms is too slow, so the symbols of vmlinux are required.
        if is_kgdb() and Ksym.peek() is None:
            if Ksym.Vmlinux.loaded_path(ignore_loaded_vmlinux=False, quiet=True) is None:
                err("Load vmlinux with symbols first in KGDB mode")
                return
            # A failed parse is not kept, so parse once here instead of each lookup
            if Ksym.get_kallsyms() is None:
                return
        self.print_security_properties_qemu_system()
        return



@register_command
class KernelMagicCommand(GenericCommand):
    """Display useful kernel addresses and offsets."""

    _cmdline_ = "kmagic"
    _category_ = "06-c. Qemu-system/KGDB Cooperation - Linux Basic"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("filter", metavar="FILTER", nargs="*", help="filter string.")
    _syntax_ = parser.format_help()

    def should_be_print(self, sym):
        if not self.args.filter:
            return True

        if isinstance(sym, str):
            sym = [sym]
        for filt in self.args.filter:
            if any(filt in name for name in sym):
                return True
        return False

    def resolve_and_print_kernel(self, sym, base, maps, external_func=None, to_string=False, value_only=False):

        def get_permission(addr, maps):
            entry = AddrMap.find_virtual(addr, maps=maps)
            if entry is not None:
                return str(entry.permission)
            return "???"

        if not self.should_be_print(sym):
            return

        width = AddressUtil.get_format_address_width()
        if external_func:
            try:
                addr = external_func()
            except Exception:
                gef_print("{:42s} {:>{:d}s}".format(sym, "Not found", width))
                return
            if addr is None:
                gef_print("{:42s} {:>{:d}s}".format(sym, "Not found", width))
                return
        else:
            if isinstance(sym, str):
                addr = Ksym.get_addr(sym)
                if addr is None:
                    gef_print("{:42s} {:>{:d}s}".format(sym, "Not found", width))
                    return
            elif isinstance(sym, list):
                for s in sym:
                    addr = Ksym.get_addr(s)
                    if addr:
                        sym = s
                        break
                else:
                    sym = sym[0]
                    gef_print("{:42s} {:>{:d}s}".format(sym, "Not found", width))
                    return

        if value_only:
            self.print_kernel_value(sym, addr)
            return

        if not is_valid_addr(addr):
            gef_print("{:42s} {:#0{:d}x} [---]               -> Inaccessible".format(
                sym, addr, width,
            ))
            return

        perm = get_permission(addr, maps)
        if base is None:
            val = read_int_from_memory(addr)
            gef_print("{:42s} {:#0{:d}x} [{:3s}]               -> {:#0{:d}x}".format(
                sym, addr, width, perm, val, width,
            ))
        elif to_string:
            val = read_cstring_from_memory(addr) or "???"
            gef_print("{:42s} {:#0{:d}x} [{:3s}] ({:+#011x}) -> {:s}".format(
                sym, addr, width, perm, addr - base, val,
            ))
        else:
            val = read_int_from_memory(addr)
            gef_print("{:42s} {:#0{:d}x} [{:3s}] ({:+#011x}) -> {:#0{:d}x}".format(
                sym, addr, width, perm, addr - base, val, width,
            ))
        return

    def print_kernel_value(self, sym, value):
        if not self.should_be_print(sym):
            return

        width = AddressUtil.get_format_address_width()
        if value is None:
            gef_print("{:42s} {:>{:d}s}".format(sym, "Not found", width))
        else:
            gef_print("{:42s} {:#0{:d}x}".format(sym, value, width))
        return

    def magic_kernel(self):
        info("Wait for memory scan")
        kversion = Kernel.version()
        constants = KernelAddressHeuristicFinder.consts()
        if constants is None:
            err("Failed to resolve kernel version")
            return

        klayout = Kernel.layout()
        maps = klayout.maps
        text_base = klayout.text_base
        text_size = klayout.text_size
        if text_base is None or text_size is None:
            return
        gef_print("{:42s} {:#x} ({:#x} bytes)".format("kernel_base", text_base, text_size))

        gef_print(titlify("Legend"))
        fmt = "{:42s} {:{:d}s} {:5s} (+{:10s}) -> {:{:d}s}"
        width = AddressUtil.get_format_address_width()
        legend = ["Symbol", "Addr", width, "Perm", "Offset", "Value", width]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        gef_print(titlify("Credential"))
        self.resolve_and_print_kernel("commit_creds", text_base, maps)
        self.resolve_and_print_kernel("prepare_kernel_cred", text_base, maps)
        self.resolve_and_print_kernel(
            "init_cred", text_base, maps, KernelAddressHeuristicFinder.get_init_cred,
        )
        self.resolve_and_print_kernel(["sys_setuid", "__sys_setuid"], text_base, maps)
        self.resolve_and_print_kernel(
            "init_task", text_base, maps, KernelAddressHeuristicFinder.get_init_task,
        )
        gef_print(titlify("Usermode helper"))
        self.resolve_and_print_kernel("call_usermodehelper", text_base, maps)
        self.resolve_and_print_kernel("run_cmd", text_base, maps)
        self.resolve_and_print_kernel(
            "modprobe_path", text_base, maps, KernelAddressHeuristicFinder.get_modprobe_path, to_string=True,
        )
        self.resolve_and_print_kernel("orderly_poweroff", text_base, maps)
        self.resolve_and_print_kernel(
            "poweroff_cmd", text_base, maps, KernelAddressHeuristicFinder.get_poweroff_cmd, to_string=True,
        )
        self.resolve_and_print_kernel(
            "core_pattern", text_base, maps, KernelAddressHeuristicFinder.get_core_pattern, to_string=True,
        )
        gef_print(titlify("ROP finalizer"))
        if is_x86_64():
            self.resolve_and_print_kernel(
                "swapgs_restore_regs_and_return_to_usermode", text_base, maps,
            )
        self.resolve_and_print_kernel("msleep", text_base, maps)
        gef_print(titlify("Memory protection modifier"))
        if is_x86():
            self.resolve_and_print_kernel("native_write_cr0", text_base, maps)
            self.resolve_and_print_kernel("native_write_cr4", text_base, maps)
        self.resolve_and_print_kernel("set_memory_rw", text_base, maps)
        self.resolve_and_print_kernel("set_memory_x", text_base, maps)
        gef_print(titlify("Memory patcher"))
        if is_x86():
            self.resolve_and_print_kernel("text_poke", text_base, maps)
        self.resolve_and_print_kernel("memcpy", text_base, maps)
        if is_x86():
            self.resolve_and_print_kernel(["_copy_to_user", "copy_to_user"], text_base, maps)
            self.resolve_and_print_kernel(["_copy_from_user", "copy_from_user"], text_base, maps)
        elif is_arm32():
            self.resolve_and_print_kernel(["arm_copy_to_user", "__copy_to_user"], text_base, maps)
            self.resolve_and_print_kernel(["arm_copy_from_user", "__copy_from_user"], text_base, maps)
        elif is_arm64():
            self.resolve_and_print_kernel("__arch_copy_to_user", text_base, maps)
            self.resolve_and_print_kernel("__arch_copy_from_user", text_base, maps)
        gef_print(titlify("Memory remapper"))
        self.resolve_and_print_kernel(["ioremap", "__ioremap", "ioremap_cache"], text_base, maps)
        self.resolve_and_print_kernel(["iounmap", "__iounmap"], text_base, maps)
        if is_x86():
            gef_print(titlify("Automatically called function pointer"))
            self.resolve_and_print_kernel("kvm_clock", text_base, maps)
            self.resolve_and_print_kernel(
                "clocksource_tsc", text_base, maps, KernelAddressHeuristicFinder.get_clocksource_tsc,
            )
        gef_print(titlify("Function pointer table"))
        self.resolve_and_print_kernel(
                "capability_hooks", text_base, maps, KernelAddressHeuristicFinder.get_capability_hooks,
            )
        self.resolve_and_print_kernel(
            "n_tty_ops", text_base, maps, KernelAddressHeuristicFinder.get_n_tty_ops,
        )
        gef_print(titlify("Function pointer table array"))
        self.resolve_and_print_kernel(
            "tty_ldiscs", text_base, maps, KernelAddressHeuristicFinder.get_tty_ldiscs,
        )
        gef_print(titlify("Allocator"))
        self.resolve_and_print_kernel(["__kmalloc", "__kmalloc_noprof"], text_base, maps)
        self.resolve_and_print_kernel(["kzalloc", "kzalloc.constprop.0"], text_base, maps)
        self.resolve_and_print_kernel("kfree", text_base, maps)
        self.resolve_and_print_kernel(["kzfree", "kfree_sensitive"], text_base, maps)
        self.resolve_and_print_kernel(
            "slab_caches", text_base, maps, KernelAddressHeuristicFinder.get_slab_caches,
        )
        gef_print(titlify("Dynamic resolver"))
        self.resolve_and_print_kernel("kallsyms_lookup_name", text_base, maps)
        if is_x86_64():
            if kversion and "3.16" <= kversion:
                gef_print(titlify("vDSO"))
                self.resolve_and_print_kernel(
                    "vdso_image_64", text_base, maps, KernelAddressHeuristicFinder.get_vdso_image_64,
                )
                self.resolve_and_print_kernel(
                    "vdso_image_32", text_base, maps, KernelAddressHeuristicFinder.get_vdso_image_32,
                )
                self.resolve_and_print_kernel(
                    "vdso_image_x32", text_base, maps, KernelAddressHeuristicFinder.get_vdso_image_x32,
                )
        elif is_x86_32():
            if kversion and "3.16" <= kversion:
                gef_print(titlify("vDSO"))
                self.resolve_and_print_kernel(
                    "vdso_image_32", text_base, maps, KernelAddressHeuristicFinder.get_vdso_image_32,
                )
        elif is_arm64():
            if kversion and "5.8" <= kversion:
                gef_print(titlify("vDSO"))
                self.resolve_and_print_kernel(
                    "vdso_info", text_base, maps, KernelAddressHeuristicFinder.get_vdso_info,
                )
                self.resolve_and_print_kernel(
                    "vdso_start", text_base, maps, KernelAddressHeuristicFinder.get_vdso_start,
                )
                self.resolve_and_print_kernel(
                    "vdso32_start", text_base, maps, KernelAddressHeuristicFinder.get_vdso32_start,
                )
            elif kversion and "5.3" <= kversion:
                gef_print(titlify("vDSO"))
                self.resolve_and_print_kernel(
                    "vdso_lookup", text_base, maps, KernelAddressHeuristicFinder.get_vdso_lookup,
                )
                self.resolve_and_print_kernel(
                    "vdso_start", text_base, maps, KernelAddressHeuristicFinder.get_vdso_start,
                )
                self.resolve_and_print_kernel(
                    "vdso32_start", text_base, maps, KernelAddressHeuristicFinder.get_vdso32_start,
                )
            elif kversion and "3.7" <= kversion:
                gef_print(titlify("vDSO"))
                self.resolve_and_print_kernel(
                    "vdso_start", text_base, maps, KernelAddressHeuristicFinder.get_vdso_start,
                )
        elif is_arm32():
            if kversion and "4.1" <= kversion:
                gef_print(titlify("vDSO"))
                self.resolve_and_print_kernel(
                    "vdso_start", text_base, maps, KernelAddressHeuristicFinder.get_vdso_start,
                )
        gef_print(titlify("Others"))
        self.resolve_and_print_kernel(["do_fchmodat", "sys_fchmodat"], text_base, maps)
        self.resolve_and_print_kernel(
            "mmap_min_addr", text_base, maps, KernelAddressHeuristicFinder.get_mmap_min_addr,
        )
        self.resolve_and_print_kernel(
            "__per_cpu_offset", text_base, maps, KernelAddressHeuristicFinder.get_per_cpu_offset,
        )
        if is_x86():
            gef_print(titlify("Descriptor Table"))
            self.resolve_and_print_kernel(
                "IDT base (fixed address?)", None, maps, KernelAddressHeuristicFinder.get_idt_base,
            )
            self.resolve_and_print_kernel(
                "GDT base (fixed address?)", None, maps, KernelAddressHeuristicFinder.get_gdt_base,
            )
            self.resolve_and_print_kernel(
                "LDT base (fixed address?)", None, maps, KernelAddressHeuristicFinder.get_ldt_base,
            )
            self.resolve_and_print_kernel(
                "TSS base (fixed address?)", None, maps, KernelAddressHeuristicFinder.get_tss_base,
            )
        gef_print(titlify("Memory base"))
        self.resolve_and_print_kernel(
            "PAGE_OFFSET (physmem direct map)", None, maps, KernelAddressHeuristicFinder.get_PAGE_OFFSET,
        )
        self.resolve_and_print_kernel(
            "PAGE_OFFSET_END", None, maps, KernelAddressHeuristicFinder.get_PAGE_OFFSET_END, value_only=True,
        )
        self.resolve_and_print_kernel(
            "VMALLOC_START", None, maps, KernelAddressHeuristicFinder.get_VMALLOC_START,
        )
        self.resolve_and_print_kernel(
            "VMALLOC_END", None, maps, KernelAddressHeuristicFinder.get_VMALLOC_END, value_only=True,
        )
        if is_x86_64() or is_arm64():
            self.resolve_and_print_kernel(
                "VMEMMAP_START (struct page[])", None, maps, KernelAddressHeuristicFinder.get_VMEMMAP_START,
            )
            self.resolve_and_print_kernel(
                "VMEMMAP_END", None, maps, KernelAddressHeuristicFinder.get_VMEMMAP_END, value_only=True,
            )
        if is_x86_64() and (
            self.should_be_print("phys_base (load delta)") or self.should_be_print("kbase@phys")
        ):
            try:
                phys_base = KernelAddressHeuristicFinder.get_phys_base()
            except Exception:
                phys_base = None
            self.print_kernel_value("phys_base (load delta)", phys_base)

            start_kernel_map = constants.START_KERNEL_map
            if phys_base is None or start_kernel_map is None:
                kbase_phys = None
            else:
                kbase_phys = AddressUtil.normalize_address(phys_base + text_base - start_kernel_map)
            self.print_kernel_value("kbase@phys", kbase_phys)
        if is_x86_32() or is_arm32():
            self.resolve_and_print_kernel(
                "mem_map (struct page[])", None, maps, KernelAddressHeuristicFinder.get_mem_map,
            )
            self.resolve_and_print_kernel(
                "mem_section (struct page[][])", None, maps, KernelAddressHeuristicFinder.get_mem_section,
            )
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.magic_kernel()
        return



@register_command
class KernelbaseCommand(GenericCommand):
    """Display kernel base address."""

    _cmdline_ = "kbase"
    _category_ = "06-c. Qemu-system/KGDB Cooperation - Linux Basic"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if args.rescan:
            Cache.reset_gef_caches(all=True)

        # resolve text_base, ro_base
        self.quiet_info("Wait for memory scan")
        kinfo = Kernel.get_kernel_layout()

        self.out = []
        if kinfo.text_base:
            self.out.append("kernel text:   {:#x}-{:#x} ({:#x} bytes)".format(kinfo.text_base, kinfo.text_end, kinfo.text_size))
            gdb.execute(f"set $kbase = {kinfo.text_base:#x}")
        else:
            err("Failed to resolve kernel text")
        if kinfo.ro_base:
            self.out.append("kernel rodata: {:#x}-{:#x} ({:#x} bytes)".format(kinfo.ro_base, kinfo.ro_end, kinfo.ro_size))
            gdb.execute(f"set $kro_base = {kinfo.ro_base:#x}")
        else:
            err("Failed to resolve kernel rodata")
        if kinfo.rw_base:
            self.out.append("kernel data:   {:#x}-{:#x} ({:#x} bytes)".format(kinfo.rw_base, kinfo.rw_end, kinfo.rw_size))
            gdb.execute(f"set $kdata_base = {kinfo.rw_base:#x}")
        else:
            err("Failed to resolve kernel data")
        if self.out:
            gef_print("\n".join(self.out))
        return


@register_command
class KernelVersionCommand(GenericCommand):
    """Display or override the kernel version."""

    _cmdline_ = "kversion"
    _category_ = "06-c. Qemu-system/KGDB Cooperation - Linux Basic"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("version", nargs="?", metavar="VERSION", help="use this kernel version (e.g. 6.18.0).")
    parser.add_argument("-r", "--rescan", action="store_true", help="clear the version override and do not use cache.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if args.rescan:
            KernelVersion.clear_override()
            Cache.reset_gef_caches(all=True)

        # override by user specified version
        if args.version is not None:
            match = re.fullmatch(r"v?(\d+)\.(\d+)(?:\.(\d+))?", args.version)
            if match is None:
                message = "Invalid kernel version: {!r} (expected MAJOR.MINOR[.PATCH])"
                self.quiet_err(message.format(args.version))
                return

            detected = Kernel.version()
            if detected is not None:
                address = detected.address
            else:
                address = 0
            if detected is not None:
                version_string = detected.version_string
            else:
                version_string = "Linux version {:s} (user specified)".format(args.version)
            major, minor, patch = (int(value) if value is not None else 0 for value in match.groups())
            inferior = gdb.selected_inferior()
            KernelVersion.overrides[inferior, inferior.connection_num] = KernelVersion(
                address, version_string, major, minor, patch)
            Cache.reset_gef_caches(all=True)

        self.quiet_info("Wait for memory scan")
        kversion = Kernel.version()
        if kversion is None:
            self.quiet_err("Failed to resolve")
            return

        self.out = []
        if kversion.address:
            self.out.append("{:#x}: {:s}".format(kversion.address, kversion.version_string))
        if KernelVersion.get_override() is not None:
            self.out.append("User-specified kernel version: {:s}".format(str(kversion)))
        if self.out:
            gef_print("\n".join(self.out))
        return


@register_command
class KernelCmdlineCommand(GenericCommand):
    """Display kernel command-line string."""

    _cmdline_ = "kcmdline"
    _category_ = "06-c. Qemu-system/KGDB Cooperation - Linux Basic"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if args.rescan:
            Cache.reset_gef_caches(all=True)

        self.quiet_info("Wait for memory scan")
        kcmdline = Kernel.kernel_cmdline()
        if kcmdline is None:
            self.quiet_err("Failed to resolve")
            return

        self.out = []
        self.out.append("{:#x}: '{:s}'".format(kcmdline.address, kcmdline.cmdline))
        if self.out:
            gef_print("\n".join(self.out))
        return


@register_command
class KernelCurrentCommand(GenericCommand):
    """Display current task."""

    _cmdline_ = "kcurrent"
    _category_ = "06-c. Qemu-system/KGDB Cooperation - Linux Basic"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    def get_cpu_offset(self):
        # `Kernel.per_cpu()` is cached per stop, so it does not need one more here
        percpu = Kernel.per_cpu()
        if percpu.per_cpu_offset is None:
            return None
        self.quiet_info("__per_cpu_offset: {:#x}".format(percpu.per_cpu_offset))
        self.quiet_info("Num of cpu: {:d} (guessed)".format(percpu.nr_cpus))
        return percpu.offsets

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_offset_comm(self):
        task = Kernel.task()
        task.initialize()
        self.meta = Kernel.export_meta(self, task.meta)
        return task.offset_comm

    def resolve_offset_comm(self):
        """Resolve `offsetof(task_struct, comm)` once per CPU context in this invocation.
        This must not be called while another thread is temporarily selected unless
        it is intended to retry in that CPU context."""

        if self.offset_comm is None:
            context = Cache.cpu_context()
            if context not in self.comm_tried_contexts:
                self.comm_tried_contexts.add(context)
                self.offset_comm = self.get_offset_comm()
        return self.offset_comm

    def get_comm_str(self, task_addr):
        if self.resolve_offset_comm() is None:
            return "???"

        comm = read_cstring_from_memory(task_addr + self.offset_comm)
        return comm or "???"

    @staticmethod
    def search_selected_thread(res):
        """Return the match of the line of the selected thread in the output of `kcurrent`, or None.
        The groups are the task address and its comm."""
        thread = gdb.selected_thread()
        labels = [KernelPerCpu.get_cpu_label(thread)]
        if not labels[0].startswith("cpu"):
            # the x86 lines are labeled by the index of `__per_cpu_offset`
            labels.append("cpu{:d}".format(thread.num - 1))
        for label in labels:
            r = re.search(r"current \({:s}\): (0x\S+) (.*)".format(re.escape(label)), res)
            if r:
                return r
        return re.search(r"current: (0x\S+) (.*)", res)

    def get_unavailable_reason(self):
        if is_arm32():
            cpsr = get_register(runtime.current_arch.flag_register)
            if cpsr is not None and (cpsr & 0b11111) == 0b10000:
                return "CPU is in USR mode; sp holds a user stack pointer"
        elif is_arm64():
            cpsr = get_register(runtime.current_arch.flag_register)
            if cpsr is not None and ((cpsr >> 2) & 0b11) == 0:
                return "CPU is in EL0; sp_el0 holds a user stack pointer"
        elif is_riscv32() or is_riscv64():
            priv = get_register("priv")
            if priv == 3:
                return "hart is in M-mode; tp belongs to the SBI firmware"
        return "failed to resolve current task"

    def dump_current_by_thread(self):
        # Resolve `offsetof(task_struct, comm)` before switching to another thread.
        # If this CPU cannot resolve it, it is retried on the other CPUs in the kernel.
        self.resolve_offset_comm()
        results = []
        with ContextManager.threads(KernelPerCpu.get_cpu_threads()) as threads:
            for thread in threads:
                label = KernelPerCpu.get_cpu_label(thread)
                task = KernelAddressHeuristicFinder.get_current_task_for_current_thread()
                if task is None:
                    results.append((label, None, self.get_unavailable_reason()))
                    continue
                results.append((label, task, None))
                if is_in_kernel():
                    self.resolve_offset_comm()

        # A CPU halted in userland may not reach the kernel, so `comm` is read from the selected CPU.
        for label, task, reason in results:
            if task is None:
                gef_print("current ({:s}): unavailable ({:s})".format(label, reason))
            else:
                gef_print("current ({:s}): {:#x} {:s}".format(label, task, self.get_comm_str(task)))
        return

    def dump_current_x86(self):
        current_task = KernelAddressHeuristicFinder.get_current_task()
        if not current_task:
            self.quiet_err("Failed to resolve `current_task`")
            return

        cpu_bases = self.get_cpu_offset()

        if cpu_bases:
            # pattern 1. Offset from __per_cpu_offset.
            self.quiet_info("current_task: {:#x}".format(current_task))
            task_offset = current_task
            for i, cpu_base in enumerate(cpu_bases):
                task = KernelAddressHeuristicFinder.dereference_current_task(task_offset, cpu_base)
                if task is None:
                    gef_print("current (cpu{:d}): unavailable".format(i))
                    continue
                gef_print("current (cpu{:d}): {:#x} {:s}".format(i, task, self.get_comm_str(task)))
        else:
            # pattern 2: current_task is the address that stores a pointer to the current task (not per_cpu).
            task = KernelAddressHeuristicFinder.dereference_current_task(current_task)
            if task is not None:
                self.quiet_info("__per_cpu_offset is unused")
                gef_print("current: {:#x} {:s}".format(task, self.get_comm_str(task)))
            else:
                self.quiet_err("Failed to resolve `__per_cpu_offset`")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        self.offset_comm = None
        self.comm_tried_contexts = set()
        if is_arm32() or is_arm64() or is_riscv32() or is_riscv64():
            self.dump_current_by_thread()
        elif is_x86():
            self.dump_current_x86()
        if self.comm_tried_contexts and self.offset_comm is None:
            self.quiet_err("ktask failed")
        return



@register_command
class KernelPerCpuCommand(GenericCommand, BufferingOutput):
    """Resolve the per-cpu variables and the per-cpu areas."""

    _cmdline_ = "kpercpu"
    _category_ = "06-c. Qemu-system/KGDB Cooperation - Linux Basic"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("target", metavar="SYMBOL|ADDRESS", nargs="?",
                        help="a per-cpu symbol name to resolve, or an address to reverse-resolve.")
    parser.add_argument("-c", "--cpu", action="append", type=lambda x: int(x, 0), default=[], help="filter by specific cpu.")
    parser.add_argument("--online", action="store_true", help="filter by online cpus.")
    parser.add_argument("-o", "--offset", type=AddressUtil.parse_address, default=0, help="add this offset to the resolved symbol.")
    parser.add_argument("-l", "--list", action="store_true", help="list all the static per-cpu symbols.")
    parser.add_argument("-x", "--dump", metavar="SIZE", type=AddressUtil.parse_address, default=0,
                        help="hexdump SIZE bytes at each resolved address.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                        # show the per-cpu area of each cpu",
        "{0:s} runqueues              # show per_cpu(runqueues, cpu) of each cpu",
        "{0:s} --online runqueues     # show per_cpu(runqueues, cpu) of each online cpu",
        "{0:s} -o 0x120 runqueues     # add an offset to the resolved symbol",
        "{0:s} 0xffff888100600120     # tell which cpu and which variable the address belongs to",
        "{0:s} -l                     # list all the static per-cpu symbols",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "per_cpu(var, cpu) is based on the static per-cpu symbol representation and the",
        "per-cpu offset selected for the detected kernel layout. Older x86-64 kernels use",
        "a zero-based representation; x86-64 v6.15 and later use relative offsets as well.",
        "",
        "`__per_cpu_start` and the per-cpu variables are data symbols, so a",
        "CONFIG_KALLSYMS_ALL=n kernel has none of them. `__per_cpu_start` is recovered from",
        "the code of `__is_kernel_percpu_address`, which keeps the areas and the reverse",
        "lookup working, but there the variables cannot be named nor looked up by name.",
        "CONFIG_SMP=n has no `__per_cpu_offset` at all, and `&var` is the address as is.",
        "Whether it is CONFIG_SMP=n or just unresolved is told by the \"SMP\" of the banner.",
        "",
        "The cpu-id upper bound comes from `nr_cpu_ids` or the possible cpu mask; it is",
        "estimated from `__per_cpu_offset[]` if both are unknown. Each cpu is tagged with the masks,",
        "which are recovered from `init_cpu_*()`/`set_cpu_online()` without the symbols.",
    ]
    _note_ = "\n".join(_note_)

    @staticmethod
    def format_cpus(cpus):
        """Return a cpu set as a cpulist string, e.g. {0, 1, 2, 5} -> "0-2,5"."""
        if not cpus:
            return "none"
        ranges = []
        for cpu in sorted(cpus):
            if ranges and ranges[-1][1] == cpu - 1:
                ranges[-1][1] = cpu
            else:
                ranges.append([cpu, cpu])
        return ",".join(str(a) if a == b else "{:d}-{:d}".format(a, b) for a, b in ranges)

    def cpu_state(self, cpu):
        """Return the tag of `cpu` from the cpu masks, e.g. "[possible, present, online]", or ""."""
        possible, present, online = (self.cpu_masks[x] for x in ("possible", "present", "online"))
        tags = []
        if possible is not None:
            tags.append("possible" if cpu in possible else "not possible")
        if present is not None and (possible is None or cpu in possible):
            tags.append("present" if cpu in present else "not present")
        if online is not None and (possible is None or cpu in possible):
            tags.append("online" if cpu in online else "offline")
        if not tags:
            return ""
        return "  [{:s}]".format(", ".join(tags))

    def dump_meta(self, pc):
        if pc.per_cpu_offset is not None:
            self.quiet_info_add_out("__per_cpu_offset: {:#x}".format(pc.per_cpu_offset))
        elif pc.is_up:
            self.quiet_info_add_out("__per_cpu_offset: None (CONFIG_SMP=n, treated as one cpu at +0x0)")
        else:
            self.quiet_info_add_out("__per_cpu_offset: Not found")
        if pc.state == "unknown":
            self.err_add_out("This kernel is CONFIG_SMP=y, but `__per_cpu_offset[]` could not be resolved")
        if pc.start is None:
            self.quiet_info_add_out("static per-cpu section: {:s}".format("None" if pc.is_up else "Not found"))
        elif pc.end is None:
            self.quiet_info_add_out("static per-cpu section: {:#x}- (end unknown)".format(pc.start))
        else:
            self.quiet_info_add_out("static per-cpu section: {:#x}-{:#x}".format(pc.start, pc.end))
        if pc.unit_size is not None:
            self.quiet_info_add_out("per-cpu unit size: {:#x}".format(pc.unit_size))
        if pc.state != "unknown":
            if pc.is_up:
                source = "CONFIG_SMP=n"
            else:
                source = pc.cpu_count_source
            if pc.is_smp and pc.nr_cpu_ids is not None and pc.nr_cpus < pc.nr_cpu_ids:
                source = "readable entries; {:d} cpu ids from {:s}".format(pc.nr_cpu_ids, source)
            self.quiet_info_add_out("number of cpus: {:d} ({:s}, the upper bound of the cpu ids)".format(pc.nr_cpus, source))
        for kind in ("possible", "present", "online"):
            cpus = self.cpu_masks[kind]
            self.quiet_info_add_out("{:s} cpus: {:s}".format(kind, "unknown" if cpus is None else self.format_cpus(cpus)))
        return

    def target_cpus(self, pc):
        """Return the cpu numbers to display, honoring --cpu and --online."""
        cpus = list(range(pc.nr_cpus))
        if self.args.cpu:
            cpus = [c for c in cpus if c in self.args.cpu]
        if self.args.online:
            online = self.cpu_masks["online"]
            if online is None:
                self.warn_add_out("The online cpu mask is unknown, so every cpu is shown")
            else:
                cpus = [c for c in cpus if c in online]
        return cpus

    def add_dump_out(self, addr):
        if not self.args.dump:
            return
        data = read_memory(addr, self.args.dump, safe=True)
        if data is None:
            self.out.append("       (memory read error)")
            return
        for line in hexdump(data, base=addr, unit=runtime.current_arch.ptrsize).splitlines():
            self.out.append("       " + line)
        return

    def dump_area(self, pc):
        """Show the per-cpu area of each cpu."""
        if pc.is_up:
            self.info_add_out("This kernel is CONFIG_SMP=n, so cpu0 is at +0x0")
        elif pc.state == "unknown":
            return
        elif pc.start is None:
            self.warn_add_out("`__per_cpu_start` is unknown, so the base of each unit cannot be told")
        for cpu in self.target_cpus(pc):
            rng = pc.unit_range(cpu)
            if rng is None:
                self.out.append("CPU{:<4d} offset: {:s}{:s}".format(
                    cpu, AddressUtil.format_address(pc.get_offset(cpu)), self.cpu_state(cpu),
                ))
                continue
            self.out.append("CPU{:<4d} offset: {:s}  unit: {:#x}-{:#x}{:s}".format(
                cpu, AddressUtil.format_address(pc.get_offset(cpu)), rng[0], rng[1], self.cpu_state(cpu),
            ))
            self.add_dump_out(rng[0])
        return

    def dump_symbol_list(self, pc):
        """List the static per-cpu symbols."""
        symbols = pc.get_symbols()
        if not symbols:
            self.err_add_out("No static per-cpu symbol was found; this kernel may be CONFIG_KALLSYMS_ALL=n")
            return
        self.quiet_info_add_out("Number of the static per-cpu symbols: {:d}".format(len(symbols)))
        for addr, name in symbols:
            self.out.append("{:s} {:s}".format(AddressUtil.format_address(addr), name))
        return

    def dump_symbol(self, pc, name):
        """Show per_cpu(name, cpu) for each cpu."""
        static_addr = Ksym.get_addr(name)
        if static_addr is None:
            self.err_add_out("Could not find the symbol `{:s}`".format(name))
            return
        if pc.get_symbols():
            percpu_addr = pc.get_symbol_addr(name)
            # an assembler constant of a vmlinux can fall into the section linked at 0
            if percpu_addr is None and pc.is_static(static_addr):
                self.err_add_out("`{:s}` ({:#x}) is an absolute symbol, not a per-cpu variable".format(name, static_addr))
                return
            if percpu_addr is not None:
                static_addr = percpu_addr
        if pc.start is not None and not pc.is_static(static_addr):
            if pc.end is not None:
                self.err_add_out("`{:s}` ({:#x}) is not in the static per-cpu section {:#x}-{:#x}".format(
                    name, static_addr, pc.start, pc.end,
                ))
                return
            self.warn_add_out("The end of the static per-cpu section is unknown; `{:s}` could not be verified".format(name))

        static_addr += self.args.offset
        if pc.start is not None and pc.end is not None and not pc.is_static(static_addr):
            self.err_add_out("The requested offset leaves the static per-cpu section: {:#x}".format(static_addr))
            return
        if self.args.offset:
            self.quiet_info_add_out("{:s}: {:#x} (+{:#x})".format(name, static_addr, self.args.offset))
        else:
            self.quiet_info_add_out("{:s}: {:#x}".format(name, static_addr))

        for cpu in self.target_cpus(pc):
            addr = pc.addr_of(static_addr, cpu)
            self.out.append("CPU{:<4d} {:s}".format(cpu, AddressUtil.format_address(addr)))
            self.add_dump_out(addr)
        return

    def dump_address(self, pc, addr):
        """Reverse-resolve an address to the cpu and the per-cpu variable."""
        if pc.state == "unknown":
            self.err_add_out("The per-cpu areas are unknown, so {:#x} cannot be resolved".format(addr))
            return
        ret = pc.resolve(addr)
        if ret is None:
            self.err_add_out("{:#x} is not in any per-cpu area".format(addr))
            if pc.start is None:
                self.info_add_out("The static per-cpu section is unknown, so only the unit range was checked")
            return
        cpu, static_addr, sym = ret
        self.out.append("{:<10s}{:s}".format("Address", AddressUtil.format_address(addr)))
        self.out.append("{:<10s}{:d}".format("CPU", cpu))
        if sym is None:
            self.out.append("{:<10s}{:s}".format("Symbol", "Not found (dynamic per-cpu area?)"))
        else:
            name, offset = sym
            self.out.append("{:<10s}{:s}".format("Symbol", name))
            self.out.append("{:<10s}+{:#x}".format("Offset", offset))
        self.out.append("{:<10s}{:#x}".format("Static", static_addr))
        self.add_dump_out(addr)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if Kernel.version() is None:
            err("Could not find Linux kernel")
            return

        pc = Kernel.per_cpu()
        if any(cpu < 0 or cpu >= pc.nr_cpus for cpu in args.cpu):
            err("CPU number is invalid")
            return
        self.cpu_masks = pc.get_cpu_masks()
        self.out = []
        self.dump_meta(pc)

        if args.list:
            self.dump_symbol_list(pc)
        elif args.target is None:
            self.dump_area(pc)
        elif re.fullmatch(r"[A-Za-z_.][\w.$]*", args.target): # `$reg` is an address expression
            self.dump_symbol(pc, args.target)
        else:
            try:
                addr = AddressUtil.parse_address(args.target)
            except Exception:
                err("Could not parse `{:s}` as an address".format(args.target))
                return
            self.dump_address(pc, addr)

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelAddressHeuristicSelftestCommand(GenericCommand, BufferingOutput):
    """Compare kernel-address heuristic finders with kallsyms results."""

    _cmdline_ = "ks-selftest"
    _category_ = "06-c. Qemu-system/KGDB Cooperation - Linux Basic"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    parser.add_argument("--failures-only", action="store_true", help="show only failed finders.")
    _syntax_ = parser.format_help()

    _note_ = [
        "False means explicitly unsupported; None means not found; '-' means unavailable or not run.",
        "$ks_selftest_failures is nonzero if the test cannot run, otherwise it is the number of failed results.",
    ]
    _note_ = "\n".join(_note_)

    def invoke(self, args, from_tty):
        gdb.set_convenience_variable("ks_selftest_failures", -1)
        return super().invoke(args, from_tty)

    @staticmethod
    def direct_symbol_name(finder_name):
        if finder_name == "get_sys_call_table_x86":
            if is_x86_64():
                return "ia32_sys_call_table"
            if is_x86_32():
                return "sys_call_table"
            return None

        m = re.fullmatch(r"get_cpu_(possible|present|online)_mask", finder_name)
        if m:
            # the symbol changed in v4.5, and some old kernels keep only the pointer to the bitmap
            names = [x.format(m.group(1)) for x in ("__cpu_{:s}_mask", "cpu_{:s}_bits", "cpu_{:s}_mask")]
            return next((x for x in names if Ksym.get_addr(x) is not None), names[0])

        exceptions = {
            "get_sys_call_table_x64": "sys_call_table",
            "get_sys_call_table_x32": "x32_sys_call_table",
            "get_sys_call_table_arm32": "sys_call_table",
            "get_sys_call_table_arm64": "sys_call_table",
            "get_sys_call_table_arm64_compat": "compat_sys_call_table",
            "get_per_cpu_offset": "__per_cpu_offset",
            "get_PAGE_OFFSET_base": "page_offset_base",
            "get_current_clocksource": "curr_clocksource",
            "get_log_buffer": "log_buf",
            "get_vmap_nodes_busy_head": "vmap_nodes",
        }
        return exceptions.get(finder_name, finder_name[len("get_"):])

    @staticmethod
    def finders():
        finders = []
        for name in dir(KernelAddressHeuristicFinder):
            if not name.startswith("get_"):
                continue
            finder = getattr(KernelAddressHeuristicFinder, name)
            implementation = finder
            while hasattr(implementation, "__wrapped__"):
                implementation = implementation.__wrapped__
            if "USE_DIRECTLY" in implementation.__code__.co_names:
                finders.append((name, finder))
        return finders

    @staticmethod
    def invoke_finder(finder, args):
        try:
            return finder(*args), None
        except Exception as exception:
            return None, "{:s}: {:s}".format(type(exception).__name__, str(exception))

    @staticmethod
    def format_result(value, error, available=True):
        if error is not None:
            return "ERROR"
        if not available:
            return "-"
        if value is None:
            return "None"
        if isinstance(value, bool):
            return str(value)
        if isinstance(value, int):
            return "{:#x}".format(value)
        return str(value)

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for kallsyms and heuristic scans")

        direct_results = {}
        heuristic_results = {}
        errors = []
        original_use_directly = KernelAddressHeuristicFinder.USE_DIRECTLY

        try:
            KernelAddressHeuristicFinder.USE_DIRECTLY = True
            Cache.reset_gef_caches(all=True)
            if Ksym.get_kallsyms() is None:
                self.quiet_err("Could not read kallsyms")
                return

            for name, finder in self.finders():
                symbol_name = self.direct_symbol_name(name)
                if symbol_name is not None:
                    symbol_address = Ksym.get_addr(symbol_name)
                else:
                    symbol_address = None
                if symbol_address is None:
                    direct_results[name] = (None, None, False, ())
                    continue

                finder_args = ()
                if name in ("get_current_clocksource", "get_log_buffer"):
                    try:
                        if name == "get_current_clocksource":
                            current_clocksource = read_int_from_memory(symbol_address)
                            finder_args = ((current_clocksource,),)
                        else:
                            length_address = Ksym.get_addr("log_buf_len")
                            if length_address is None:
                                direct_results[name] = (None, None, False, ())
                                continue
                            finder_args = (read_int32_from_memory(length_address),)
                    except (gdb.MemoryError, MemoryError) as exception:
                        message = "{:s}: {:s}".format(type(exception).__name__, str(exception))
                        direct_results[name] = (None, message, True, ())
                        errors.append("{:s} direct: {:s}".format(name, message))
                        continue

                value, error = self.invoke_finder(finder, finder_args)
                direct_results[name] = (value, error, True, finder_args)
                if error is not None:
                    errors.append("{:s} direct: {:s}".format(name, error))

            KernelAddressHeuristicFinder.USE_DIRECTLY = False
            Cache.reset_gef_caches(all=True)

            for name, finder in self.finders():
                direct, error, available, finder_args = direct_results[name]
                if not available or error is not None or direct is None or direct is False:
                    heuristic_results[name] = (None, None)
                    continue
                value, error = self.invoke_finder(finder, finder_args)
                heuristic_results[name] = (value, error)
                if error is not None:
                    errors.append("{:s} heuristic: {:s}".format(name, error))
        finally:
            KernelAddressHeuristicFinder.USE_DIRECTLY = original_use_directly
            Cache.reset_gef_caches(all=True)

        rows = []
        verdict_counts = collections.Counter()
        for name, _ in self.finders():
            direct, direct_error, available, _ = direct_results[name]
            heuristic, heuristic_error = heuristic_results[name]
            if (not available or direct is False or heuristic is False or
                    (direct is None and direct_error is None)):
                verdict = "n/a"
            elif direct_error is not None or heuristic_error is not None:
                verdict = "ERROR"
            elif direct == heuristic:
                verdict = "OK"
            elif heuristic is None:
                verdict = "MISS"
            else:
                verdict = "MISMATCH"
            verdict_counts[verdict] += 1
            rows.append((
                name,
                self.format_result(direct, direct_error, available),
                self.format_result(
                    heuristic, heuristic_error,
                    available and direct is not None and direct is not False,
                ),
                verdict,
            ))

        failure_verdicts = ("MISS", "MISMATCH", "ERROR")
        failure_count = sum(verdict_counts[verdict] for verdict in failure_verdicts)
        gdb.set_convenience_variable("ks_selftest_failures", failure_count)
        if args.failures_only:
            visible_rows = [row for row in rows if row[-1] in failure_verdicts]
        else:
            visible_rows = rows

        headers = ("finder", "direct", "heuristic", "verdict")
        widths = [max(len(row[i]) for row in [headers] + visible_rows) for i in range(len(headers))]
        row_format = "  ".join("{{:<{:d}s}}".format(width) for width in widths)
        self.out = [GefUtil.make_legend(row_format.format(*headers))]
        for row in visible_rows:
            line = row_format.format(*row).rstrip()
            if row[-1] in failure_verdicts:
                line = Color.colorify(line, "yellow bold")
            self.out.append(line)
        self.out.append("")
        self.out.append("  ".join(
            "{:s}: {:d}".format(verdict, verdict_counts[verdict])
            for verdict in ("OK", "MISS", "MISMATCH", "ERROR", "n/a")
        ))
        if errors:
            self.out.append("")
            self.out.append(GefUtil.make_legend("errors"))
            self.out.extend(errors)
        self.print_output(check_terminal_size=True)
        return
