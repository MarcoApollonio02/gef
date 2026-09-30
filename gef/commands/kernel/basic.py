"""GEF kernel commands (category 06-c) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Linux Basic: kernel checksec, magic, base,
version, cmdline and current-state commands. Auto-discovered by
gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import re

import gdb

from gef.commands.base import (
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
from gef.core.kernel import Kernel
from gef.core.memory import (
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
    is_kvm_enabled,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import get_register
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil


@register_command
class KernelChecksecCommand(GenericCommand):
    """Check the security properties of the current kernel."""

    _cmdline_ = "kchecksec"
    _category_ = "06-c. Qemu-system/KGDB Cooperation - Linux Basic"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def check_basic_information(self):
        kcmdline = Kernel.kernel_cmdline()
        if kcmdline is None or kcmdline.cmdline is None:
            gef_print("{:<40s}: {:s}".format("Kernel cmdline", "Not found"))
        else:
            gef_print("{:<40s}: {:s}".format("Kernel cmdline", kcmdline.cmdline.strip()))

        text_base = Kernel.get_kernel_base()
        if text_base is None:
            gef_print("{:<40s}: {:s}".format("Kernel base (heuristic)", "Not found"))
        else:
            gef_print("{:<40s}: {:#x}".format("Kernel base (heuristic)", text_base))

        stext = Symbol.get_ksymaddr("_stext")
        if stext is None:
            gef_print("{:<40s}: {:s}".format("Kernel base (_stext from kallsyms)", "Not found"))
        else:
            gef_print("{:<40s}: {:#x}".format("Kernel base (_stext from kallsyms)", stext))
        return

    def x86_specific(self):
        if not is_x86():
            return

        cr0 = get_register("cr0", use_monitor=True)
        cr4 = get_register("cr4", use_monitor=True)

        # WP
        if (cr0 >> 16) & 1:
            gef_print("{:<40s}: {:s}".format("Write Protection (CR0 bit 16)", Color.colorify("Enabled", "bold green")))
        else:
            gef_print("{:<40s}: {:s}".format("Write Protection (CR0 bit 16)", Color.colorify("Disabled", "bold red")))

        # PAE
        if (cr4 >> 5) & 1:
            gef_print("{:<40s}: {:s} (NX is supported)".format("PAE (CR4 bit 5)", Color.colorify("Enabled", "bold green")))
        else:
            gef_print("{:<40s}: {:s} (NX is unsupported)".format("PAE (CR4 bit 5)", Color.colorify("Disabled", "bold red")))

        # SMEP
        if (cr4 >> 20) & 1:
            gef_print("{:<40s}: {:s}".format("SMEP (CR4 bit 20)", Color.colorify("Enabled", "bold green")))
        else:
            gef_print("{:<40s}: {:s}".format("SMEP (CR4 bit 20)", Color.colorify("Disabled", "bold red")))

        # SMAP
        if (cr4 >> 21) & 1:
            gef_print("{:<40s}: {:s}".format("SMAP (CR4 bit 21)", Color.colorify("Enabled", "bold green")))
        else:
            gef_print("{:<40s}: {:s}".format("SMAP (CR4 bit 21)", Color.colorify("Disabled", "bold red")))

        # CET
        if (cr4 >> 23) & 1:
            gef_print("{:<40s}: {:s}".format("CET (CR4 bit 23)", Color.colorify("Enabled", "bold green")))
        else:
            gef_print("{:<40s}: {:s}".format("CET (CR4 bit 23)", Color.colorify("Disabled", "bold red")))

        # CET MSR
        if (cr4 >> 23) & 1:
            if is_kvm_enabled():
                additional = "for more precisely, use `msr MSR_IA32_S_CET` without `-enable-kvm`"
                gef_print("{:<40s}: {:s} ({:s})".format("CET SHSTK (MSR_IA32_S_CET bit 0)", Color.grayify("Unknown"), additional))
                gef_print("{:<40s}: {:s} ({:s})".format("CET IBT (MSR_IA32_S_CET bit 2)", Color.grayify("Unknown"), additional))
            else:
                ret = gdb.execute("msr --quiet MSR_IA32_S_CET", to_string=True)
                MSR_IA32_S_CET = int(ret, 16)
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

    def check_kaslr(self):
        cfg = "CONFIG_RANDOMIZE_BASE (KASLR)"
        kcmdline = Kernel.kernel_cmdline()
        ksym_ret = gdb.execute("ksymaddr-remote --quiet --no-pager kaslr_", to_string=True)

        if not ksym_ret:
            additional = "`kaslr_*`: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        if kcmdline and "nokaslr" in kcmdline.cmdline:
            additional = "nokaslr is in cmdline"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            additional = "`kaslr_*`: Found, nokaslr is not in cmdline"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def check_fgkaslr(self):
        if not is_x86_64():
            return

        # https://github.com/alobakin/linux/pull/3
        cfg = "CONFIG_FG_KASLR (FGKASLR)"

        kversion = Kernel.kernel_version()
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

        swapgs_restore_regs_and_return_to_usermode = Symbol.get_ksymaddr("swapgs_restore_regs_and_return_to_usermode")
        commit_creds = Symbol.get_ksymaddr("commit_creds")

        # something is wrong
        if not swapgs_restore_regs_and_return_to_usermode or not commit_creds:
            gef_print("{:<40s}: {:s}".format(cfg, Color.grayify("Unknown")))
            cfg = "CONFIG_MODULE_FG_KASLR (FGKASLR)"
            gef_print("{:<40s}: {:s}".format(cfg, Color.grayify("Unknown")))
            return

        # swapgs_restore_regs_and_return_to_usermode is in a fixed location.
        # commit_creds are placed dynamically.
        if swapgs_restore_regs_and_return_to_usermode < commit_creds: # For some reason this works fine
            kcmdline = Kernel.kernel_cmdline()
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
        kversion = Kernel.kernel_version()
        if "6.9" <= kversion:
            cfg = "CONFIG_MITIGATION_PAGE_TABLE_ISOLATION (KPTI)"
        else:
            cfg = "CONFIG_PAGE_TABLE_ISOLATION (KPTI)"
        kcmdline = Kernel.kernel_cmdline()

        if is_x86():
            pti_init = Symbol.get_ksymaddr("pti_init")
            if pti_init is None:
                additional = "pti_init: Not found"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            elif kcmdline and "nopti" in kcmdline.cmdline:
                additional = "nopti is in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            elif kcmdline and "pti=off" in kcmdline.cmdline:
                additional = "pti=off is in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            elif kcmdline and "mitigations=off" in kcmdline.cmdline:
                additional = "mitigations=off is in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            elif kcmdline and "pti=on" in kcmdline.cmdline:
                additional = "pti=on is in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            elif is_in_kernel():
                lines = PageMap.get_page_maps_by_pagewalk("pagewalk --quiet --no-pager --simple --disable-color").splitlines()
                for line in lines:
                    if "USER" in line and "R-X" in line:
                        # If the qemu startup option does not include `-cpu kvm64`,
                        # isolation will not occur even if KPTI is enabled.
                        additional = "USER memory has R-X permission in kernel context"
                        gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
                        return
                else:
                    additional = "USER memory has no R-X permission in kernel context"
                    gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled (maybe)", "bold green"), additional))
            else:
                gef_print("{:<40s}: {:s}".format(cfg, Color.grayify("Unknown")))

        if is_arm32():
            gef_print("{:<40s}: {:s} (ARMv7 is unsupported)".format(cfg, Color.colorify("Unsupported", "bold red")))

        if is_arm64():
            pti_init = Symbol.get_ksymaddr("pti_init")
            if pti_init is None:
                additional = "pti_init: Not found"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            elif kcmdline and "kpti=0" in kcmdline.cmdline:
                additional = "kpti=0 is in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            elif kcmdline and "mitigations=off" in kcmdline.cmdline and "nokaslr" in kcmdline.cmdline:
                additional = "mitigations=off and nokaslr are in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            elif kcmdline and "mitigations=off" in kcmdline.cmdline and "nokaslr" not in kcmdline.cmdline:
                additional = "mitigations=off is in cmdline, nokaslr is not in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            elif kcmdline and "kpti=1" in kcmdline.cmdline:
                additional = "kpti=1 is in cmdline"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            else:
                gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("Enabled (maybe)", "bold green")))
        return

    def check_rwx_page(self):
        cfg = "RWX kernel page"
        kinfo = Kernel.get_kernel_layout()
        for m in kinfo.maps:
            if m[2] == "RWX":
                gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("Found", "bold red")))
                return

        gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("Not found", "bold green")))
        return

    def check_secure_world(self):
        if not is_arm32() and not is_arm64():
            return

        mtree_ret = gdb.execute("monitor info mtree -f", to_string=True)
        if ".secure-ram" in mtree_ret:
            gef_print("{:<40s}: {:s}".format("Secure world", "Found"))
        else:
            gef_print("{:<40s}: {:s}".format("Secure world", "Not found"))
        return

    def check_CONFIG_SLAB_FREELIST_HARDENED(self):
        cfg = "CONFIG_SLAB_FREELIST_HARDENED"
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
            gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("Disabled", "bold red")))
        return

    def check_CONFIG_SLAB_VIRTUAL(self):
        cfg = "CONFIG_SLAB_VIRTUAL"
        # https://patchwork.kernel.org/project/linux-mm/patch/20230915105933.495735-12-matteorizzo@google.com/#25548022
        stw = "slub_tlbflush_worker"
        if not Symbol.get_ksymaddr(stw):
            additional = "{:s}: {:s}".format(stw, "Not found")
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
            return

        kversion = Kernel.kernel_version()
        if kversion < "6.6":
            additional = "{:s}: Found (kernel version < 6.6)".format(stw)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        else:
            # If version is >= 6.6, vmlinux can switch `slab_virtual` status with boot-parameter
            kcmdline = Kernel.kernel_cmdline()
            r = re.search(r"slab_virtual=(\d+)", kcmdline.cmdline)
            if r:
                additional = "{:s}: Found, {:s} is in cmdline".format(stw, r.group(0))
                if r.group(1) == "0":
                    gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
                else:
                    gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            else:
                additional = "{:s}: Found, slab_virtual is NOT in cmdline".format(stw)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_selinux(self):
        cfg = "SELinux"
        # SELinux does not support being built as a kernel module.
        # Therefore, only symbols in the kernel can be used to determine whether SELinux is supported or not.
        selinux_init = Symbol.get_ksymaddr("selinux_init")
        if selinux_init is None:
            additional = "selinux_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        kversion = Kernel.kernel_version()
        if kversion < "4.17":
            selinux_enabled_addr = Symbol.get_ksymaddr("selinux_enabled")
            selinux_enforcing_addr = Symbol.get_ksymaddr("selinux_enforcing")
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

        selinux_disable = Symbol.get_ksymaddr("selinux_disable")
        CONFIG_SECURITY_SELINUX_DISABLE = selinux_disable is not None
        enforcing_setup = Symbol.get_ksymaddr("enforcing_setup")
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
        smack_init = Symbol.get_ksymaddr("smack_init")
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
        apparmor_init = Symbol.get_ksymaddr("apparmor_init")
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

        if apparmor_initialized_addr is None:
            additional = "apparmor_init: Found, apparmor_initialized: Not detected"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        kversion = Kernel.kernel_version()
        if kversion < "5.1":
            apparmor_enabled = read_int8_from_memory(apparmor_enabled_addr) # bool
        else:
            apparmor_enabled = read_int32_from_memory(apparmor_enabled_addr) # int
        apparmor_initialized = read_int32_from_memory(apparmor_initialized_addr)

        if apparmor_enabled not in [0, 1]:
            additional = "apparmor_init: Found, apparmor_enabled: {:#x}".format(apparmor_enabled)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        if apparmor_initialized not in [0, 1]:
            additional = "apparmor_init: Found, apparmor_initialized: {:#x}".format(apparmor_initialized)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        additional = "apparmor_init: Found"
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
        tomoyo_init = Symbol.get_ksymaddr("tomoyo_init")
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

    def check_yama(self):
        cfg = "Yama (ptrace_scope)"
        yama_init = Symbol.get_ksymaddr("yama_init")
        if yama_init is None:
            additional = "yama_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        ptrace_scope_addr = KernelAddressHeuristicFinder.get_ptrace_scope()
        if ptrace_scope_addr is None:
            additional = "yama_init: Found, kernel.yama.ptrace_scope: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        ptrace_scope = read_int32_from_memory(ptrace_scope_addr)
        additional = "yama_init: Found, kernel.yama.ptrace_scope: {:d}".format(ptrace_scope)
        if ptrace_scope == 0:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        return

    def check_integrity(self):
        cfg = "Integrity (IMA/EVM)"
        integrity_iintcache_init = Symbol.get_ksymaddr("integrity_iintcache_init")
        if integrity_iintcache_init is None:
            additional = "integrity_iintcache_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        kcmdline = Kernel.kernel_cmdline()
        if kcmdline and "ima_appraise=enforce" in kcmdline.cmdline:
            additional = "integrity_iintcache_init: Found, ima_appraise=enforce is in cmdline"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        elif kcmdline and "ima_appraise=off" in kcmdline.cmdline:
            additional = "integrity_iintcache_init: Found, ima_appraise=off is in cmdline"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        elif kcmdline and "ima_appraise=log" in kcmdline.cmdline:
            additional = "integrity_iintcache_init: Found, ima_appraise=log is in cmdline"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Permissive", "bold red"), additional))
        elif kcmdline and "ima_appraise=fix" in kcmdline.cmdline:
            additional = "integrity_iintcache_init: Found, ima_appraise=fix is in cmdline"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Permissive", "bold red"), additional))
        else:
            additional = "integrity_iintcache_init: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
        return

    def check_loadpin(self):
        cfg = "LoadPin"
        loadpin_init = Symbol.get_ksymaddr("loadpin_init")
        if loadpin_init is None:
            additional = "loadpin_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        kversion = Kernel.kernel_version()
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
        safesetid_security_init = Symbol.get_ksymaddr("safesetid_security_init")
        if safesetid_security_init is None:
            additional = "safesetid_security_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        additional = "safesetid_security_init: Found"
        gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
        return

    def check_lockdown(self):
        cfg = "Lockdown"

        kversion = Kernel.kernel_version()
        if kversion < "5.4":
            additional = "{:s}: implemented from linux 5.4".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unimplemented", "bold red"), additional))
            return

        lockdown_lsm_init = Symbol.get_ksymaddr("lockdown_lsm_init")
        if lockdown_lsm_init is None:
            additional = "lockdown_lsm_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        kernel_locked_down = KernelAddressHeuristicFinder.get_kernel_locked_down()
        if kernel_locked_down is None:
            additional = "lockdown_lsm_init: Found, kernel_locked_down: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
            return

        try:
            val = read_int32_from_memory(kernel_locked_down)
        except gdb.MemoryError:
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
        bpf_lsm_init = Symbol.get_ksymaddr("bpf_lsm_init")
        if bpf_lsm_init is None:
            additional = "bpf_lsm_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        additional = "bpf_lsm_init: Found"
        gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
        return

    def check_landlock(self):
        cfg = "Landlock"
        landlock_init = Symbol.get_ksymaddr("landlock_init")
        if landlock_init is None:
            additional = "landlock_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unsupported", "bold red"), additional))
            return

        additional = "landlock_init: Found"
        gef_print("{:<40s}: {:s} ({:s})".format(cfg, "Supported", additional))
        return

    def check_lkrg(self):
        cfg = "Linux Kernel Runtime Guard (LKRG)"
        kmod_ret = gdb.execute("kmod --quiet --no-pager", to_string=True)
        if "Not found" in kmod_ret:
            additional = "kmod is failed"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        if ": lkrg " in kmod_ret:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), "Loaded"))
        else:
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), "Not loaded"))
        return

    def check_unprivileged_userfaultfd(self):
        cfg = "vm.unprivileged_userfaultfd"

        stv_uff_ret = gdb.execute("syscall-table-view -f userfaultfd --quiet --no-pager", to_string=True)
        if "userfaultfd" not in stv_uff_ret:
            additional = "userfaultfd syscall: Unimplemented"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Syscall unsupported", "bold green"), additional))
            return

        if "invalid userfaultfd" in stv_uff_ret:
            additional = "userfaultfd syscall: Disabled"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Syscall unsupported", "bold green"), additional))
            return

        kversion = Kernel.kernel_version()
        if kversion < "5.2":
            additional = "userfaultfd syscall: Enabled, but without {:s} restriction! (implemented from linux 5.2)".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unimplemented", "bold red"), additional))
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

        stv_bpf_ret = gdb.execute("syscall-table-view -f bpf --quiet --no-pager", to_string=True)
        if "bpf" not in stv_bpf_ret:
            additional = "bpf syscall: Unimplemented"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Syscall unsupported", "bold green"), additional))
            return

        if "invalid bpf" in stv_bpf_ret:
            additional = "bpf syscall: Disabled"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Syscall unsupported", "bold green"), additional))
            return

        kversion = Kernel.kernel_version()
        if kversion < "4.4":
            additional = "bpf syscall: Enabled, without {:s}, but it needs CAP_SYS_ADMIN (implemented from linux 4.4)".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unimplemented", "bold green"), additional))
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
        kversion = Kernel.kernel_version()
        if kversion < "3.14":
            additional = "{:s}: implemented from linux 3.14".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unimplemented", "bold red"), additional))
            return

        r1 = gdb.execute("syscall-table-view -f kexec_load --quiet --no-pager", to_string=True)
        r2 = gdb.execute("syscall-table-view -f kexec_file_load --quiet --no-pager", to_string=True)
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
        kversion = Kernel.kernel_version()
        ksysctl_ret = Kernel.get_ksysctl("kernel.version")
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
        prev_fail = False
        for kv, cfg in cfgs:
            if kversion < kv:
                additional = "{:s}: implemented from linux {:s}".format(cfg, kv)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unimplemented", "bold red"), additional))
                continue

            if not ksysctl_ret: # maybe CONFIG_RANDSTRUCT=y
                additional = "{:s}: Not found".format(cfg)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
                continue

            if prev_fail: # Kernel.get_ksysctl is very slow, so skip if previous Kernel.get_ksysctl() was failed
                additional = "{:s}: Not found".format(cfg)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
                continue

            addr = Kernel.get_ksysctl(cfg) # very slow
            if addr is None:
                additional = "{:s}: Not found".format(cfg)
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
                prev_fail = True
                continue

            val = read_int32_from_memory(addr)
            if val:
                gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("{:d}".format(val), "bold red")))
            else:
                gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("{:d}".format(val), "bold green")))
        return

    def check_unprivileged_userns_clone(self):
        cfg = "kernel.unprivileged_userns_clone"
        addr = Kernel.get_ksysctl(cfg)
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
        addr = Kernel.get_ksysctl(cfg)
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
        modprobe_path = Symbol.get_ksymaddr("modprobe_path")
        if modprobe_path:
            additional = "modprobe_path: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
        else:
            additional = "modprobe_path: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        return

    def check_CONFIG_IKCONFIG(self):
        cfg = "CONFIG_IKCONFIG"
        ikconfig_init = Symbol.get_ksymaddr("ikconfig_init")
        if ikconfig_init:
            additional = "ikconfig_init: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
        else:
            additional = "ikconfig_init: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        return

    def check_CONFIG_DEBUG_INFO_BTF(self):
        cfg = "CONFIG_DEBUG_INFO_BTF"
        __start_BTF = Symbol.get_ksymaddr("__start_BTF")
        if __start_BTF:
            additional = "__start_BTF: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
        else:
            additional = "__start_BTF: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        return

    def check_CONFIG_RANDSTRUCT(self):
        cfg = "CONFIG_RANDSTRUCT"
        # In cases where kallsyms could be resolved, but ksysctl could not be resolved correctly,
        # it is assumed that the structure is strange.
        # Each structure parsed by ksysctl has no difference among kernel versions, except for `struct ctl_dir.inodes`.
        # Additionally, the first member of struct ctl_table is a *char procname, which will almost certainly
        # readable something. If this fails, it can be determined that the randstruct is used.
        ksysctl_ret = Kernel.get_ksysctl("kernel.version")
        if not ksysctl_ret:
            additional = "ksysctl was failed"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            warn(Color.boldify("With `CONFIG_RANDSTRUCT=y`, identifying structure members may be unreliable."))
            warn(Color.boldify("As a result, many GEF commands will not work correctly."))
        else:
            additional = "ksysctl was successful"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_CONFIG_STATIC_USERMODEHELPER(self):

        def get_permission(addr):
            maps = Kernel.get_maps()
            if not maps:
                return None
            for vaddr, size, perm in maps:
                if vaddr <= addr < vaddr + size:
                    return perm
            return None

        cfg = "CONFIG_STATIC_USERMODEHELPER"
        kversion = Kernel.kernel_version()
        if kversion < "4.11":
            additional = "{:s}: implemented from linux 4.11".format(cfg)
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Unimplemented", "bold red"), additional))
            return

        call_usermodehelper_setup = Symbol.get_ksymaddr("call_usermodehelper_setup")
        if call_usermodehelper_setup is None:
            additional = "call_usermodehelper_setup: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
            return

        res = gdb.execute("x/50i {:#x}".format(call_usermodehelper_setup), to_string=True)
        use_static = False
        if is_x86_64():
            g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
        elif is_x86_32():
            g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
        elif is_arm64():
            g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
        elif is_arm32():
            g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
        for x in g:
            if not is_valid_addr(x):
                continue
            # default value of CONFIG_STATIC_USERMODEHELPER_PATH is "/sbin/usermode-helper".
            if read_memory(x, 5) == b"/sbin":
                use_static = True
                break
            # sometimes CONFIG_STATIC_USERMODEHELPER_PATH is set to "".
            # If CONFIG_STATIC_USERMODEHELPER_PATH is "", one NUL should be stored.
            # In many cases, another string seems to start being stored at the next address of NUL.
            # It is rare for two consecutive NULs to occur, and we use this in the detection logic.
            if read_memory(x, 1) == b"\x00" and read_memory(x + 1, 1) != b"\x00":
                # check if the address is read-only or not
                if get_permission(x) == "R--":
                    use_static = True
                    break
        if use_static:
            additional = "call_usermodehelper_setup uses static path"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        else:
            additional = "call_usermodehelper_setup uses dynamic path"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_CONFIG_STACKPROTECTOR(self):
        cfg = "CONFIG_STACKPROTECTOR"
        ktask_ret = gdb.execute("ktask --meta", to_string=True)
        r = re.search(r"offsetof\(task_struct, stack_canary\): (0x\S+)", ktask_ret)
        if r:
            additional = "offsetof(task_struct, stack_canary): {:s}".format(r.group(1))
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
            return

        if "stack_canary" in ktask_ret:
            gef_print("{:<40s}: {:s}".format(cfg, Color.colorify("Disabled", "bold red")))
        else:
            additional = "ktask was failed"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.grayify("Unknown"), additional))
        return

    def check_CONFIG_SHADOW_CALL_STACK(self):
        if not is_arm64():
            return

        cfg = "CONFIG_SHADOW_CALL_STACK (Clang ARM64)"
        scs_alloc = Symbol.get_ksymaddr("scs_alloc")
        if scs_alloc:
            additional = "scs_alloc: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        else:
            additional = "scs_alloc: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_CONFIG_HARDENED_USERCOPY(self):
        cfg = "CONFIG_HARDENED_USERCOPY"
        __check_heap_object = Symbol.get_ksymaddr("__check_heap_object")
        if __check_heap_object:
            additional = "__check_heap_object: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold green"), additional))
        else:
            additional = "__check_heap_object: Not found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold red"), additional))
        return

    def check_CONFIG_FUSE_FS(self):
        cfg = "CONFIG_FUSE_FS"
        fuse_do_open = Symbol.get_ksymaddr("fuse_do_open")
        if fuse_do_open:
            additional = "fuse_do_open: Found"
            gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
        else:
            ret = gdb.execute("kmod --filter fuse --quiet", to_string=True)
            if ret:
                additional = "fuse module: Found"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Enabled", "bold red"), additional))
            else:
                additional = "fuse module: Not found"
                gef_print("{:<40s}: {:s} ({:s})".format(cfg, Color.colorify("Disabled", "bold green"), additional))
        return

    def check_kadr_kallsyms(self):
        cfg = "KADR (kallsyms)"
        kversion = Kernel.kernel_version()
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
        v2 = u32(read_memory(sysctl_perf_event_paranoid, 4), s=True)
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
            elif Symbol.get_ksymaddr("ia32_sys_call"): # 6.6.26~
                supported_syscall.append("x86(compat)")
            if KernelAddressHeuristicFinder.get_sys_call_table_x32():
                supported_syscall.append("x32")
            elif Symbol.get_ksymaddr("x32_sys_call"): # 6.6.26~
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

    def print_security_properties_qemu_system(self):
        gef_print(titlify("Kernel information"))
        kversion = Kernel.kernel_version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        gef_print("{:<40s}: {:d}.{:d}.{:d}".format("Kernel version", *kversion.version_tuple))
        self.check_basic_information()

        gef_print(titlify("Register settings"))
        self.x86_specific()
        self.arm32_specific()
        self.arm64_specific()

        if Symbol.get_ksymaddr("_stext") is None:
            err("ksymaddr-remote is failed")
            return

        gef_print(titlify("Memory settings"))
        self.check_kaslr()
        self.check_fgkaslr()
        self.check_kpti()
        self.check_rwx_page()
        self.check_secure_world()

        gef_print(titlify("Allocator"))
        allocator = Kernel.get_slab_type()
        gef_print("{:<40s}: {:s}".format("Allocator", allocator))
        if allocator == "SLUB":
            self.check_CONFIG_SLAB_FREELIST_HARDENED()
            self.check_CONFIG_SLAB_VIRTUAL()

        gef_print(titlify("Security Module"))
        self.check_selinux()
        self.check_smack()
        self.check_apparmor()
        self.check_tomoyo()
        self.check_yama()
        self.check_integrity()
        self.check_loadpin()
        self.check_safe_setid()
        self.check_lockdown()
        self.check_bpf()
        self.check_landlock()
        self.check_lkrg()

        gef_print(titlify("Dangerous system call"))
        self.check_unprivileged_userfaultfd()
        self.check_unprivileged_bpf_disabled()
        self.check_kexec_load_disabled()

        gef_print(titlify("namespaces"))
        self.check_namespaces()
        self.check_unprivileged_userns_clone()
        self.check_userns_restrict()

        gef_print(titlify("Other"))
        self.check_CONFIG_KALLSYMS_ALL()
        self.check_CONFIG_IKCONFIG()
        self.check_CONFIG_DEBUG_INFO_BTF()
        self.check_CONFIG_RANDSTRUCT()
        self.check_CONFIG_STATIC_USERMODEHELPER()
        self.check_CONFIG_STACKPROTECTOR()
        self.check_CONFIG_SHADOW_CALL_STACK()
        self.check_CONFIG_HARDENED_USERCOPY()
        self.check_CONFIG_FUSE_FS()
        self.check_kadr_kallsyms()
        self.check_kadr_dmesg()
        self.check_mmap_min_addr()
        self.check_supported_syscall()
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
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

        for filt in self.args.filter:
            if filt in sym:
                return True
        return False

    def resolve_and_print_kernel(self, sym, base, maps, external_func=None, to_string=False):

        def get_permission(addr, maps):
            if maps is None:
                return "???"
            for vaddr, size, perm in maps:
                if vaddr <= addr and addr < vaddr + size:
                    return perm
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
                addr = Symbol.get_ksymaddr(sym)
                if addr is None:
                    gef_print("{:42s} {:>{:d}s}".format(sym, "Not found", width))
                    return
            elif isinstance(sym, list):
                for s in sym:
                    addr = Symbol.get_ksymaddr(s)
                    if addr:
                        sym = s
                        break
                else:
                    sym = sym[0]
                    gef_print("{:42s} {:>{:d}s}".format(sym, "Not found", width))
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
            gef_print("{:42s} {:#0{:d}x} [{:3s}] (+{:#010x}) -> {:s}".format(
                sym, addr, width, perm, addr - base, val,
            ))
        else:
            val = read_int_from_memory(addr)
            gef_print("{:42s} {:#0{:d}x} [{:3s}] (+{:#010x}) -> {:#0{:d}x}".format(
                sym, addr, width, perm, addr - base, val, width,
            ))
        return

    def magic_kernel(self):
        info("Wait for memory scan")
        kversion = Kernel.kernel_version()

        kinfo = Kernel.get_kernel_layout()
        maps = kinfo.maps
        text_base = kinfo.text_base
        text_size = kinfo.text_size
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
        self.resolve_and_print_kernel("__kmalloc", text_base, maps)
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
            "PAGE_OFFSET_END", None, maps, KernelAddressHeuristicFinder.get_PAGE_OFFSET_END,
        )
        self.resolve_and_print_kernel(
            "VMALLOC_START", None, maps, KernelAddressHeuristicFinder.get_VMALLOC_START,
        )
        self.resolve_and_print_kernel(
            "VMALLOC_END", None, maps, KernelAddressHeuristicFinder.get_VMALLOC_END,
        )
        if is_x86_64() or is_arm64():
            self.resolve_and_print_kernel(
                "VMEMMAP_START (struct page[])", None, maps, KernelAddressHeuristicFinder.get_VMEMMAP_START,
            )
            self.resolve_and_print_kernel(
                "VMEMMAP_END", None, maps, KernelAddressHeuristicFinder.get_VMEMMAP_END,
            )
        if is_x86_64():
            self.resolve_and_print_kernel(
                "phys_base (kbase@phys)", text_base, maps, KernelAddressHeuristicFinder.get_phys_base,
            )
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
    """Display kernel version string."""

    _cmdline_ = "kversion"
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

        self.quiet_info("Wait for memory scan")
        kversion = Kernel.kernel_version()
        if kversion is None:
            self.quiet_err("Failed to resolve")
            return

        self.out = []
        self.out.append("{:#x}: {:s}".format(kversion.address, kversion.version_string))
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

    def __init__(self):
        super().__init__()
        self.__per_cpu_offset = None
        self.cpu_offset = None
        self.offset_comm = None
        return

    @staticmethod
    def get_each_cpu_offset(__per_cpu_offset):
        """
        Note that the number of CPUs and the number of threads may not match.
        x64 example:
        len(gdb.selected_inferior().threads()) == 2; but __per_cpu_offset entry is 1
        0xffffffff93980680|+0x0000|+000: 0xffff9724c7800000  ->  0x0000000000000000
        0xffffffff93980688|+0x0008|+001: 0xffffffff93d0d000
        0xffffffff93980690|+0x0010|+002: 0xffffffff93d0d000
        Therefore, when the same address is repeated, it is considered to be the end.
        """
        cpu_offset = []
        i = 0
        while True:
            off = read_int_from_memory(__per_cpu_offset + i * runtime.current_arch.ptrsize)
            """
            off itself may refer to inaccessible memory.
            x86 example:
            __per_cpu_offset: 0xc6a27440
            0xc6a27440|+0x0000|+000: 0x2d849000 -> inaccessible
            0xc6a27444|+0x0004|+001: 0x00000000
            """
            if (off <= 0x10) or (off & 0xf):
                break
            if len(cpu_offset) >= 1 and off == cpu_offset[-1]:
                cpu_offset.pop() # remove last one
                break
            cpu_offset.append(off)
            i += 1
        return cpu_offset

    def get_cpu_offset(self):
        # use cache
        if self.cpu_offset:
            self.quiet_info("__per_cpu_offset: {:#x}".format(self.__per_cpu_offset))
            self.quiet_info("Num of cpu: {:d} (guessed)".format(len(self.cpu_offset)))
            return self.cpu_offset

        # resolve __per_cpu_offset
        __per_cpu_offset = KernelAddressHeuristicFinder.get_per_cpu_offset()

        # not found
        if __per_cpu_offset is None:
            self.quiet_err("Failed to resolve `__per_cpu_offset`")
            return None

        # found
        self.quiet_info("__per_cpu_offset: {:#x}".format(__per_cpu_offset))
        self.__per_cpu_offset = __per_cpu_offset

        self.cpu_offset = KernelCurrentCommand.get_each_cpu_offset(__per_cpu_offset)
        self.quiet_info("Num of cpu: {:d} (guessed)".format(len(self.cpu_offset)))
        return self.cpu_offset

    def get_comm_str(self, task_addr):
        if self.offset_comm is None:
            ret = gdb.execute("ktask --no-pager --meta", to_string=True)
            r = re.search(r"offsetof\(task_struct, comm\): (0x\S+)", ret)
            if r is not None:
                self.offset_comm = int(r.group(1), 16)
            else:
                self.quiet_err("ktask is failed")
                self.offset_comm = False

        if self.offset_comm is False:
            return "???"

        comm = read_cstring_from_memory(task_addr + self.offset_comm)
        return comm or "???"

    def dump_current_arm(self):
        orig_thread = gdb.selected_thread()
        orig_frame = gdb.selected_frame()
        threads = gdb.selected_inferior().threads()
        threads = sorted(threads, key=lambda th: th.num)
        for thread in threads:
            thread.switch() # change thread
            task = KernelAddressHeuristicFinder.get_current_task_for_current_thread()
            if task is None:
                continue
            if is_valid_addr(task):
                cpu_num = thread.num - 1 # ?
                gef_print("current (cpu{:d}): {:#x} {:s}".format(cpu_num, task, self.get_comm_str(task)))
        orig_thread.switch() # revert thread
        orig_frame.select()
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
                task = read_int_from_memory(AddressUtil.normalize_address(cpu_base + task_offset))
                if not is_valid_addr(task):
                    break
                gef_print("current (cpu{:d}): {:#x} {:s}".format(i, task, self.get_comm_str(task)))
        else:
            # pattern 2: current_task is the address that stores a pointer to the current task (not per_cpu).
            self.quiet_info("__per_cpu_offset is unused")
            task = read_int_from_memory(current_task)
            if is_valid_addr(task):
                gef_print("current: {:#x} {:s}".format(task, self.get_comm_str(task)))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        if is_arm32() or is_arm64():
            self.dump_current_arm()
        elif is_x86():
            self.dump_current_x86()
        return

