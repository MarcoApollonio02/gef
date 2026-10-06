"""GEF process-info commands (category 02-f) extracted from the monolithic gef.py.

Security-related commands (canary, capabilities, pointer mangling, checksec, ASLR, MTE tags).

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import os
import re
import struct

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_arch,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_gdb_target_local,
    only_if_specific_arch,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import Address, AddressUtil, Permission
from gef.core.auxv import Auxv
from gef.core.bitinfo import BitInfo
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, ok, titlify, warn
from gef.core.config import Config
from gef.core.elf import Checksec, Elf
from gef.core.exec import ExecAsm
from gef.core.instruction import get_insn
from gef.core.memory import is_valid_addr, read_int_from_memory, read_memory, u32, u64
from gef.core.process import (
    Path,
    Pid,
    ProcessMap,
    get_pagesize,
    is_alive,
    is_arm32,
    is_arm32_cortex_m,
    is_arm64,
    is_attach,
    is_in_kernel,
    is_pin,
    is_qemu_system,
    is_qiling,
    is_remote_debug,
    is_rr,
    is_s390x,
    is_vmware,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil, slice_unpack

@register_command
class CanaryCommand(GenericCommand):
    """Display the canary value of the current process from auxv information."""

    _cmdline_ = "canary"
    _category_ = "02-f. Process Information - Security"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @staticmethod
    @Cache.cache_this_session
    def gef_read_canary():
        """Read the canary of a running process using Auxiliary Vector.
        Return a tuple of (canary, location) if found, None otherwise."""
        if is_in_kernel():
            return None

        try:
            auxval = Auxv.get_auxiliary_values()
            if not auxval:
                return None
            canary_location = auxval["AT_RANDOM"]
            canary = read_int_from_memory(canary_location)
            canary &= ~0xff
            return canary, canary_location
        except (KeyError, gdb.MemoryError):
            return None

    def dump_canary(self):
        res = CanaryCommand.gef_read_canary()
        if not res:
            err("Failed to get the canary")
            return

        canary, location = res
        gef_print(titlify("Canary value"))
        info("Found AT_RANDOM at {!s}, reading {:d} bytes".format(
            ProcessMap.lookup_address(location), runtime.current_arch.ptrsize,
        ))
        info("The canary is {:s}".format(Color.colorify_hex(canary, "bold")))

        gef_print(titlify("Found canaries"))
        vmmap = ProcessMap.get_process_maps_exclude_special_regions(allow_vdso=True)
        unpack = u32 if runtime.current_arch.ptrsize == 4 else u64
        sp = runtime.current_arch.sp
        printed_flag_sp = False
        for m in vmmap:
            if not (m.permission & Permission.READ):
                continue
            if not (m.permission & Permission.WRITE):
                continue
            try:
                data = read_memory(m.page_start, m.page_end - m.page_start)
            except gdb.MemoryError:
                continue
            prev_addr = -1
            for pos in range(0, m.page_end - m.page_start, runtime.current_arch.ptrsize):
                addr = m.page_start + pos
                d = data[pos: pos + runtime.current_arch.ptrsize]
                if canary != unpack(d):
                    continue
                if m.path == "":
                    path = "unknown"
                else:
                    path = m.path
                if prev_addr <= sp <= addr:
                    if printed_flag_sp is False:
                        info("(Stack pointer is at {!s})".format(ProcessMap.lookup_address(sp)))
                        printed_flag_sp = True
                if path == "[stack]":
                    info("Found at {!s} in {!r} (sp{:+#x})".format(
                        ProcessMap.lookup_address(addr), path, addr - sp,
                    ))
                else:
                    info("Found at {!s} in {!r}".format(ProcessMap.lookup_address(addr), path))
                prev_addr = addr
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @require_arch_set
    def do_invoke(self, args):
        self.dump_canary()
        return


@register_command
class CapabilityCommand(GenericCommand, BufferingOutput):
    """Display the capabilities of the debugging process."""

    _cmdline_ = "capability"
    _category_ = "02-f. Process Information - Security"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also display detailed bit information other than cap_eff.")
    _syntax_ = parser.format_help()

    def get_thread_ids(self, pid):
        try:
            tids = os.listdir("/proc/{:d}/task".format(pid))
            return [int(x) for x in tids]
        except (FileNotFoundError, OSError):
            return []

    def print_cap_details(self, name, cap):
        bit_info = [
            [40, "CAP_CHECKPOINT_RESTORE", "Update /proc/sys/kernel/ns_last_pid; read /proc/[another_pid]/map_files; etc."],
            [39, "CAP_BPF", "Allow privileged BPF operations"],
            [38, "CAP_PERFMON", "Allow various performance-monitoring mechanisms; allow perf_event_open(2); allow some BPF operations"],
            [37, "CAP_AUDIT_READ", "Allow reading the audit log via a multicast netlink socket"],
            [36, "CAP_BLOCK_SUSPEND", "Allow features that can block system suspend"],
            [35, "CAP_WAKE_ALARM", "Trigger something that will wake up the system"],
            [34, "CAP_SYSLOG", "Allow privileged syslog(2) operations; View kernel addresses exposed via /proc even if kptr_restrict=1"],
            [33, "CAP_MAC_ADMIN", "Allow MAC configuration or state changes"],
            [32, "CAP_MAC_OVERRIDE", "Override MAC"],
            [31, "CAP_SETFCAP", "Set arbitrary capabilities on a file"],
            [30, "CAP_AUDIT_CONTROL", "Enable/disable kernel audit; change audit filter rules; retrieve audit status and filter rules"],
            [29, "CAP_AUDIT_WRITE", "Write records to kernel audit log"],
            [28, "CAP_LEASE", "Establish leases"],
            [27, "CAP_MKNOD", "Create special files using mknod(2)"],
            [26, "CAP_SYS_TTY_CONFIG", "Allow vhangup(2); allow various privileged ioctl(2) operations on virtual terminals"],
            [25, "CAP_SYS_TIME", "Set system clock; set real-time (hardware) clock"],
            [24, "CAP_SYS_RESOURCE", "Override disk quota limits; override RLIMIT_NPROC resource limit; etc."],
            [23, "CAP_SYS_NICE", "Lower the process nice value and change the nice value for arbitrary processes; etc."],
            [22, "CAP_SYS_BOOT", "Allow reboot(2) and kexec_load(2)"],
            [21, "CAP_SYS_ADMIN", "Allow various privileges operations"],
            [20, "CAP_SYS_PACCT", "Allow acct(2)"],
            [19, "CAP_SYS_PTRACE", "Trace arbitrary processes using ptrace(2); etc."],
            [18, "CAP_SYS_CHROOT", "Allow chroot(2); change mount namespaces using setns(2)"],
            [17, "CAP_SYS_RAWIO", "Perform I/O port operations; etc."],
            [16, "CAP_SYS_MODULE", "Load and unload kernel modules"],
            [15, "CAP_IPC_OWNER", "Bypass permission checks for operations on SystemV IPC objects"],
            [14, "CAP_IPC_LOCK", "Lock memory; allocate memory using huge pages"],
            [13, "CAP_NET_RAW", "Use RAW and PACKET sockets; bind to any address for transparent proxying"],
            [12, "CAP_NET_ADMIN", "Perform various network-related operations"],
            [11, "CAP_NET_BROADCAST", "(Unused) Make socket broadcasts, and listen to multicast"],
            [10, "CAP_NET_BIND_SERVICE", "Bind a socket to Internet domain privileged ports (less than 1024)"],
            [9, "CAP_LINUX_IMMUTABLE", "Set the FS_APPEND_FL and FS_IMMUTABLE_FL inode flags"],
            [8, "CAP_SETPCAP", "Add any capability from the calling thread's bounding set to its inheritable set; etc."],
            [7, "CAP_SETUID", "Make arbitrary manipulations of process UIDs; etc."],
            [6, "CAP_SETGID", "Make arbitrary manipulations of process GIDs and supplementary GID list; etc."],
            [5, "CAP_KILL", "Bypass permission checks for sending signals"],
            [4, "CAP_FSETID", "Don't clear SUID and SGID bits when a file is modified; etc."],
            [3, "CAP_FOWNER", "Bypass permission checks whether FSUID == file UID; set ACLs; etc."],
            [2, "CAP_DAC_READ_SEARCH", "Bypass permission checks of file read, dir read/exec; etc."],
            [1, "CAP_DAC_OVERRIDE", "Bypass permission checks of file read/write/exec"],
            [0, "CAP_CHOWN", "Make arbitrary changes to file UIDs and GIDs"],
        ]
        out = BitInfo(name, 64, bit_info).make_out(cap)
        self.out.append(titlify(""))
        self.out.extend(out)
        self.out.append(titlify(""))
        return

    def print_capability_from_pid(self):
        pid = Pid.get_pid()
        if pid is None:
            return

        tids = self.get_thread_ids(pid)
        for tid in tids:
            self.out.append(titlify("Thread capability set [PID={:d}, TID={:d}]".format(pid, tid)))
            try:
                status_path = "/proc/{:d}/task/{:d}/status".format(pid, tid)
                status = open(status_path, "r").read()
            except (FileNotFoundError, OSError):
                self.err_add_out("Failed to get the information of capability from {:s}".format(status_path))
                continue

            caps = {}
            m = re.search(r"CapInh:\s+(.+)", status)
            if m:
                caps["cap_inh"] = int(m.group(1), 16)
            m = re.search(r"CapPrm:\s+(.+)", status)
            if m:
                caps["cap_prm"] = int(m.group(1), 16)
            m = re.search(r"CapEff:\s+(.+)", status)
            if m:
                caps["cap_eff"] = int(m.group(1), 16)
            m = re.search(r"CapBnd:\s+(.+)", status)
            if m:
                caps["cap_bnd"] = int(m.group(1), 16)
            m = re.search(r"CapAmb:\s+(.+)", status)
            if m:
                caps["cap_amb"] = int(m.group(1), 16)

            if "cap_prm" in caps:
                msg = "Capability set that Effective and Inheritable are allowed to have"
                self.out.append("Permitted  : {:#018x} - {:s}".format(caps["cap_prm"], msg))
                if self.args.verbose:
                    self.print_cap_details("cap_prm", caps["cap_prm"])
            if "cap_inh" in caps:
                msg = "Capability set that can be inherited when execve(2)"
                self.out.append("Inheritable: {:#018x} - {:s}".format(caps["cap_inh"], msg))
                if self.args.verbose:
                    self.print_cap_details("cap_inh", caps["cap_inh"])
            if "cap_amb" in caps:
                msg = "Capability set that inherited when execve(2) not suid/sgid program"
                self.out.append("Ambient    : {:#018x} - {:s}".format(caps["cap_amb"], msg))
                if self.args.verbose:
                    self.print_cap_details("cap_amb", caps["cap_amb"])
            if "cap_eff" in caps:
                msg = "Capability set that kernel actually uses to determine privileges"
                self.out.append("Effective  : {:#018x} - {:s}".format(caps["cap_eff"], msg))
                if self.args.verbose:
                    self.print_cap_details("cap_eff", caps["cap_eff"])
            if "cap_bnd" in caps:
                msg = "Capability set that limits the capabilities set that can be acquired"
                self.out.append("Bounding   : {:#018x} - {:s}".format(caps["cap_bnd"], msg))
                if self.args.verbose:
                    self.print_cap_details("cap_bnd", caps["cap_bnd"])
        return

    def print_capability_from_file(self):
        filepath = Path.get_filepath()
        if filepath is None:
            return

        self.out.append(titlify("File capability set [{:s}]".format(filepath)))
        try:
            raw_caps = os.getxattr(filepath, "security.capability")
        except OSError:
            self.err_add_out("No data available")
            return

        caps = {}
        magic = struct.unpack("<I", raw_caps[:4])[0]
        caps["magic"] = magic & ~1
        caps["cap_eff"] = magic & 1
        if caps["magic"] == 0x0100_0000:
            cap_prm, cap_inh = struct.unpack("<II", raw_caps[4:12])
        elif caps["magic"] == 0x0200_0000:
            cap_prm_low, cap_inh_low, cap_prm_high, cap_inh_high = struct.unpack("<IIII", raw_caps[4:20])
            cap_prm = (cap_prm_high << 32) | cap_prm_low
            cap_inh = (cap_inh_high << 32) | cap_inh_low
        elif caps["magic"] == 0x0300_0000:
            cap_prm_low, cap_inh_low, cap_prm_high, cap_inh_high, rootid = struct.unpack("<IIIII", raw_caps[4:24])
            cap_prm = (cap_prm_high << 32) | cap_prm_low
            cap_inh = (cap_inh_high << 32) | cap_inh_low
            caps["rootid"] = rootid
        else:
            self.err_add_out("Invalid magic values: {:#x}".format(magic))
            return
        caps["cap_prm"] = cap_prm
        caps["cap_inh"] = cap_inh

        if "magic" in caps:
            msg = "Magic number: ver1: 0x01000000, ver2:0x02000000, ver3:0x03000000"
            self.out.append("Magic      : {:#010x} - {:s}".format(caps["magic"], msg))
        if "cap_eff" in caps:
            msg = "If 1, new cap_prm are added to new cap_eff after execve(2)"
            self.out.append("Effective  : {:#03x} - {:s}".format(caps["cap_eff"], msg))
        if "cap_prm" in caps:
            msg = "Capability set that permitted to the thread, regardless of the thread's cap_inh"
            self.out.append("Permitted  : {:#018x} - {:s}".format(caps["cap_prm"], msg))
            if self.args.verbose:
                self.print_cap_details("cap_prm", caps["cap_prm"])
        if "cap_inh" in caps:
            msg = "Capability set that is ANDed with thread cap_inh to determine cap_inh after execve(2)"
            self.out.append("Inheritable: {:#018x} - {:s}".format(caps["cap_inh"], msg))
            if self.args.verbose:
                self.print_cap_details("cap_inh", caps["cap_inh"])
        if "rootid" in caps:
            msg = "UID of root in user namespace"
            self.out.append("Root ID    : {:#010x} - {:s}".format(caps["rootid"], msg))
        return

    @parse_args
    @only_if_gdb_target_local
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        self.out = []
        self.print_capability_from_pid()
        self.print_capability_from_file()
        self.print_output(check_terminal_size=True)
        return


@register_command
class PtrDemangleCommand(GenericCommand):
    """Demangle a mangled value by PTR_MANGLE."""

    _cmdline_ = "ptr-demangle"
    _category_ = "02-f. Process Information - Security"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("value", metavar="VALUE", nargs="?", type=AddressUtil.parse_address,
                       help="the value to demangle.")
    group.add_argument("--source", action="store_true",
                       help="shows the source instead of displaying demangled value.")
    _syntax_ = parser.format_help()

    @staticmethod
    @Cache.cache_until_next
    def get_cookie():
        if is_in_kernel():
            return None
        if is_arm32_cortex_m():
            return None
        if is_qiling():
            return None

        try:
            if is_x86_64():
                tls = runtime.current_arch.get_tls()
                cookie = read_int_from_memory(tls + 0x30)
                return cookie
            elif is_x86_32():
                tls = runtime.current_arch.get_tls()
                cookie = read_int_from_memory(tls + 0x18)
                return cookie
            elif is_arm32() or is_arm64():
                cookie_ptr = AddressUtil.parse_address("&__pointer_chk_guard_local")
                cookie = read_int_from_memory(cookie_ptr)
                return cookie
        except (gdb.error, OverflowError):
            pass

        # generic
        try:
            auxv = Auxv.get_auxiliary_values()
            if auxv is None:
                Cache.reset_gef_caches()
                auxv = Auxv.get_auxiliary_values()
            if auxv and "AT_RANDOM" in auxv:
                if is_s390x():
                    cookie = read_int_from_memory(auxv["AT_RANDOM"]) & 0x00ff_ffff_ffff_ffff
                else:
                    cookie = read_int_from_memory(auxv["AT_RANDOM"] + runtime.current_arch.ptrsize)
                if cookie != 0:
                    return cookie
        except gdb.error:
            pass
        return None

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @exclude_specific_arch(arch=("SPARC32", "XTENSA", "CRIS"))
    @require_arch_set
    def do_invoke(self, args):
        if args.source:
            s = GefUtil.get_source(runtime.current_arch.decode_cookie)
            gef_print(s)
            return

        cookie = self.get_cookie()
        if cookie is None:
            return
        info("Cookie is {:s}".format(Color.colorify_hex(cookie, "bold")))

        decoded = runtime.current_arch.decode_cookie(args.value, cookie)
        decoded = ProcessMap.lookup_address(decoded)
        decoded_sym = Symbol.get_symbol_string(decoded.value)
        if is_valid_addr(decoded.value):
            valid_msg = Color.colorify("valid", "bold green")
        else:
            valid_msg = Color.colorify("invalid", "bold red")
        info("Decoded value is {!s}{:s} [{:s}]".format(decoded, decoded_sym, valid_msg))
        return


@register_command
class PtrMangleCommand(GenericCommand):
    """Mangle a pointer value by PTR_MANGLE."""

    _cmdline_ = "ptr-mangle"
    _category_ = "02-f. Process Information - Security"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("value", metavar="VALUE", nargs="?", type=AddressUtil.parse_address,
                       help="the value to mangle.")
    group.add_argument("--source", action="store_true",
                       help="shows the source instead of displaying mangled value.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @exclude_specific_arch(arch=("SPARC32", "XTENSA", "CRIS"))
    @require_arch_set
    def do_invoke(self, args):
        if args.source:
            s = GefUtil.get_source(runtime.current_arch.encode_cookie)
            gef_print(s)
            return

        cookie = PtrDemangleCommand.get_cookie()
        if cookie is None:
            return
        info("Cookie is {:s}".format(Color.colorify_hex(cookie, "bold")))

        encoded = runtime.current_arch.encode_cookie(args.value, cookie)
        info("Encoded value is {:#x}".format(encoded))
        return


@register_command
class SearchMangledPtrCommand(GenericCommand):
    """Search for mangled values in RW memory."""

    _cmdline_ = "search-mangled-ptr"
    _category_ = "02-f. Process Information - Security"
    _aliases_ = ["cookie"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="shows the section currently being searched.")
    _syntax_ = parser.format_help()

    def print_section(self, section):
        if isinstance(section, Address):
            section = section.section

        if section is None:
            return

        title = "In "
        if section.path:
            title += "'{}' ".format(Color.blueify(section.path))

        title += "({:#x}-{:#x} [{}])".format(section.page_start, section.page_end, section.permission)
        ok(title)
        return

    def print_loc(self, addr, value, decoded):
        addr_sym = Symbol.get_symbol_string(addr)
        decoded = ProcessMap.lookup_address(decoded)
        decoded_sym = Symbol.get_symbol_string(decoded.value)

        if is_valid_addr(decoded.value):
            valid_msg = Color.colorify("valid", "bold green")
        else:
            valid_msg = Color.colorify("invalid", "bold red")

        base_address_color = Config.get_gef_setting("theme.dereference_base_address")
        width = AddressUtil.get_format_address_width()
        addr = Color.colorify("{:#0{:d}x}".format(addr, width), base_address_color)

        gef_print("  {:s}{:s}: {:#x} (={!s}{:s}) [{:s}]".format(addr, addr_sym, value, decoded, decoded_sym, valid_msg))
        return

    def search_mangled_ptr(self, start_address, end_address, cookie):
        """Search for a mangled pointer within a range defined by arguments."""
        if is_qemu_system():
            step = get_pagesize()
        else:
            step = 0x400 * get_pagesize()
        locations = []

        for chunk_addr in range(start_address, end_address, step):
            if chunk_addr + step > end_address:
                chunk_size = end_address - chunk_addr
            else:
                chunk_size = step

            try:
                mem = read_memory(chunk_addr, chunk_size)
            except gdb.MemoryError:
                # cannot access memory this range. It doesn't make sense to try any more
                break

            for i, value in enumerate(slice_unpack(mem, runtime.current_arch.ptrsize)):
                decoded = runtime.current_arch.decode_cookie(value, cookie)
                if not is_valid_addr(decoded):
                    continue
                addr = chunk_addr + i * runtime.current_arch.ptrsize
                locations.append((addr, value, decoded))
            del mem
        return locations

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @exclude_specific_arch(arch=("SPARC32", "XTENSA", "CRIS"))
    @require_arch_set
    def do_invoke(self, args):
        # init
        cookie = PtrDemangleCommand.get_cookie()
        if cookie is None:
            return
        info("Cookie is {:s}".format(Color.colorify_hex(cookie, "bold")))

        # check
        if runtime.current_arch.decode_cookie(0, 1) == 0:
            err("In this architecture, the value is not encrypted with cookies")
            return

        # search
        maps_generator = ProcessMap.get_process_maps()
        for section in maps_generator:
            if not section.permission & Permission.READ:
                continue
            if not section.permission & Permission.WRITE:
                continue
            if args.verbose:
                self.print_section(section) # verbose: always print section before search

            start = section.page_start
            end = section.page_end
            ret = self.search_mangled_ptr(start, end, cookie)

            if ret:
                if not args.verbose:
                    self.print_section(section) # default: print section if found

            for addr, value, decoded in ret:
                self.print_loc(addr, value, decoded)

            if not is_alive():
                err("The process is dead")
                break
        return


@register_command
class ChecksecCommand(GenericCommand):
    """Check the security properties of the current executable or passed as argument."""

    _cmdline_ = "checksec"
    _category_ = "02-f. Process Information - Security"
    _aliases_ = ["cs"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--remote", action="store_true",
                        help="parse remote binary if download feature is available.")
    parser.add_argument("-f", "--file", help="the file path to parse.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -f /bin/ls",
        "{0:s} -r",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    def check_CET_SHSTK(self, sec):
        # Intel CET SHSTK flags via Ehdr
        if "CET SHSTK flag" not in sec:
            # ELF is not x86_64
            return
        if sec["CET SHSTK flag"]:
            gef_print("{:<40s}: {:s}".format("CET SHSTK feature flag (via Ehdr)", Color.colorify("Found", "bold green")))
        else:
            gef_print("{:<40s}: {:s}".format("CET SHSTK feature flag (via Ehdr)", Color.colorify("Not found", "bold red")))

        # gdb mode check
        if not is_x86():
            return
        if not is_alive():
            return
        if is_rr():
            return

        # Intel CET SHSTK status via arch_prctl
        if is_pin():
            # Intel SDE implements userspace CET SHSTK but old interface
            r = Checksec.get_cet_status_old_interface()
            if r is None:
                msg = Color.colorify("Disabled", "bold red") + " (kernel does not support; Intel SDE has no `-cet` option)"
                gef_print("{:<40s}: {:s}".format("CET IBT status (via old arch_prctl IF)", msg))
            else:
                if r & 0b10:
                    msg = Color.colorify("Enabled", "bold green") + " (kernel supports; Intel SDE has `-cet` option)"
                    gef_print("{:<40s}: {:s}".format("CET SHSTK status (via old arch_prctl IF)", msg))
                else:
                    msg = Color.colorify("Disabled", "bold red") + " (kernel supports but disabled; Intel SDE has `-cet` option)"
                    gef_print("{:<40s}: {:s}".format("CET SHSTK status (via old arch_prctl IF)", msg))
        else:
            # kernel 6.6 or after supports userspace CET SHSTK
            r = Checksec.get_cet_status_new_interface()
            if r is None:
                msg = Color.colorify("Unimplemented", "bold red") + " (kernel does not support; kernel supports it from 6.6)"
                gef_print("{:<40s}: {:s}".format("CET SHSTK status (via new arch_prctl IF)", msg))
            else:
                if r & 0b01:
                    msg = Color.colorify("Enabled", "bold green") + " (kernel supports and enabled)"
                    gef_print("{:<40s}: {:s}".format("CET SHSTK status (via new arch_prctl IF)", msg))
                else:
                    msg = Color.colorify("Disabled", "bold red") + " (kernel supports but disabled)"
                    gef_print("{:<40s}: {:s}".format("CET SHSTK status (via new arch_prctl IF)", msg))

        # Intel CET SHSTK status via procfs
        r = Checksec.get_cet_status_via_procfs()
        if r is None:
            msg = Color.grayify("Unknown") + " (failed to open /proc/PID/status)"
            gef_print("{:<40s}: {:s}".format("CET SHSTK status (via procfs)", msg))
            gef_print("{:<40s}: {:s}".format("CET SHSTK Lock status (via procfs)", msg))
        elif r is False:
            msg = Color.colorify("Unimplemented", "bold red") + " (kernel does not support; kernel supports it from 6.6)"
            gef_print("{:<40s}: {:s}".format("CET SHSTK status (via procfs)", msg))
            gef_print("{:<40s}: {:s}".format("CET SHSTK Lock status (via procfs)", msg))
        else:
            if r["shstk"]:
                gef_print("{:<40s}: {:s}".format("CET SHSTK status (via procfs)", Color.colorify("Enabled", "bold green")))
            else:
                msg = Color.colorify("Disabled", "bold red") + " (kernel supports but disabled)"
                gef_print("{:<40s}: {:s}".format("CET SHSTK status (via procfs)", msg))
            if r["shstk lock"]:
                gef_print("{:<40s}: {:s}".format("CET SHSTK Lock status (via procfs)", Color.colorify("Enabled", "bold green")))
            else:
                msg = Color.colorify("Disabled", "bold red") + " (kernel supports but no locked)"
                gef_print("{:<40s}: {:s}".format("CET SHSTK Lock status (via procfs)", msg))
        return

    def check_CET_IBT(self, sec):
        # Intel CET IBT flags via Ehdr
        if "CET IBT flag" not in sec:
            # ELF is not x86_64
            return
        if sec["CET IBT flag"]:
            gef_print("{:<40s}: {:s}".format("CET IBT feature flag (via Ehdr)", Color.colorify("Found", "bold green")))
        else:
            gef_print("{:<40s}: {:s}".format("CET IBT feature flag (via Ehdr)", Color.colorify("Not found", "bold red")))

        # gdb mode check
        if not is_x86():
            return
        if not is_alive():
            return
        if is_rr():
            return

        # Intel CET IBT status via arch_prctl
        if is_pin():
            # Intel SDE implements userspace CET IBT but old interface
            r = Checksec.get_cet_status_old_interface()
            if r is None:
                msg = Color.colorify("Disabled", "bold red") + " (kernel does not support; Intel SDE has no `-cet` option)"
                gef_print("{:<40s}: {:s}".format("CET IBT status (via old arch_prctl IF)", msg))
            else:
                if r & 0b01:
                    msg = Color.colorify("Enabled", "bold green") + " (kernel supports; Intel SDE has `-cet` option)"
                    gef_print("{:<40s}: {:s}".format("CET IBT status (via old arch_prctl IF)", msg))
                else:
                    msg = Color.colorify("Disabled", "bold red") + " (kernel supports but disabled; Intel SDE has `-cet` option)"
                    gef_print("{:<40s}: {:s}".format("CET IBT status (via old arch_prctl IF)", msg))
        else:
            # kernel does not support userspace CET IBT yet, only supports kernel space CET IBT.
            # https://lwn.net/Articles/889475/ (2022/3/31)
            msg = Color.colorify("Unimplemented", "bold red") + " (at least kernel 6.6 does not support userspace IBT)"
            gef_print("{:<40s}: {:s}".format("CET IBT status", msg))
        return

    def check_PAC(self, sec):
        # PAC opcode
        if "PAC" not in sec:
            # ELF is not ARM64
            return
        if sec["PAC"] is None:
            gef_print("{:<40s}: {:s}".format("PAC opcode", Color.grayify("Unknown")))
        elif sec["PAC"]:
            gef_print("{:<40s}: {:s}".format("PAC opcode", Color.colorify("Found", "bold green")))
        else:
            gef_print("{:<40s}: {:s}".format("PAC opcode", Color.colorify("Not found", "bold red")))

        # gdb mode check
        if not is_arm64():
            return
        if not is_alive():
            return
        if is_rr():
            return

        # PAC status
        r = Checksec.get_pac_status()
        if r is None:
            msg = Color.colorify("Disabled", "bold red") + " (kernel does not support PAC)"
            gef_print("{:<40s}: {:s}".format("PAC", msg))
        elif r < 0:
            msg = Color.grayify("Unknown") + " (kernel supports PAC but does not support PR_PAC_GET_ENABLED_KEYS prctl option)"
            gef_print("{:<40s}: {:s}".format("PAC", msg))
        elif r == 0:
            msg = Color.colorify("Disabled", "bold red") + " (kernel supports PAC but no keys are enabled)"
            gef_print("{:<40s}: {:s}".format("PAC", msg))
        elif r > 0:
            keys = []
            if r & 0b00001:
                keys.append("APIAKEY")
            if r & 0b00010:
                keys.append("APIBKEY")
            if r & 0b00100:
                keys.append("APDAKEY")
            if r & 0b01000:
                keys.append("APDBKEY")
            if r & 0b10000:
                keys.append("APGAKEY")
            keys = ", ".join(keys)
            msg = Color.colorify("Enabled", "bold green") + " (enabled keys: {:s})".format(keys)
            gef_print("{:<40s}: {:s}".format("PAC", msg))
        return

    def check_MTE(self, sec):
        # gdb mode check
        if not is_arm64():
            return
        if not is_alive():
            return
        if is_rr():
            return

        # MTE status
        r = Checksec.get_mte_status()
        if r is None:
            msg = Color.colorify("Disabled", "bold red") + " (kernel does not support MTE)"
            gef_print("{:<40s}: {:s}".format("MTE", msg))
        elif r < 0:
            msg = Color.grayify("Unknown") + " (kernel supports MTE but does not support PR_SET_TAGGED_ADDR_CTRL)"
            gef_print("{:<40s}: {:s}".format("MTE", msg))
        elif (r & 0b1) == 0:
            msg = Color.colorify("Disabled", "bold red") + " (kernel supports MTE but disabled)"
            gef_print("{:<40s}: {:s}".format("MTE", msg))
        elif (r & 0b1) == 1 and (r & 0b110) == 0:
            msg = Color.colorify("Disabled", "bold red") + " (MTE is enabled, but fault is ignored)"
            gef_print("{:<40s}: {:s}".format("MTE", msg))
        else:
            keys = []
            if r & 0b010:
                keys.append("PR_MTE_TCF_SYNC")
            if r & 0b100:
                keys.append("PR_MTE_TCF_ASYNC")
            keys = ", ".join(keys)
            msg = Color.colorify("Enabled", "bold green") + " (MTE is enabled as: {:s})".format(keys)
            gef_print("{:<40s}: {:s}".format("MTE", msg))
        return

    def check_system_ASLR(self):
        if is_remote_debug():
            msg = Color.grayify("Unknown")
            gef_print("{:<40s}: {:s} (remote process)".format("System-ASLR", msg))
        else:
            try:
                system_aslr = int(open("/proc/sys/kernel/randomize_va_space").read())
                if system_aslr == 0:
                    msg = Color.colorify("Disabled", "bold red")
                    gef_print("{:<40s}: {:s} (randomize_va_space: 0)".format("System ASLR", msg))
                elif system_aslr == 1:
                    msg = Color.colorify("Partially Enabled", "bold yellow")
                    gef_print("{:<40s}: {:s} (randomize_va_space: 1)".format("System ASLR", msg))
                elif system_aslr == 2:
                    msg = Color.colorify("Enabled", "bold green")
                    gef_print("{:<40s}: {:s} (randomize_va_space: 2)".format("System ASLR", msg))
            except (FileNotFoundError, OSError):
                msg = Color.grayify("Unknown")
                gef_print("{:<40s}: {:s} (randomize_va_space: error)".format("System-ASLR", msg))
        return

    def check_gdb_ASLR(self):
        if is_attach() or is_remote_debug():
            msg = Color.grayify("Ignored")
            gef_print("{:<40s}: {:s} (attached or remote process)".format("GDB ASLR setting", msg))
        else:
            ret = gdb.parameter("disable-randomization")
            if ret is True:
                msg = Color.colorify("Disabled", "bold red")
                gef_print("{:<40s}: {:s} (disable-randomization: on)".format("GDB ASLR setting", msg))
            elif ret is False:
                msg = Color.colorify("Enabled", "bold green")
                gef_print("{:<40s}: {:s} (disable-randomization: off)".format("GDB ASLR setting", msg))
            else:
                msg = Color.grayify("Unknown")
                gef_print("{:<40s}: {:s}".format("GDB ASLR setting", msg))
        return

    def get_colored_msg(self, val):
        if val is True:
            msg = Color.greenify(Color.boldify("Enabled"))
        elif val is False:
            msg = Color.redify(Color.boldify("Disabled"))
        elif val is None:
            msg = Color.grayify("Unknown")
        return msg

    def print_security_properties(self, filename):
        elf = Elf.get_elf(filename)
        if elf is None or not elf.is_valid():
            err("checksec is failed")
            return

        sec = elf.checksec()
        if sec is False:
            err("checksec is failed")
            return

        gef_print(titlify("Basic information"))

        # Canary
        msg = self.get_colored_msg(sec["Canary"])
        if sec["Canary"] is True and is_alive():
            res = CanaryCommand.gef_read_canary()
            if not res:
                msg += " (Could not get the canary value)"
            else:
                msg += " (value: {:#x})".format(res[0])
        gef_print("{:<40s}: {:s}".format("Canary", msg))

        # NX
        gef_print("{:<40s}: {:s}".format("NX", self.get_colored_msg(sec["NX"])))

        # PIE
        if sec["PIE"]:
            gef_print("{:<40s}: {:s}".format("PIE", self.get_colored_msg(sec["PIE"])))
        else:
            vaddr = min([p.p_vaddr for p in elf.phdrs if p.p_type == Elf.Phdr.PT_LOAD])
            gef_print("{:<40s}: {:s} ({:#x})".format("PIE", self.get_colored_msg(sec["PIE"]), vaddr))

        # RELRO
        if sec["Full RELRO"]:
            # -Wl,-z,relro -Wl,-z,now
            gef_print("{:<40s}: {:s}".format("RELRO", Color.colorify("Full RELRO", "bold green")))
        elif sec["Partial RELRO"]:
            # -Wl,-z,relro -Wl,-z,lazy
            gef_print("{:<40s}: {:s}".format("RELRO", Color.colorify("Partial RELRO", "bold yellow")))
        else:
            # -Wl,-z,norelro
            gef_print("{:<40s}: {:s}".format("RELRO", Color.colorify("No RELRO", "bold red")))

        # Fortify
        if sec["Fortify"]:
            gef_print("{:<40s}: {:s}".format("Fortify", Color.colorify("Found", "bold green")))
        else:
            gef_print("{:<40s}: {:s}".format("Fortify", Color.colorify("Not found", "bold red")))

        gef_print(titlify("Additional information"))

        # Static
        if sec["Static"]:
            if sec["PIE"]:
                gef_print("{:<40s}: {:s}".format("Static/Dynamic", "Static-PIE"))
            else:
                gef_print("{:<40s}: {:s}".format("Static/Dynamic", "Static"))
        else:
            gef_print("{:<40s}: {:s}".format("Static/Dynamic", "Dynamic"))

        # Symbol
        if sec["Symbol"]:
            gef_print("{:<40s}: {:s}".format("Symbol", Color.colorify("Found", "bold red")))
        else:
            gef_print("{:<40s}: {:s}".format("Symbol", Color.colorify("Stripped", "bold green")))

        # Debug information
        if sec["Debuginfo"]:
            gef_print("{:<40s}: {:s}".format("Debuginfo", Color.colorify("With debuginfo", "bold red")))
        else:
            gef_print("{:<40s}: {:s}".format("Debuginfo", Color.colorify("No debuginfo", "bold green")))

        # Intel CET
        self.check_CET_SHSTK(sec)
        self.check_CET_IBT(sec)

        # ARM64 PAC/MTE
        self.check_PAC(sec)
        self.check_MTE(sec)

        # RPATH
        if sec["RPATH"]:
            gef_print("{:<40s}: {:s} ({!r})".format("RPATH", Color.colorify("Found", "bold red"), sec["RPATH"]))

        # RUNPATH
        if sec["RUNPATH"]:
            gef_print("{:<40s}: {:s} ({!r})".format("RUNPATH", Color.colorify("Found", "bold red"), sec["RUNPATH"]))

        # Clang CFI
        if sec["Clang CFI"]:
            gef_print("{:<40s}: {:s}".format("Clang CFI", self.get_colored_msg(sec["Clang CFI"])))

        # Clang SafeStack
        if sec["Clang SafeStack"]:
            gef_print("{:<40s}: {:s}".format("Clang SafeStack", self.get_colored_msg(sec["Clang SafeStack"])))

        # ASLR
        self.check_system_ASLR()
        self.check_gdb_ASLR()
        return

    @parse_args
    @exclude_specific_gdb_mode(mode=("wine", "kgdb"))
    @require_arch_set
    def do_invoke(self, args):
        if is_qemu_system() or is_vmware():
            info("Redirect to kchecksec")
            gdb.execute("kchecksec")
            return

        local_filepath = None
        remote_filepath = None
        tmp_filepath = None

        if args.remote:
            if not is_remote_debug():
                err("-r option is allowed only remote debug")
                return

            if args.file:
                remote_filepath = args.file # if specified, assume it is remote
            elif gdb.current_progspace().filename:
                f = gdb.current_progspace().filename
                if f.startswith("target:"): # gdbserver
                    f = f[7:]
                remote_filepath = f
            elif Pid.get_pid(remote=True):
                remote_filepath = "/proc/{:d}/exe".format(Pid.get_pid(remote=True))
            else:
                err("File name could not be determined")
                return

            data = Path.read_remote_file(remote_filepath, as_byte=True) # qemu-user is failed here, it is ok
            if not data:
                err("Failed to read remote filepath")
                return
            tmp_fd, tmp_filepath = GefUtil.mkstemp(prefix="checksec", suffix=".elf")
            os.fdopen(tmp_fd, "wb").write(data)
            local_filepath = tmp_filepath
            del data

        elif args.file:
            local_filepath = args.file

        elif args.file is None:
            if is_qemu_system():
                err("Argument-less calls are unsupported under qemu-system")
                return
            local_filepath = Path.get_filepath()

        if local_filepath is None:
            err("File name could not be determined")
            return

        self.print_security_properties(local_filepath)

        if tmp_filepath and os.path.exists(tmp_filepath):
            os.unlink(tmp_filepath)
        return


@register_command
class ExploitableCommand(GenericCommand):
    """Heuristically classify the exploitability of the current crash."""

    _cmdline_ = "exploitable"
    _category_ = "02-f. Process Information - Security"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show every signal/heuristic detail that fed the risk rating.")
    _syntax_ = parser.format_help()

    _example_ = "{:s}".format(_cmdline_)

    _note_ = [
        "Inspects the current stop (a fatal signal) and gives an MSEC !exploitable-style",
        "rating: EXPLOITABLE / PROBABLY_EXPLOITABLE / PROBABLY_NOT_EXPLOITABLE / UNKNOWN.",
        "It is a heuristic triage hint (signal, $_siginfo fault address, $pc mapping, and",
        "faulting instruction class), not a proof. Userland x86/x86-64 only.",
    ]
    _note_ = "\n".join(_note_)

    RISK = {
        "exploitable": "EXPLOITABLE",
        "probably": "PROBABLY_EXPLOITABLE",
        "probably_not": "PROBABLY_NOT_EXPLOITABLE",
        "unknown": "UNKNOWN",
    }

    def risk_color(self, key):
        text = self.RISK[key]
        if key == "exploitable":
            return Color.redify(text)
        if key == "probably":
            return Color.yellowify(text)
        if key == "probably_not":
            return Color.greenify(text)
        return Color.grayify(text)

    def current_signal_name(self):
        """Return the stop signal name (e.g. 'SIGSEGV')"""
        try:
            res = gdb.execute("info program", to_string=True).splitlines()
        except gdb.error:
            return None
        for line in res:
            line = line.strip()
            if line.startswith("It stopped with signal "):
                return line.replace("It stopped with signal ", "").split(",", 1)[0].strip()
        return None

    def fault_address(self):
        """Return the faulting address from siginfo, or None if unavailable."""

        # $_siginfo is a gdb convenience variable whose siginfo type is built into gdb,
        # so the member access works even on stripped binaries (it does not rely on the
        # target's debug symbols). It has no memory address, so there is no raw-memory
        # fallback; we just try the known member paths.
        for expr in ("$_siginfo._sifields._sigfault.si_addr", "$_siginfo.si_addr"):
            try:
                return AddressUtil.normalize_address(int(gdb.parse_and_eval(expr)))
            except Exception:
                continue
        return None

    def near_null(self, addr):
        """A fault very close to 0 usually means a NULL-pointer deref (rarely exploitable)."""
        if addr is None:
            return False
        return addr < 0x1000

    def insn_is_control_transfer(self, insn):
        """True if the $pc instruction is a call/jmp/ret-style control transfer."""
        if insn is None:
            return False
        return (runtime.current_arch.is_call(insn) or runtime.current_arch.is_jump(insn)
                or runtime.current_arch.is_ret(insn))

    def classify(self):
        """Return (risk_key, headline) and fill self.details."""
        signame = self.current_signal_name()
        pc = runtime.current_arch.pc
        sp = runtime.current_arch.sp
        fault = self.fault_address()
        pc_addr = Address(pc)
        pc_mapped = pc_addr.section is not None
        pc_exec = pc_addr.is_in_executable()
        try:
            insn = get_insn()
        except Exception:
            insn = None

        self.details.append("signal: {}".format(signame if signame else "none/unknown"))
        self.details.append("$pc = {:#x} (mapped={}, executable={})".format(pc, pc_mapped, pc_exec))
        self.details.append("$sp = {:#x}".format(sp))
        if fault is not None:
            fault_addr = Address(fault)
            self.details.append("fault address (si_addr) = {:#x} (mapped={}, writable={})".format(
                fault, fault_addr.section is not None, fault_addr.is_in_writable()))
        else:
            self.details.append("fault address (si_addr) = unavailable")

        if signame is None:
            return "unknown", "Not stopped by a signal; nothing to triage."

        if signame in ("SIGSEGV", "SIGILL", "SIGBUS") and pc_mapped is False:
            self.details.append("=> $pc points to unmapped memory: corrupted/controlled control flow.")
            return "exploitable", "Execution reached an unmapped address ($pc not in any mapping)."

        if signame in ("SIGSEGV", "SIGILL", "SIGBUS") and pc_mapped and not pc_exec:
            self.details.append("=> $pc is in a non-executable mapping: control flow corrupted.")
            return "exploitable", "$pc is in a non-executable mapping (corrupted control flow)."

        if signame == "SIGILL":
            self.details.append("=> SIGILL: illegal instruction executed.")
            return "exploitable", "Illegal instruction executed (SIGILL)."

        if signame == "SIGSEGV" and fault is not None and fault == pc:
            self.details.append("=> fault address equals $pc: bad instruction fetch (controlled execution).")
            return "exploitable", "Faulted fetching an instruction at $pc (controlled jump target)."

        if signame == "SIGSEGV" and self.insn_is_control_transfer(insn):
            if runtime.current_arch.is_ret(insn):
                self.details.append("=> faulting instruction is RET: possibly a corrupted return address.")
                return "exploitable", "RET to a faulting address (possible return-address corruption)."
            self.details.append("=> faulting instruction is a call/jmp to a faulting target.")
            return "probably", "Indirect call/jump to a faulting target (possible pointer corruption)."

        if signame == "SIGABRT":
            self.details.append("=> SIGABRT: libc aborted (stack canary / heap check / assert).")
            return "probably", "Process aborted by libc (corruption check or failed assertion)."

        if signame == "SIGSEGV" and self.near_null(fault):
            self.details.append("=> near-NULL fault address: typically a NULL-pointer dereference.")
            return "probably_not", "Near-NULL dereference (commonly not exploitable)."

        if signame == "SIGSEGV" and fault is not None and not self.near_null(fault):
            self.details.append("=> SIGSEGV at a non-trivial address: possible controlled read/write.")
            return "probably", "Access violation at a non-NULL address (possible controlled access)."

        if signame in ("SIGFPE", "SIGBUS"):
            self.details.append("=> arithmetic or bus error: typically not directly exploitable.")
            return "probably_not", "{} is usually not directly exploitable.".format(signame)

        self.details.append("=> no specific heuristic matched.")
        return "unknown", "Could not classify this stop with the available heuristics."

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        self.details = []
        key, headline = self.classify()

        gef_print(titlify("exploitability triage"))
        gef_print("Risk: {} (HEURISTIC)".format(self.risk_color(key)))
        gef_print("Reason: {}".format(headline))

        if args.verbose:
            gef_print(titlify("details"))
            for line in self.details:
                gef_print("  {}".format(line))
        return


@register_command
class ASLRCommand(GenericCommand):
    """View / modify the ASLR setting of GDB."""

    _cmdline_ = "aslr"
    _category_ = "02-f. Process Information - Security"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    modes = [None, "on", "off"]
    parser.add_argument("command", nargs="?", default=None, choices=modes, metavar="{on,off}",
                        help="set gdb aslr settings.")
    _syntax_ = parser.format_help()

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

    @parse_args
    @only_if_gdb_target_local
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        if is_attach() or is_remote_debug():
            warn("ASLR setting is ignored because it is remote or attached process")

        if args.command is None:
            aslr = gdb.parameter("disable-randomization")
            if aslr:
                msg = "ASLR is currently " + Color.redify("disabled")
            else:
                msg = "ASLR is currently " + Color.greenify("enabled")
            gef_print(msg)
        elif args.command == "on":
            info("Enabling ASLR")
            gdb.execute("set disable-randomization off")
        elif args.command == "off":
            info("Disabling ASLR")
            gdb.execute("set disable-randomization on")
        return


@register_command
class MteTagsCommand(GenericCommand):
    """Display the MTE tag for the specified address (ARM64 only)."""

    _cmdline_ = "mte-tags"
    _category_ = "02-f. Process Information - Security"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the start address to display the MTE tag.")
    parser.add_argument("count", metavar="COUNT", nargs="?", type=AddressUtil.parse_address,
                        help="repeat count for MTE tag displaying (every 16 bytes).")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("rr",))
    @only_if_specific_arch(arch=("ARM64",))
    def do_invoke(self, args):
        auxv = Auxv.get_auxiliary_values()
        HWCAP2_MTE = 1 << 18
        if auxv and "AT_HWCAP2" in auxv and (auxv["AT_HWCAP2"] & HWCAP2_MTE) == 0:
            err("MTE is unsupported")
            return

        codes = [b"\x00\x00\x60\xD9"] # ldg x0, [x0]
        count = args.count or 1
        for i in range(count):
            address = args.address + 16 * i
            if not is_valid_addr(address):
                break
            ret = ExecAsm(codes, regs={"$x0": address}).exec_code()
            tag = (ret["reg"]["$x0"] >> 56) & 0xff
            gef_print("{!s}: {:#04x} ({:#018x})".format(ProcessMap.lookup_address(address), tag, tag << 56))
        return
