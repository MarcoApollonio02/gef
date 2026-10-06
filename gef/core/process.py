"""GEF process helpers (Layer 1).

Mode/detection helpers (`is_*`, `get_pagesize` and friends), the arch-type
predicates, `get_arch`/`set_arch`, and the `Pid` / `Path` / `ProcessMap`
utility classes.

Reads of the mutable global `current_arch` go through `runtime.current_arch`
(never a by-name import) to avoid the stale-binding pitfall documented in
runtime.py. `set_arch` rewires the monolith's inline
`Architecture.__subclasses__()` traversal to `ArchRegistry.find()` and
rebinds via `runtime.set_current_arch` (declaring the binding as a module
global no longer happens here).

References to modules that are not yet extracted (qemu's QemuMonitor, utils,
gef.commands.*) are imported lazily inside the referencing function/method to
avoid the process<->qemu import cycle. `is_alive` (gef.py L12539) lives here
per the plan's module table.
"""
import collections
import gdb
import os
import re

from gef.core import runtime
from gef.core.runtime import ArchRegistry, set_current_arch
from gef.core.address import Address, AddressUtil, Permission, Section
from gef.core.auxv import Auxv
from gef.core.cache import Cache
from gef.core.color import err, info
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.memory import is_valid_addr, read_cstring_from_memory, read_int_from_memory, read_memory
from gef.core.registers import get_register


def is_remote_debug():
    """GDB mode determination function for remote debugging."""
    try:
        connection = gdb.selected_inferior().connection
        if connection is None:
            return False
        return connection and connection.type == "remote"
    except AttributeError:
        # before gdb 11.x: AttributeError: 'gdb.Inferior' object has no attribute 'connection'
        res = gdb.execute("maintenance print target-stack", to_string=True)
        return "remote" in res


# Removed is_remote_same_host.
# It can detect that gdb connects to a process in the same host.
# However, it cannot detect that traffic is being redirected to another host.


@Cache.cache_this_session
def is_normal_run():
    """GDB mode determination function for normal running."""
    ret = gdb.execute("info files", to_string=True)
    return "Using the running image of child" in ret


@Cache.cache_this_session
def is_attach():
    """GDB mode determination function for attaching."""
    try:
        return gdb.selected_inferior().was_attached
    except AttributeError:
        ret = gdb.execute("info files", to_string=True)
        return "Using the running image of attached" in ret


@Cache.cache_this_session
def is_container_attach():
    """GDB mode determination function for attaching another namespace."""
    filename = gdb.current_progspace().filename
    if filename and filename.startswith("target:"):
        return True
    pid = Pid.get_pid()
    if pid is None:
        return False
    path = "/proc/{:d}/status".format(pid)
    if os.path.exists(path):
        content = open(path, "rb").read()
        r = re.search(rb"\nNSpid:\s+(\d+)\s+(\d+)", content)
        return bool(r)
    return False


@Cache.cache_this_session
def is_pin():
    """GDB mode determination function for pin and SDE."""
    if not is_remote_debug():
        return False
    try:
        response = gdb.execute("maintenance packet qSupported", to_string=True, from_tty=False)
    except gdb.error as e:
        err("{}".format(e))
        os._exit(0)
    return "intel.name=" in response


@Cache.cache_this_session
def is_qemu():
    """GDB mode determination function for qemu-user or qemu-system."""
    if not is_remote_debug():
        return False
    try:
        response = gdb.execute("maintenance packet Qqemu.sstepbits", to_string=True, from_tty=False)
    except gdb.error as e:
        err("{}".format(e))
        os._exit(0)
    return "ENABLE=" in response


@Cache.cache_this_session
def is_qemu_user():
    """GDB mode determination function for qemu-user gdb stub."""
    if is_qemu() is False:
        return False
    try:
        response = gdb.execute("maintenance packet qOffsets", to_string=True, from_tty=False)
    except gdb.error as e:
        err("{}".format(e))
        os._exit(0)
    return "Text=" in response


@Cache.cache_this_session
def is_qemu_system():
    """GDB mode determination function for qemu-system gdb stub."""
    if is_qemu() is False:
        return False
    try:
        response = gdb.execute("maintenance packet qOffsets", to_string=True, from_tty=False)
    except gdb.error as e:
        err("{}".format(e))
        os._exit(0)
    return 'received: ""' in response


@Cache.cache_this_session
def is_over_serial():
    """GDB mode determination function for serial device."""
    if not is_remote_debug():
        return False
    try:
        dev = gdb.selected_inferior().connection.details
        return dev.startswith(("/dev/ttyS", "/dev/ttyAMA", "/dev/ttyUSB"))
    except AttributeError:
        # before gdb 11.x: AttributeError: 'gdb.Inferior' object has no attribute 'connection'
        return False


@Cache.cache_this_session
def is_kgdb():
    """GDB mode determination function for KGDB."""
    # Forcing KGDB mode is useful when KGDB is being used via agent-proxy
    # and thus GDB cannot see the serial device name.
    if Config.get_gef_setting("gef.kgdb_force") is True:
        return True
    return bool((is_x86_64() or is_arm64()) and is_over_serial())


@Cache.cache_this_session
def kgdb_has_system_registers():
    return Config.get_gef_setting("gef.kgdb_system_registers") is True


@Cache.cache_this_session
def is_kdb():
    """GDB mode determination function for KDB (over KGDB)."""
    if not is_kgdb():
        return False
    try:
        res = gdb.execute("monitor _stext", to_string=True)
    except gdb.error:
        return False
    r = re.search(r"_stext = 0x(\S+)", res)
    return bool(r)


@Cache.cache_this_session
def is_vmware():
    """GDB mode determination function for VMware gdb stub."""
    if not is_remote_debug():
        return False
    # The `monitor help` command takes a very long time in kgdb mode.
    # We can speed it up by making sure we're not in kgdb mode beforehand.
    if is_over_serial() or is_kgdb():
        return False
    # https://xuanxuanblingbling.github.io/ctf/tools/2021/10/22/vmware/
    try:
        res = gdb.execute("monitor help r", to_string=True)
        return "Dump hidden register" in res
    except gdb.error:
        return False


@Cache.cache_this_session
def is_qiling():
    """GDB mode determination function for qiling framework gdb stub."""
    if not is_remote_debug():
        return False
    pid = Pid.get_pid(remote=True)
    if pid is None or pid < 42000:
        return False
    for m in ProcessMap.get_process_maps():
        if m.path == "[hook_mem]":
            return True
    return False


@Cache.cache_this_session
def is_rr():
    """GDB mode determination function for rr."""
    return Pid.get_pid_from_tcp_session(filepath="rr") is not None


@Cache.cache_this_session
def is_wine():
    """GDB mode determination function for winedbg."""
    return Pid.get_pid_from_tcp_session(filepath="wineserver") is not None


@Cache.cache_until_next
def is_in_kernel():
    """GDB mode determination function for kernel mode."""
    if not is_alive():
        return False
    if is_arm32_cortex_m():
        return False
    if is_qiling():
        return False

    # If it fails to obtain the flag register required for the judgment,
    # it will be considered as userland.
    if is_x86():
        cs = get_register("$cs")
        if cs is None:
            return False
        return (cs & 0b11) != 3
    elif is_arm32():
        if is_in_secure():
            return False
        cpsr = get_register(runtime.current_arch.flag_register)
        if cpsr is None:
            return False
        return (cpsr & 0b11111) not in [0b10000, 0b11010]
    elif is_arm64():
        if is_in_secure():
            return False
        cpsr = get_register(runtime.current_arch.flag_register)
        if cpsr is None:
            return False
        return ((cpsr >> 2) & 0b11) == 1
    elif is_riscv64() or is_riscv32():
        priv = get_register("priv")
        if priv is None:
            return False
        return priv == 1
    # All other architectures are considered userland.
    return False


@Cache.cache_this_session
def is_support_secure_world():
    if not is_arm32() and not is_arm64():
        return False
    if not is_qemu_system():
        return False
    ret = gdb.execute("monitor info mtree -f", to_string=True)
    return ".secure-ram" in ret


@Cache.cache_until_next
def is_in_secure():
    """GDB mode determination function for secure world."""
    if not is_support_secure_world():
        return False
    if is_arm32():
        scr = get_register("$SCR")
    elif is_arm64():
        scr = get_register("$SCR_EL3")
    # In environments without a secure world:
    # Older qemu versions did not have the SCR register. (return None)
    # Newer qemu versions always return 0.
    if not scr:
        return False
    return (scr & 0b1) == 0


@Cache.cache_this_session
def is_kvm_enabled():
    """GDB mode determination function for KVM."""
    try:
        res = gdb.execute("monitor info kvm", to_string=True)
        return "enabled" in res
    except gdb.error:
        return False


@Cache.cache_this_session
def is_smp_enabled():
    """GDB mode determination function for smp."""
    try:
        res = gdb.execute("monitor info cpus", to_string=True)
        return len(res.splitlines()) >= 2
    except gdb.error:
        return False


@Cache.cache_until_next
def is_in_smm():
    """Determine whether the CPU is currently in System Management Mode (SMM).

    SMM entry code (SMBASE + 0x8000 in the legacy DOS layout) lies inside the
    SMRAM physical window, which is otherwise inaccessible to instruction
    fetch. Thus ``$pc in SMRAM`` is a reliable in-SMM indicator on QEMU.
    Cached ``until_next`` so it ticks over as the user steps/continues.
    """
    from gef.core.qemu import QemuMonitor
    smram = QemuMonitor.get_smram_map()
    if smram is None:
        return False
    smram_base, smram_size = smram
    pc = get_register("$pc")
    if pc is None:
        return False
    return smram_base <= pc < smram_base + smram_size


@Cache.cache_until_next
def scan_smm_token_in_monitor():
    """Scan ``monitor info registers`` for an SMM indicator token.

    Returns ``(bool, token_or_None)``. QEMU's x86 dump prints a state line
    like ``EIP=... EFL=... SMM=N HLT=...`` where ``SMM=0`` means inactive and
    ``SMM=1`` means active. We trigger only on a nonzero ``SMM=`` value (plus
    two defensive substrings for QEMU-version variation). Absence of a token
    does not prove non-SMM state.
    """
    if not is_qemu_system() or not is_x86():
        return False, None
    try:
        res = gdb.execute("monitor info registers", to_string=True)
    except gdb.error:
        return False, None
    low = res.lower()
    m = re.search(r"\bsmm=([0-9]+)\b", low)
    if m and int(m.group(1)) != 0:
        return True, "SMM={}".format(int(m.group(1)))
    for needle in ("in smm", "smmode"):
        if needle in low:
            return True, needle
    return False, None


def is_alive():
    """GDB mode determination function for running."""
    try:
        return gdb.selected_inferior().pid > 0
    except gdb.error:
        return False


def is_64bit():
    """GDB mode determination function for 64-bit architecture."""
    return AddressUtil.ptr_width() == 8


def is_32bit():
    """GDB mode determination function for 32-bit architecture."""
    return AddressUtil.ptr_width() == 4


def is_emulated32():
    """GDB mode determination function for 32-bit architecture on 64-bit environment."""
    if is_64bit():
        return False

    if is_qemu_user():
        # This case cannot be determined
        return False

    if is_qemu_system():
        # corner case (e.g., using qemu-system-x86_64, but process is executed as 32bit mode)
        # is not able to be detected
        return True

    for m in ProcessMap.get_process_maps():
        # native x86:
        # 0xbffdf000 0xc0000000 0x021000 0x000000 rw- [stack]
        # emulated x86 on x86_64
        # 0xfffdd000 0xffffe000 0x021000 0x000000 rw- [stack]
        # native arm:
        # 0xbefdf000 0xbf000000 0x021000 0x000000 rw- [stack]
        # emulated arm on aarch64
        # 0xfffcf000 0xffff0000 0x021000 0x000000 rw- [stack]
        if m.path == "[stack]":
            return (m.page_start >> 28) == 0xf
    else:
        return False # by default it considers on native


def is_x86_64():
    """Architecture determination function for x86-64."""
    return runtime.current_arch and runtime.current_arch.arch == "X86" and runtime.current_arch.mode == "64"


def is_x86_32():
    """Architecture determination function for x86-32."""
    return runtime.current_arch and runtime.current_arch.arch == "X86" and runtime.current_arch.mode == "32"


def is_x86_16():
    """Architecture determination function for x86-16."""
    return runtime.current_arch and runtime.current_arch.arch == "X86" and runtime.current_arch.mode == "16"


def is_x86():
    """Architecture determination function for x86-32 or x86-64 or x86_16."""
    return is_x86_32() or is_x86_64() or is_x86_16()


def is_arm32():
    """Architecture determination function for ARM 32 bit (Cortex-A)."""
    return runtime.current_arch and runtime.current_arch.arch == "ARM" and not runtime.current_arch.is_cortex_m()


def is_arm32_cortex_m():
    """Architecture determination function for ARM 32 bit (Cortex-M)."""
    return runtime.current_arch and runtime.current_arch.arch == "ARM" and runtime.current_arch.is_cortex_m()


def is_arm64():
    """Architecture determination function for ARM 64 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "ARM64"


def is_mips32():
    """Architecture determination function for mips 32 bit (o32 ABI)."""
    return runtime.current_arch and runtime.current_arch.arch == "MIPS" and runtime.current_arch.mode == "32"


def is_mips64():
    """Architecture determination function for mips 64 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "MIPS" and runtime.current_arch.mode == "64"


def is_mipsn32():
    """Architecture determination function for mips 32 bit (n32 ABI)."""
    return runtime.current_arch and runtime.current_arch.arch == "MIPS" and runtime.current_arch.mode == "n32"


def is_ppc32():
    """Architecture determination function for powerpc 32 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "PPC" and runtime.current_arch.mode == "32"


def is_ppc64():
    """Architecture determination function for powerpc 64 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "PPC" and runtime.current_arch.mode == "64"


def is_sparc32():
    """Architecture determination function for sparc 32 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "SPARC" and runtime.current_arch.mode == "32"


def is_sparc32plus():
    """Architecture determination function for sparc 32 bit (v8+)."""
    return runtime.current_arch and runtime.current_arch.arch == "SPARC" and runtime.current_arch.mode == "32PLUS"


def is_sparc64():
    """Architecture determination function for sparc 64 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "SPARC" and runtime.current_arch.mode == "64"


def is_riscv32():
    """Architecture determination function for RISC-V 32 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "RISCV" and runtime.current_arch.mode == "32"


def is_riscv64():
    """Architecture determination function for RISC-V 64 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "RISCV" and runtime.current_arch.mode == "64"


def is_s390x():
    """Architecture determination function for s390x."""
    return runtime.current_arch and runtime.current_arch.arch == "S390X"


def is_sh4():
    """Architecture determination function for sh4."""
    return runtime.current_arch and runtime.current_arch.arch == "SH4"


def is_m68k():
    """Architecture determination function for m68k."""
    return runtime.current_arch and runtime.current_arch.arch == "M68K"


def is_alpha():
    """Architecture determination function for alpha."""
    return runtime.current_arch and runtime.current_arch.arch == "ALPHA"


def is_hppa32():
    """Architecture determination function for HP-PA 32 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "HPPA" and runtime.current_arch.mode == "32"


def is_hppa64():
    """Architecture determination function for HP-PA 64 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "HPPA" and runtime.current_arch.mode == "64"


def is_or1k():
    """Architecture determination function for OpenRISC 1000."""
    return runtime.current_arch and runtime.current_arch.arch == "OR1K"


def is_nios2():
    """Architecture determination function for Nios II."""
    return runtime.current_arch and runtime.current_arch.arch == "NIOS2"


def is_microblaze():
    """Architecture determination function for Microblaze."""
    return runtime.current_arch and runtime.current_arch.arch == "MICROBLAZE"


def is_xtensa():
    """Architecture determination function for Xtensa."""
    return runtime.current_arch and runtime.current_arch.arch == "XTENSA"


def is_cris():
    """Architecture determination function for CRIS."""
    return runtime.current_arch and runtime.current_arch.arch == "CRIS"


def is_loongarch64():
    """Architecture determination function for Loongarch 64 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "LOONGARCH" and runtime.current_arch.mode == "64"


def is_arc32():
    """Architecture determination function for ARC 32 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "ARC" and runtime.current_arch.mode in ["32v2", "32v3"]


def is_arc64():
    """Architecture determination function for ARC 64 bit."""
    return runtime.current_arch and runtime.current_arch.arch == "ARC" and runtime.current_arch.mode == "64v3"


def is_csky():
    """Architecture determination function for csky."""
    return runtime.current_arch and runtime.current_arch.arch == "CSKY"


@Cache.cache_until_next
def get_arch():
    """Return the binary's architecture."""
    if is_alive():
        try:
            arch = gdb.selected_frame().architecture()
            name = arch.name()
            # check i386 or i8086
            if name != "i386":
                return name
        except gdb.error:
            # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
            # Resolve by moving to the slow path.
            pass

    # slow path
    arch_str = gdb.execute("show architecture", to_string=True).strip()

    # The target architecture is set automatically (currently i386)
    # The target architecture is set to "auto" (currently "i386").
    # The target architecture is assumed to be mips
    # The target architecture is set to "mips".

    if "The target architecture is set automatically (currently " in arch_str:
        arch_str = arch_str.split("(currently ", 1)[1]
        arch_str = arch_str.split(")", 1)[0]
    elif 'The target architecture is set to "auto" (currently "' in arch_str:
        arch_str = arch_str.split('(currently "', 1)[1]
        arch_str = arch_str.split('")', 1)[0]
    elif "The target architecture is assumed to be " in arch_str:
        arch_str = arch_str.replace("The target architecture is assumed to be ", "")
    elif "The target architecture is set to " in arch_str:
        arch_str = arch_str.split('"')[1]
    else:
        # Unknown, we throw an exception to be safe
        raise RuntimeError("Unknown architecture: {}".format(arch_str))
    return arch_str


def set_arch(arch_str=None):
    """Set the current architecture.
    If an arch is explicitly specified, use that one, otherwise try to parse it out of the current target.
    If that fails, and default is specified, select and set that arch.
    Return the selected arch, or raise an OSError."""
    from gef.arch.mips import MIPS64

    # Determined from the specified arch string
    if arch_str:
        key = arch_str.upper()

    else:
        # Determined from loaded ELF
        elf = Elf.get_elf()
        if elf is None or not elf.is_valid():
            raise OSError("Could not determine architecture.")

        if elf.e_machine not in [Elf.EM_MIPS, Elf.EM_RISCV, Elf.EM_PARISC]:
            key = elf.e_machine

        else:
            # On some architectures, it is not possible to determine whether it is 32-bit or 64-bit
            # from the ELF header e_machine. so we use the detection result of gdb.
            key = get_arch().upper()

    # Even if it is determined to be MIPS64, if it is in 32-bit mode, it is n32.
    if key in MIPS64.load_condition and is_32bit():
        key = "MIPSN32"

    if isinstance(key, str):
        arch_cls = ArchRegistry.find(key)
    else:
        # ArchRegistry.find() normalizes to a string key; integer keys (ELF
        # e_machine) are matched here against the classes' load_condition lists
        # exactly as the monolith's `arches = {}` dict lookup did.
        arch_cls = None
        for cls in ArchRegistry.all():
            if key in cls.load_condition:
                arch_cls = cls
                break

    if arch_cls is None:
        err("Specified arch {!s} is not supported".format(key))
        info("A generic mode with minimal functionality will be applied")
        return

    set_current_arch(arch_cls())
    Cache.reset_gef_caches(all=True)
    return


@Cache.cache_this_session
def get_pagesize():
    """Get the page size from auxiliary values."""
    auxval = Auxv.get_auxiliary_values()
    if not auxval or "AT_PAGESZ" not in auxval:
        return 0x1000
    return auxval["AT_PAGESZ"]


@Cache.cache_this_session
def get_pagesize_mask_low():
    """Get the page size mask from auxiliary values."""
    auxval = Auxv.get_auxiliary_values()
    if not auxval or "AT_PAGESZ" not in auxval:
        return 0xfff
    return auxval["AT_PAGESZ"] - 1


@Cache.cache_this_session
def get_pagesize_mask_high():
    """Get the page size mask from auxiliary values."""
    auxval = Auxv.get_auxiliary_values()
    if not auxval or "AT_PAGESZ" not in auxval:
        return ~0xfff
    return ~(auxval["AT_PAGESZ"] - 1)


class Pid:
    """A collection of utility functions that obtains a pid."""

    @staticmethod
    def get_tcp_sess(pid):
        # get inode information from opened file descriptor
        inodes = []
        for openfd in os.listdir("/proc/{:d}/fd".format(pid)):
            try:
                fdname = os.readlink("/proc/{:d}/fd/{:s}".format(pid, openfd))
            except (FileNotFoundError, ProcessLookupError, OSError):
                continue
            if fdname.startswith("socket:["):
                inode = fdname[8:-1]
                inodes.append(inode)

        def decode(addr):
            ip, port = addr.split(":")
            import socket
            ip = socket.inet_ntop(socket.AF_INET, bytes.fromhex(ip)[::-1])
            port = int(port, 16)
            return (ip, port)

        # get connection information
        sessions = []
        with open("/proc/{:d}/net/tcp".format(pid)) as fd:
            for line in fd.readlines()[1:]:
                _, laddr, raddr, status, _, _, _, _, _, inode = line.split()[:10]
                if status != "01": # ESTABLISHED
                    continue
                if inode not in inodes:
                    continue
                laddr = decode(laddr)
                raddr = decode(raddr)
                sessions.append({"laddr": laddr, "raddr": raddr})
        return sessions

    @staticmethod
    def get_all_process():
        pids = [int(x) for x in os.listdir("/proc") if x.isdigit()]
        process = []
        for pid in pids:
            try:
                filepath = os.readlink("/proc/{:d}/exe".format(pid))
            except (FileNotFoundError, ProcessLookupError, OSError):
                continue
            process.append({"pid": pid, "filepath": os.path.basename(filepath)})
        return process

    @staticmethod
    def get_pid_from_name(filepath):
        all_process = Pid.get_all_process()

        # strict matching
        candidate = [process for process in all_process if process["filepath"] == filepath]
        if len(candidate) == 1:
            return candidate[0]["pid"]
        if len(candidate) > 1: # If it cannot be uniquely identified, return None
            return None

        # relax the restrictions
        candidate = [process for process in all_process if process["filepath"].startswith(filepath)]
        if len(candidate) == 1:
            return candidate[0]["pid"]
        if len(candidate) > 1: # If it cannot be uniquely identified, return None
            return None

        # more relax the restrictions
        candidate = [process for process in all_process if filepath in process["filepath"]]
        if len(candidate) == 1:
            return candidate[0]["pid"]
        if len(candidate) > 1: # If it cannot be uniquely identified, return None
            return None
        return None

    @staticmethod
    def get_pid_from_tcp_session(filepath=None):
        gdb_tcp_sess = [x["raddr"] for x in Pid.get_tcp_sess(os.getpid())]
        if not gdb_tcp_sess:
            return None
        for process in Pid.get_all_process():
            if filepath and not process["filepath"].startswith(filepath):
                continue
            for c in Pid.get_tcp_sess(process["pid"]):
                if c["laddr"] in gdb_tcp_sess:
                    return process["pid"]
        return None

    @staticmethod
    def get_pid_wine():
        ws_pid = Pid.get_pid_from_tcp_session(filepath="wineserver")
        if ws_pid is None:
            return None

        def get_external_pipe_inodes(pid):
            inodes = set()
            if not os.path.exists("/proc/{:d}/".format(pid)):
                return inodes
            # get inode information from opened file descriptor
            for openfd in os.listdir("/proc/{:d}/fd".format(pid)):
                try:
                    fdname = os.readlink("/proc/{:d}/fd/{:s}".format(pid, openfd))
                except (FileNotFoundError, ProcessLookupError, OSError):
                    continue
                if fdname.startswith("pipe:["):
                    inode = fdname[6:-1]
                    if inode in inodes:
                        inodes.remove(inode)
                    else:
                        inodes.add(inode)
            return inodes

        ws_inodes = get_external_pipe_inodes(ws_pid)

        gdb_pid = os.getpid()
        for candidate_pid in range(gdb_pid - 1, ws_pid, -1):
            candidate_inodes = get_external_pipe_inodes(candidate_pid)
            if candidate_inodes & ws_inodes:
                return candidate_pid
        return None

    @staticmethod
    @Cache.cache_this_session
    def get_pid(remote=False):
        """Return the PID of the debuggee process."""
        if is_pin():
            return Pid.get_pid_from_tcp_session()
        elif is_qemu_user() or is_qemu_system():
            pid = Pid.get_pid_from_tcp_session("qemu") # strict way
            if pid is None:
                pid = Pid.get_pid_from_name("qemu") # ambiguous way
            return pid
        elif is_wine():
            return Pid.get_pid_wine()
        elif remote is False and is_remote_debug():
            return None # gdbserver etc.
        return gdb.selected_inferior().pid

    @staticmethod
    def get_tid():
        ptid = gdb.selected_thread().ptid
        return ptid[1] or ptid[2]


class Path:
    """A collection of utility functions that obtains a path."""

    @staticmethod
    def append_proc_root(filepath):
        if filepath is None:
            return None
        pid = Pid.get_pid()
        if pid is None:
            return None
        if pid == 0: # under gdbserver, when target exited then pid is 0
            return None
        prefix = "/proc/{}/root".format(pid)
        relative_path = filepath.lstrip("/")
        return os.path.join(prefix, relative_path)

    @staticmethod
    @Cache.cache_this_session
    def get_filepath(append_proc_root_prefix=True):
        """Return the local absolute path of the file currently debugged."""
        filepath = gdb.current_progspace().filename

        if is_remote_debug():
            if filepath is None:
                return None
            elif filepath.startswith("target:"):
                return None
            elif filepath.startswith(".gnu_debugdata for target:"):
                return None
            else:
                return filepath
        else:
            # inferior probably did not have name, extract cmdline from info proc
            if filepath is None:
                filepath = Path.get_filepath_from_info_proc()
                if append_proc_root_prefix:
                    # maybe different mnt namespace, so use /proc/<PID>/root
                    filepath = Path.append_proc_root(filepath)
            # not remote, but different PID namespace and attaching by pid. it shows with `target:`
            elif filepath.startswith("target:"):
                # /proc/PID/root is not given when used for purposes such as comparing with entry in vmmap
                filepath = filepath[len("target:"):]
                if append_proc_root_prefix:
                    # maybe different mnt namespace, so use /proc/<PID>/root
                    filepath = Path.append_proc_root(filepath)
            # normal path
            return filepath

    @staticmethod
    def get_filepath_from_info_proc():
        try:
            response = gdb.execute("info proc", to_string=True)
        except gdb.error:
            return None
        for x in response.splitlines():
            if x.startswith("exe = "):
                return x.split(" = ")[1].replace("'", "")
        return None

    @staticmethod
    @Cache.cache_this_session
    def get_filename():
        """Return the full filename of the file currently debugged."""
        filename = Path.get_filepath()
        if filename is None:
            return None
        return os.path.basename(filename)

    @staticmethod
    def read_remote_file(filepath, as_byte=True):
        from gef.core.utils import GEF_TEMP_DIR
        tmp_name = os.path.join(GEF_TEMP_DIR, "read_remote_file.tmp")
        try:
            gdb.execute("remote get {!r} {!r}".format(filepath, tmp_name), to_string=True)
        except gdb.error:
            return ""
        if as_byte:
            data = open(tmp_name, "rb").read()
        else:
            data = open(tmp_name, "r").read()
        os.unlink(tmp_name)
        return data


class ProcessMap:
    """A collection of utility functions that obtains a process map."""

    @staticmethod
    @Cache.cache_until_next
    def get_process_maps_linux(pid, remote=False):
        """Parse the Linux process `/proc/pid/maps` file."""

        if Config.get_gef_setting("context.disable_vmmap"):
            return []

        # open & read maps
        proc_map_file = "/proc/{:d}/maps".format(pid)
        if remote:
            data = Path.read_remote_file(proc_map_file, as_byte=False)
            if not data:
                return []
            lines = data.splitlines()
        else:
            if not os.path.exists(proc_map_file):
                return []
            lines = open(proc_map_file, "r").readlines()

        # tls and $sp of each threads
        extra_info = []
        if is_x86():
            tls_list = []
            orig_thread = gdb.selected_thread()
            orig_frame = gdb.selected_frame()
            if orig_thread: # orig_thread may be None if under winedbg
                for thread in gdb.selected_inferior().threads():
                    thread.switch() # change thread
                    tls = None
                    if is_x86_64():
                        tls = get_register("$fs_base") # note: for speed up
                    if is_x86_32() or tls is None:
                        tls = runtime.current_arch.get_tls()
                    tls_list.append([thread.num, tls, runtime.current_arch.sp])
                orig_thread.switch() # revert thread
                orig_frame.select()
                extra_info = sorted(tls_list)

                # When using gdbserver, thread.num may start from 2 even though there is no thread.
                # This is confusing, so if there is only the main thread, force it to 1.
                if len(extra_info) == 1:
                    extra_info[0][0] = 1

        # parse
        maps = []
        for line in lines:
            line = line.replace("\t", " ") # for qiling framework
            line = line.strip()
            addr, perm, off, _, rest = line.split(" ", 4)
            addr_start, addr_end = [int(x, 16) for x in addr.split("-")]
            rest = rest.split(" ", 1)
            if len(rest) == 1:
                pathname = ""
            else:
                pathname = rest[1].lstrip()
            inode = int(rest[0])

            for th_num, tls_addr, _ in extra_info:
                if tls_addr and addr_start <= tls_addr < addr_end:
                    pathname += "<tls-th{:d}>".format(th_num)
                    break

            for th_num, _, stack_addr in extra_info:
                if th_num > 1 and stack_addr and addr_start <= stack_addr < addr_end:
                    pathname += "<stack-th{:d}>".format(th_num)
                    break

            off = int(off, 16)
            perm = Permission.from_process_maps(perm)
            sect = Section(
                page_start=addr_start, page_end=addr_end,
                offset=off, permission=perm, inode=inode, path=pathname,
            )
            maps.append(sect)
        return maps

    # get_explored_regions (used at qemu-user mode) is very slow,
    # Because it repeats read_memory many times to find the upper and lower bounds of the page.
    # Cache.cache_until_next is ineffective due to frequent resets (each time the `stepi` runs).
    # Fortunately, memory maps rarely change.
    # The cache is cleared and rechecked when the `vmmap` command is called explicitly.
    @staticmethod
    @Cache.cache_this_session
    def get_explored_regions():
        """Return sections from auxv exploring."""

        if Config.get_gef_setting("context.disable_vmmap"):
            return []

        if runtime.current_arch is None:
            return []

        from gef.commands.process.general import ElfInfoCommand

        def is_valid_addr_fast(addr):
            try:
               gdb.selected_inferior().read_memory(addr, 1)
               return True
            except gdb.MemoryError:
                return False

        def get_region_start_end(addr):
            addr &= get_pagesize_mask_high()
            if not is_valid_addr_fast(addr):
                return None, None
            region_start = addr
            region_end = addr + get_pagesize()

            nonlocal regions
            end_addrs = [r.page_end for r in regions]
            start_addrs = [r.page_start for r in regions]

            # up search
            lower_bound = 0
            while True:
                if region_start <= lower_bound:
                    break
                if region_start in end_addrs:
                    break
                if not is_valid_addr_fast(region_start - get_pagesize()):
                    break
                region_start -= get_pagesize()

            upper_bound = 1 << AddressUtil.get_memory_alignment(in_bits=True)
            # down search
            while True:
                if region_end >= upper_bound:
                    break
                if region_end in start_addrs:
                    break
                if not is_valid_addr_fast(region_end):
                    break
                region_end += get_pagesize()
            return region_start, region_end

        def make_regions(addr, label, perm="rw-"):
            if addr is None:
                return []
            # check if already in region
            nonlocal regions
            for rg in regions:
                if rg.page_start <= addr < rg.page_end:
                    return []
            # make region
            start, end = get_region_start_end(addr)
            if start is None:
                return []
            perm = Permission.from_process_maps(perm)
            sect = Section(page_start=start, page_end=end, permission=perm, path=label)
            return [sect]

        def get_ehdr(addr):
            upper_bound = 1 << AddressUtil.get_memory_alignment(in_bits=True)
            for _ in range(128):
                if addr < 0 or addr > upper_bound:
                    return None
                try:
                    e_magic = read_memory(addr, 4)
                except gdb.MemoryError:
                    return None
                if e_magic == b"\x7fELF":
                    return Elf.get_elf(addr)
                addr -= get_pagesize()
            return None

        def parse_region_from_ehdr(addr, label):
            elf = get_ehdr(addr & get_pagesize_mask_high())
            if elf is None:
                return []

            pages = []
            for phdr in elf.phdrs:
                if not phdr.p_memsz:
                    continue

                vaddr = phdr.p_vaddr
                if elf.is_pie():
                    vaddr += elf.addr
                vaddr_end = vaddr + phdr.p_memsz

                offset = phdr.p_offset
                flags = phdr.p_flags

                # align
                vaddr &= get_pagesize_mask_high()
                offset &= get_pagesize_mask_high()
                vaddr_end = (vaddr_end + get_pagesize_mask_low()) & get_pagesize_mask_high()

                # add per pages
                for page_addr in range(vaddr, vaddr_end, get_pagesize()):
                    # check already exist
                    for i, page in enumerate(pages):
                        if page["vaddr"] == page_addr:
                            # found, so fix flags
                            if page["flags"] & Elf.Phdr.PF_X: # already has PF_X
                                flags |= Elf.Phdr.PF_X
                            pages[i]["flags"] = flags # overwrite, because RELRO
                            break
                    else:
                        # not found, so add new page
                        page = {
                            "vaddr": page_addr,
                            "memsize": get_pagesize(),
                            "flags": flags,
                            "offset": offset + (page_addr - vaddr),
                        }
                        pages.append(page)

            pages = sorted(pages, key=lambda x: x["vaddr"])

            # merge contiguous
            prev = pages[0]
            for page in pages[1:]:
                prev_vend = prev["vaddr"] + prev["memsize"]
                if prev["flags"] == page["flags"] and prev_vend == page["vaddr"]:
                    prev["memsize"] += page["memsize"]
                    pages.remove(page)
                else:
                    prev = page

            # page -> section
            sects = []
            for page in pages:
                perm = Permission.from_process_maps(ElfInfoCommand.pflags[page["flags"]].lower())
                page_start = page["vaddr"]
                page_end = page["vaddr"] + page["memsize"]
                off = page["offset"]
                sect = Section(
                    page_start=page_start, page_end=page_end,
                    offset=off, permission=perm, path=label,
                )
                sects.append(sect)
            return sects

        def get_linker(addr):
            if addr is None:
                return None

            # get interp
            elf = get_ehdr(addr & get_pagesize_mask_high())
            phdr = elf.get_phdr(Elf.Phdr.PT_INTERP)
            if phdr is None:
                return None

            vaddr = phdr.p_vaddr
            if elf.is_pie():
                vaddr += elf.addr

            linker = read_cstring_from_memory(vaddr)
            return linker

        def get_link_map(addr):
            if addr is None:
                return None

            # get dynamic
            elf = get_ehdr(addr & get_pagesize_mask_high())
            phdr = elf.get_phdr(Elf.Phdr.PT_DYNAMIC)
            if phdr is None:
                return None

            vaddr = phdr.p_vaddr
            vaddr_end = vaddr + phdr.p_memsz
            if elf.is_pie():
                vaddr += elf.addr
                vaddr_end += elf.addr

            # search DT_DEBUG
            for tag_addr in range(vaddr, vaddr_end, runtime.current_arch.ptrsize * 2):
                tag = read_int_from_memory(tag_addr)
                if tag == 21: # DT_DEBUG
                    dt_debug = read_int_from_memory(tag_addr + runtime.current_arch.ptrsize)
                    break
            else:
                # not found
                return None

            # get link_map
            try:
                link_map = read_int_from_memory(dt_debug + runtime.current_arch.ptrsize)
            except gdb.MemoryError:
                return None
            return link_map

        def get_filepath_wrapper():
            filepath = Path.get_filepath()
            if filepath:
                return filepath
            filepath = gdb.current_progspace().filename
            if filepath and filepath.startswith("target:"):
                filepath = filepath[7:]
            return filepath

        def parse_region_from_link_map(link_map):
            current = link_map
            new_regions = []
            while True:
                l_addr = read_int_from_memory(current + runtime.current_arch.ptrsize * 0)
                l_name = read_int_from_memory(current + runtime.current_arch.ptrsize * 1)
                l_next = read_int_from_memory(current + runtime.current_arch.ptrsize * 3)
                name = read_cstring_from_memory(l_name)
                if not name:
                    name = get_filepath_wrapper() or "[code]"
                new_regions += parse_region_from_ehdr(l_addr, name)
                if l_next == 0:
                    break
                current = l_next
            return new_regions

        def parse_auxv():
            auxv = Auxv.get_auxiliary_values()
            if not auxv:
                return []

            new_regions = []
            codebase = auxv.get("AT_PHDR", None) or auxv.get("AT_ENTRY", None)

            # plan1: from link_map info (code, all loaded shared library)
            link_map = get_link_map(codebase)
            if link_map:
                new_regions += parse_region_from_link_map(link_map)

            # plan2: use each auxv info (for code, linker)
            else:
                # code
                if "AT_PHDR" in auxv:
                    new_regions += parse_region_from_ehdr(auxv["AT_PHDR"], get_filepath_wrapper() or "[code]")
                elif "AT_ENTRY" in auxv:
                    new_regions += parse_region_from_ehdr(auxv["AT_ENTRY"], get_filepath_wrapper() or "[code]")
                # linker
                if "AT_BASE" in auxv:
                    new_regions += parse_region_from_ehdr(auxv["AT_BASE"], get_linker(codebase) or "[linker]")

            # vdso
            if "AT_SYSINFO_EHDR" in auxv:
                new_regions += parse_region_from_ehdr(auxv["AT_SYSINFO_EHDR"], "[vdso]")
            elif "AT_SYSINFO" in auxv:
                new_regions += parse_region_from_ehdr(auxv["AT_SYSINFO"], "[vdso]")
            return new_regions

        def parse_stack_register():
            # get permission
            stack_permission = "rw-" # default
            auxv = Auxv.get_auxiliary_values()
            if auxv and "AT_PHDR" in auxv:
                elf = get_ehdr(auxv["AT_PHDR"] & get_pagesize_mask_high())
                phdr = elf.get_phdr(Elf.Phdr.PT_GNU_STACK)
                if phdr:
                    stack_permission = ElfInfoCommand.pflags[phdr.p_flags].lower()
                else:
                    stack_permission = "rwx" # no GNU_STACK phdr means no-NX
            # add region
            return make_regions(runtime.current_arch.sp, "[stack]", stack_permission)

        def parse_registers_and_stack():
            from gef.core.utils import slice_unpack
            queue = set()

            # registers
            for regname in runtime.current_arch.all_registers:
                v = get_register(regname)
                if v is None:
                    continue
                queue.add(v & get_pagesize_mask_high())

            # walk value from stack top
            sp = runtime.current_arch.sp
            if sp is not None:
                try:
                    data = read_memory(sp & get_pagesize_mask_high(), get_pagesize())
                    data = slice_unpack(data, runtime.current_arch.ptrsize)
                    queue |= {d & get_pagesize_mask_high() for d in set(data)}
                except gdb.MemoryError:
                    pass

            # contiguous areas are removed from the queue
            merged_queue = []
            for addr in sorted(queue):
                if not is_valid_addr(addr):
                    continue
                if addr - get_pagesize() in merged_queue:
                    continue
                merged_queue.append(addr)

            # add regions
            new_regions = []
            for addr in merged_queue:
                skip = False
                for rg in new_regions:
                    if rg.page_start <= addr < rg.page_end:
                        skip = True
                if not skip:
                    new_regions += make_regions(addr, "<explored>")
            return new_regions

        # ----

        regions = []
        regions += parse_auxv()
        regions += parse_stack_register()

        # walk from known map, because qemu may maps extra regions (?)
        for r in regions.copy():
            regions += make_regions(r.page_start - 1, "<explored>", str(r.permission))
            regions += make_regions(r.page_end + 1, "<explored>", str(r.permission))

        regions += parse_registers_and_stack()

        # ok
        regions = sorted(regions, key=lambda x: x.page_start)

        return regions

    @staticmethod
    def get_process_maps_from_info_proc():
        if Config.get_gef_setting("context.disable_vmmap"):
            return []

        res = gdb.execute("info proc mappings", to_string=True)

        """
        process 2897541
        Mapped address spaces:

                  Start Addr           End Addr       Size     Offset  Perms  objfile
                    0x400000           0x478000    0x78000        0x0  r-xp   /tmp/a.out
                    0x478000           0x48c000    0x14000        0x0  ---p
                    0x48c000           0x492000     0x6000    0x7c000  rw-p   /tmp/a.out
                    0x492000           0x498000     0x6000        0x0  rw-p
              0x400000000000     0x400000001000     0x1000        0x0  ---p
              0x400000001000     0x400000801000   0x800000        0x0  rw-p   [stack]
              0x400000801000     0x400000802000     0x1000        0x0  r-xp
        """
        maps = []
        for line in res.splitlines()[4:]:
            line = line.strip()
            addr_start, addr_end, size, offset, perm, *path = line.split()
            addr_start = int(addr_start, 16)
            addr_end = int(addr_end, 16)
            size = int(size, 16)
            offset = int(offset, 16)
            perm = Permission.from_process_maps(perm)
            if len(path) == 1:
                path = path[0]
            else:
                path = ""
            sect = Section(
                page_start=addr_start, page_end=addr_end,
                offset=offset, permission=perm, inode=None, path=path,
            )
            maps.append(sect)
        return maps

    __gef_use_info_proc_mappings__ = None # the flag to use `info proc mappings`

    @staticmethod
    def get_process_maps_heuristic():
        if Config.get_gef_setting("context.disable_vmmap"):
            return []

        if ProcessMap.__gef_use_info_proc_mappings__ is None:
            try:
                res = gdb.execute("info proc mappings", to_string=True)
                if "warning" in res:
                    ProcessMap.__gef_use_info_proc_mappings__ = False
                elif "Perms" not in res: # xtensa-linux-gdb
                    ProcessMap.__gef_use_info_proc_mappings__ = False
                else: # for core files
                    ProcessMap.__gef_use_info_proc_mappings__ = True
            except gdb.error:
                ProcessMap.__gef_use_info_proc_mappings__ = False

        # fast path
        if ProcessMap.__gef_use_info_proc_mappings__ is True:
            res = ProcessMap.get_process_maps_from_info_proc() # don't use cache
            if res:
                return res
            # something is wrong
            ProcessMap.__gef_use_info_proc_mappings__ = False

        # slow path
        return ProcessMap.get_explored_regions() # use cache

    @staticmethod
    @Cache.cache_until_next
    def get_process_maps(outer=False):
        """Return the mapped memory sections."""
        if Config.get_gef_setting("context.disable_vmmap"):
            return []

        if is_qemu_user():
            if outer:
                pid = Pid.get_pid()
                if pid:
                    return ProcessMap.get_process_maps_linux(pid)
                return []
            else: # scan heuristic
                return ProcessMap.get_process_maps_heuristic()

        elif is_pin():
            pid = Pid.get_pid()
            if pid:
                return ProcessMap.get_process_maps_linux(pid)

        elif is_qemu_system():
            return []

        elif is_wine():
            # Wine loads the EXE at Wine's own virtual address space.
            # For typical pwner use cases, Wine itself and its libraries should also be displayed.
            # However, Wine's `monitor mem` does not show them, so this approach is not used.
            # Resolving Wine's PID and retrieving its memory maps is more reliable.
            pid = Pid.get_pid()
            if pid:
                return ProcessMap.get_process_maps_linux(pid)
            return []

        elif is_remote_debug():
            remote_pid = Pid.get_pid(remote=True)
            if remote_pid:
                return ProcessMap.get_process_maps_linux(remote_pid, remote=True)

        elif is_rr():
            return ProcessMap.get_process_maps_from_info_proc()

        else: # normal pattern
            pid = Pid.get_pid()
            if pid:
                r = ProcessMap.get_process_maps_linux(pid)
                if r:
                    return r

        return ProcessMap.get_process_maps_heuristic()

    @staticmethod
    @Cache.cache_until_next
    def get_process_maps_exclude_special_regions(outer=False, allow_vdso=False, allow_vsyscall=False):
        """Return the mapped memory sections,
        exclude [vvar], [vvar_vclock], [vdso], [vsyscall], [sigpage], etc."""
        vmmap = ProcessMap.get_process_maps(outer)
        if vmmap == []:
            return vmmap

        valid_maps = []
        for m in vmmap:
            if "[vvar]" in m.path:
                continue
            if "[vvar_vclock]" in m.path:
                continue
            if "[vdso]" in m.path:
                if not allow_vdso:
                    continue
            if "[vsyscall]" in m.path:
                if not allow_vsyscall:
                    continue
            if "[sigpage]" in m.path: # ARM
                continue
            if "[vectors]" in m.path: # ARM
                continue
            valid_maps.append(m)
        return valid_maps

    @staticmethod
    @Cache.cache_until_next
    def get_loaded_files():
        files = set()
        for m in ProcessMap.get_process_maps():
            if not m.path:
                continue
            if m.path.startswith(("<", "[")):
                continue
            if not os.path.exists(m.path):
                continue
            files.add(m.path)
        return files

    # `info files` called from get_info_files is heavy processing.
    # Moreover, AddressUtil.recursive_dereference causes each address to be resolved every time.
    # Cache.cache_until_next is ineffective due to frequent resets (each time the `stepi` runs).
    # Fortunately, zone information rarely changes.
    # The cache is retained until explicitly cleared.
    @staticmethod
    @Cache.cache_this_session
    def get_info_files():
        """Retrieve all the files loaded by debuggee."""
        lines = gdb.execute("info files", to_string=True).splitlines()
        info_files = []
        seen = []
        for line in lines:
            line = line.strip()
            if not line:
                break
            if not line.startswith("0x"):
                continue
            if line in seen:
                continue
            seen.append(line)

            blobs = [x.strip() for x in line.split(" ")]
            addr_start = int(blobs[0], 16)
            addr_end = int(blobs[2], 16)
            if len(blobs) > 4:
                section_name = blobs[4]
            else:
                section_name = ""
            if "system-supplied DSO" in line:
                filepath = "[vdso]"
            elif len(blobs) == 7:
                filepath = blobs[6]
            else:
                filepath = Path.get_filepath(append_proc_root_prefix=False)
            Zone = collections.namedtuple("Zone", ["name", "zone_start", "zone_end", "filename"])
            info = Zone(section_name, addr_start, addr_end, filepath)
            info_files.append(info)
        return info_files

    @staticmethod
    @Cache.cache_until_next
    def process_lookup_address(addr):
        """Look up for an address in memory. Return an Address object if found, None otherwise."""
        if not is_alive():
            err("Process is not running")
            return None
        if is_qemu_system() or is_vmware() or is_kgdb():
            return None
        for sect in ProcessMap.get_process_maps():
            if sect.page_start <= addr < sect.page_end:
                return sect
        return None

    @staticmethod
    @Cache.cache_until_next
    def process_lookup_path(names, perm_mask=Permission.ALL):
        """Look up for paths in the process memory mapping.
        Return a Section object of the load base address if found, None otherwise."""
        if not is_alive():
            err("Process is not running")
            return None
        if isinstance(names, str):
            names = (names,) # make tuple to iterate
        for sect in ProcessMap.get_process_maps():
            for name in names:
                if name in sect.path and sect.permission.value & perm_mask:
                    return sect
        return None

    @staticmethod
    @Cache.cache_until_next
    def file_lookup_address(addr):
        """Look up for a file by its address. Return a Zone object if found, None otherwise."""
        if is_qemu_system() or is_vmware() or is_kgdb():
            # If FGKASLR is enabled, there are too many sections and it will take a long time, so skip them.
            return None
        for info in ProcessMap.get_info_files():
            if info.zone_start <= addr < info.zone_end:
                return info
        return None

    @staticmethod
    @Cache.cache_until_next
    def lookup_address(addr):
        """Try to find the address in the process address space. Return an Address object with caching."""
        return Address(addr)

    @staticmethod
    @Cache.cache_until_next
    def get_section_base_address(name):
        if name is None:
            return None
        section = ProcessMap.process_lookup_path(name)
        if section:
            return section.page_start
        # Fail, retry with real path
        section = ProcessMap.process_lookup_path(os.path.realpath(name))
        if section:
            return section.page_start
        return None

    @staticmethod
    def get_section_base_address_by_list(names):
        for name in names:
            page_start = ProcessMap.get_section_base_address(name)
            if page_start is not None:
                return page_start
        return None

    @staticmethod
    @Cache.cache_this_session
    def get_codebase():
        filepath = Path.get_filepath(append_proc_root_prefix=is_container_attach())
        code_base = ProcessMap.get_section_base_address(filepath)
        if code_base is not None:
            return code_base

        filepath = Path.get_filepath_from_info_proc()
        code_base = ProcessMap.get_section_base_address(filepath)
        return code_base
