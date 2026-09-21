"""QEMU monitor / physical-memory access helpers (Layer 1).

`read_physmem`/`write_physmem` read and write guest *physical* memory via
qemu-system (monitor `gpa2hva`, legacy `xp`, or a virt/phys MMU mode switch),
VMware (`monitor phys/virt`), KGDB (`physmap`) and KDB (`mdp`). `QemuMonitor`
collects `monitor info mtree` parsers (GIC addresses, secure-ram, SMRAM) and
the phy/virt MMU mode query; `is_supported_physmode`, `enable_phys` and
`disable_phys` wrap the `PhyMemMode` maintenance packets.

This module TOP-imports only from already-extracted Layer-1 modules
(address, cache, color, config, memory). References to not-yet-extracted
modules (`process`, `pagewalk`, `utils`) are late-imported inside the
referencing function/method.
"""
import gdb
import re

from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import err, info, warn
from gef.core.config import Config
from gef.core.memory import read_memory, write_memory


def read_physmem(paddr, size, already_physmode=False):
    """Return a `size` long byte array with the copy of the physical memory at `paddr`."""

    def transparent_read(paddr, size):
        try:
            switched = False
            if QemuMonitor.get_current_mmu_mode() == "virt":
                # switch virt/phys mode
                switched = enable_phys() is True
                if not switched:
                    return None
            return read_memory(paddr, size)
        except Exception:
            pass
        finally:
            if switched:
                disable_phys()
        return None

    def qemu_system_proc_mem(paddr, size):
        from gef.core.process import Pid
        qemu_system_pid = Pid.get_pid()
        if qemu_system_pid is None:
            return None
        res = gdb.execute("monitor gpa2hva {:#x}".format(paddr), to_string=True)
        r = re.search("is (0x[0-9a-f]+)", res)
        if not r:
            return None
        virt_addr = int(r.group(1), 16)
        try:
            with open("/proc/{:d}/mem".format(qemu_system_pid), "rb") as fd:
                fd.seek(virt_addr)
                return fd.read(size)
        except Exception:
            pass
        return None

    def qemu_system_use_xp(paddr, size):
        # for older than qemu 4.1.0
        try:
            res = gdb.execute("monitor xp/{:d}xb {:#x}".format(size, paddr), to_string=True)
            """
            gef> monitor xp/16xb 0
            0000000000000000: 0x53 0xff 0x00 0xf0 0x53 0xff 0x00 0xf0
            0000000000000008: 0xc3 0xe2 0x00 0xf0 0x53 0xff 0x00 0xf0
            """
        except gdb.error:
            return None
        out = b""
        for line in res.splitlines():
            if not line:
                continue
            data = line.split()[1:]
            out += bytes([int(x, 16) for x in data])
        return out

    def kgdb_use_physmap(paddr, size):
        from gef.core.pagewalk import KernelAddressHeuristicFinder
        from gef.core.process import is_arm64, is_x86_64
        # Use workaround value if provided. Useful if KGDB does not expose system registers.
        physmap = Config.get_gef_setting("gef.physmap_base_for_read_physmem_kgdb_work_around")
        if physmap == 0:
            if is_arm64():
                # On arm64, calculate physmap address based on PAGE_OFFSET and memstart_addr.
                # This requires access to TCR_EL1 register to calculate PAGE_OFFSET.
                physmap = KernelAddressHeuristicFinder.consts().physmap_base
            elif is_x86_64():
                physmap = KernelAddressHeuristicFinder.get_PAGE_OFFSET()
            else:
                return None
            if physmap is None:
                return None

        vaddr = physmap + paddr
        try:
            return read_memory(vaddr, size)
        except gdb.MemoryError:
            return None

    def kdb_use_mdp(paddr, size):
        # for KDB; not supported by KGDB
        # Note: `mdp` command can only handle aligned addresses.
        paddr_aligned = paddr & ~0xf
        read_n_line = (size + (paddr - paddr_aligned) + 15) // 16
        try:
            res = gdb.execute("monitor mdp {:#x} {:d}".format(paddr_aligned, read_n_line), to_string=True)
            """
            gef> monitor mdp 0 2
            phys 0x0000000000000000 f000ff53f000ff53 f000ff53f000e2c3   S...S.......S...
            phys 0x0000000000000010 f000ff54f000ff53 f000ff53f0008488   S...T.......S...
            """
        except gdb.error:
            return None
        out = b""
        for line in res.splitlines():
            if not line:
                continue
            if line.endswith("zero suppressed"):
                start, end = AddressUtil.parse_string_range(line.split(" ")[0])
                zlen = (end + 1) - start
                out += b"\x00" * zlen
                continue
            out += b"".join([bytes.fromhex(x)[::-1] for x in line.split()[2:4]])
        return out[paddr & 0xf:][:size]

    # ----

    from gef.core.process import is_kdb, is_kgdb, is_qemu_system, is_vmware

    if size == 0:
        return b""

    if already_physmode:
        try:
            return read_memory(paddr, size)
        except gdb.MemoryError:
            pass

    if is_qemu_system():
        out = qemu_system_proc_mem(paddr, size)
        if out:
            return out
        if is_supported_physmode():
            out = transparent_read(paddr, size)
            if out:
                return out
        out = qemu_system_use_xp(paddr, size)
        if out:
            return out
        return None

    if is_vmware():
        return transparent_read(paddr, size)

    if is_kgdb():
        out = kgdb_use_physmap(paddr, size) # fast path
        if out:
            return out
        if is_kdb():
            return kdb_use_mdp(paddr, size) # slow path

    return None


def write_physmem(paddr, data, already_physmode=False):
    """Write `data` at physical memory address `paddr`."""

    def transparent_write(paddr, data):
        try:
            switched = False
            if QemuMonitor.get_current_mmu_mode() == "virt":
                # switch virt/phys mode
                switched = enable_phys() is True
                if not switched:
                    return None
            return write_memory(paddr, data)
        except Exception:
            pass
        finally:
            if switched:
                disable_phys()
        return None

    # ----

    from gef.core.process import is_qemu_system, is_vmware

    if len(data) == 0:
        return 0

    if already_physmode:
        try:
            return write_memory(paddr, data)
        except gdb.MemoryError:
            pass

    if not is_qemu_system() and not is_vmware(): # kgdb is unsupported
        return None

    if not is_supported_physmode():
        return None

    return transparent_write(paddr, data)


class QemuMonitor:
    """A collection of utility functions that are related to qemu-monitor."""

    @staticmethod
    @Cache.cache_this_session
    def get_gic_addrs():
        """Return physical addresses of ARM GIC(General Interrupt Controller)."""
        from gef.core.process import is_arm32, is_arm64, is_qemu_system
        if not is_qemu_system():
            return []

        if not is_arm32() and not is_arm64():
            return []

        try:
            res = gdb.execute("monitor info mtree -f", to_string=True)
        except gdb.error:
            return []

        gic_list = []
        for line in res.splitlines():
            # gef> monitor info mtree -f # these are physical addresses
            #   0000000008000000-0000000008000fff (prio 0, i/o): gic_dist
            #   0000000008010000-0000000008011fff (prio 0, i/o): gic_cpu
            if not line.startswith("  "):
                continue
            m = re.search(r"  ([0-9a-f]+)-([0-9a-f]+).*i/o\): gic_(dist|cpu)", line)
            if not m:
                continue
            paddr = int(m.group(1), 16)
            pend = int(m.group(2), 16)
            # fix size
            size = pend - paddr
            if (size & 0xfff) == 0xfff:
                size += 1
            gic_list.append([paddr, paddr + size])
        return gic_list

    @staticmethod
    @Cache.cache_until_next
    def check_gic_address(vaddr):
        gic_addrs = QemuMonitor.get_gic_addrs()
        if not gic_addrs:
            return False

        try:
            ret = gdb.execute("monitor gva2gpa {:#x}".format(vaddr), to_string=True)
        except gdb.error:
            return False
        r = re.search(r"gpa: (0x\S+)", ret)
        if not r:
            return False
        paddr = int(r.group(1), 16)

        for s, e in gic_addrs:
            if s <= paddr < e:
                return True
        return False

    @staticmethod
    def get_current_mmu_mode():
        from gef.core.process import is_qemu_system, is_vmware
        if is_qemu_system():
            try:
                response = gdb.execute("maintenance packet qqemu.PhyMemMode", to_string=True, from_tty=False)
                if 'received: "0"' in response:
                    return "virt"
                elif 'received: "1"' in response:
                    return "phys"
                else:
                    return False
            except gdb.error:
                return False
        elif is_vmware():
            try:
                read_memory(0, 1)
                return "phys"
            except gdb.MemoryError:
                return "virt"
        return None

    @staticmethod
    def get_secure_memory_map(verbose=False):
        from gef.core.process import Pid, ProcessMap
        # find secure-ram base
        ret = gdb.execute("monitor info mtree -f", to_string=True)
        for line in ret.splitlines():
            m = re.search(r"([0-9a-f]{16})-([0-9a-f]{16}).*: \S+.secure-ram", line)
            if m:
                secure_memory_base = int(m.group(1), 16)
                secure_memory_size = int(m.group(2), 16) + 1 - secure_memory_base
                if verbose:
                    info("secure memory base: {:#x}-{:#x} ({:#x} bytes)".format(
                        secure_memory_base,
                        secure_memory_base + secure_memory_size,
                        secure_memory_size,
                    ))
                break
        else:
            return None

        # find virtual address
        ret = gdb.execute("monitor gpa2hva {:#x}".format(secure_memory_base), to_string=True)
        r = re.search("is (0x[0-9a-f]+)", ret)
        if not r:
            return None
        secure_memory_page_addr = int(r.group(1), 16)

        # find target map of qemu-system's pid
        qemu_system_pid = Pid.get_pid()
        if qemu_system_pid is None:
            if verbose:
                err("Could not find the qemu-system pid")
            return None
        maps = ProcessMap.get_process_maps_linux(qemu_system_pid)
        for m in maps:
            if m.page_start != secure_memory_page_addr:
                continue
            if m.size != secure_memory_size:
                continue
            if verbose:
                info("secure memory page of pid {:d}: {:#x}".format(qemu_system_pid, m.page_start))
            m.sm_base = secure_memory_base
            m.sm_size = secure_memory_size
            return m
        return None

    @staticmethod
    @Cache.cache_this_session
    def get_smram_map(verbose=False):
        """Return ``(smram_base, smram_size)`` for the SMRAM region, or ``None``.

        SMM (System Management Mode) lives in dedicated physical memory whose
        name varies across QEMU machine models: ``smram`` (legacy DOS layout),
        ``tseg`` (Top Of Low Usable DRAM — modern Q35/OVMF), ``hseg``/``abseg``
        (high/AB segments on older i440fx). Scan ``monitor info mtree -f`` and
        pick the largest labelled region. If none is found, warn once and fall
        back to the legacy DOS-style default ``(0x30000, 0x10000)``.
        """
        from gef.core.process import is_qemu_system, is_x86
        if not is_qemu_system() or not is_x86():
            return None

        try:
            ret = gdb.execute("monitor info mtree -f", to_string=True)
        except gdb.error as e:
            err("Could not query `monitor info mtree -f`: {}".format(e))
            return None

        candidates = []
        # e.g.  "  0000000000030000-000000000003ffff (prio 0, i/o): smram"
        pat = re.compile(r"^\s+([0-9a-f]+)-([0-9a-f]+)\s+\([^:]*\):\s*(\S+)")
        for line in ret.splitlines():
            m = pat.search(line)
            if not m:
                continue
            base = int(m.group(1), 16)
            end = int(m.group(2), 16)
            label = m.group(3).lower()
            if any(name in label for name in ("smram", "tseg", "hseg", "abseg", "smm")):
                size = end - base
                if (size & 0xFFF) == 0xFFF:
                    size += 1  # same page-frame fixup as get_gic_addrs (gef.py:12277)
                candidates.append((base, size))
                if verbose:
                    info("Found SMRAM candidate via mtree: base={:#x} size={:#x} label={}".format(
                        base, size, m.group(3)))

        if candidates:
            from gef.core.utils import GefUtil
            smram_base, smram_size = max(candidates, key=lambda c: c[1])
            if verbose:
                info("SMRAM range resolved to base={:#x} size={:#x} ({})".format(
                    smram_base, smram_size, GefUtil.get_size_str(smram_size)))
            return (smram_base, smram_size)

        warn("No SMRAM/tseg/hseg region in `monitor info mtree -f`; "
             "falling back to legacy default 0x30000/0x10000.")
        return (0x30000, 0x10000)


def is_supported_physmode():
    """GDB mode determination function for physmem support."""
    return QemuMonitor.get_current_mmu_mode() in ["virt", "phys"]


def enable_phys():
    from gef.core.process import is_qemu_system, is_vmware
    if is_qemu_system():
        gdb.execute("maintenance packet Qqemu.PhyMemMode:1", to_string=True, from_tty=False)
        response = gdb.execute("maintenance packet qqemu.PhyMemMode", to_string=True, from_tty=False)
        gdb.execute("maintenance flush dcache", to_string=True)
        return 'received: "1"' in response
    elif is_vmware():
        gdb.execute("monitor phys", to_string=True)
        gdb.execute("maintenance flush dcache", to_string=True)
        return True


def disable_phys():
    from gef.core.process import is_qemu_system, is_vmware
    if is_qemu_system():
        gdb.execute("maintenance packet Qqemu.PhyMemMode:0", to_string=True, from_tty=False)
        response = gdb.execute("maintenance packet qqemu.PhyMemMode", to_string=True, from_tty=False)
        gdb.execute("maintenance flush dcache", to_string=True)
        return 'received: "0"' in response
    elif is_vmware():
        gdb.execute("monitor virt", to_string=True)
        gdb.execute("maintenance flush dcache", to_string=True)
        return True
