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
import contextlib
import gdb
import re

from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import err, info, warn
from gef.core.config import Config
from gef.core.memory import MemoryCache, read_memory, write_memory


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
    @Cache.cache_until_next(per_inferior=True)
    def get_physical_memory_ranges():
        return [(start, end) for start, end, _, _ in QemuMonitor.get_mtree_regions("memory")]

    @staticmethod
    @Cache.cache_this_session(per_inferior=True)
    def get_cpu_property(name):
        """Return the QOM property `name` of the first CPU that has it, decoded from the JSON of `monitor qom-get`.
        Return None if it is unavailable, e.g. QEMU before 5.1 has no qom-get in HMP."""
        if not is_qemu_system():
            return None
        try:
            res = gdb.execute("monitor info qom-tree", to_string=True)
        except gdb.error:
            return None
        for obj in QemuMonitor.parse_qom_tree(res):
            if not obj["type"].endswith("-cpu"):
                continue
            try:
                value = gdb.execute("monitor qom-get {:s} {:s}".format(obj["path"], name), to_string=True)
                return json.loads(value)
            except (gdb.error, ValueError):
                continue
        return None

    @staticmethod
    def parse_qom_tree(output):
        objects = []
        parents = []
        for line in output.splitlines():
            match = re.match(r"^( *)/(.*) \(([^()]*)\)\s*$", line)
            if match is None:
                continue

            indent = len(match.group(1))
            while parents and parents[-1][0] >= indent:
                parents.pop()
            if parents:
                parent_path = parents[-1][1]
            else:
                parent_path = ""
            name = match.group(2)
            path = "{:s}/{:s}".format(parent_path, name)
            obj = {"name": name, "type": match.group(3), "path": path}
            objects.append(obj)
            parents.append((indent, path))
        return objects

    @staticmethod
    @Cache.cache_until_next(per_cpu=True, per_inferior=True)
    def get_x86_segments():
        try:
            res = gdb.execute("monitor info registers", to_string=True)
        except gdb.error:
            return {}
        segments = {}
        for name, selector, base, flags in re.findall(
                r"^(CS|SS|DS|ES|FS|GS)\s*=\s*([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)",
                res, re.I | re.M):
            segments[name.upper()] = (int(selector, 16), int(base, 16), int(flags, 16))
        base, limit = QemuMonitor.parse_x86_descriptor_table_register(res, "GDT")
        if base is not None:
            segments["GDT"] = (base, limit)
        ldt = QemuMonitor.parse_x86_system_segment(res, "LDT")
        if ldt and not ldt["base_truncated"]:
            segments["LDT"] = (ldt["base"], ldt["limit"])
        cr0 = re.search(r"\bCR0=([0-9a-f]+)", res, re.I)
        flags = re.search(r"\bEFL=([0-9a-f]+)", res, re.I)
        vm86 = flags is not None and int(flags.group(1), 16) & (1 << 17)
        segments["protected"] = bool(cr0 and int(cr0.group(1), 16) & 1 and not vm86)
        return segments

    @staticmethod
    def parse_x86_descriptor_table_register(registers, name):
        match = re.search(r"^{:s}\s*=\s*([0-9a-f]+)\s+([0-9a-f]+)".format(name), registers, re.I | re.M)
        if not match:
            return None, None
        return int(match.group(1), 16), int(match.group(2), 16)

    @staticmethod
    def parse_x86_system_segment(registers, name):
        match = re.search(
            r"^{:s}\s*=\s*([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)".format(name),
            registers, re.I | re.M,
        )
        if not match:
            return None
        selector, base, limit, flags = [int(value, 16) for value in match.groups()]
        efer = re.search(r"\bEFER=([0-9a-f]+)", registers, re.I)
        truncated = bool(selector & ~3 and efer and int(efer.group(1), 16) & (1 << 10)
                         and len(match.group(2)) <= 8)
        return {"selector": selector, "base": base, "limit": limit, "flags": flags, "base_truncated": truncated}

    @staticmethod
    def infer_x86_ldt_base(registers, ldtr):
        base, limit = QemuMonitor.parse_x86_descriptor_table_register(registers, "GDT")
        offset = ldtr["selector"] & ~7
        if base is None or ldtr["selector"] & 4 or offset == 0:
            return None
        if limit > 0xffff or offset + 15 > limit:
            return None
        try:
            data = GefUtil.read_x86_descriptor_table(base + offset, 16)
        except gdb.error:
            return None
        if len(data) != 16:
            return None
        descriptor = int.from_bytes(data, "little")
        flags = (descriptor >> 32) & 0x00ffff00
        if (flags >> 8) & 0x1f != 2 or not flags & (1 << 15) or descriptor >> 96:
            return None
        limit = (descriptor & 0xffff) | ((descriptor >> 32) & 0xf0000)
        if flags & (1 << 23):
            limit = (limit << 12) | 0xfff
        base = ((descriptor >> 16) & 0xffffff) | ((descriptor >> 32) & 0xff000000)
        if base != ldtr["base"] or limit != ldtr["limit"] or flags != ldtr["flags"]:
            return None
        return base | (((descriptor >> 64) & 0xffffffff) << 32)

    @staticmethod
    @Cache.cache_this_session(cache_None=False)
    def get_gic_addrs():
        """Return physical addresses of ARM GIC(General Interrupt Controller) and the devices like it.
        QEMU crashes when the gdb stub reads the GICv2 of a multi-core machine or the Cortex-A9 global timer
        (they need the current CPU), and reading the GIC CPU interface may acknowledge an interrupt."""
        # memory may be read before the architecture is known; do not cache that answer
        if not is_alive() or runtime.current_arch is None:
            return None

        if not is_qemu_system():
            return []

        if not is_arm32() and not is_arm64():
            return []

        gic_list = []
        for start, end, attr, name in QemuMonitor.get_mtree_regions():
            # gef> monitor info mtree -f # these are physical addresses
            #   0000000008000000-0000000008000fff (prio 0, i/o): gic_dist
            #   0000000008010000-0000000008011fff (prio 0, i/o): gic_cpu
            #   000000001e000200-000000001e00021f (prio 0, i/o): a9gtimer shared
            if attr.endswith("i/o") and re.match(r"gic_(dist|cpu|viface|vcpu)|a9gtimer", name):
                gic_list.append([start, end])
        return gic_list

    @staticmethod
    def check_gic_address(addr, length=1, physical=False):
        """Return True if [addr, addr + length) shares a 4KB page with get_gic_addrs().
        A page is checked as a whole, because MemoryCache reads the other registers of the page too."""
        if not QemuMonitor.get_gic_addrs():
            return False
        return any(QemuMonitor.is_gic_page(page, physical) for page in range(addr & ~0xfff, addr + length, 0x1000))

    @staticmethod
    @Cache.cache_this_session
    def is_gic_page(page, physical):
        # These devices are mapped at boot and kept mapped, so the answer is kept for the session.
        paddr = page
        if not physical:
            try:
                ret = gdb.execute("monitor gva2gpa {:#x}".format(page), to_string=True)
            except gdb.error:
                return False
            r = re.search(r"gpa: (0x\S+)", ret)
            if not r:
                return False
            paddr = int(r.group(1), 16) & ~0xfff
        return any(s < paddr + 0x1000 and paddr < e for s, e in QemuMonitor.get_gic_addrs())

    @staticmethod
    def get_current_mmu_mode():
        if is_qemu_system():
            try:
                response = gdb.execute("maintenance packet qqemu.PhyMemMode", to_string=True, from_tty=False)
                if 'received: "0"' in response:
                    MemoryCache.set_default_namespace("virtual")
                    return "virt"
                elif 'received: "1"' in response:
                    MemoryCache.set_default_namespace("physical")
                    return "phys"
                else:
                    return False
            except gdb.error:
                return False
        elif is_vmware():
            try:
                MemoryCache.read_raw(0, 1)
                MemoryCache.set_default_namespace("physical")
                return "phys"
            except gdb.MemoryError:
                MemoryCache.set_default_namespace("virtual")
                return "virt"
        return None

    @staticmethod
    @contextlib.contextmanager
    def use_mmu_mode(target_mode):
        """Temporarily select QEMU/VMware virtual or physical memory mode."""
        if target_mode not in ("virt", "phys"):
            raise ValueError("Unsupported MMU mode: {!r}".format(target_mode))

        original_mode = QemuMonitor.get_current_mmu_mode()
        if original_mode is None:
            # not QEMU-system/VMware: memory is always virtual
            yield target_mode == "virt"
            return
        if original_mode not in ("virt", "phys"):
            yield False
            return
        if original_mode == target_mode:
            yield True
            return

        if target_mode == "phys":
            switch_mode = enable_phys
        else:
            switch_mode = disable_phys
        if original_mode == "phys":
            restore_mode = enable_phys
        else:
            restore_mode = disable_phys
        switched = switch_mode() is True
        try:
            yield switched
        finally:
            if switched and restore_mode() is not True:
                QemuMonitor.get_current_mmu_mode()
        return


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
    def check_gic_address(addr, length=1, physical=False):
        """Return True if [addr, addr + length) shares a 4KB page with get_gic_addrs().
        A page is checked as a whole, because MemoryCache reads the other registers of the page too."""
        if not QemuMonitor.get_gic_addrs():
            return False
        return any(QemuMonitor.is_gic_page(page, physical) for page in range(addr & ~0xfff, addr + length, 0x1000))

    @staticmethod
    @Cache.cache_this_session
    def is_gic_page(page, physical):
        # These devices are mapped at boot and kept mapped, so the answer is kept for the session.
        paddr = page
        if not physical:
            try:
                ret = gdb.execute("monitor gva2gpa {:#x}".format(page), to_string=True)
            except gdb.error:
                return False
            r = re.search(r"gpa: (0x\S+)", ret)
            if not r:
                return False
            paddr = int(r.group(1), 16) & ~0xfff
        return any(s < paddr + 0x1000 and paddr < e for s, e in QemuMonitor.get_gic_addrs())

    @staticmethod
    def get_current_mmu_mode():
        from gef.core.process import is_qemu_system, is_vmware
        if is_qemu_system():
            try:
                response = gdb.execute("maintenance packet qqemu.PhyMemMode", to_string=True, from_tty=False)
                if 'received: "0"' in response:
                    MemoryCache.set_default_namespace("virtual")
                    return "virt"
                elif 'received: "1"' in response:
                    MemoryCache.set_default_namespace("physical")
                    return "phys"
                else:
                    return False
            except gdb.error:
                return False
        elif is_vmware():
            try:
                MemoryCache.read_raw(0, 1)
                MemoryCache.set_default_namespace("physical")
                return "phys"
            except gdb.MemoryError:
                MemoryCache.set_default_namespace("virtual")
                return "virt"
        return None

    @staticmethod
    @contextlib.contextmanager
    def use_mmu_mode(target_mode):
        """Temporarily select QEMU/VMware virtual or physical memory mode."""
        if target_mode not in ("virt", "phys"):
            raise ValueError("Unsupported MMU mode: {!r}".format(target_mode))

        original_mode = QemuMonitor.get_current_mmu_mode()
        if original_mode is None:
            # not QEMU-system/VMware: memory is always virtual
            yield target_mode == "virt"
            return
        if original_mode not in ("virt", "phys"):
            yield False
            return
        if original_mode == target_mode:
            yield True
            return

        if target_mode == "phys":
            switch_mode = enable_phys
        else:
            switch_mode = disable_phys
        if original_mode == "phys":
            restore_mode = enable_phys
        else:
            restore_mode = disable_phys
        switched = switch_mode() is True
        try:
            yield switched
        finally:
            if switched and restore_mode() is not True:
                QemuMonitor.get_current_mmu_mode()
        return

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
    @Cache.cache_until_next(per_inferior=True)
    def get_mtree_regions(address_space=None):
        """Return the regions of `monitor info mtree -f` as a list of (start, end, attr, name).
        `end` is exclusive and `attr` is like "prio 0, ram". If `address_space` is given, only its FlatView is used."""
        try:
            res = gdb.execute("monitor info mtree -f", to_string=True)
        except gdb.error:
            return []
        regions = []
        for view in re.split(r"(?m)^FlatView", res):
            if address_space is not None and 'AS "{:s}"'.format(address_space) not in view:
                continue
            for start, end, attr, name in re.findall(r"(?m)^  ([0-9a-f]+)-([0-9a-f]+) \(([^)]*)\): (.*?)\r?$", view):
                # the end is inclusive
                regions.append((int(start, 16), int(end, 16) + 1, attr, name))
        return regions

    @staticmethod
    @Cache.cache_until_next(per_cpu=True, per_inferior=True)
    def get_x86_segments():
        try:
            res = gdb.execute("monitor info registers", to_string=True)
        except gdb.error:
            return {}
        segments = {}
        for name, selector, base, flags in re.findall(
                r"^(CS|SS|DS|ES|FS|GS)\s*=\s*([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)",
                res, re.I | re.M):
            segments[name.upper()] = (int(selector, 16), int(base, 16), int(flags, 16))
        base, limit = QemuMonitor.parse_x86_descriptor_table_register(res, "GDT")
        if base is not None:
            segments["GDT"] = (base, limit)
        ldt = QemuMonitor.parse_x86_system_segment(res, "LDT")
        if ldt and not ldt["base_truncated"]:
            segments["LDT"] = (ldt["base"], ldt["limit"])
        cr0 = re.search(r"\bCR0=([0-9a-f]+)", res, re.I)
        flags = re.search(r"\bEFL=([0-9a-f]+)", res, re.I)
        vm86 = flags is not None and int(flags.group(1), 16) & (1 << 17)
        segments["protected"] = bool(cr0 and int(cr0.group(1), 16) & 1 and not vm86)
        return segments

    @staticmethod
    def parse_x86_descriptor_table_register(registers, name):
        match = re.search(r"^{:s}\s*=\s*([0-9a-f]+)\s+([0-9a-f]+)".format(name), registers, re.I | re.M)
        if not match:
            return None, None
        return int(match.group(1), 16), int(match.group(2), 16)

    @staticmethod
    def parse_x86_system_segment(registers, name):
        match = re.search(
            r"^{:s}\s*=\s*([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+([0-9a-f]+)".format(name),
            registers, re.I | re.M,
        )
        if not match:
            return None
        selector, base, limit, flags = [int(value, 16) for value in match.groups()]
        efer = re.search(r"\bEFER=([0-9a-f]+)", registers, re.I)
        truncated = bool(selector & ~3 and efer and int(efer.group(1), 16) & (1 << 10)
                         and len(match.group(2)) <= 8)
        return {"selector": selector, "base": base, "limit": limit, "flags": flags, "base_truncated": truncated}


def is_supported_physmode():
    """GDB mode determination function for physmem support."""
    return QemuMonitor.get_current_mmu_mode() in ["virt", "phys"]


def enable_phys():
    from gef.core.process import is_qemu_system, is_vmware
    if is_qemu_system():
        gdb.execute("maintenance packet Qqemu.PhyMemMode:1", to_string=True, from_tty=False)
        response = gdb.execute("maintenance packet qqemu.PhyMemMode", to_string=True, from_tty=False)
        gdb.execute("maintenance flush dcache", to_string=True)
        success = 'received: "1"' in response
        if success:
            MemoryCache.set_default_namespace("physical")
        return success
    elif is_vmware():
        gdb.execute("monitor phys", to_string=True)
        gdb.execute("maintenance flush dcache", to_string=True)
        MemoryCache.set_default_namespace("physical")
        return True


def disable_phys():
    from gef.core.process import is_qemu_system, is_vmware
    if is_qemu_system():
        gdb.execute("maintenance packet Qqemu.PhyMemMode:0", to_string=True, from_tty=False)
        response = gdb.execute("maintenance packet qqemu.PhyMemMode", to_string=True, from_tty=False)
        gdb.execute("maintenance flush dcache", to_string=True)
        success = 'received: "0"' in response
        if success:
            MemoryCache.set_default_namespace("virtual")
        return success
    elif is_vmware():
        gdb.execute("monitor virt", to_string=True)
        gdb.execute("maintenance flush dcache", to_string=True)
        MemoryCache.set_default_namespace("virtual")
        return True


class SystemManagementMemory:

    @staticmethod
    @Cache.cache_until_next(per_inferior=True)
    def get_smram_map():

        from gef.core.process import is_qemu_system, is_x86
        """Return the most useful SMRAM range as ``(base, size, label)``.
        QEMU names the protected range differently depending on the chipset and
        firmware (TSEG, HSEG, ABSEG, or SMRAM).  The flat memory tree is a more
        reliable source than assuming the architectural reset SMBASE.  Do not
        guess the range when QEMU does not expose a labelled region: firmware
        may have relocated SMBASE away from its architectural reset value.
        """
        if not is_qemu_system() or not is_x86():
            return None

        candidates = []
        rank = {"tseg": 4, "smram": 4, "hseg": 3, "abseg": 3}
        for base, end, _, region_name in QemuMonitor.get_mtree_regions():
            label = region_name.split(" ")[0]
            words = re.split(r"[^a-z0-9]+", label.lower())
            kind = next((name for name in rank if name in words), None)
            if kind is None or end <= base:
                continue
            candidates.append((rank[kind], end - base, base, label))

        if candidates:
            _, size, base, label = max(candidates)
            return base, size, label
        return None

    @staticmethod
    @Cache.cache_until_next(per_cpu=True)
    def get_smm_monitor_state():

        from gef.core.process import is_qemu_system, is_x86
        """Return ``(state, token)`` from QEMU's current-CPU register dump.
        ``state`` is None when this QEMU version does not expose an SMM marker.
        """
        if not is_qemu_system() or not is_x86():
            return None, None
        try:
            output = gdb.execute("monitor info registers", to_string=True)
        except gdb.error:
            return None, None

        match = re.search(r"\bSMM\s*=\s*(0x[0-9a-f]+|[0-9]+)\b", output, re.IGNORECASE)
        if match:
            token = match.group(1)
            value = int(token, 16 if token.lower().startswith("0x") else 10)
            return value != 0, "SMM={:d}".format(value)

        lowered = output.lower()
        for marker in ("in smm", "smmode"):
            if marker in lowered:
                return True, marker
        return None, None

    @staticmethod
    @Cache.cache_until_next(per_cpu=True)
    def get_smm_status():

        from gef.core.kernel import Kernel
        from gef.core.process import is_qemu_system, is_x86
        from gef.core.registers import get_register
        """Return details about the current CPU's SMM state.
        QEMU's explicit ``SMM=`` marker is authoritative.  Older builds without
        that marker fall back to checking whether the physical instruction address lies in SMRAM.
        """
        smram = SystemManagementMemory.get_smram_map()
        monitor_state, monitor_token = SystemManagementMemory.get_smm_monitor_state()
        pc = get_register("$pc")
        pc_phys = None
        pc_in_smram = None
        if smram is not None and pc is not None:
            cs = QemuMonitor.get_x86_segments().get("CS")
            if cs is not None:
                linear = pc if cs[2] & (1 << 21) else (cs[1] + pc) & 0xffffffff
                pc_phys = Kernel.v2p(linear)
        if smram is not None and pc_phys is not None:
            base, size, _ = smram
            pc_in_smram = base <= pc_phys < base + size

        if monitor_state is not None:
            state = monitor_state
            source = "qemu-monitor"
        elif pc_in_smram is not None:
            state = pc_in_smram
            source = "pc-range"
        else:
            state = None
            source = None

        return {
            "state": state,
            "source": source,
            "monitor_state": monitor_state,
            "monitor_token": monitor_token,
            "pc": pc,
            "pc_phys": pc_phys,
            "pc_in_smram": pc_in_smram,
            "smram": smram,
        }

    @staticmethod
    def read_smram_backing(base, size):

        from gef.core.process import Pid
        """Read SMRAM from QEMU's pc.ram backing, bypassing the TSEG blackhole."""
        smram = SystemManagementMemory.get_smram_map()
        if smram is None:
            return None
        smram_base, smram_size, _ = smram
        if not smram_base <= base or base + size > smram_base + smram_size:
            return None

        qemu_pid = Pid.get_pid()
        if qemu_pid is None:
            return None

        # TSEG overlays pc.ram with tseg-blackhole. Resolve pc.ram at address zero,
        # then apply the guest-physical offset ourselves.
        try:
            output = gdb.execute("monitor gpa2hva 0", to_string=True)
            match = re.search(r"is\s+(0x[0-9a-f]+)", output, re.IGNORECASE)
            if not match:
                return None
            host_address = int(match.group(1), 16) + base
            with open("/proc/{:d}/mem".format(qemu_pid), "rb") as file:
                file.seek(host_address)
                data = file.read(size)
        except (gdb.error, OSError, ValueError):
            return None
        if len(data) == size:
            return data
        return None

    @staticmethod
    def read_smram_current_address_space(base, size):
        """Return readable ``(offset, data)`` chunks from the current SMM address space."""
        chunks = []
        with QemuMonitor.use_mmu_mode("virt") as available:
            if not available:
                return chunks

            offset = 0
            while offset < size:
                current = base + offset
                chunk_size = min(0x1000 - (current & 0xfff), size - offset)
                try:
                    output = gdb.execute("monitor gva2gpa {:#x}".format(current), to_string=True)
                    match = re.search(r"gpa:\s*(0x[0-9a-f]+)", output, re.IGNORECASE)
                    if match and int(match.group(1), 16) == current:
                        chunk = read_memory(current, chunk_size)
                        if len(chunk) == chunk_size:
                            chunks.append((offset, chunk))
                except (gdb.error, gdb.MemoryError):
                    pass
                offset += chunk_size
        return chunks

    @staticmethod
    def read_smram(base, size, in_smm=False, return_stats=False):

        from gef.core.utils import align
        """Read SMRAM through the current CPU's SMM address space when possible."""
        stats = {"smm_chunks": 0, "fallback_chunks": 0, "read_bytes": 0, "unreadable_ranges": []}
        if size == 0:
            if return_stats:
                return (b"", stats)
            return b""
        result = SystemManagementMemory.read_smram_backing(base, size)

        if result is None:
            try:
                result = read_physmem(base, size)
            except Exception:
                result = None

        if result is not None:
            fallback_size = min(len(result), size)
        else:
            fallback_size = 0
        data = bytearray(size)
        if fallback_size:
            data[:fallback_size] = result[:fallback_size]
        if in_smm:
            chunks = SystemManagementMemory.read_smram_current_address_space(base, size)
        else:
            chunks = []
        end = fallback_size
        for offset, chunk in chunks:
            data[offset:offset + len(chunk)] = chunk
            if end < offset:
                stats["unreadable_ranges"].append((base + end, base + offset))
            end = max(end, offset + len(chunk))

        if end < size:
            stats["unreadable_ranges"].append((base + end, base + size))

        stats["smm_chunks"] = len(chunks)
        if in_smm and fallback_size:
            total_chunks = align((base & 0xfff) + fallback_size, 0x1000) // 0x1000
            stats["fallback_chunks"] = total_chunks - sum(offset < fallback_size for offset, chunk in chunks)
        stats["read_bytes"] = size - sum(end - start for start, end in stats["unreadable_ranges"])
        if stats["unreadable_ranges"]:
            result = None
        else:
            result = bytes(data)
        if return_stats:
            return (result, stats)
        return result


