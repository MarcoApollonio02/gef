"""Page-table walk / kernel-object heuristic finders (Layer 1).

`PageMap` collects (virtual, physical) memory maps obtained by walking page
tables (x86/x64/ARM64 via the `pagewalk` command, plus the OP-TEE secure
memory heuristic for qemu-system). `KernelAddressHeuristicFinder` (and its
`KernelAddressHeuristicFinderUtil` alias) locate Linux-kernel objects
(`init_task`, `init_cred`, syscall tables, `selinux_state`, etc.) by memory
scanning.

Reads of the mutable global `runtime.current_arch` go through `runtime.current_arch`.
References to not-yet-extracted modules (gef.core.kernel `Kernel*` constants,
gef.commands `TlsCommand` / `XSecureMemAddrCommand`) are late-imported inside
the referencing method.
"""
import gdb
import itertools
import re

from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, warn
from gef.core.memory import is_valid_addr, is_valid_addr_addr, p32, p64, read_cstring_from_memory, read_int32_from_memory, read_int_from_memory, read_memory
from gef.core.process import is_32bit, is_64bit, is_arm32, is_arm64, is_kgdb, is_qemu_system, is_vmware, is_x86, is_x86_32, is_x86_64, get_pagesize
from gef.core.registers import get_register
from gef.core.qemu import QemuMonitor
from gef.core.symbols import Symbol
from gef.core.utils import is_double_link_list, is_single_link_list, slice_unpack, switch_to_intel_syntax


class PageMap:
    """A collection of utility functions that are related to memory map from page tables."""

    @staticmethod
    @Cache.cache_until_next
    def get_page_maps_by_pagewalk(command):
        if is_kgdb():
            info("Start `pagewalk`")
        res = gdb.execute(command, to_string=True)
        if 'Exception raised' in res:
            gef_print(res)
        return res

    @staticmethod
    @Cache.cache_until_next
    def get_page_maps_arm64_optee_secure_memory(verbose=False):
        from gef.commands.xsecure_mem import XSecureMemAddrCommand
        # heuristic search of qemu-system memory
        sm = QemuMonitor.get_secure_memory_map(verbose)
        if sm is None:
            err("Could not find secure memory maps")
            return None
        data = XSecureMemAddrCommand.read_secure_memory(sm, 0x0, sm.size, verbose)
        data_list = slice_unpack(data, 8)

        """
        enum teecore_memtypes {
            MEM_AREA_TEE_RAM = 1,
            MEM_AREA_TEE_RAM_RX,
            MEM_AREA_TEE_RAM_RO,
            MEM_AREA_TEE_RAM_RW,
            MEM_AREA_INIT_RAM_RO,
            MEM_AREA_INIT_RAM_RX,
            MEM_AREA_NEX_RAM_RO,
            MEM_AREA_NEX_RAM_RW,
            MEM_AREA_NEX_DYN_VASPACE,
            MEM_AREA_TEE_DYN_VASPACE,
            MEM_AREA_TEE_COHERENT,
            MEM_AREA_TEE_ASAN,
            MEM_AREA_IDENTITY_MAP_RX,
            MEM_AREA_NSEC_SHM,
            MEM_AREA_NEX_NSEC_SHM,
            MEM_AREA_RAM_NSEC,
            MEM_AREA_RAM_SEC,
            MEM_AREA_ROM_SEC,
            MEM_AREA_IO_NSEC,
            MEM_AREA_IO_SEC,
            MEM_AREA_EXT_DT,
            MEM_AREA_MANIFEST_DT,
            MEM_AREA_TRANSFER_LIST,
            MEM_AREA_RES_VASPACE,
            MEM_AREA_SHM_VASPACE,
            MEM_AREA_TS_VASPACE,
            MEM_AREA_PAGER_VASPACE,
            MEM_AREA_SDP_MEM,
            MEM_AREA_DDR_OVERALL,
            MEM_AREA_SEC_RAM_OVERALL,
            MEM_AREA_MAXTYPE
        };
        struct tee_mmap_region {
            unsigned int type; /* enum teecore_memtypes */
            unsigned int region_size;
            paddr_t pa;
            vaddr_t va;
            size_t size;
            uint32_t attr; /* TEE_MATTR_* above */
        };
        """
        maps = []
        old_i = -1
        for i in range(len(data_list) - 4):
            type_ = data_list[i] & 0xffff_ffff
            region_size = (data_list[i] >> 32) & 0xffff_ffff
            if type_ == 0 or 30 < type_: # enum teecore_memtypes
                continue
            if region_size & 0xfff or region_size < 0x1000 or 0xffff_f000 < region_size:
                continue
            pa, va, size, attr = data_list[i + 1:i + 5]
            if pa & 0xfff or 0xffff_f000 < pa:
                continue
            if va & 0xfff or 0xffff_f000 < va:
                continue
            if size & 0xfff or size < 0x1000 or 0xffff_f000 < size:
                continue
            if len(maps) > 0 and old_i + 5 != i: # Judging continuity
                continue
            maps.append([va, va + size, pa, pa + size])
            old_i = i
        return maps

    @staticmethod
    def get_page_maps(FORCE_PREFIX_S, verbose=False):
        if is_arm64():
            if FORCE_PREFIX_S is True:
                return PageMap.get_page_maps_arm64_optee_secure_memory(verbose) # already parsed
            else:
                res = PageMap.get_page_maps_by_pagewalk("pagewalk 1 --quiet --no-pager --no-merge --disable-color")
        else:
            if FORCE_PREFIX_S is None:
                res = PageMap.get_page_maps_by_pagewalk("pagewalk --quiet --no-pager --no-merge --disable-color")
            elif FORCE_PREFIX_S is True:
                res = PageMap.get_page_maps_by_pagewalk("pagewalk -S --quiet --no-pager --no-merge --disable-color")
            elif FORCE_PREFIX_S is False:
                res = PageMap.get_page_maps_by_pagewalk("pagewalk -s --quiet --no-pager --no-merge --disable-color")
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
            if is_x86():
                warn("Make sure you are in ring0 (=kernel mode)")
            elif is_arm32():
                warn("Make sure you are in supervisor mode (=kernel mode)")
                warn("Make sure qemu 3.x or higher")
            elif is_arm64():
                warn("Make sure you are in EL1 (=kernel mode)")
                warn("Make sure qemu 3.x or higher")
            return None
        return maps

    @staticmethod
    def v2p_from_map(address, maps):
        for vstart, vend, pstart, _pend in maps:
            if vstart <= address < vend:
                offset = address - vstart
                paddr = pstart + offset
                return paddr
        return None

    @staticmethod
    def p2v_from_map(address, maps): # return list
        vaddrs = []
        for vstart, _vend, pstart, pend in maps:
            if pstart <= address < pend:
                offset = address - pstart
                vaddr = vstart + offset
                vaddrs.append(vaddr)
        return vaddrs



class KernelAddressHeuristicFinderUtil:
    """A class that has utility for KernelAddressHeuristicFinder."""

    @staticmethod
    def common_addr_gen(res, regexp, skip, skip_msb_check, read_valid):
        for line in res.splitlines():
            m = re.search(regexp, line)
            if not m:
                continue
            v = AddressUtil.normalize_address(int(m.group(1), 16))
            if not skip_msb_check and not AddressUtil.is_msb_on(v):
                continue
            if read_valid and not is_valid_addr_addr(v): # not is_valid_addr, but is_valid_addr_addr
                continue
            if skip > 0:
                skip -= 1
                continue
            yield v

    @staticmethod
    def x64_x86_any_const(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"(?:# |,)(0x\w{8,})"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_x86_mov_reg_const(res, reg=r"\w+", skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"mov\s+" + reg + r"\s*,\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_lea_reg_const(res, reg=r"\w+", skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"lea\s+" + reg + r"\s*,\s*\[.*([+-]0x\w+)\]"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_x86_cmp_const(res, reg=r"\w+", skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"cmp\s+" + reg + r"\s*,\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_x86_imul_const(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"imul\s+\w+\s*,\s*\w+\s*,\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_x86_dword_ptr_src(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r",\s*DWORD PTR \[.*([+-]0x\w+)\]"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_x86_byte_ptr(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"BYTE PTR \[.*([+-]0x\w+)\]"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_dword_ptr_rip_base(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"DWORD PTR \[rip\+0x\w+\].*#\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_qword_ptr_rip_base(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"QWORD PTR \[rip\+0x\w+\].*#\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_qword_ptr_gs_rip_base(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"QWORD PTR gs:\[rip\+0x\w+\].*#\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_qword_ptr_array_base(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"QWORD PTR \[.*\*8([-+]0x\w+)\]"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x86_dword_ptr_array4_base(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"DWORD PTR \[.*\*4([+-]0x\w+)\]"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x86_dword_ptr_array8_base(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"DWORD PTR \[.*\*8([+-]0x\w+)\]"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_qword_ptr_ds(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"QWORD PTR ds:\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_qword_ptr_gs(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"QWORD PTR gs:\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x86_dword_ptr_ds(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"DWORD PTR ds:\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x86_dword_ptr_fs(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"DWORD PTR fs:\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x86_noptr_ds(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"ds:\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x86_mov_noptr_ds(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"mov.*ds:\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def aarch64_cmp_const(res, reg=r"\w+", skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"cmp\s+" + reg + r"\s*,\s*#(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def aarch64_adrp_ldr(res, skip=0, skip_msb_check=False, read_valid=False):
        bases = {}
        for line in res.splitlines():
            m = re.search(r"adrp\s+(\w+),\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16)
                bases[reg] = v
                continue
            m = re.search(r"ldr\s+\w+,\s*\[(\w+),\s*#(\d+)\]", line)
            if m:
                srcreg = m.group(1)
                v = int(m.group(2), 0)
                if srcreg in bases:
                    w = AddressUtil.normalize_address(bases[srcreg] + v)
                    if not skip_msb_check and not AddressUtil.is_msb_on(w):
                        continue
                    if read_valid and not is_valid_addr_addr(w):
                        continue
                    if skip > 0:
                        skip -= 1
                        continue
                    yield w

    @staticmethod
    def aarch64_adrp_add(res, skip=0, skip_msb_check=False, read_valid=False):
        bases = {}
        for line in res.splitlines():
            m = re.search(r"adrp\s+(\w+),\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16)
                bases[reg] = v
                continue
            m = re.search(r"add\s+(\w+),\s*(\w+),\s*#(0x\w+)", line)
            if m:
                srcreg = m.group(2)
                v = int(m.group(3), 16)
                if srcreg in bases:
                    w = AddressUtil.normalize_address(bases[srcreg] + v)
                    if not skip_msb_check and not AddressUtil.is_msb_on(w):
                        continue
                    if read_valid and not is_valid_addr_addr(w):
                        continue
                    if skip > 0:
                        skip -= 1
                        continue
                    yield w

    @staticmethod
    def aarch64_adrp_add_add(res, skip=0, skip_msb_check=False, read_valid=False):
        bases = {}
        add1time = {}
        for line in res.splitlines():
            m = re.search(r"adrp\s+(\w+),\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                base = int(m.group(2), 16)
                bases[reg] = base
                continue
            m = re.search(r"add\s+(\w+),\s*(\w+),\s*#(0x\w+)", line)
            if m:
                dstreg = m.group(1)
                srcreg = m.group(2)
                v = int(m.group(3), 16)
                if srcreg in add1time:
                    w = AddressUtil.normalize_address(add1time[srcreg] + v)
                    if not skip_msb_check or AddressUtil.is_msb_on(w):
                        if not read_valid or is_valid_addr_addr(w):
                            if skip <= 0:
                                yield w
                            skip -= 1
                if srcreg in bases:
                    add1time[dstreg] = bases[srcreg] + v
                    continue

    @staticmethod
    def aarch64_adrp_add_ldr(res, skip=0, skip_msb_check=False, read_valid=False):
        bases = {}
        add1time = {}
        for line in res.splitlines():
            m = re.search(r"adrp\s+(\w+),\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16)
                bases[reg] = v
                continue
            m = re.search(r"add\s+(\w+),\s*(\w+),\s*#(0x\w+)", line)
            if m:
                dstreg = m.group(1)
                srcreg = m.group(2)
                v = int(m.group(3), 16)
                if srcreg in bases:
                    add1time[dstreg] = bases[srcreg] + v
                    continue
            m = re.search(r"ldr\s+\w+,\s*\[(\w+),\s*#(\d+)\]", line)
            if m:
                srcreg = m.group(1)
                v = int(m.group(2), 0)
                if srcreg in add1time:
                    w = AddressUtil.normalize_address(add1time[srcreg] + v)
                    if not skip_msb_check and not AddressUtil.is_msb_on(w):
                        continue
                    if read_valid and not is_valid_addr_addr(w):
                        continue
                    if skip > 0:
                        skip -= 1
                        continue
                    yield w

    @staticmethod
    def arm32_movw_movt(res, skip=0, skip_msb_check=False, read_valid=False, allow_cc=False):
        bases = {}
        for line in res.splitlines():
            if allow_cc:
                m = re.search(r"movw(?:cc)?\s+(\w+),.+[;@]\s*(0x\w+)", line)
            else:
                m = re.search(r"movw\s+(\w+),.+[;@]\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16)
                bases[reg] = v
                continue
            if allow_cc:
                m = re.search(r"movt(?:cc)?\s+(\w+),.+[;@]\s*(0x\w+)", line)
            else:
                m = re.search(r"movt\s+(\w+),.+[;@]\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16) << 16
                if reg in bases:
                    w = AddressUtil.normalize_address(bases[reg] + v)
                    if not skip_msb_check and not AddressUtil.is_msb_on(w):
                        continue
                    if read_valid and not is_valid_addr_addr(w):
                        continue
                    if skip > 0:
                        skip -= 1
                        continue
                    yield w

    @staticmethod
    def arm32_movw_movt_ldr(res, skip=0, skip_msb_check=False, read_valid=False, allow_cc=False):
        bases = {}
        add1time = {}
        for line in res.splitlines():
            if allow_cc:
                m = re.search(r"movw(?:cc)?\s+(\w+),.+[;@]\s*(0x\w+)", line)
            else:
                m = re.search(r"movw\s+(\w+),.+[;@]\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16)
                bases[reg] = v
                continue
            if allow_cc:
                m = re.search(r"movt(?:cc)?\s+(\w+),.+[;@]\s*(0x\w+)", line)
            else:
                m = re.search(r"movt\s+(\w+),.+[;@]\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16) << 16
                if reg in bases:
                    add1time[reg] = bases[reg] + v
                    continue
            m = re.search(r"ldr\s+\w+,\s*\[(\w+),\s*#(\d+)\]", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 0)
                if reg in add1time:
                    w = AddressUtil.normalize_address(add1time[reg] + v)
                    if not skip_msb_check and not AddressUtil.is_msb_on(w):
                        continue
                    if read_valid and not is_valid_addr_addr(w):
                        continue
                    if skip > 0:
                        skip -= 1
                        continue
                    yield w

    @staticmethod
    def arm32_movw_movt_add(res, skip=0, skip_msb_check=False, read_valid=False):
        bases = {}
        add1time = {}
        for line in res.splitlines():
            m = re.search(r"movw\s+(\w+),.+[;@]\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16)
                bases[reg] = v
                continue
            m = re.search(r"movt\s+(\w+),.+[;@]\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16) << 16
                if reg in bases:
                    add1time[reg] = bases[reg] + v
                    continue
            m = re.search(r"add\s+\w+,\s*(\w+),\s*#(\d+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 0)
                if reg in add1time:
                    w = AddressUtil.normalize_address(add1time[reg] + v)
                    if not skip_msb_check and not AddressUtil.is_msb_on(w):
                        continue
                    if read_valid and not is_valid_addr_addr(w):
                        continue
                    if skip > 0:
                        skip -= 1
                        continue
                    yield w

    @staticmethod
    def arm32_ldr_reg_const(res, reg=r"\w+", skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"ldr\s+" + reg + r",.*[;@]\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def arm32_ldr_pc_relative(res, skip=0, read_valid=False):
        for line in res.splitlines():
            m = re.search(r"ldr\s+\w+,\s*\[pc,\s*#(\d+)\]", line)
            if m:
                ofs = AddressUtil.normalize_address(int(m.group(1), 0))
                pos = AddressUtil.normalize_address(int(line.split()[0].replace(":", ""), 16))
                v = read_int_from_memory(pos + 4 * 2 + ofs)
                if is_valid_addr(v):
                    if skip <= 0:
                        yield v
                    skip -= 1
                    continue
            m = re.search(r"ldr\s+\w+,\s*\[pc\]", line)
            if m:
                pos = AddressUtil.normalize_address(int(line.split()[0].replace(":", ""), 16))
                v = read_int_from_memory(pos + 4 * 2)
                if is_valid_addr(v):
                    if read_valid and not is_valid_addr_addr(v):
                        continue
                    if skip <= 0:
                        yield v
                    skip -= 1
                    continue

    @staticmethod
    def arm32_ldr_pc_relative_ldr(res, skip=0, read_valid=False):
        bases = {}
        for line in res.splitlines():
            m = re.search(r"ldr\s+(\w+),\s*\[pc,\s*#(\d+)\]", line)
            if m:
                reg = m.group(1)
                ofs = AddressUtil.normalize_address(int(m.group(2), 0))
                pos = AddressUtil.normalize_address(int(line.split()[0].replace(":", ""), 16))
                v = read_int_from_memory(pos + 4 * 2 + ofs)
                bases[reg] = v
                continue
            m = re.search(r"ldr\s+\w+,\s*\[(\w+),\s*#(\d*)\]", line)
            if m:
                reg = m.group(1)
                ofs = AddressUtil.normalize_address(int(m.group(2), 0))
                if reg in bases:
                    w = AddressUtil.normalize_address(bases[reg] + ofs)
                    if skip <= 0:
                        yield w
                    skip -= 1
                    continue
            m = re.search(r"ldr\s+\w+,\s*\[(\w+)\]", line)
            if m:
                reg = m.group(1)
                if reg in bases:
                    w = AddressUtil.normalize_address(bases[reg])
                    if read_valid and not is_valid_addr_addr(w):
                        continue
                    if skip <= 0:
                        yield w
                    skip -= 1
                    continue



class KernelAddressHeuristicFinder:
    """A class that heuristically finds a specific symbol in the kernel."""

    USE_DIRECTLY = True # for debug
    USE_KSYSCTL = True # for debug
    CONSTS = None

    @staticmethod
    def consts():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.CONSTS:
            return KernelAddressHeuristicFinder.CONSTS
        if is_x86_64():
            KernelAddressHeuristicFinder.CONSTS = KernelConstsX64()
        elif is_x86_32():
            KernelAddressHeuristicFinder.CONSTS = KernelConstsX86()
        elif is_arm64():
            KernelAddressHeuristicFinder.CONSTS = KernelConstsArm64()
        elif is_arm32():
            KernelAddressHeuristicFinder.CONSTS = KernelConstsArm32()
        return KernelAddressHeuristicFinder.CONSTS

    @staticmethod
    @switch_to_intel_syntax
    def get_saved_command_line():
        # Do not use Symbol.get_ksymaddr since this function is used to discover KPTI,
        # because Symbol.get_ksymaddr uses a cache.

        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        kversion = Kernel.kernel_version()

        # plan 1 (available v2.6.28 or later)
        if kversion and "2.6.28" <= kversion:
            # This is OK since we are not looking for `saved_command_line` directly.
            addr = Symbol.get_ksymaddr("cmdline_proc_show")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_current_task():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("current_task")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.1 or later)
        if kversion and "4.1" <= kversion:
            addr = Symbol.get_ksymaddr("common_cpu_up")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True)
                for x in g:
                    if x < 0x100:
                        continue
                    if is_x86_64():
                        if x & 0x7:
                            continue
                        if not AddressUtil.is_msb_on(x) and x > 0x10_0000:
                            continue
                    elif is_x86_32():
                        if x & 0x3:
                            continue
                    return x

        # plan 3 (available v2.5.33 or later)
        if kversion and "2.5.33" <= kversion:
            addr = Symbol.get_ksymaddr("setup_arg_pages")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_ds(res),
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_gs(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_gs_rip_base(res, skip_msb_check=True),
                    )
                elif is_x86_32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res),
                        KernelAddressHeuristicFinderUtil.x86_dword_ptr_fs(res, skip_msb_check=True),
                    )
                for x in g:
                    if x < 0x100:
                        continue
                    if is_x86_64():
                        if x & 0x7:
                            continue
                    elif is_x86_32():
                        if x & 0x3:
                            continue
                    return x
        return None

    @staticmethod
    def get_current_task_for_current_thread():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if is_arm32():
            # plan 1 (from special register)
            r = get_register("$TPIDRURO")
            if r and is_valid_addr(r):
                return r
            r = get_register("$TPIDRURO_S")
            if r and is_valid_addr(r):
                return r

            # plan 2 (from stack top)
            # We need to consider the case where Linux and RTOS are running on different CPUs at the same time.
            # If the stack is not the address the kernel expects to use, it should not be interpreted as a task.

            # check if valid kernel address or not
            current_thread_info = runtime.current_arch.sp & ~0x1fff
            if current_thread_info < KernelAddressHeuristicFinder.get_PAGE_OFFSET():
                return None

            kversion = Kernel.kernel_version()
            try:
                """
                struct thread_info {
                    unsigned long flags;
                    int preempt_count;
                    mm_segment_t addr_limit; // ~v5.14
                    struct task_struct *task; // ~v5.17
                    ...
                }
                """
                if kversion < "5.15":
                    v = read_int_from_memory(current_thread_info + runtime.current_arch.ptrsize * 3)
                    if v and is_valid_addr(v):
                        return v
                elif kversion < "5.18":
                    v = read_int_from_memory(current_thread_info + runtime.current_arch.ptrsize * 2)
                    if v and is_valid_addr(v):
                        return v
            except gdb.MemoryError:
                # In some threads, $sp points to an invalid address.
                return None
        elif is_arm64():
            # plan 1 (from special register)
            return get_register("$SP_EL0")
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_init_task():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("init_task")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # Detecting `init_task` is very difficult.
        # This is because `init_task` itself is rarely used, while `init_task.tasks` is used in most cases.
        # On x86/x64, only one case has been found where detection is stable.
        # However, there appear to be cases where it cannot be detected.

        # plan 2 (available v3.4 or later)
        if kversion and "3.4" <= kversion:
            if is_x86_64() or is_x86_32():
                addr = Symbol.get_ksymaddr("do_exit")
                if addr:
                    res = gdb.execute("x/600i {:#x}".format(addr), to_string=True)
                    if is_x86_64():
                        g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res)
                    elif is_x86_32():
                        g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res)
                    for x in g:
                        # There are cases where init_pid_ns is falsely detected as init_task.
                        # The initial value of kref is 2, so exclude this.
                        if not is_valid_addr(x):
                            continue
                        if read_int_from_memory(x) == 2:
                            continue
                        return x

        # On arm32/arm64, that pattern could not be found.
        # However, there is a method to locate `current_task` with 100% stability on arm32/arm64
        # using a special register.
        # In addition, `init_task` is always located in the kernel .data section.
        # Therefore, the following method is implemented:
        # 1. Traverse the linked list `current_task.tasks` starting from `current_task`
        #    and collect all task addresses.
        # 2. Select the task with the smallest distance from the kernel .data section.
        # This method can also be applied to x86/x64 as long as `current_task` can be obtained.

        def get_offset_tasks(current_task):
            # search for init_task->tasks
            # On CPU1, the task list is doubly linked, but on others it is not.
            # For example:
            #   CPU1: cpu1_current_task <-> task1 <-> task2 <-> ... <-> cpu1_current_task
            #   CPU2: cpu2_current_task  -> task1 <-> task2 <-> ... <-> cpu1_current_task
            # Therefore, we should read one element at a time and verify the linkage.
            for i in range(0x200):
                offset_tasks = runtime.current_arch.ptrsize * i
                current_task_tasks = current_task + offset_tasks
                if not is_valid_addr(current_task_tasks):
                    return None
                task1 = read_int_from_memory(current_task_tasks)
                if is_double_link_list(task1, min_len=5):
                    return offset_tasks
            return None

        def get_task_list(task, offset_tasks):
            pos = task + offset_tasks
            task_list = [pos]
            # validating candidate offset
            while True:
                pos = read_int_from_memory(pos)
                if pos in task_list:
                    break
                task_list.append(pos)
            return [x - offset_tasks for x in task_list]

        # plan 3 (from current)
        current = None
        if is_arm64() or is_arm32():
            current = KernelAddressHeuristicFinder.get_current_task_for_current_thread()
        elif is_x86_64() or is_x86_32():
            current_task = KernelAddressHeuristicFinder.get_current_task()
            if current_task:
                if AddressUtil.is_msb_on(current_task) and is_valid_addr(current_task):
                    # no __per_cpu_offset
                    current = read_int_from_memory(current_task)
                else:
                    # use __per_cpu_offset
                    p = KernelAddressHeuristicFinder.get_per_cpu_offset()
                    if p and is_valid_addr(p):
                        cpu_base = read_int_from_memory(p)
                        current_ptr = AddressUtil.normalize_address(cpu_base + current_task)
                        current = read_int_from_memory(current_ptr)
        if current:
            offset_tasks = get_offset_tasks(current)
            if offset_tasks:
                task_list = get_task_list(current, offset_tasks)
                kinfo = Kernel.get_kernel_layout()
                min_distance_task = (None, 0xffff_ffff_ffff_ffff)
                for task in task_list:
                    distance = abs((kinfo.rw_base or kinfo.text_base) - task)
                    if min_distance_task[1] > distance:
                        min_distance_task = (task, distance)
                if min_distance_task[0] is not None:
                    return min_distance_task[0]
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_init_cred():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("init_cred")
            if x:
                return x

        # plan2 (from ktask)
        res = gdb.execute("ktask --filter swapper/0 --no-pager", to_string=True)
        m = re.search(r"offsetof\(task_struct, cred\): (0x\w+)", res)
        if m:
            cred_offset = int(m.group(1), 16)
            line = res.strip().splitlines()[-1]
            addr, _, _, name, *_ = line.split()
            if name == "swapper/0":
                task = int(addr, 16)
                return read_int_from_memory(task + cred_offset)

        # plan3 (from ktask, not swapper/0, just swapper)
        res = gdb.execute("ktask --filter swapper --no-pager", to_string=True)
        m = re.search(r"offsetof\(task_struct, cred\): (0x\w+)", res)
        if m:
            cred_offset = int(m.group(1), 16)
            line = res.strip().splitlines()[-1]
            addr, _, _, name, *_ = line.split()
            if name == "swapper":
                task = int(addr, 16)
                return read_int_from_memory(task + cred_offset)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_init_net():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("init_net")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.6.35 or later)
        if kversion and "2.6.35" <= kversion:
            addr = Symbol.get_ksymaddr("net_initial_ns")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x

        # plan 3 (available v2.6.24 or later)
        if kversion and "2.6.24" <= kversion:
            addr = Symbol.get_ksymaddr("netdev_boot_base")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    if not is_valid_addr(x):
                        continue
                    if read_cstring_from_memory(x) == "%s%d":
                        continue
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_init_user_ns():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("init_user_ns")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.6.39 or later)
        if kversion and "2.6.39" <= kversion:
            addr = Symbol.get_ksymaddr("has_capability")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_modules():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("modules")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v3.7.5 or later)
        if kversion and "3.7.5" <= kversion:
            addr = Symbol.get_ksymaddr("find_module_all")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                    )
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_chrdevs():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("chrdevs")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.6.16.12 or later)
        if kversion and "2.6.17" <= kversion:
            addr = Symbol.get_ksymaddr("chrdev_show")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_array4_base(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                    )
                for x in g:
                    if not is_valid_addr(x):
                        continue
                    for i in range(255):
                        v = read_int_from_memory(x + runtime.current_arch.ptrsize * i)
                        if not is_single_link_list(v):
                            break
                    else:
                        # Case where all 255 entries meet the conditions
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_cdev_map():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("cdev_map")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.5.70 or later)
        if kversion and "2.5.70" <= kversion:
            addr = Symbol.get_ksymaddr("cdev_del")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                    )
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sys_call_table_x64():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("sys_call_table")
            if x:
                return x

        kversion = Kernel.kernel_version()

        if kversion and "6.6.26" <= kversion:
            # On x64, each entry is embedded in `x64_sys_call` as call instruction.
            # So sys_call_table is no longer in use, but it still remains.
            # We won't return yet because we may be able to detect this in plan 5.
            pass

        # plan 2 (available v4.6 ~ v6.6.26)
        if kversion and "4.6" <= kversion < "6.6.26":
            addr = Symbol.get_ksymaddr("do_syscall_64")
            if addr:
                res = gdb.execute("x/40i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res)
                for x in g:
                    return x

        # plan 3 (available v4.2 ~ v4.13)
        if kversion and "4.2" <= kversion < "4.14":
            addr = Symbol.get_ksymaddr("entry_SYSCALL_64_fastpath")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res)
                for x in g:
                    return x

        # plan 4 (available v2.6.27 ~ v4.1)
        if kversion and "2.6.27" <= kversion < "4.2":
            addr = Symbol.get_ksymaddr("system_call_fastpath")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res)
                for x in g:
                    return x

        # plan 5 (search for the memory)
        sys_read = Symbol.get_ksymaddr("__x64_sys_read")
        sys_write = Symbol.get_ksymaddr("__x64_sys_write")
        sys_open = Symbol.get_ksymaddr("__x64_sys_open")
        sys_close = Symbol.get_ksymaddr("__x64_sys_close")
        seq_to_find = p64(sys_read) + p64(sys_write) + p64(sys_open) + p64(sys_close)
        kinfo = Kernel.get_kernel_layout()
        if kinfo and kinfo.ro_base:
            ro_data = read_memory(kinfo.ro_base, kinfo.ro_size)
            sys_call_table_offset = ro_data.find(seq_to_find)
            if sys_call_table_offset >= 0:
                return kinfo.ro_base + sys_call_table_offset
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sys_call_table_x32():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("x32_sys_call_table")
            if x:
                return x

        kversion = Kernel.kernel_version()

        if kversion and kversion < "5.4":
            # Not introduced
            return None

        if kversion and "6.6.26" <= kversion:
            # On x64, each entry is embedded in `x32_sys_call` as call instruction.
            # So x32_sys_call_table is no longer in use, and removed from 6.6.26.
            return None

        # plan 2 (available v5.4 or later)
        if kversion and "5.4" <= kversion:
            addr = Symbol.get_ksymaddr("do_syscall_64")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res, skip=1)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sys_call_table_x86():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            if is_x86_64():
                x = Symbol.get_ksymaddr("ia32_sys_call_table")
            elif is_x86_32():
                x = Symbol.get_ksymaddr("sys_call_table")
            if x:
                return x

        kversion = Kernel.kernel_version()

        if kversion and "6.6.26" <= kversion:
            if is_x86_64():
                # On x64, ia32_sys_call_table is removed from 6.6.26.
                return None
            else:
                # On i386, each entry is embedded in `ia32_sys_call` as call instruction.
                # So sys_call_table is no longer in use, but it still remains.
                # We won't return yet because we may be able to detect this in plan 3.
                pass

        # plan 2 (available v2.6.24 ~ v6.6.26)
        if kversion and "6.6.7" <= kversion < "6.6.26":
            if is_x86_64():
                # ia32_sys_call_table is still used, but no detection logic.
                addr = None
            else:
                addr = Symbol.get_ksymaddr("do_int80_syscall_32")
        elif kversion and "4.6" <= kversion < "6.6.7":
            addr = Symbol.get_ksymaddr("do_int80_syscall_32")
        elif kversion and "4.4" <= kversion < "4.6":
            if is_x86_64():
                addr = Symbol.get_ksymaddr("do_syscall_32_irqs_off")
            else:
                addr = Symbol.get_ksymaddr("do_syscall_32_irqs_on")
        elif kversion and "2.6.24" <= kversion < "4.4":
            addr = Symbol.get_ksymaddr("syscall_call")
        else:
            addr = None
        if addr:
            res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_array4_base(res)
            for x in g:
                return x

        # plan 3 (search for the memory)
        sys_restart_syscall = Symbol.get_ksymaddr("sys_restart_syscall")
        sys_exit = Symbol.get_ksymaddr("sys_exit")
        sys_fork = Symbol.get_ksymaddr("sys_fork")
        sys_read = Symbol.get_ksymaddr("sys_read")
        if None not in [sys_restart_syscall, sys_exit, sys_fork, sys_read]:
            if is_x86_64():
                seq_to_find = p64(sys_restart_syscall) + p64(sys_exit) + p64(sys_fork) + p64(sys_read)
            else:
                seq_to_find = p32(sys_restart_syscall) + p32(sys_exit) + p32(sys_fork) + p32(sys_read)
            kinfo = Kernel.get_kernel_layout()
            if kinfo and kinfo.ro_base:
                ro_data = read_memory(kinfo.ro_base, kinfo.ro_size)
                sys_call_table_offset = ro_data.find(seq_to_find)
                if sys_call_table_offset >= 0:
                    return kinfo.ro_base + sys_call_table_offset
        return None

    @staticmethod
    def get_sys_call_table_arm32():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_arm32():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("sys_call_table")
            if x:
                return x

        # plan 2 (search for the memory)
        sys_restart_syscall = Symbol.get_ksymaddr("sys_restart_syscall")
        sys_exit = Symbol.get_ksymaddr("sys_exit")
        sys_fork = Symbol.get_ksymaddr("sys_fork")
        sys_read = Symbol.get_ksymaddr("sys_read")
        if None not in [sys_restart_syscall, sys_exit, sys_fork, sys_read]:
            seq_to_find = p32(sys_restart_syscall) + p32(sys_exit) + p32(sys_fork) + p32(sys_read)
            kinfo = Kernel.get_kernel_layout()
            # `sys_call_table` is embedded in the .text area even if `CONFIG_KALLSYMS_ALL=n`
            if kinfo and kinfo.text_base:
                text_data = read_memory(kinfo.text_base, kinfo.text_size)
                sys_call_table_offset = text_data.find(seq_to_find)
                if sys_call_table_offset >= 0:
                    return kinfo.text_base + sys_call_table_offset
        return None

    @staticmethod
    def get_sys_call_table_arm64():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("sys_call_table")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v3.7 or later)
        if kversion and "5.6" <= kversion:
            addr = Symbol.get_ksymaddr("do_el0_svc")
        elif kversion and "4.18" <= kversion < "5.6":
            addr = Symbol.get_ksymaddr("el0_svc_handler")
        elif kversion and "3.7" <= kversion < "4.18":
            addr = Symbol.get_ksymaddr("el0_svc")
        else:
            addr = None
        if addr:
            res = gdb.execute("x/100i {:#x}".format(addr), to_string=True)
            g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, read_valid=True)
            for x in g:
                return x

        # plan 3 (search for the memory)
        sys_io_setup = Symbol.get_ksymaddr("__arm64_sys_io_setup")
        sys_io_destroy = Symbol.get_ksymaddr("__arm64_sys_io_destroy")
        sys_io_submit = Symbol.get_ksymaddr("__arm64_sys_io_submit")
        sys_io_cancel = Symbol.get_ksymaddr("__arm64_sys_io_cancel")
        if None not in [sys_io_setup, sys_io_destroy, sys_io_submit, sys_io_cancel]:
            seq_to_find = p64(sys_io_setup) + p64(sys_io_destroy) + p64(sys_io_submit) + p64(sys_io_cancel)
            kinfo = Kernel.get_kernel_layout()
            if kinfo and kinfo.ro_base:
                ro_data = read_memory(kinfo.ro_base, kinfo.ro_size)
                sys_call_table_offset = ro_data.find(seq_to_find)
                if sys_call_table_offset >= 0:
                    return kinfo.ro_base + sys_call_table_offset
        return None

    @staticmethod
    def get_sys_call_table_arm64_compat():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("compat_sys_call_table")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v3.7 or later)
        if kversion and "5.6" <= kversion:
            addr = Symbol.get_ksymaddr("do_el0_svc_compat")
        elif kversion and "4.18" <= kversion < "5.6":
            addr = Symbol.get_ksymaddr("el0_svc_compat_handler")
        elif kversion and "3.7" <= kversion < "4.18":
            addr = Symbol.get_ksymaddr("el0_svc_compat")
        else:
            addr = None
        if addr:
            res = gdb.execute("x/100i {:#x}".format(addr), to_string=True)
            g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, read_valid=True)
            for x in g:
                return x

        # plan 3 (search for the memory)
        sys_restart_syscall = Symbol.get_ksymaddr("__arm64_sys_restart_syscall")
        sys_exit = Symbol.get_ksymaddr("__arm64_sys_exit")
        sys_fork = Symbol.get_ksymaddr("__arm64_sys_fork")
        sys_read = Symbol.get_ksymaddr("__arm64_sys_read")
        sys_write = Symbol.get_ksymaddr("__arm64_sys_write")
        sys_open = Symbol.get_ksymaddr("__arm64_compat_sys_open")
        if None not in [sys_restart_syscall, sys_exit, sys_fork, sys_read, sys_write, sys_open]:
            seq_to_find = p64(sys_restart_syscall) + p64(sys_exit) + p64(sys_fork) + p64(sys_read) + p64(sys_write) + p64(sys_open)
            kinfo = Kernel.get_kernel_layout()
            if kinfo and kinfo.ro_base:
                ro_data = read_memory(kinfo.ro_base, kinfo.ro_size)
                sys_call_table_offset = ro_data.find(seq_to_find)
                if sys_call_table_offset >= 0:
                    return kinfo.ro_base + sys_call_table_offset
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_per_cpu_offset():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("__per_cpu_offset")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v3.3 or later)
        if kversion and "3.3" <= kversion:
            addr = Symbol.get_ksymaddr("nr_iowait_cpu")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res),
                        KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res),
                    )
                elif is_x86_32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x86_dword_ptr_array4_base(res),
                        KernelAddressHeuristicFinderUtil.x64_x86_dword_ptr_src(res),
                    )
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    if not is_valid_addr(x):
                        continue
                    cpu0 = read_int_from_memory(x)
                    if cpu0 and (cpu0 & 0xfff) == 0:
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_slab_caches():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("slab_caches")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.9 or later)
        if kversion and "4.9" <= kversion:
            addr = Symbol.get_ksymaddr("slub_cpu_dead")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res, skip=1)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res, skip=1)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, skip=1)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x

        # plan 3 (available v5.9 or later)
        if kversion and "5.9" <= kversion:
            addr = Symbol.get_ksymaddr("find_mergeable")
            if addr:
                res = gdb.execute("x/50i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_add(res)
                for x in g:
                    return x

        # plan 4 (available v4.10 or before and CONFIG_MEMCG=y)
        if kversion and kversion < "4.11":
            addr = Symbol.get_ksymaddr("memcg_update_all_caches")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x

        # plan 5 (available v3.11 ~ v4.10 and CONFIG_SLABINFO=y)
        if kversion and "3.11" <= kversion < "4.11":
            addr = Symbol.get_ksymaddr("slab_next")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_arm64():
                    # TODO
                    g = []
                elif is_arm32():
                    # TODO
                    g = []
                for x in g:
                    return x

        # plan 6 (available if CONFIG_SLAB=y)
        addr = Symbol.get_ksymaddr("cache_reap")
        if addr:
            res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
            elif is_x86_32():
                # TODO
                g = []
            elif is_arm64():
                # TODO
                g = []
            elif is_arm32():
                g = KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res, skip=1)
            for x in g:
                return x

        # plan 7 (available v2.6.24 ~ v3.10 and CONFIG_SLABINFO=y)
        if kversion and "2.6.24" <= kversion < "3.11":
            addrs = Symbol.get_ksymaddr_multiple("s_next")
            if addrs:
                for s_next in addrs:
                    res = gdb.execute("x/20i {:#x}".format(s_next), to_string=True)
                    if is_x86_64():
                        g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, read_valid=True)
                    elif is_x86_32():
                        g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, read_valid=True)
                    elif is_arm64():
                        # TODO
                        g = []
                    elif is_arm32():
                        # TODO
                        g = []
                    for x in g:
                        v1 = read_int_from_memory(x)
                        v2 = read_int_from_memory(x + runtime.current_arch.ptrsize)
                        if is_valid_addr(v1) and is_valid_addr(v2):
                            return x

        # plan 8 (available v4.11 ~ v6.11)
        if kversion and "4.11" <= kversion < "6.12":
            addr = Symbol.get_ksymaddr("slab_caches_to_rcu_destroy_workfn")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for slab_mutex in g:
                    for i in range(16):
                        x = slab_mutex + runtime.current_arch.ptrsize * i
                        if is_double_link_list(x, min_len=10):
                            return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_slab_kset():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("slab_kset")
            if x:
                return x

        # plan 2
        addr = Symbol.get_ksymaddr("sysfs_slab_add")
        if addr:
            res = gdb.execute("x/100i {:#x}".format(addr), to_string=True)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res)
            elif is_arm64():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res),
                )
            elif is_arm32():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                )
            for x in g:
                if is_valid_addr(x):
                    y = read_int_from_memory(x)
                    if is_double_link_list(y):
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_modprobe_path():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("modprobe_path")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.modprobe")
            if x:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_poweroff_cmd():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("poweroff_cmd")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.poweroff_cmd")
            if x:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_core_pattern():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("core_pattern")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.core_pattern")
            if x:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_phys_base():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("phys_base")
            if x:
                return read_int_from_memory(x)

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.6.24 or later)
        if kversion and "2.6.24" <= kversion:
            addr = Symbol.get_ksymaddr("secondary_startup_64")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                for x in g:
                    return read_int_from_memory(x)

        # plan 3 (available v2.6.25 ~ v5.5)
        if kversion and "2.6.25" <= kversion < "5.5":
            addr = Symbol.get_ksymaddr("arch_crash_save_vmcoreinfo")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                for x in g:
                    s = read_cstring_from_memory(x)
                    if not s:
                        return read_int_from_memory(x)

        # plan 4 (available v3.9 or later)
        if kversion and "3.9" <= kversion:
            addr = Symbol.get_ksymaddr("__virt_addr_valid")
            if addr:
                res = gdb.execute("x/50i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                for x in g:
                    return read_int_from_memory(x)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_PAGE_OFFSET_base():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("page_offset_base")
            if x:
                return x

        # plan 2 (from pagewalk)
        kinfo = Kernel.get_kernel_layout()
        page_offset_base_raw = kinfo.maps[0][0]
        ro_data = read_memory(kinfo.ro_base, kinfo.ro_size)
        ro_data = slice_unpack(ro_data, runtime.current_arch.ptrsize)
        try:
            index = ro_data.index(page_offset_base_raw)
            return kinfo.ro_base + index * runtime.current_arch.ptrsize
        except ValueError:
            pass
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_PAGE_OFFSET():
        return KernelAddressHeuristicFinder.consts().PAGE_OFFSET

    @staticmethod
    @switch_to_intel_syntax
    def _get_PAGE_OFFSET():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if is_x86_64():
            # plan 1 (fixed address)
            kversion = Kernel.kernel_version()
            if kversion and kversion < "4.8":
                # kASLR and Level5 pagetable is unsupported, so fixed address
                return 0xffff_8800_0000_0000

            # plan 2 (from get_PAGE_OFFSET_base)
            page_offset_base = KernelAddressHeuristicFinder.get_PAGE_OFFSET_base()
            if page_offset_base:
                return read_int_from_memory(page_offset_base)

            # plan 3 (from pagewalk)
            kinfo = Kernel.get_kernel_layout()
            if kinfo.maps and len(kinfo.maps) > 0:
                page_offset_base_raw = kinfo.maps[0][0]
                return page_offset_base_raw
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_PAGE_OFFSET_END():
        return KernelAddressHeuristicFinder.consts().PAGE_OFFSET_END

    @staticmethod
    @switch_to_intel_syntax
    def get_VMALLOC_START():
        return KernelAddressHeuristicFinder.consts().VMALLOC_START

    @staticmethod
    @switch_to_intel_syntax
    def _get_VMALLOC_START():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            vmalloc_base = Symbol.get_ksymaddr("vmalloc_base")
            if vmalloc_base:
                return read_int_from_memory(vmalloc_base)

        kversion = Kernel.kernel_version()
        if is_x86_64():
            # plan 2 (fixed address)
            if kversion and kversion < "4.8":
                # kASLR and Level5 pagetable is unsupported, so fixed address
                return 0xffff_c900_0000_0000

            # plan 3 (from get_PAGE_OFFSET_base)
            page_offset_base = KernelAddressHeuristicFinder.get_PAGE_OFFSET_base()
            if page_offset_base:
                """
                [v6.13.9]
                0xffffffff8d1f0198|+0x0018|+003: 0x0000000100000027  // ?
                0xffffffff8d1f01a0|+0x0020|+004: 0xffff9d9080000000  // page_offset_base
                0xffffffff8d1f01a8|+0x0028|+005: 0xffffaeed80000000  // vmalloc_base
                0xffffffff8d1f01b0|+0x0030|+006: 0xffffec7a80000000  // vmemmap_base

                [v6.2.8]
                0xffffffffa5549a68|+0x0000|+000: 0xffffea0000000000  // vmemmap_base
                0xffffffffa5549a70|+0x0008|+001: 0xffffc90000000000  // vmalloc_base
                0xffffffffa5549a78|+0x0010|+002: 0xffff888000000000  // page_offset_base
                0xffffffffa5549a80|+0x0018|+003: 0x0000002700000001  // ?
                """
                page_offset_base_b = read_int_from_memory(page_offset_base - runtime.current_arch.ptrsize)
                page_offset_base_0 = read_int_from_memory(page_offset_base)
                page_offset_base_a = read_int_from_memory(page_offset_base + runtime.current_arch.ptrsize)
                if page_offset_base_0 < page_offset_base_b:
                    return page_offset_base_b
                if page_offset_base_0 < page_offset_base_a:
                    return page_offset_base_a

        # plan 4 (from vmalloc-dump)
        if kversion and "5.2" <= kversion:
            res = gdb.execute("vmalloc-dump --quiet --no-pager --only-freed", to_string=True)
            """
            #    state  virtual address                       size               flags
            0    freed  0x0000000000000001-0xffffc90000000000 0xffffc8ffffffffff
            """
            if res:
                res = Color.remove_color(res)
                lines = res.splitlines()
                if len(lines) >= 2:
                    _, _, vrange, _, *_ = lines[1].split()
                    s, e = vrange.split("-")
                    s = int(s, 16)
                    e = int(e, 16)
                    if s == 1:
                        return e

        # plan 5 (from vmalloc-dump and pagewalk)
        if kversion and kversion < "6.9":
            res = gdb.execute("vmalloc-dump --quiet --no-pager --only-used", to_string=True)
            """
            [vmalloc-dump; x64]
            #    state  virtual address                       size               flags
            0    in-use 0xffffa1c040000000-0xffffa1c040002000 0x2000             VM_IOREMAP

            [pagewalk; x64]
            0xffff9927bfe00000-0xffff9927bffe0000 0x1e0000 0x1000 480 [RW- KERN ACCESSED DIRTY]
            0xffffa1c040000000-0xffffa1c040001000 0x1000   0x1000 1   [RW- KERN ACCESSED DIRTY]

            [vmalloc-dump; x86]
            #    state  virtual address                       size               flags
            0    in-use 0x00000000e07e0000-0x00000000e07e2000 0x2000             VM_IOREMAP

            [pagewalk; x86]
            0x00000000c1b83000-0x00000000dffe0000 - 0x1e45d000 - - [RWX KERN]
            0x00000000e07e0000-0x00000000e07e1000 - 0x1000     - - [RWX KERN]
            """
            if res:
                res = Color.remove_color(res)
                lines = res.splitlines()
                if len(lines) >= 2:
                    _, _, vrange, _, *_ = lines[1].split()
                    s, _ = vrange.split("-")
                    s = int(s, 16)

                    # incontinuity check
                    kinfo = Kernel.get_kernel_layout()
                    prev = None
                    for vstart, _, _ in kinfo.maps:
                        if vstart == s:
                            break
                        prev = vstart

                    if prev is not None:
                        if is_64bit():
                            mask = 0xffff_ff00_0000_0000
                            if (prev & mask) != (s & mask):
                                if (s & 0x0fff_ffff) == 0:
                                    return s
                        else:
                            mask = 0xff00_0000
                            if (prev & mask) != (s & mask):
                                if (s & 0x0fff) == 0:
                                    return s
                    else:
                        return s
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_VMALLOC_END():
        return KernelAddressHeuristicFinder.consts().VMALLOC_END

    @staticmethod
    @switch_to_intel_syntax
    def get_VMEMMAP_START():
        if is_x86_64() or is_arm64():
            return KernelAddressHeuristicFinder.consts().VMEMMAP_START
        return None

    @staticmethod
    @switch_to_intel_syntax
    def _get_VMEMMAP_START():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if is_x86_64():
            # plan 1 (fixed address)
            kversion = Kernel.kernel_version()
            if kversion and kversion < "4.8":
                # kASLR and Level5 pagetable is unsupported, so fixed address
                return 0xffff_ea00_0000_0000

            # plan 2 (directly)
            if KernelAddressHeuristicFinder.USE_DIRECTLY:
                vmemmap_base = Symbol.get_ksymaddr("vmemmap_base")
                if vmemmap_base:
                    return read_int_from_memory(vmemmap_base)

            def get_min_page(r):
                if r is None:
                    return None
                min_page = None
                for x in r:
                    x = int(x, 16)
                    if not is_valid_addr(x):
                        continue
                    if min_page is None or x < min_page:
                        min_page = x
                return min_page

            # plan 3 (from slub-dump / slub-tiny-dump)
            allocator = Kernel.get_slab_type()
            if allocator in ["SLUB", "SLUB_TINY"]:
                command = {"SLUB": "slub-dump --node --skip-sheaf", "SLUB_TINY": "slub-tiny-dump"}[allocator]
                for n in [8, 16, 32, 64, 128, 192, 256, 512]:
                    ret = gdb.execute(
                        "{:s} --simple --no-pager --quiet kmalloc-{:d}".format(command, n),
                        to_string=True,
                    )
                    r = re.findall(r"(?:active|partial|node) page: (0x\S\S+)", Color.remove_color(ret))
                    min_page = get_min_page(r)
                    if min_page is not None:
                        return min_page & 0xffff_ffff_c000_0000 # ~((1 << PUD_SHIFT) - 1)

            # plan 4 (from slab-dump)
            if allocator == "SLAB":
                ret = gdb.execute("slab-dump --simple --no-pager --quiet kmalloc-256", to_string=True)
                r = re.findall(r"node\[\d+\]\.slabs_(?:partial|full): (0x\S+)", Color.remove_color(ret))
                min_page = get_min_page(r)
                if min_page is not None:
                    return min_page & 0xffff_ffff_c000_0000 # ~((1 << PUD_SHIFT) - 1)

            # plan 5 (from slob-dump)
            if allocator == "SLOB":
                ret = gdb.execute("slob-dump --simple --large --no-pager --quiet", to_string=True)
                r = re.findall(r"page: (0x\S+)", Color.remove_color(ret))
                min_page = get_min_page(r)
                if min_page is not None:
                    return min_page & 0xffff_ffff_c000_0000 # ~((1 << PUD_SHIFT) - 1)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_VMEMMAP_END():
        if is_x86_64() or is_arm64():
            return KernelAddressHeuristicFinder.consts().VMEMMAP_END
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_end_of_fixed_addresses():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86() and not is_arm64():
            return

        kversion = Kernel.kernel_version()

        # plan 1 (available v2.6.27 ~)
        if is_x86():
            if kversion and "2.6.27" <= kversion:
                addr = Symbol.get_ksymaddr("__native_set_fixmap")
                if addr:
                    res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                    g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res, skip_msb_check=True)
                    for x in g:
                        return x

        # plan 2 (available v3.19 ~)
        if is_arm64():
            if kversion and "3.19" <= kversion:
                addr = Symbol.get_ksymaddr("__set_fixmap")
                if addr:
                    res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                    g = KernelAddressHeuristicFinderUtil.aarch64_cmp_const(res, skip_msb_check=True)
                    for x in g:
                        if x <= 1:
                            continue
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sizeof_cpu_entry_area():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86_32():
            return None

        kversion = Kernel.kernel_version()
        if kversion and "4.14" <= kversion:
            addr = Symbol.get_ksymaddr("get_cpu_entry_area")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_x86_imul_const(res, skip_msb_check=True)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_mem_section():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86_32() and not is_arm32():
            return None

        # Since mem_map and mem_section are mutually exclusive, make sure that mem_map is not being used
        if KernelAddressHeuristicFinder.get_mem_map() is not None:
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            addr = Symbol.get_ksymaddr("mem_section")
            if addr:
                return addr

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.4.0 or later)
        if kversion and "2.4" <= kversion:
            addr = Symbol.get_ksymaddr("free_pages")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_32():
                    # 0xc12f491b <free_pages+27>:  mov    eax,DWORD PTR [eax*8-0x3d19e3a0]
                    # gef> x/w -0x3d19e3a0
                    # 0xc2e61c60 <mem_section>:       0xf708000f
                    g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_array8_base(res)
                elif is_arm32():
                    # 0xc0501dd4 <free_pages+8>:   movw    r3, #45144      @ 0xb058
                    # 0xc0501dd8 <free_pages+12>:  movt    r3, #49664      @ 0xc200
                    # 0xc0501df0 <free_pages+36>:  movwcc  r2, #17344      @ 0x43c0
                    # 0xc0501df4 <free_pages+40>:  movtcc  r2, #49707      @ 0xc22b
                    # gef> x/w 0xc200b058
                    # 0xc200b058 <__pv_phys_pfn_offset>:   0x00060000
                    # gef> x/w 0xc22b43c0
                    # 0xc22b43c0 <mem_section>:   0x00000000
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, allow_cc=True)
                for x in g:
                    v = read_int_from_memory(x)
                    if v and not is_valid_addr(v):
                        continue
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_mem_map():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86_32() and not is_arm32():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            addr = Symbol.get_ksymaddr("mem_map")
            if addr:
                v = read_int_from_memory(addr)
                if v != 0:
                    return v
                return None

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.4.0 or later)
        if kversion and "2.4" <= kversion:
            addr = Symbol.get_ksymaddr("free_pages")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_32():
                    g = itertools.chain(
                        # 0xd3bf91d9 <free_pages+13>:  mov    ecx,DWORD PTR ds:0xd4f337c4
                        # gef> x/w 0xd4f337c4
                        # 0xd4f337c4 <mem_map>:   0xf67fe000
                        KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res),
                        KernelAddressHeuristicFinderUtil.x86_noptr_ds(res),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        # 0xc049f880 <free_pages+8>:   movw    r3, #46272      @ 0xb4c0
                        # 0xc049f884 <free_pages+12>:  movt    r3, #49625      @ 0xc1d9
                        # gef> x/w 0xc1d9b4c0
                        # 0xc1d9b4c0 <mem_map>:   0xcbdd9000
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    v = read_int_from_memory(x)
                    if v != 0:
                        return v
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_page_address_htable():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86_32() and not is_arm32():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("page_address_htable")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.5.41 or later)
        if kversion and "2.5.41" <= kversion:
            addr = Symbol.get_ksymaddr("set_page_address")
            if addr:
                res = gdb.execute("x/40i {:#x}".format(addr), to_string=True)
                if is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    if is_double_link_list(x):
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_clocksource_tsc():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("clocksource_tsc")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.16.8 or later)
        if kversion and "4.16.8" <= kversion:
            addr = Symbol.get_ksymaddr("mark_tsc_unstable.part.0") or Symbol.get_ksymaddr("mark_tsc_unstable.cold")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rdi", skip=2)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "eax", skip=1)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_clocksource_list():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("clocksource_list")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.6.21 or later / v2.6.32 or later)
        if kversion and "2.6.21" <= kversion:
            addr = Symbol.get_ksymaddr("clocksource_enqueue") or Symbol.get_ksymaddr("clocksource_resume")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_capability_hooks():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("capability_hooks")
            if x:
                return x

        # plan 2 nothing
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_n_tty_ops():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("n_tty_ops")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.6 or later)
        if kversion and "4.6" <= kversion:
            addr = Symbol.get_ksymaddr("n_tty_inherit_ops")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_x86_dword_ptr_src(res),
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res),
                    )
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_tty_ldiscs():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("tty_ldiscs")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.6.37 or later)
        if kversion and "2.6.37" <= kversion:
            addr = Symbol.get_ksymaddr("tty_register_ldisc")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_array4_base(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    for i in range(2):
                        v = read_int_from_memory(x + runtime.current_arch.ptrsize * i)
                        if not is_valid_addr(v):
                            continue
                        if kversion < "5.13":
                            w = read_int32_from_memory(v)
                            if w == 0x00005403: # magic
                                return x
                        else:
                            w = read_int_from_memory(v)
                            if not is_valid_addr(w):
                                continue
                            s = read_cstring_from_memory(w) # name
                            if s and len(s) > 2:
                                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sysctl_table_root():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("sysctl_table_root")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v3.4 or later)
        if kversion and "3.4" <= kversion:
            addr = Symbol.get_ksymaddr("register_sysctl") or Symbol.get_ksymaddr("register_sysctl_sz")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rdi")
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "e[a-d]x")
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_selinux_state():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("selinux_state")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v5.0 ~ v6.3)
        if kversion and "5.0" <= kversion < "6.4":
            addr = Symbol.get_ksymaddr("show_sid")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rdi")
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "e[a-d]x")
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_ldr_reg_const(res, "r0")
                for x in g:
                    if not is_valid_addr(x):
                        continue
                    if is_arm32():
                        v = read_int32_from_memory(x)
                        if is_valid_addr(v):
                            return v
                    else:
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_apparmor_enabled():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("apparmor_enabled")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.12 or later)
        if kversion and "4.12" <= kversion:
            addr = Symbol.get_ksymaddr("param_get_aauint")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_apparmor_initialized():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("apparmor_initialized")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.12 or later)
        if kversion and "4.12" <= kversion:
            addr = Symbol.get_ksymaddr("param_get_aauint")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res, skip=1)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res, skip=1)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, skip=1)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, skip=1)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_kernel_locked_down():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("kernel_locked_down")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v5.4 or later)
        if kversion and "5.4" <= kversion:
            addr = Symbol.get_ksymaddr("lock_kernel_down")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_tomoyo_enabled():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("tomoyo_enabled")
            if x:
                return x

        # plan 2 nothing
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_mmap_min_addr():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("mmap_min_addr")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("vm.mmap_min_addr")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 3 (available v4.19.27 or later)
        if kversion and "4.19.27" <= kversion:
            addr = Symbol.get_ksymaddr("expand_downwards")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sysctl_unprivileged_userfaultfd():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("sysctl_unprivileged_userfaultfd")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("vm.unprivileged_userfaultfd")
            if x:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sysctl_unprivileged_bpf_disabled():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("sysctl_unprivileged_bpf_disabled")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.unprivileged_bpf_disabled")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 3 (available v4.9.91 ~ v5.18.19)
        if kversion and "4.9.91" <= kversion < "5.19":
            addr = Symbol.get_ksymaddr("__do_sys_bpf")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_kptr_restrict():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("kptr_restrict")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.kptr_restrict")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 3 (available v4.15 or later)
        if kversion and "4.15" <= kversion:
            addr = Symbol.get_ksymaddr("kallsyms_show_value")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sysctl_perf_event_paranoid():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("sysctl_perf_event_paranoid")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.perf_event_paranoid")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 3 (available v4.15 or later)
        if kversion and "4.15" <= kversion:
            addr = Symbol.get_ksymaddr("kallsyms_show_value")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res, skip=1)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res, skip=1)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, skip=1)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, skip=1)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_dmesg_restrict():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("dmesg_restrict")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.dmesg_restrict")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 3 (available v3.11 or later)
        if kversion and "3.11" <= kversion:
            addr = Symbol.get_ksymaddr("check_syslog_permissions")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_kexec_load_disabled():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("kexec_load_disabled")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.kexec_load_disabled")
            if x:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_loadpin_enabled():
        # plan 1 (from ksysctl)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.loadpin.enabled")
            if x:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_loadpin_enforce():
        # plan 1 (from ksysctl)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.loadpin.enforce")
            if x:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_ptrace_scope():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("ptrace_scope")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = Kernel.get_ksysctl("kernel.yama.ptrace_scope")
            if x:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_vdso_image_64():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("vdso_image_64")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.2 or later)
        if kversion and "4.2" <= kversion:
            addr = Symbol.get_ksymaddr("arch_setup_additional_pages")
            if addr:
                res = gdb.execute("x/40i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rdi", read_valid=True)
                for x in g:
                    v = read_int_from_memory(x)
                    if read_memory(v, 4) == b"\x7fELF":
                        return x

                # another pattern
                # gef> |x/40i arch_setup_additional_pages | grep mov
                # 0xffffffff82401030 <arch_setup_additional_pages>:    mov eax,DWORD PTR [rip+0x43738a] # 0xffffffff828383c0 <vdso64_enabled>
                # 0xffffffff8240103e <arch_setup_additional_pages+14>: mov edx,DWORD PTR [rip+0x1ffb24] # 0xffffffff82600b68 <vdso_image_64+8>
                g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                for x in g:
                    if not is_valid_addr(x):
                        continue
                    for i in range(10):
                        v = read_int_from_memory(x - runtime.current_arch.ptrsize * i)
                        if not is_valid_addr(v):
                            continue
                        if read_memory(v, 4) == b"\x7fELF":
                            return x - runtime.current_arch.ptrsize * i
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_vdso_image_x32():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("vdso_image_x32")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.2 or later)
        if kversion and "4.2" <= kversion:
            addr = Symbol.get_ksymaddr("compat_arch_setup_additional_pages")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rdi", read_valid=True)
                for x in g:
                    v = read_int_from_memory(x)
                    if read_memory(v, 4) == b"\x7fELF" and read_memory(v + 0x12, 1) == b"\x3e": # Elf.Machine
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_vdso_image_32():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_x86():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("vdso_image_32")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.2 or later)
        if kversion and "4.2" <= kversion:
            if is_x86_64():
                addr = Symbol.get_ksymaddr("compat_arch_setup_additional_pages")
                if addr:
                    res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rdi", read_valid=True)
                    for x in g:
                        v = read_int_from_memory(x)
                        if read_memory(v, 4) == b"\x7fELF" and read_memory(v + 0x12, 1) == b"\x03": # Elf.Machine
                            return x
            elif is_x86_32():
                addr = Symbol.get_ksymaddr("arch_setup_additional_pages")
                if addr:
                    # pattern 1
                    res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "eax", read_valid=True)
                    for x in g:
                        v = read_int_from_memory(x)
                        if read_memory(v, 4) == b"\x7fELF":
                            return x
                    # pattern 2
                    res = gdb.execute("x/40i {:#x}".format(addr), to_string=True)
                    g2 = KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res)
                    for x in g2:
                        if read_int_from_memory(x) == 0x1000:
                            v = read_int_from_memory(x - 4)
                            if read_memory(v, 4) == b"\x7fELF":
                                return x - 4
        return None

    @staticmethod
    def get_vdso_info():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("vdso_info")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # vdso_info is introduced from v5.8
        if kversion < "5.8":
            return None

        # plan 2 (available v5.8 or later)
        if kversion and "5.8" <= kversion:
            addr = Symbol.get_ksymaddr("__vdso_init")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                for x in g:
                    return x

        # plan 3 (from .rodata)
        """
        static struct vdso_abi_info vdso_info[] __ro_after_init = {
            [VDSO_ABI_AA64] = {
                .name = "vdso",
                .vdso_code_start = vdso_start,
                .vdso_code_end = vdso_end,
            },
        """
        kinfo = Kernel.get_kernel_layout()
        if kinfo.ro_base and kinfo.ro_size:
            ro_data = read_memory(kinfo.ro_base, kinfo.ro_size)
            pos = -1
            while True:
                # search for aligned ELF header from .rodata
                pos = ro_data.find(b"\x7fELF", pos + 1)
                if pos == -1:
                    break
                if pos % get_pagesize() != 0:
                    continue

                # calc address of ELF header
                if is_32bit():
                    vdso_addr_byteseq = p32(kinfo.ro_base + pos)
                else:
                    vdso_addr_byteseq = p64(kinfo.ro_base + pos)

                # search for it from .rodata again
                pos2 = -1
                while True:
                    pos2 = ro_data.find(vdso_addr_byteseq, pos2 + 1)
                    if pos2 == -1:
                        break
                    if pos2 % runtime.current_arch.ptrsize != 0:
                        continue
                    maybe_vdso_info = kinfo.ro_base + pos2
                    maybe_vdso_info -= runtime.current_arch.ptrsize
                    name = read_int_from_memory(maybe_vdso_info)
                    if not is_valid_addr(name):
                        continue
                    if read_cstring_from_memory(name) == "vdso":
                        return maybe_vdso_info
        return None

    @staticmethod
    def get_vdso_lookup():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("vdso_lookup")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # vdso_info is introduced until v5.8
        if kversion and (kversion < "5.3" or "5.8" <= kversion):
            return None

        # plan 2 (available v5.3 or later)
        if kversion and "5.3" <= kversion:
            addr = Symbol.get_ksymaddr("__vdso_init")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                for x in g:
                    return x

        # plan 3 (from .rodata)
        """
        static struct __vdso_abi vdso_lookup[VDSO_TYPES] __ro_after_init = {
            {
                .name = "vdso",
                .vdso_code_start = vdso_start,
                .vdso_code_end = vdso_end,
            },
        """
        kinfo = Kernel.get_kernel_layout()
        if kinfo.ro_base and kinfo.ro_size:
            ro_data = read_memory(kinfo.ro_base, kinfo.ro_size)
            pos = -1
            while True:
                # search for aligned ELF header from .rodata
                pos = ro_data.find(b"\x7fELF", pos + 1)
                if pos == -1:
                    break
                if pos % get_pagesize() != 0:
                    continue

                # calc address of ELF header
                if is_32bit():
                    vdso_addr_byteseq = p32(kinfo.ro_base + pos)
                else:
                    vdso_addr_byteseq = p64(kinfo.ro_base + pos)

                # search for it from .rodata again
                pos2 = -1
                while True:
                    pos2 = ro_data.find(vdso_addr_byteseq, pos2 + 1)
                    if pos2 == -1:
                        break
                    if pos2 % runtime.current_arch.ptrsize != 0:
                        continue
                    maybe_vdso_lookup = kinfo.ro_base + pos2
                    maybe_vdso_lookup -= runtime.current_arch.ptrsize
                    name = read_int_from_memory(maybe_vdso_lookup)
                    if not is_valid_addr(name):
                        continue
                    if read_cstring_from_memory(name) == "vdso":
                        return maybe_vdso_lookup
        return None

    @staticmethod
    def get_vdso_start():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_arm32() and not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("vdso_start")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (from vdso_info or vdso_lookup)
        if kversion and is_arm64():
            if "5.8" <= kversion:
                vdso_info = KernelAddressHeuristicFinder.get_vdso_info()
            else:
                vdso_info = KernelAddressHeuristicFinder.get_vdso_lookup()
            if vdso_info and is_valid_addr(vdso_info):
                vdso_name = read_int_from_memory(vdso_info)
                if is_valid_addr(vdso_name):
                    if "vdso" == read_cstring_from_memory(vdso_name):
                        x = read_int_from_memory(vdso_info + runtime.current_arch.ptrsize)
                        return x

        # plan 3 (from .rodata)
        kinfo = Kernel.get_kernel_layout()
        if kinfo.ro_base and kinfo.ro_size:
            ro_data = read_memory(kinfo.ro_base, kinfo.ro_size)
            pos = -1
            while True:
                # search for aligned ELF header from .rodata
                pos = ro_data.find(b"\x7fELF", pos + 1)
                if pos == -1:
                    break
                if pos % get_pagesize() == 0:
                    return kinfo.ro_base + pos
        return None

    @staticmethod
    def get_vdso32_start():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("vdso32_start")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (from vdso_info or vdso_lookup)
        if kversion:
            if "5.8" <= kversion:
                vdso_info = KernelAddressHeuristicFinder.get_vdso_info()
            else:
                vdso_info = KernelAddressHeuristicFinder.get_vdso_lookup()
            if vdso_info:
                vdso_info_2 = vdso_info + runtime.current_arch.ptrsize * 6
                if vdso_info_2 and is_valid_addr(vdso_info_2):
                    vdso_name = read_int_from_memory(vdso_info_2)
                    if is_valid_addr(vdso_name):
                        if "vdso32" == read_cstring_from_memory(vdso_name):
                            x = read_int_from_memory(vdso_info_2 + runtime.current_arch.ptrsize)
                            return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_file_systems():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("file_systems")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.5.7 or later)
        if kversion and "2.5.7" <= kversion:
            addr = Symbol.get_ksymaddr("unregister_filesystem")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res, read_valid=True)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res, read_valid=True)
                elif is_arm64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, read_valid=True),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res, read_valid=True),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, read_valid=True),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res, read_valid=True),
                    )
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_printk_rb_static():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("printk_rb_static")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v5.13 or later)
        if kversion and "5.13" <= kversion:
            addr = Symbol.get_ksymaddr("kmsg_dump_rewind")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res, read_valid=True)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res, read_valid=True)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, read_valid=True)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res, read_valid=True)
                for x in g:
                    return read_int_from_memory(x)

        # plan 3 (available v5.10 or later)
        if kversion and "5.10" <= kversion:
            addr = Symbol.get_ksymaddr("kmsg_dump_rewind_nolock")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res, read_valid=True)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res, read_valid=True)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, read_valid=True)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res, read_valid=True)
                for x in g:
                    return read_int_from_memory(x)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_log_first_idx():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("log_first_idx")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # this is old dmesg structure
        if kversion and "5.10" <= kversion:
            return False

        # plan 2 (available v3.5 or later)
        if kversion and "3.5" <= kversion:
            addr = Symbol.get_ksymaddr("devkmsg_open")
            if addr:
                res = gdb.execute("x/50i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_mov_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                    )
                for x in g:
                    v = read_int32_from_memory(x)
                    if is_valid_addr(v):
                        continue
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_log_next_idx():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("log_next_idx")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # this is old dmesg structure
        if kversion and "5.10" <= kversion:
            return False

        # plan 2 (available v3.5 or later)
        if kversion and "3.5" <= kversion:
            addr = Symbol.get_ksymaddr("kmsg_dump_rewind_nolock")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res, skip=1)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res)
                    g = list(g)[::-1]
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res, skip=1)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res, skip=1),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res, skip=1),
                    )
                for x in g:
                    v = read_int32_from_memory(x)
                    if v == 0:
                        continue
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get___log_buf():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("__log_buf")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # this is old dmesg structure
        if kversion and "5.10" <= kversion:
            return False

        # plan 2 (available v3.5 or later)
        if kversion and "3.5" <= kversion:
            log_buf_len = KernelAddressHeuristicFinder.get_log_buf_len()
            if log_buf_len:
                # static char *log_buf = __log_buf;
                # static u32 log_buf_len = __LOG_BUF_LEN;
                if is_32bit():
                    # pattern1 (x86): log_buf_len -> log_buf
                    # 0xc1ba30b8|+0x0000|+000: 0x00040000
                    # 0xc1ba30bc|+0x0004|+001: 0xc1cf7720  ->  0x00000000
                    # pattern2 (ARM): log_buf -> log_buf_len
                    # 0xc03d26dc|+0x0000|+000: 0xc03ec9f8  ->  0x00000000
                    # 0xc03d26e0|+0x0004|+001: 0x00004000
                    pattern = [4, -4]
                elif is_64bit():
                    # pattern1 (x64): log_buf_len -> log_buf
                    # 0xffffffffaa240720|+0x0000|+000: 0x0000000000020000
                    # 0xffffffffaa240728|+0x0008|+001: 0xffffffffaa2f87dc  ->  0x0000000000000000
                    # pattern1 (ARM64): log_buf_len -> log_buf
                    # 0xffff000011256c68|+0x0000|+000: 0x0000000000020000
                    # 0xffff000011256c70|+0x0008|+001: 0xffff0000113f5350 <__log_buf>  ->  0x0000000000000000
                    # pattern2 (x64): log_buf_len -> log_buf (no-padding)
                    # 0xffffffffa5c476cc|+0x0000|+000: 0xa62e9cf400040000
                    # 0xffffffffa5c476d4|+0x0008|+001: 0x00000000ffffffff (=0xffffffffa62e9cf4)
                    # pattern3 (x64): log_buf -> log_buf_len
                    # 0xffffffff81c1df48|+0x0008|+001: 0xffffffff81d98e20  ->  0x0000000000000000
                    # 0xffffffff81c1df50|+0x0010|+002: 0xffffffff00040000 (=0x00040000)
                    pattern = [8, 4, -8]
                for diff in pattern:
                    log_buf = log_buf_len + diff
                    __log_buf = read_int_from_memory(log_buf)
                    if is_valid_addr(__log_buf):
                        return __log_buf
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_log_buf_len():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("log_buf_len")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # this is old dmesg structure
        if kversion and "5.10" <= kversion:
            return False

        # plan 2 (available v3.17 or later)
        if kversion and "3.17" <= kversion:
            addr = Symbol.get_ksymaddr("log_buf_len_get")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                    )
                for x in g:
                    v = read_int32_from_memory(x)
                    if v and (v & 0xfff) == 0:
                        return x

        # plan 3 (available v3.5 or later)
        if kversion and "3.5" <= kversion:
            addr = Symbol.get_ksymaddr("do_syslog")
            if addr:
                res = gdb.execute("x/300i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    # TODO
                    g = []
                elif is_arm32():
                    # TODO
                    g = []
                for x in g:
                    v = read_int32_from_memory(x)
                    if v and (v & 0xfff) == 0:
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_idt_base():
        if is_x86():
            if is_qemu_system():
                res = gdb.execute("monitor info registers", to_string=True)
                idtr = re.search(r"IDT\s*=\s*(\w+) (\w+)", res)
                base, _limit = [int(idtr.group(i), 16) for i in range(1, 3)]
                return base
            elif is_vmware():
                res = gdb.execute("monitor r idtr", to_string=True)
                r = re.search(r"idtr base=(\w+) limit=(\w+)", res)
                base = int(r.group(1), 16)
                return base
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_gdt_base():
        if is_x86():
            if is_qemu_system():
                res = gdb.execute("monitor info registers", to_string=True)
                gdtr = re.search(r"GDT\s*=\s*(\w+) (\w+)", res)
                base, _limit = [int(gdtr.group(i), 16) for i in range(1, 3)]
                return base
            elif is_vmware():
                res = gdb.execute("monitor r gdtr", to_string=True)
                r = re.search(r"gdtr base=(\w+) limit=(\w+)", res)
                base = int(r.group(1), 16)
                return base
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_tss_base():
        if is_x86():
            if is_qemu_system():
                res = gdb.execute("monitor info registers", to_string=True)
                tr = re.search(r"TR\s*=\s*(\w+) (\w+) (\w+) (\w+)", res)
                _trseg, base, _limit, _attr = [int(tr.group(i), 16) for i in range(1, 5)]
                return base
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_ldt_base():
        if is_x86():
            if is_qemu_system():
                res = gdb.execute("monitor info registers", to_string=True)
                ldtr = re.search(r"LDT\s*=\s*(\w+) (\w+) (\w+) (\w+)", res)
                _seg, base, _limit, _attr = [int(ldtr.group(i), 16) for i in range(1, 5)]
                return base
            elif is_vmware():
                # `monitor r ldtr` is buggy
                return None
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_node_data():
        # when CONFIG_NUMA=y (maybe)

        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("node_data")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.6.17 or later)
        if kversion and "2.6.17" <= kversion:
            addr = Symbol.get_ksymaddr("first_online_pgdat")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res),
                        KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res),
                    )
                elif is_x86_32():
                    # TODO
                    g = []
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    # TODO
                    g = []
                for x in g:
                    """
                    node_data[]: 0xffffdfab1c1be0b8

                    gef> telescope 0xffffdfab1c1be0b8
                    0xffffdfab1c1be0b8|+0x0000|+000: 0xffff00007fbf09c0  ->  0x0000000000001600
                    0xffffdfab1c1be0c0|+0x0008|+001: 0x0000000000000000
                    0xffffdfab1c1be0c8|+0x0010|+002: 0x0000000000000000

                    gef> telescope 0xffff00007fbf09c0
                    0xffff00007fbf09c0|+0x0000|+000: 0x0000000000001600
                    0xffff00007fbf09c8|+0x0008|+001: 0x0000000000001b80
                    0xffff00007fbf09d0|+0x0010|+002: 0x0000000000002100
                    0xffff00007fbf09d8|+0x0018|+003: 0x0000000000002680
                    0xffff00007fbf09e0|+0x0020|+004: 0x0000000000000000
                    0xffff00007fbf09e8|+0x0028|+005: 0x0000000000000000
                    0xffff00007fbf09f0|+0x0030|+006: 0x0000000000000000
                    0xffff00007fbf09f8|+0x0038|+007: 0x0000000000000000
                    0xffff00007fbf0a00|+0x0040|+008: 0x0000000000000000
                    0xffff00007fbf0a08|+0x0048|+009: 0x0000000000000000
                    0xffff00007fbf0a10|+0x0050|+010: 0x0000000000000000
                    0xffff00007fbf0a18|+0x0058|+011: 0xffff00007fbf09c0  ->  0x0000000000001600
                    0xffff00007fbf0a20|+0x0060|+012: 0xffffdfab1ba8a540
                    0xffff00007fbf0a28|+0x0068|+013: 0xffffdfab1ba8a4e0
                    0xffff00007fbf0a30|+0x0070|+014: 0x0000003f000006e0
                    0xffff00007fbf0a38|+0x0078|+015: 0x0000000000040000
                    0xffff00007fbf0a40|+0x0080|+016: 0x0000000000077153
                    0xffff00007fbf0a48|+0x0088|+017: 0x0000000000080000
                    0xffff00007fbf0a50|+0x0090|+018: 0x0000000000080000
                    0xffff00007fbf0a58|+0x0098|+019: 0x0000000000080000
                    0xffff00007fbf0a60|+0x00a0|+020: 0x0000000000002000
                    0xffff00007fbf0a68|+0x00a8|+021: 0xffffdfab1b792690  ->  0x0000000000414d44 ('DMA'?)
                    """
                    v = read_int_from_memory(x)
                    if not v or not is_valid_addr(v):
                        continue
                    # avoid false positive
                    if is_double_link_list(x):
                        continue
                    # avoid false positive
                    water_mark0 = read_int_from_memory(v)
                    if water_mark0 > 0x0000_1000_0000_0000:
                        continue
                    # ok
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_node_data0():
        # when CONFIG_NUMA=n
        # This method can only be called when `get_node_data()` fails.

        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        kversion = Kernel.kernel_version()

        # plan 1 (available v2.6.17 or later)
        if kversion and "2.6.17" <= kversion:
            addr = Symbol.get_ksymaddr("first_online_pgdat")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rax")
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "eax")
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res)
                    )
                for x in g:
                    v = read_int_from_memory(x)
                    if v and is_valid_addr(v):
                        continue
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_prog_idr():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("prog_idr")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.13 or later)
        # In certain cases it may return `prog_idr_lock` instead of `prog_idr`.
        # It was not possible to distinguish them because their structures are very similar.
        # However, `prog_idr` and `prog_idr_lock` are placed consecutively.
        # Even if there is a slight deviation, there is no problem because the member
        # identification logic of the caller (`kbpf` command) works.
        if kversion and "4.13" <= kversion:
            addr = Symbol.get_ksymaddr("bpf_prog_free_id.part.0") or Symbol.get_ksymaddr("bpf_prog_free_id")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_map_idr():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("map_idr")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.13 or later)
        # In certain cases it may return `map_idr_lock` instead of `map_idr`.
        # It was not possible to distinguish them because their structures are very similar.
        # However, `map_idr` and `map_idr_lock` are placed consecutively.
        # Even if there is a slight deviation, there is no problem because the member
        # identification logic of the caller (`kbpf` command) works.
        if kversion and "4.13" <= kversion:
            addr = Symbol.get_ksymaddr("bpf_map_free_id")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_vmap_area_list():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("vmap_area_list")
            if x:
                return x

        kversion = Kernel.kernel_version()
        if "6.9" <= kversion:
            return None

        # plan 2 (available v4.7~)
        if kversion and "4.7" <= kversion:
            addr = Symbol.get_ksymaddr("register_vmap_purge_notifier")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                    """
                    x86 or x64

                    [~v5.1] mm/vmalloc.c
                    vmap_notify_list     # rarely leads to long lists
                    vmap_area_list       <- here

                    [v5.2~v6.8] mm/vmalloc.c
                    vmap_notify_list     # rarely leads to long lists
                    free_vmap_area_list  <- here (false positive)
                    vmap_area_list       <- here
                    """
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                    """
                    arm32 or arm64

                    [~v6.8] mm/vmalloc.c
                    vmap_notify_list     # rarely leads to long lists
                    vmap_area_list       <- here
                    free_vmap_area_list
                    """
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    if is_x86():
                        if kversion < "5.2":
                            count = 1
                        else:
                            count = 2
                    else:
                        count = 1
                    for i in range(16):
                        a = x + runtime.current_arch.ptrsize * i
                        if is_double_link_list(a, min_len=5):
                            count -= 1
                        if count == 0:
                            return a

        # plan 3 (available v3.10 ~ v6.3: vread, v6.4~: vread_iter)
        if kversion and "3.17" <= kversion:
            addr = Symbol.get_ksymaddr("vread") or Symbol.get_ksymaddr("vread_iter")
            if addr:
                res = gdb.execute("x/100i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res, read_valid=True)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res, read_valid=True)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    if is_double_link_list(x):
                        return x

        # plan 4 (available v4.10~)
        if kversion and "4.10" <= kversion:
            addrs = Symbol.get_ksymaddr_multiple("s_next")
            if addrs:
                for s_next in addrs:
                    res = gdb.execute("x/20i {:#x}".format(s_next), to_string=True)
                    if is_x86_64():
                        g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rsi")
                    elif is_x86_32():
                        g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "e.x")
                    elif is_arm64():
                        g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res, read_valid=True)
                    elif is_arm32():
                        g = KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res)
                    for x in g:
                        if is_double_link_list(x):
                            return x

        # plan 5 (available v2.6.28 ~ v5.1)
        if kversion and "2.6.28" <= kversion < "5.2":
            addr = Symbol.get_ksymaddr("__insert_vmap_area")
            if addr:
                res = gdb.execute("x/100i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res, read_valid=True)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res, read_valid=True)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    if is_double_link_list(x):
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_free_vmap_area_list():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("free_vmap_area_list")
            if x:
                return x

        kversion = Kernel.kernel_version()
        if kversion < "5.2":
            return None

        # plan 2 (available v4.7~; here, always True)
        addr = Symbol.get_ksymaddr("register_vmap_purge_notifier")
        if addr:
            res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                """
                x86 or x64

                [v5.2~v6.8] mm/vmalloc.c
                vmap_notify_list     # rarely leads to long lists
                free_vmap_area_list  <- here
                vmap_area_list

                [v6.9~] mm/vmalloc.c
                vmap_notify_list     # rarely leads to long lists
                free_vmap_area_list  <- here
                """
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
            elif is_arm64():
                g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                """
                arm32 or arm64

                [v5.2~v6.8] mm/vmalloc.c
                vmap_notify_list     # rarely leads to long lists
                vmap_area_list       <- here (false positive)
                free_vmap_area_list  <- here

                [v6.9~] mm/vmalloc.c
                vmap_notify_list     # rarely leads to long lists
                free_vmap_area_list  <- here
                """
            elif is_arm32():
                g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
            for x in g:
                if is_arm32() or is_arm64():
                    if kversion < "6.9":
                        count = 2
                    else:
                        count = 1
                else:
                    count = 1
                for i in range(16):
                    a = x + runtime.current_arch.ptrsize * i
                    if is_double_link_list(a, min_len=3):
                        count -= 1
                    if count == 0:
                        return a
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_timer_bases():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("timer_bases")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.8 or later)
        if kversion and "4.8" <= kversion:
            addr = Symbol.get_ksymaddr("run_timer_softirq")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res, skip_msb_check=True),
                    )
                    g2 = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True)
                    g2 = KernelAddressHeuristicFinderUtil.x64_x86_dword_ptr_src(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, skip_msb_check=True)
                    g2 = []
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, skip_msb_check=True)
                    g2 = []

                __per_cpu_offset = KernelAddressHeuristicFinder.get_per_cpu_offset()
                if __per_cpu_offset:
                    # pattern1: per_cpu
                    # pattern1-a:
                    # 0xffffffff8cf25b05 <run_timer_softirq+5>:  mov rdi,0x24b40 <-- timer_bases
                    # pattern1-b:
                    # 0xffffffffa440831e <run_timer_softirq+46>: lea rbx,[rax+0x22400]
                    for x in g:
                        if not is_valid_addr(x) and (x & 0x7) == 0:
                            return x
                else:
                    # pattern2: not per_cpu
                    # 0xffffffff8aa6e450 <run_timer_softirq>:    mov rax,QWORD PTR [rip+0x7cfba9] # 0xffffffff8b23e000 <jiffies_64>
                    # 0xffffffff8aa6e457 <run_timer_softirq+7>:  cmp rax,QWORD PTR [rip+0x7ce92a] # 0xffffffff8b23cd88 <timer_bases+8>
                    # 0xffffffff8aa6e474 <run_timer_softirq+36>: mov rdx,QWORD PTR [rip+0x7cfb85] # 0xffffffff8b23e000 <jiffies_64>
                    # 0xffffffff8aa6e47b <run_timer_softirq+43>: mov rax,QWORD PTR [rip+0x7ce906] # 0xffffffff8b23cd88 <timer_bases+8>
                    jiffies = KernelAddressHeuristicFinder.get_jiffies()
                    addrs = [x for x in g2 if (is_valid_addr(x) and (not jiffies or jiffies != x))]
                    if addrs:
                        return min(addrs)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_hrtimer_bases():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("hrtimer_bases")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v4.8 or later)
        if kversion and "4.8" <= kversion:
            addr = Symbol.get_ksymaddr("hrtimer_run_queues")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_x86_byte_ptr(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res, skip_msb_check=True),
                    )
                    g2 = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True)
                    g2 = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, skip_msb_check=True)
                    g2 = []
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, skip_msb_check=True)
                    g2 = []

                __per_cpu_offset = KernelAddressHeuristicFinder.get_per_cpu_offset()
                if __per_cpu_offset:
                    # pattern1: per_cpu
                    # pattern1-a:
                    # 0xffffffff9b127acb: mov rbx,0x27040 <-- hrtimer_bases
                    # pattern1-b:
                    # 0xffffffffa440b87d <hrtimer_run_queues+13>: test BYTE PTR [rax+0x25b90],0x1
                    # The exact value is 0x25b80, but don't worry about a slight deviation.
                    # pattern1-c:
                    # 0xffffffff818f57b5 <hrtimer_run_queues+21>: lea rbx,[rax+0x1df00]
                    for x in g:
                        if not is_valid_addr(x) and (x & 0x7) == 0:
                            return x
                else:
                    # pattern2: not per_cpu
                    # 0xffffffffbb8668bc <hrtimer_run_queues+12>: mov rdx,0xffffffffbc046138
                    # 0xffffffffbb8668c3 <hrtimer_run_queues+19>: mov rcx,0xffffffffbc046178
                    # 0xffffffffbb8668ca <hrtimer_run_queues+26>: mov rsi,0xffffffffbc0460f8
                    # 0xffffffffbb8668d1 <hrtimer_run_queues+33>: mov rdi,0xffffffffbc046048 <-- hrtimer_bases+8
                    addrs = [x for x in g2 if is_valid_addr(x)]
                    if addrs:
                        return min(addrs)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_jiffies():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("jiffies")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.6.18 or later)
        if kversion and "2.6.18" <= kversion:
            addr = Symbol.get_ksymaddr("jiffies_read")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_pci_root_buses():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("pci_root_buses")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v2.5.71 or later)
        if kversion and "2.5.71" <= kversion:
            addr = Symbol.get_ksymaddr("pci_find_next_bus")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, read_valid=True)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, read_valid=True)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_ioport_resource():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("ioport_resource")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v3.3 or later)
        if kversion and "3.3" <= kversion:
            addr = Symbol.get_ksymaddr("pci_scan_bus")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, r"r\w+")
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, r"e\w+")
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    name_ptr = read_int_from_memory(x + 0x8 * 2) # sizeof(resource_size_t) == 8
                    if name_ptr and is_valid_addr(name_ptr):
                        name = read_cstring_from_memory(name_ptr)
                        if name == "PCI IO":
                            return x
                    name_ptr = read_int_from_memory(x + 0x4 * 2) # sizeof(resource_size_t) == 4
                    if name_ptr and is_valid_addr(name_ptr):
                        name = read_cstring_from_memory(name_ptr)
                        if name == "PCI IO":
                            return x

        # plan 3 (from .rodata)
        kinfo = Kernel.get_kernel_layout()
        if kinfo.ro_base and kinfo.ro_size and is_valid_addr(kinfo.ro_base):
            ro_data = read_memory(kinfo.ro_base, kinfo.ro_size)
            if kinfo.rw_base and kinfo.rw_size:
                rw_data = read_memory(kinfo.rw_base, min(kinfo.rw_size, 0x1000000))
            else:
                rw_data = ro_data
            pos = -1
            while True:
                # search for aligned string from .rodata
                pos = ro_data.find(b"PCI IO\x00", pos + 1)
                if pos == -1:
                    break

                # calc address of ELF header
                if is_32bit():
                    addr_byteseq = p32(kinfo.ro_base + pos)
                else:
                    addr_byteseq = p64(kinfo.ro_base + pos)

                # search for it from .data
                pos2 = -1
                while True:
                    pos2 = rw_data.find(addr_byteseq, pos2 + 1)
                    if pos2 == -1:
                        break
                    if pos2 % runtime.current_arch.ptrsize != 0:
                        continue
                    # TODO: How to find the exact value of sizeof(resource_size_t)
                    if kinfo.rw_base and kinfo.rw_size:
                        maybe_ioport_resource = kinfo.rw_base + pos2 - runtime.current_arch.ptrsize * 2
                    else:
                        maybe_ioport_resource = kinfo.ro_base + pos2 - runtime.current_arch.ptrsize * 2
                    return maybe_ioport_resource
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_iomem_resource():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("iomem_resource")
            if x:
                return x

        # plan 2 (from ioport_resource)
        x = KernelAddressHeuristicFinder.get_ioport_resource()
        if x:
            # offsetof(resource, name)
            offset_name = None
            name_ptr = read_int_from_memory(x + 0x8 * 2) # sizeof(resource_size_t) == 8
            if name_ptr and is_valid_addr(name_ptr):
                name = read_cstring_from_memory(name_ptr)
                if name == "PCI IO":
                    offset_name = 0x8 * 2
            if offset_name is None:
                name_ptr = read_int_from_memory(x + 0x4 * 2) # sizeof(resource_size_t) == 4
                if name_ptr and is_valid_addr(name_ptr):
                    name = read_cstring_from_memory(name_ptr)
                    if name == "PCI IO":
                        offset_name = 0x4 * 2

            # find "PCI mem"
            if offset_name is not None:
                for i in range(-30, 30):
                    diff = (runtime.current_arch.ptrsize * i)
                    name_ptr = read_int_from_memory(x + diff)
                    if name_ptr and is_valid_addr(name_ptr):
                        name = read_cstring_from_memory(name_ptr)
                        if name == "PCI mem":
                            return x + diff - offset_name
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_db_list():
        # need DMA_SHARED_BUFFER=y

        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("db_list")
            if x:
                return x

        kversion = Kernel.kernel_version()
        if kversion and "6.10" <= kversion:
            return None

        # plan 2 (available v5.10 ~ v6.9)
        if kversion and "5.10" <= kversion < "6.10":
            addr = Symbol.get_ksymaddr("dma_buf_file_release")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    # here, x points &db_list.lock
                    v = x - runtime.current_arch.ptrsize * 2
                    if is_double_link_list(v):
                        return v

        # plan 3 (available v3.17 ~ v5.9)
        if kversion and "3.17" <= kversion < "5.10":
            addr = Symbol.get_ksymaddr("dma_buf_release")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    # here, x points &db_list.lock
                    v = x - runtime.current_arch.ptrsize * 2
                    if is_double_link_list(v):
                        return v
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_debugfs_list():
        # need DMA_SHARED_BUFFER=y

        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        from gef.commands.tls_command import TlsCommand
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("debugfs_list")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v6.10 ~ v6.15)
        if kversion and "6.10" <= kversion < "6.16":
            addr = Symbol.get_ksymaddr("dma_buf_file_release")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                direction = TlsCommand.get_direction()
                # x64/x86:
                #   debugfs_list
                #   debugfs_list_mutex
                # arm64/arm32:
                #   debugfs_list_mutex
                #   debugfs_list
                for x in g:
                    if is_x86():
                        count = 1
                    else:
                        count = 2
                    for i in range(2, 30):
                        v = x + runtime.current_arch.ptrsize * direction * i
                        # here, x points &debugfs_list_mutex
                        if is_double_link_list(v):
                            count -= 1
                            if count == 0:
                                return v
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_dmabuf_list():
        # need DMA_SHARED_BUFFER=y

        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        from gef.commands.tls_command import TlsCommand
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("dmabuf_list")
            if x:
                return x

        kversion = Kernel.kernel_version()

        # plan 2 (available v6.16 or later)
        if kversion and "6.16" <= kversion:
            addr = Symbol.get_ksymaddr("dma_buf_file_release")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                direction = TlsCommand.get_direction()
                # x64/x86:
                #   debugfs_list
                #   debugfs_list_mutex
                # arm64/arm32:
                #   debugfs_list_mutex
                #   debugfs_list
                for x in g:
                    if is_x86():
                        count = 1
                    else:
                        count = 2
                    for i in range(2, 30):
                        v = x + runtime.current_arch.ptrsize * direction * i
                        # here, x points &debugfs_list_mutex
                        if is_double_link_list(v):
                            count -= 1
                            if count == 0:
                                return v
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_irq_desc_tree():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("irq_desc_tree")
            if x:
                return x

        kversion = Kernel.kernel_version()

        if kversion and "6.5" <= kversion:
            return False

        # plan 2 (available v2.6.37 ~ v6.4)
        if kversion and "2.6.37" <= kversion < "6.5":
            addr = Symbol.get_ksymaddr("irq_to_desc")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sparse_irqs():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("sparse_irqs")
            if x:
                return x

        kversion = Kernel.kernel_version()

        if kversion and kversion < "6.5":
            return False

        # plan 2 (available v6.5 or later)
        if kversion and "6.5" <= kversion:
            addr = Symbol.get_ksymaddr("irq_to_desc")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_slub_tlbflush_queue():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("slub_tlbflush_queue")
            if x:
                return x

        # plan 2 (from slub_tlbflush_worker)
        addr = Symbol.get_ksymaddr("slub_tlbflush_worker")
        if addr:
            res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
            elif is_x86_32():
                # TODO
                g = []
            elif is_arm64():
                # TODO
                g = []
            elif is_arm32():
                # TODO
                g = []

            for x in g:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_slub_addr_base():
        # plan 1 (directly)
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Symbol.get_ksymaddr("slub_addr_base")
            if x:
                return x

        kversion = Kernel.kernel_version()
        if not kversion:
            return None

        if kversion < "6.6":
            # plan 2 (available in 6.1-based from `alloc_slab_pv_page`)
            # bruteforces all accesses into global variables in `alloc_slab_pv_page`
            # In source, `slub_addr_base` is referenced only by `alloc_slab_meta`, but
            # compiler seems to inline this function (because calls once, maybe)
            addr = Symbol.get_ksymaddr("alloc_slab_pv_page")
            if addr:
                res = gdb.execute("x/200i {:#x}".format(addr), to_string=True)
                r"""
                gef> |x/200i alloc_slab_pv_page| grep -i 'qword ptr \[rip\+.*\]'
                0xffffffff8901e65a <alloc_slab_pv_page+394>: mov    rsi,QWORD PTR [rip+0x162c627]
                0xffffffff8901e672 <alloc_slab_pv_page+418>: sub    rax,QWORD PTR [rip+0x12ec317]
                0xffffffff8901e6a8 <alloc_slab_pv_page+472>: and    rcx,QWORD PTR [rip+0x162c5e1]
                0xffffffff8901e758 <alloc_slab_pv_page+648>: mov    rax,QWORD PTR [rip+0x15432c1] <- this
                gef>
                """
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    # TODO
                    g = []
                elif is_arm64():
                    # TODO
                    g = []
                elif is_arm32():
                    # TODO
                    g = []

                for x in g:
                    v = read_int_from_memory(x)
                    if v in [0xffff_ffff_ffff_ffff, 0xffff_ffff_ffff_feff, 1]:
                        continue
                    # the value of `slub_addr_base` is unmapped address.
                    if not is_valid_addr(v):
                        return x
        else:
            # plan 3 (available in 6.6-based from vaddr_ranges_debug_start)
            addr = Symbol.get_ksymaddr("vaddr_ranges_debug_start")
            if addr:
                res = gdb.execute("x/8i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    # TODO
                    g = []
                elif is_arm64():
                    # TODO
                    g = []
                elif is_arm32():
                    # TODO
                    g = []

                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_slub_addr_current():
        from gef.core.kernel import Kernel, KernelConstsArm32, KernelConstsArm64, KernelConstsX64, KernelConstsX86
        if Kernel.kernel_version() < "6.6":
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            addr = Symbol.get_ksymaddr("slub_addr_current")
            if addr:
                return

        # plan 2 (from vaddr_ranges_first_valid_slab)
        addr = Symbol.get_ksymaddr("vaddr_ranges_first_valid_slab")
        if addr:
            res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
            elif is_x86_32():
                # TODO
                g = []
            elif is_arm64():
                # TODO
                g = []
            elif is_arm32():
                # TODO
                g = []

            for x in g:
                return x
        return None


KF = KernelAddressHeuristicFinder # for convenience using from python-interactive # noqa: F841
KFU = KernelAddressHeuristicFinderUtil # for convenience using from python-interactive # noqa: F841


