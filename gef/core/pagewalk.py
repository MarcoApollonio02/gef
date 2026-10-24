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
import functools
import gdb
import itertools
import re
import sys

from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, warn
from gef.core.memory import (is_valid_addr, is_valid_addr_addr, p32, p64, read_cstring_from_memory,
                             read_int32_from_memory, read_int_from_memory, read_memory, u32)
from gef.core.process import (get_pagesize, is_32bit, is_64bit, is_arm32, is_arm64, is_kgdb, is_qemu_system,
                              is_riscv32, is_riscv64, is_vmware, is_x86, is_x86_32, is_x86_64)
from gef.core.registers import get_register
from gef.core.qemu import QemuMonitor
from gef.core.symbols import Symbol
from gef.core.utils import (GefUtil, align, align_to_ptrsize, is_double_link_list, is_single_link_list,
                            slice_unpack, switch_to_intel_syntax, u2i)


class _LateKernelModule:
    """Proxy for the kernel model layer, imported on first attribute access.

    `gef.core.kernel` imports this module, so importing it here at module scope
    would be circular. The ported finder bodies stay verbatim and reach
    `Kernel`/`Ksym`/`AddrMap`/`KernelPerCpu` through this proxy instead.
    """

    def __init__(self, name):
        self._name = name

    def __getattr__(self, item):
        import importlib
        module = importlib.import_module("gef.core.kernel")
        return getattr(getattr(module, self._name), item)


Kernel = _LateKernelModule("Kernel")
Ksym = _LateKernelModule("Ksym")
AddrMap = _LateKernelModule("AddrMap")
KernelPerCpu = _LateKernelModule("KernelPerCpu")
KernelTask = _LateKernelModule("KernelTask")
KernelNamespace = _LateKernelModule("KernelNamespace")
KernelXArray = _LateKernelModule("KernelXArray")


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
        from gef.commands.kernel.trustzone import XSecureMemAddrCommand
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
    def is_kernel_space(v):
        if AddressUtil.is_msb_on(v):
            return True
        # VMSPLIT_1G and VMSPLIT_2G_OPT place the kernel space below the MSB
        if not is_32bit():
            return False
        constants = KernelAddressHeuristicFinder.consts()
        if constants:
            task_size = constants.TASK_SIZE
        else:
            task_size = None
        return task_size is not None and task_size <= v

    @staticmethod
    def common_addr_gen(res, regexp, skip, skip_msb_check, read_valid):
        for line in res.splitlines():
            m = re.search(regexp, line)
            if not m:
                continue
            v = AddressUtil.normalize_address(int(m.group(1), 16))
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(v):
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
    def x64_x86_add_reg_const(res, reg=r"\w+", skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"add\s+" + reg + r"\s*,\s*(0x\w+)"
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
    def x64_x86_dword_ptr_src(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r",\s*DWORD PTR \[.*([+-]0x\w+)\]"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_x86_byte_ptr(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"BYTE PTR \[.*([+-]0x\w+)\]"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x86_ds_absolute(res, skip=0, skip_msb_check=False, read_valid=False):
        # x86_32 uses absolute addressing for globals. (e.g., `test BYTE PTR ds:0xc2c0cbec,0x1`)
        regexp = r"\bds:(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_dword_ptr_rip_base(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"DWORD PTR \[rip\+0x\w+\].*#\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_byte_ptr_rip_base(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"BYTE PTR \[rip\+0x\w+\].*#\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_qword_ptr_rip_base(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"QWORD PTR \[rip\+0x\w+\].*#\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_qword_ref(res, skip=0, skip_msb_check=False, read_valid=False):
        # A word-sized global, either accessed rip-relative or passed by address (e.g., to memcpy).
        # An int (`DWORD PTR`) is skipped. (e.g., `mov QWORD PTR [rip+0x...],rax  # 0x...`, `mov rdi,0x...`)
        regexp = r"(?:(?:QWORD|XMMWORD|YMMWORD) PTR \[rip\+0x\w+\].*#\s*|\bmov\s+\w+\s*,\s*)(0x\w{8,})\b"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_any_ptr_rip_base(res, skip=0, skip_msb_check=False, read_valid=False):
        # Use this when the C type of the global changes between versions. (e.g., `bool` -> `int`)
        regexp = r"(?:BYTE|WORD|DWORD|QWORD) PTR \[rip\+0x\w+\].*#\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_qword_ptr_rip_base_store(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"QWORD PTR \[rip\+0x\w+\],[^#]*#\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_qword_ptr_disp_load(res, skip=0, skip_msb_check=False, read_valid=False):
        # The load side of `x64_qword_ptr_disp_store`.
        # (e.g., `mov rsi,QWORD PTR [rax-0x7df3ef38]` where rax is an array index already scaled)
        regexp = r",\s*QWORD PTR \[(?!rip)\w+([-+]0x\w{8,})\]"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x64_qword_ptr_disp_store(res, skip=0, skip_msb_check=False, read_valid=False):
        # Use this when the symbol is folded into the displacement of a store.
        # (e.g., `mov QWORD PTR [rax-0x63ea2fe0],r14` where rax is a per-cpu base)
        # The 8 digits keep the stack slots (`[rbp-0x20]`) out, and rip-relative belongs to
        # `x64_qword_ptr_rip_base_store` because there the displacement is not the address.
        regexp = r"QWORD PTR \[(?!rip)\w+([-+]0x\w{8,})\]\s*,"
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
    def x64_lea_array_base(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"lea\s+\w+\s*,\s*\[.*\*8([-+]0x\w+)\]"
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
        regexp = r"(?:DWORD PTR |mov\s+eax,\s*)fs:\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x86_noptr_ds(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"ds:\s*(0x\w+)"
        return KernelAddressHeuristicFinderUtil.common_addr_gen(res, regexp, skip, skip_msb_check, read_valid)

    @staticmethod
    def x86_noptr_ds_store(res, skip=0, skip_msb_check=False, read_valid=False):
        regexp = r"ds:\s*(0x\w+)\s*,"
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
    def drop_clobbered_regs(line, *regmaps):
        """Forget the bases whose register the instruction in `line` overwrites."""
        m = re.search(r":\s*(\S+)\s+(\w+)", line)
        if not m:
            return
        mnemonic, dst = m.group(1), m.group(2)
        if mnemonic in ("bl", "blr", "blx"):
            regs = ["x{:d}".format(i) for i in range(19)] + ["r0", "r1", "r2", "r3", "r12", "ip"] # caller-saved
        elif mnemonic.startswith(("ld", "mov", "mrs")):
            regs = [re.sub(r"^w", "x", dst)] # the bases are keyed by the `x` name
        else:
            return
        for reg in regs:
            for regmap in regmaps:
                regmap.pop(reg, None)
        return

    @staticmethod
    def aarch64_adrp_ldr(res, skip=0, skip_msb_check=False, read_valid=False, allow_add=False):
        bases = {}
        for line in res.splitlines():
            m = re.search(r"adrp\s+(\w+),\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16)
                bases[reg] = v
                continue
            if allow_add:
                # A displacement too large for the ldr is folded into an add first. Unlike
                # `aarch64_adrp_add_ldr` this keeps the candidates in instruction order, which
                # matters when the same function also has a plain adrp + ldr.
                m = re.search(r"add\s+(\w+),\s*(\w+),\s*#(0x\w+)", line)
                if m:
                    dstreg = m.group(1)
                    srcreg = m.group(2)
                    v = int(m.group(3), 16)
                    if srcreg in bases:
                        bases[dstreg] = bases[srcreg] + v
                    else:
                        bases.pop(dstreg, None)
                    continue
            w = None
            m = re.search(r"ldr\s+\w+,\s*\[(\w+),\s*#(\d+)\]", line)
            if m:
                srcreg = m.group(1)
                v = int(m.group(2), 0)
                if srcreg in bases:
                    w = AddressUtil.normalize_address(bases[srcreg] + v)
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
                continue
            if read_valid and not is_valid_addr_addr(w):
                continue
            if skip > 0:
                skip -= 1
                continue
            yield w

    @staticmethod
    def aarch64_adrp_ldrb(res, skip=0, skip_msb_check=False, read_valid=False):
        # Use this when the global is a `bool`/`u8`, which is loaded by `ldrb` instead of `ldr`.
        bases = {}
        for line in res.splitlines():
            m = re.search(r"adrp\s+(\w+),\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16)
                bases[reg] = v
                continue
            w = None
            m = re.search(r"ldrb\s+\w+,\s*\[(\w+)(?:,\s*#(\d+))?\]", line)
            if m:
                srcreg = m.group(1)
                if m.group(2):
                    v = int(m.group(2), 0)
                else:
                    v = 0
                if srcreg in bases:
                    w = AddressUtil.normalize_address(bases[srcreg] + v)
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
                continue
            if read_valid and not is_valid_addr_addr(w):
                continue
            if skip > 0:
                skip -= 1
                continue
            yield w

    @staticmethod
    def aarch64_adrp_ldrsw(res, skip=0, skip_msb_check=False, read_valid=False):
        # Use this when the global is an `int` that feeds a 64-bit operand, which makes the
        # compiler load it by `ldrsw` instead of `ldr`.
        bases = {}
        for line in res.splitlines():
            m = re.search(r"adrp\s+(\w+),\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16)
                bases[reg] = v
                continue
            w = None
            m = re.search(r"ldrsw\s+\w+,\s*\[(\w+)(?:,\s*#(\d+))?\]", line)
            if m:
                srcreg = m.group(1)
                if m.group(2):
                    v = int(m.group(2), 0)
                else:
                    v = 0
                if srcreg in bases:
                    w = AddressUtil.normalize_address(bases[srcreg] + v)
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
                continue
            if read_valid and not is_valid_addr_addr(w):
                continue
            if skip > 0:
                skip -= 1
                continue
            yield w

    @staticmethod
    def aarch64_adrp_str(res, skip=0, skip_msb_check=False, read_valid=False):
        bases = {}
        for line in res.splitlines():
            m = re.search(r"adrp\s+(\w+),\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16)
                bases[reg] = v
                continue
            w = None
            m = re.search(r"str\s+\w+,\s*\[(\w+)(?:,\s*#(\d+))?\]", line)
            if m:
                dstreg = m.group(1)
                if m.group(2):
                    v = int(m.group(2), 0)
                else:
                    v = 0
                if dstreg in bases:
                    w = AddressUtil.normalize_address(bases[dstreg] + v)
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
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
            w = None
            m = re.search(r"add\s+(\w+),\s*(\w+),\s*#(0x\w+)", line)
            if m:
                dstreg = m.group(1)
                srcreg = m.group(2)
                v = int(m.group(3), 16)
                if srcreg in bases:
                    w = AddressUtil.normalize_address(bases[srcreg] + v)
                # the add leaves a page offset in dstreg, so a following add must not restart
                # from the adrp page (`aarch64_adrp_add_add` handles that sequence)
                bases.pop(dstreg, None)
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
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
                add1time.pop(reg, None) # adrp overwrites reg, so the pending add1time is stale
                continue
            m = re.search(r"add\s+(\w+),\s*(\w+),\s*#(0x\w+)", line)
            if m:
                dstreg = m.group(1)
                srcreg = m.group(2)
                v = int(m.group(3), 16)
                if srcreg in add1time:
                    w = AddressUtil.normalize_address(add1time[srcreg] + v)
                    if skip_msb_check or KernelAddressHeuristicFinderUtil.is_kernel_space(w):
                        if not read_valid or is_valid_addr_addr(w):
                            if skip <= 0:
                                yield w
                            skip -= 1
                if srcreg in bases:
                    add1time[dstreg] = bases[srcreg] + v
                continue
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases, add1time)

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
                add1time.pop(reg, None)
                continue
            m = re.search(r"add\s+(\w+),\s*(\w+),\s*#(0x\w+)", line)
            if m:
                dstreg = m.group(1)
                srcreg = m.group(2)
                v = int(m.group(3), 16)
                if srcreg in bases:
                    add1time[dstreg] = bases[srcreg] + v
                    bases.pop(dstreg, None)
                    continue
            w = None
            m = re.search(r"ldr\s+\w+,\s*\[(\w+),\s*#(\d+)\]", line)
            if m:
                srcreg = m.group(1)
                v = int(m.group(2), 0)
                if srcreg in add1time:
                    w = AddressUtil.normalize_address(add1time[srcreg] + v)
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases, add1time)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
                continue
            if read_valid and not is_valid_addr_addr(w):
                continue
            if skip > 0:
                skip -= 1
                continue
            yield w

    @staticmethod
    def aarch64_adrp_use(res, skip=0, skip_msb_check=False, read_valid=False):
        """Yield the `adrp` based addresses where a 64-bit datum is accessed through them.

        This follows a section anchor, whose `adrp` + `add` is not the variable itself:
            adrp x1, 0xffffffc008988000; add x1, x1, #0x658; stp x2, x3, [x1, #32]  <-- anchor+0x678
            adrp x19, ...; add x19, x19, #0x210; add x0, x19, #0x8; bl memcpy         <-- the argument
        A 32-bit access (`ldr w20, [x1, #704]`, an int such as `nr_cpu_ids`) is skipped."""
        bases = {}
        for line in res.splitlines():
            m = re.search(r":\s*(\S+)\s*(.*)", line)
            if not m:
                continue
            mnemonic, operands = m.group(1), m.group(2)
            m = re.match(r"(x\d+),\s*(0x\w+)", operands)
            if mnemonic == "adrp" and m:
                bases[m.group(1)] = int(m.group(2), 16)
                continue
            found = []
            m = re.match(r"(x\d+),\s*(x\d+|sp),\s*(?:#(0x\w+|\d+)(,\s*lsl\s*#12)?|[xw]\d+)", operands)
            if mnemonic == "add" and m:
                # an index register (`add x0, x4, x0, lsl #3`) keeps the base of the array
                if m.group(2) in bases:
                    if m.group(3):
                        v = int(m.group(3), 0) << (12 if m.group(4) else 0)
                    else:
                        v = 0
                    bases[m.group(1)] = bases[m.group(2)] + v
                else:
                    bases.pop(m.group(1), None)
                continue
            m = re.fullmatch(r"(x\d+),\s*(x\d+)", operands)
            if mnemonic == "mov" and m:
                if m.group(2) in bases:
                    bases[m.group(1)] = bases[m.group(2)]
                else:
                    bases.pop(m.group(1), None)
                continue
            m = re.match(r"x\d+,.*\[(x\d+)(?:,\s*#(-?0x\w+|-?\d+))?(?:,\s*[xw]\d+[^\]]*)?\]", operands)
            if m and m.group(1) in bases and mnemonic != "prfm":
                found.append(bases[m.group(1)] + (int(m.group(2), 0) if m.group(2) else 0))
            if mnemonic in ("bl", "blr"):
                found += [bases[reg] for reg in ("x0", "x1") if reg in bases]
                for i in range(19): # caller-saved
                    bases.pop("x{:d}".format(i), None)
            elif not re.fullmatch(r"st(?!l?xr)\w*|b|br|b\.\w+|bti|cbn?z|tbn?z|cmp|cmn|tst|ccmp|ccmn|prfm|ret|nop|dmb|dsb|isb|\w*asp|udf|\.inst", mnemonic):
                m = re.match(r"([xw])(\d+)", operands)
                if m:
                    bases.pop("x" + m.group(2), None)
            for w in found:
                w = AddressUtil.normalize_address(w)
                if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
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
            w = None
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16) << 16
                if reg in bases:
                    w = AddressUtil.normalize_address(bases[reg] + v)
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
                continue
            if read_valid and not is_valid_addr_addr(w):
                continue
            if skip > 0:
                skip -= 1
                continue
            yield w

    @staticmethod
    def arm32_movw_movt_ldr(res, skip=0, skip_msb_check=False, read_valid=False, allow_cc=False, mnemonic="ldr"):
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
                add1time.pop(reg, None)
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
            m = re.search(r"add\s+(\w+),\s*(\w+),\s*\w+,\s*lsl\s*#\d+", line)
            if m:
                dstreg = m.group(1)
                srcreg = m.group(2)
                if srcreg in add1time:
                    add1time[dstreg] = add1time[srcreg]
                    continue
            w = None
            m = re.search(mnemonic + r"\s+\w+,\s*\[(\w+)(?:,\s*#(\d+))?\]", line)
            if m:
                reg = m.group(1)
                if m.group(2):
                    v = int(m.group(2), 0)
                else:
                    v = 0
                if reg in add1time:
                    w = AddressUtil.normalize_address(add1time[reg] + v)
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases, add1time)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
                continue
            if read_valid and not is_valid_addr_addr(w):
                continue
            if skip > 0:
                skip -= 1
                continue
            yield w

    @staticmethod
    def arm32_movw_movt_str(res, skip=0, skip_msb_check=False, read_valid=False, allow_cc=False):
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
                add1time.pop(reg, None)
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
            w = None
            m = re.search(r"str\s+\w+,\s*\[(\w+)(?:,\s*#(\d+))?\]", line)
            if m:
                reg = m.group(1)
                if m.group(2):
                    v = int(m.group(2), 0)
                else:
                    v = 0
                if reg in add1time:
                    w = AddressUtil.normalize_address(add1time[reg] + v)
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases, add1time)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
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
                add1time.pop(reg, None)
                continue
            m = re.search(r"movt\s+(\w+),.+[;@]\s*(0x\w+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 16) << 16
                if reg in bases:
                    add1time[reg] = bases[reg] + v
                    continue
            w = None
            m = re.search(r"add\s+\w+,\s*(\w+),\s*#(\d+)", line)
            if m:
                reg = m.group(1)
                v = int(m.group(2), 0)
                if reg in add1time:
                    w = AddressUtil.normalize_address(add1time[reg] + v)
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases, add1time)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
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
            w = None
            m = re.search(r"ldr\s+\w+,\s*\[(\w+),\s*#(\d*)\]", line)
            if m:
                reg = m.group(1)
                ofs = AddressUtil.normalize_address(int(m.group(2), 0))
                if reg in bases:
                    w = AddressUtil.normalize_address(bases[reg] + ofs)
            else:
                m = re.search(r"ldr\s+\w+,\s*\[(\w+)\]", line)
                if m:
                    reg = m.group(1)
                    if reg in bases:
                        w = AddressUtil.normalize_address(bases[reg])
                        if read_valid and not is_valid_addr_addr(w):
                            w = None
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases)
            if w is None:
                continue
            if skip <= 0:
                yield w
            skip -= 1

    @staticmethod
    def arm32_ldr_pc_relative_str(res, skip=0, read_valid=False):
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
            w = None
            m = re.search(r"str\s+\w+,\s*\[(\w+)(?:,\s*#(\d+))?\]", line)
            if m:
                reg = m.group(1)
                if m.group(2):
                    ofs = AddressUtil.normalize_address(int(m.group(2), 0))
                else:
                    ofs = 0
                if reg in bases:
                    w = AddressUtil.normalize_address(bases[reg] + ofs)
                    if read_valid and not is_valid_addr_addr(w):
                        w = None
            KernelAddressHeuristicFinderUtil.drop_clobbered_regs(line, bases)
            if w is None:
                continue
            if skip <= 0:
                yield w
            skip -= 1

    @staticmethod
    def arm32_const_use(res, skip=0, skip_msb_check=False, read_valid=False):
        """Yield the constant based addresses where memory is accessed through them.

        The constant is `movw` + `movt` or a literal pool (`ldr r3, [pc, #4]`), and it is
        usually a section anchor rather than the variable itself:
            movw r3, #19496; movt r3, #32944; str r2, [r3, #4]  <-- 0x80b04c28+4
            movw r4, ...; movt r4, ...; mov r1, r4; bl _test_and_set_bit  <-- the argument"""
        bases = {}
        movw = {}
        for line in res.splitlines():
            m = re.search(r"^\s*(?:=>\s*)?(0x[0-9a-f]+)(?:\s+<[^>]*>)?:\s*(\S+)\s*(.*)", line)
            if not m:
                continue
            pos, mnemonic, operands = int(m.group(1), 16), m.group(2), m.group(3)
            m = re.match(r"(\w+),.+[;@]\s*(0x\w+)", operands)
            if mnemonic == "movw" and m:
                movw[m.group(1)] = int(m.group(2), 16)
                bases.pop(m.group(1), None)
                continue
            if mnemonic == "movt" and m:
                if m.group(1) in movw:
                    bases[m.group(1)] = movw.pop(m.group(1)) + (int(m.group(2), 16) << 16)
                continue
            m = re.match(r"(\w+),\s*\[pc(?:,\s*#(-?\d+))?\]", operands)
            if mnemonic == "ldr" and m:
                v = read_int_from_memory(pos + 4 * 2 + int(m.group(2) or 0), safe=True)
                if v is None:
                    bases.pop(m.group(1), None)
                else:
                    bases[m.group(1)] = v
                continue
            m = re.fullmatch(r"(\w+),\s*(\w+),\s*#(\d+)", operands)
            if mnemonic == "add" and m:
                if m.group(2) in bases:
                    bases[m.group(1)] = bases[m.group(2)] + int(m.group(3))
                else:
                    bases.pop(m.group(1), None)
                continue
            m = re.fullmatch(r"(\w+),\s*(\w+)", operands)
            if mnemonic == "mov" and m:
                if m.group(2) in bases:
                    bases[m.group(1)] = bases[m.group(2)]
                else:
                    bases.pop(m.group(1), None)
                continue
            found = []
            m = re.search(r"\[(\w+)(?:,\s*#(-?\d+))?\]", operands)
            if m and m.group(1) in bases and re.match(r"(?:ldr|str)", mnemonic):
                found.append(bases[m.group(1)] + int(m.group(2) or 0))
            if mnemonic in ("b", "bl", "blx"): # including a tail call
                found += [bases[reg] for reg in ("r0", "r1") if reg in bases]
                if mnemonic != "b":
                    for reg in ("r0", "r1", "r2", "r3", "r12", "ip", "lr"): # caller-saved
                        bases.pop(reg, None)
            elif not re.fullmatch(r"str(?!ex)\w*|stm\w*|push|cmp\w*|cmn\w*|tst\w*|teq\w*|pld|pli|nop|dmb|dsb|isb|udf"
                                  r"|bx?(?:eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)?(?:\.[wn])?", mnemonic):
                m = re.match(r"(\w+)", operands)
                if m:
                    bases.pop(m.group(1), None)
            for w in found:
                w = AddressUtil.normalize_address(w)
                if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
                    continue
                if read_valid and not is_valid_addr_addr(w):
                    continue
                if skip > 0:
                    skip -= 1
                    continue
                yield w

    @staticmethod
    def riscv_auipc_gen(res, use_addi, use_mem, skip, skip_msb_check, read_valid,
                        word_only=False, follow_addi=False, load_mnemonic=None, with_pc=False, include_lui=False):
        """Yield the addresses built from `auipc rd, hi20` and the following `lo12(rd)`.
        `use_addi` takes `addi rX, rd, lo12` (the address itself), and `use_mem` takes the
        displacement of a load/store such as `ld rX, lo12(rd)` or `sd rX, lo12(rd)`.
        `word_only` limits the latter to the accesses as wide as a pointer.
        `follow_addi` keeps the result of `addi` as a base, for a member accessed at an offset
        from the address of the whole object (e.g. `addi s4, s4, lo12` then `ld s2, 176(s4)`).
        `load_mnemonic` selects a load width and also includes gp-relative loads.
        `include_lui` also accepts absolute addresses constructed with `lui`."""
        bases = {}
        for line in res.splitlines():
            m = re.match(r"\s*(?:=>\s*)?(0x[0-9a-f]+)(?:\s+<[^>]*>)?:\s*(\S+)\s*(.*)", line)
            if not m:
                continue
            pc, mnemonic = int(m.group(1), 16), m.group(2)
            ops = [x.strip() for x in m.group(3).split("#", 1)[0].split(",")]
            if (mnemonic == "auipc" or include_lui and mnemonic == "lui") and len(ops) == 2:
                try:
                    hi20 = int(ops[1], 0) & 0xfffff
                except ValueError:
                    bases.pop(ops[0], None)
                    continue
                if hi20 & 0x80000:
                    hi20 -= 0x100000
                bases[ops[0]] = (pc if mnemonic == "auipc" else 0) + (hi20 << 12)
                continue
            w = None
            if mnemonic == "addi" and len(ops) == 3 and ops[1] in bases:
                try:
                    offset = int(ops[2], 0)
                except ValueError:
                    bases.pop(ops[0], None)
                    continue
                if use_addi:
                    w = AddressUtil.normalize_address(bases[ops[1]] + offset)
                if follow_addi:
                    bases[ops[0]] = bases[ops[1]] + offset
            elif use_mem and (not word_only or mnemonic in (("ld", "sd") if is_64bit() else ("lw", "sw"))) \
                    and (load_mnemonic is None or mnemonic == load_mnemonic):
                mm = re.fullmatch(r"(-?\d+)\((\w+)\)", ops[-1])
                if mm and mm.group(2) in bases:
                    w = AddressUtil.normalize_address(bases[mm.group(2)] + int(mm.group(1)))
                elif mm and mm.group(2) == "gp" and load_mnemonic is not None:
                    w = next(KernelAddressHeuristicFinderUtil.riscv_gp_relative(line), None)
            # a store, a branch and a fence write no register; anything else overwrites the first operand
            if mnemonic in ("jal", "jalr", "call", "tail"):
                if follow_addi:
                    # a whole object is usually kept in a callee-saved register across calls
                    bases = {k: v for k, v in bases.items() if re.fullmatch(r"s\d+|fp", k)}
                else:
                    bases.clear()
            elif follow_addi and mnemonic == "addi" and len(ops) == 3 and ops[1] in bases:
                pass
            elif not re.fullmatch(r"(?:c\.)?(?:f?s[bhwdq]|b\w+|j|jr|ret|fence\S*|nop|wfi)", mnemonic):
                bases.pop(ops[0], None)
            if w is None:
                continue
            if not skip_msb_check and not KernelAddressHeuristicFinderUtil.is_kernel_space(w):
                continue
            if read_valid and not is_valid_addr_addr(w):
                continue
            if skip > 0:
                skip -= 1
                continue
            yield (pc, w) if with_pc else w

    @staticmethod
    def riscv_auipc_addi(res, skip=0, skip_msb_check=False, read_valid=False, include_lui=False):
        return KernelAddressHeuristicFinderUtil.riscv_auipc_gen(
            res, True, False, skip, skip_msb_check, read_valid, include_lui=include_lui,
        )

    @staticmethod
    def riscv_auipc_use(res, skip=0, skip_msb_check=False, read_valid=False, include_lui=False):
        # `addi` or a pointer-sized load/store, in order. An int (`lw` on RV64) is skipped.
        return KernelAddressHeuristicFinderUtil.riscv_auipc_gen(
            res, True, True, skip, skip_msb_check, read_valid, word_only=True, include_lui=include_lui,
        )

    @staticmethod
    def riscv_load(res, mnemonic="lw", skip=0, include_lui=False):
        return KernelAddressHeuristicFinderUtil.riscv_auipc_gen(
            res, False, True, skip, False, False, follow_addi=True, load_mnemonic=mnemonic, include_lui=include_lui,
        )

    @staticmethod
    def riscv_load_store(res, base_register=None):
        """Map (base register, member offset, width) to the global load source."""
        loads = {}
        for mnemonic in ("lw", "ld"):
            loads.update(KernelAddressHeuristicFinderUtil.riscv_auipc_gen(
                res, False, True, 0, False, False, follow_addi=True, load_mnemonic=mnemonic, with_pc=True,
            ))
        registers = {}
        if base_register:
            pointers = {base_register: 0}
        else:
            pointers = {}
        stores = {}
        for line in res.splitlines():
            match = re.match(r"\s*(?:=>\s*)?(0x[0-9a-f]+)(?:\s+<[^>]*>)?:\s*(\S+)\s*(.*)", line)
            if not match:
                continue
            pc, mnemonic = int(match.group(1), 16), match.group(2)
            ops = [part.strip() for part in match.group(3).split("#", 1)[0].split(",")]
            pointer = None
            if mnemonic == "mv" and len(ops) == 2:
                pointer = pointers.get(ops[1])
            elif mnemonic == "addi" and len(ops) == 3 and ops[1] in pointers:
                try:
                    pointer = pointers[ops[1]] + int(ops[2], 0)
                except ValueError:
                    pass
            if mnemonic in ("sw", "sd") and len(ops) == 2:
                target = re.fullmatch(r"(-?\d+)\((\w+)\)", ops[1])
                if target:
                    base, offset = target.group(2), int(target.group(1))
                    if base_register:
                        if base not in pointers:
                            continue
                        offset += pointers[base]
                        base = base_register
                    key = (base, offset, 4 if mnemonic == "sw" else 8)
                    stores.pop(key, None)
                    if ops[0] in registers and registers[ops[0]][1] == key[2]:
                        stores[key] = registers[ops[0]][0]
            elif pc in loads:
                registers[ops[0]] = (loads[pc], 4 if mnemonic == "lw" else 8)
            elif mnemonic == "mv" and len(ops) == 2 and ops[1] in registers:
                registers[ops[0]] = registers[ops[1]]
            elif re.fullmatch(r"jalr?|call|tail|b\w+|j|jr|ret", mnemonic):
                registers.clear()
                pointers.clear()
            elif not re.fullmatch(r"(?:c\.)?(?:f?s[bhwdq]|fence\S*|nop|wfi)", mnemonic):
                registers.pop(ops[0], None)
            if not re.fullmatch(r"(?:c\.)?(?:f?s[bhwdq]|b\w+|j|jr|ret|fence\S*|nop|wfi)", mnemonic):
                pointers.pop(ops[0], None)
            if pointer is not None:
                pointers[ops[0]] = pointer
        return stores

    @staticmethod
    def riscv_gp_relative(res):
        """Yield the addresses built from `gp` with `addi rX, gp, lo12` or accessed as `lw/ld rX, lo12(gp)`.
        The linker relaxes an access near `__global_pointer$` to a gp-relative one, and the
        kernel keeps `__global_pointer$` in `gp` while it runs."""
        gp = Ksym.get_addr("__global_pointer$")
        if not gp:
            try:
                gp = get_register("$gp")
            except gdb.error:
                return
        if not gp or not KernelAddressHeuristicFinderUtil.is_kernel_space(gp):
            return
        for line in res.splitlines():
            line = line.split("#", 1)[0].rstrip()
            m = re.search(r"\baddi\s+\w+,\s*gp,\s*(-?\d+)$", line) or re.search(r"\b(?:lw|ld)\s+\w+,\s*(-?\d+)\(gp\)", line)
            if m:
                yield AddressUtil.normalize_address(gp + int(m.group(1)))
        return

    @staticmethod
    def get_kernel_image_range():
        """Return [start, end) of the kernel image (.text/.rodata/.data/.bss), or None if unknown."""
        try:
            klayout = Kernel.layout()
        except Exception:
            return None
        # `rw_end` is 0 when the RW area of an old (=RWX) kernel could not be detected.
        if not klayout.text_base or not klayout.text_size or not klayout.rw_end:
            return None
        # The detected RW area may be truncated because .bss can be mapped as another region,
        # or because a page freed from an alignment gap of the image was reused and had its
        # permission changed, which splits the RW area into pieces at a boot-dependent offset.
        # Merge the regions that are contiguous with .text, but stop at a region larger than
        # the image merged so far, because it is the linear map, not a part of the kernel image.
        end = klayout.text_base
        for entry in klayout.maps:
            if entry.vstart < end:
                continue
            if entry.vstart != end or entry.vsize > max(klayout.text_size, (end - klayout.text_base) * 2):
                break
            if entry.vstart < klayout.rw_end < entry.vend:
                # The RW area ending inside a region is not detected from the mapping but refined from the iomem
                # resource tree or kallsyms, so it is the exact end. The rest of the region is not a part of the
                # image, e.g. the brk area of x86, which is freed after boot and reused by the heap.
                return klayout.text_base, klayout.rw_end
            end = entry.vend
        return klayout.text_base, max(end, klayout.rw_end)

    @staticmethod
    def is_in_kernel_image(x):
        """Sanity check for a symbol that is statically allocated in the kernel image.
        `init_task`, `slab_caches`, `modprobe_path` and so on are always in the kernel image,
        so a candidate outside of it is always wrong and must not be adopted.
        It returns True when the kernel layout is unknown, to keep the legacy behavior."""
        if x is None:
            return False
        image_range = KernelAddressHeuristicFinderUtil.get_kernel_image_range()
        if image_range is None:
            return True
        return image_range[0] <= x < image_range[1]

    @staticmethod
    def is_in_freed_init_region(x):
        """True when `x` lies in the [__init_begin, __init_end) area that is freed after boot.
        A symbol placed there (e.g. `apparmor_initialized`, which is `__initdata` before v4.12)
        is discarded at runtime, so its value is meaningless and it has no live code reference
        to anchor a heuristic search."""
        if x is None:
            return False
        begin = Ksym.get_addr("__init_begin")
        end = Ksym.get_addr("__init_end")
        if not begin or not end:
            return False
        return begin <= x < end

    @staticmethod
    def filter_in_kernel_image(gen):
        """Drop the candidates that are not in the kernel image."""
        for x in gen:
            if KernelAddressHeuristicFinderUtil.is_in_kernel_image(x):
                yield x

    @staticmethod
    def select_idr(candidates):
        """Return the candidate that is really a `struct idr`, not the adjacent `*_idr_lock`.
        The anchor functions take the lock before touching the idr, so newer kernels
        materialize `&*_idr_lock` first. The lock lives in .bss and the idr in .data,
        so adopting the lock is not a slight deviation the caller can absorb.
        Return None if no candidate can be verified."""
        def is_idr(x):
            """Return True if `x` is the base of a `struct idr` whose xarray is populated.
            `xa_node->array` points back to the xarray itself, so it identifies the base address.
            It cannot decide anything while the xarray is empty or holds a single entry."""
            cls = KernelXArray
            cls.initialize_layout()
            for offset in range(0, runtime.current_arch.ptrsize * 20, cls.ptrsize):
                if not is_valid_addr(x + offset):
                    return False
                if cls.cache_head_offset(x + offset, read_int_from_memory(x + offset)):
                    return True
            return False

        def has_idr_marker(x):
            """Return True if `x` holds the IDR_RT_MARKER that IDR_INIT() stores into xa_flags.
            The marker is ROOT_IS_IDR plus the free mark of the empty tree, so only the
            low flag bits and one or two bits at __GFP_BITS_SHIFT (23 to 27 depending on
            the version and CONFIG_LOCKDEP) are ever set, and xa_head follows it.
            This recognizes an idr that `is_idr()` cannot see because it is still empty.
            The offset of xa_flags depends on sizeof(spinlock_t), which grows a lot with
            CONFIG_DEBUG_SPINLOCK, so it is searched instead of assumed."""
            for offset in range(0, runtime.current_arch.ptrsize * 9, 4):
                if not is_valid_addr(x + offset):
                    return False
                v = u32(read_memory(x + offset, 4))
                marker = v & ~0xFF
                if ((v & 0xFF) not in (0, 4)
                        or not any(marker == bits << shift
                                   for bits in (1, 3) for shift in range(23, 28))):
                    continue
                head_addr = x + align_to_ptrsize(offset + 4)
                if not is_valid_addr(head_addr):
                    return False
                head = read_int_from_memory(head_addr)
                if head == 0 or is_valid_addr(head):
                    return True
            return False

        # `is_idr()` scans a wide window of a .bss neighborhood, so it hits the lock by
        # chance on some boots. Let the exact marker decide first.
        for check in (has_idr_marker, is_idr):
            for x in candidates:
                if check(x):
                    return x
        return None

    @staticmethod
    @Cache.cache_until_next
    def get_list_head_array_stride(addr, count, max_stride=0x200):
        """Return the element size of the array at `addr` whose `count` elements start with a list_head, or None.
        The lock and the padding that follow a list_head never look like a list_head, so the smallest stride
        that makes every element a list_head is the element size. A broken list is accepted if a link
        points back to the head or both links are unreadable, so that the caller can report it."""
        ptrsize = runtime.current_arch.ptrsize

        def is_list_head(head):
            links = (read_int_from_memory(head, safe=True), read_int_from_memory(head + ptrsize, safe=True))
            if links == (head, head):
                return True
            # the lock and the padding never hold aligned kernel pointers that are unreadable or do not point back
            if not all(x and x % ptrsize == 0 and KernelAddressHeuristicFinderUtil.is_kernel_space(x) for x in links):
                return False
            back = (read_int_from_memory(links[0] + ptrsize, safe=True), read_int_from_memory(links[1], safe=True))
            return head in back or back == (None, None)

        if not is_list_head(addr):
            return None
        for stride in range(ptrsize * 2, max_stride + 1, ptrsize):
            if all(is_list_head(addr + stride * i) for i in range(1, count)):
                return stride
        return None

    @staticmethod
    def disassemble_until_next_symbol(addr, count):
        """Disassemble up to `count` instructions from `addr`, dropping what belongs to the next symbol.
        A window wide enough for a KCOV build overruns a short function, and the
        constants of the neighbors are indistinguishable from the ones of the anchor."""
        res = gdb.execute("x/{:d}i {:#x}".format(count, addr), to_string=True)
        end = Ksym.get_next_addr(addr)
        if end is None:
            return res
        lines = []
        for line in res.splitlines():
            m = re.match(r"\s*(?:=>)?\s*(0x[0-9a-f]+)", line)
            if m and int(m.group(1), 16) >= end:
                break
            lines.append(line)
        return "\n".join(lines)

    @staticmethod
    def has_networking_symbols():
        ret = Ksym.get_kallsyms()
        if ret is None or not ret[0]:
            return None
        return any(Ksym.get_addrs(name, match="split") for name in (
            "init_net", "__ksymtab_init_net", "net_initial_ns", "alloc_netdev_mqs", "net_ns_init", "sock_init",
        ))

    @staticmethod
    def collect_idr_candidates(prefix):
        """Return the address constants materialized by the functions whose name starts with `prefix`."""
        candidates = []
        for addr in Ksym.get_addrs(prefix, match="prefix"):
            # KCOV builds interleave __sanitizer_cov_trace_* calls, pushing the idr past 40 insns
            res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 60)
            if is_x86_64() or is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
            elif is_arm64():
                # gcc splits the page offset into two adds in some builds
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                )
            elif is_arm32():
                # ARMv7 builds materialize the address with movw/movt instead of a literal pool
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                )
            else:
                return []
            candidates += list(g)
        return candidates




class KernelAddressHeuristicFinder:
    """A class that heuristically finds a specific symbol in the kernel."""

    USE_DIRECTLY = True # for debug
    USE_KSYSCTL = True # for debug
    DEBUG_CONTEXT = False # for debug; report which CPU context resolved each cpu-dependent heuristic

    def cpu_context_dependent(f):
        """Decorator for the heuristics whose answer depends on which CPU (= gdb thread) is selected.
        The result is memoized per CPU context, so an answer resolved on one CPU is never reused
        on another one. If `KF.DEBUG_CONTEXT` is set, each resolution is reported together with
        the CPU context it was resolved in."""

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            ret = f(*args, **kwargs)
            if KernelAddressHeuristicFinder.DEBUG_CONTEXT:
                thread = gdb.selected_thread()
                if thread:
                    cpu = KernelPerCpu.get_cpu_label(thread)
                else:
                    cpu = "cpu?"
                if ret is None:
                    value = "None"
                else:
                    value = "{:#x}".format(ret)
                # Report to the real stderr, not via gef_print. These heuristics are often called
                # from a nested `gdb.execute(..., to_string=True)`, which swallows gef_print().
                sys.__stderr__.write("{} {:s}: {:s}() -> {:s}\n".format(
                    Color.colorify("[D]", "bold magenta"), cpu, f.__qualname__, value,
                ))
            return ret

        return Cache.cache_until_next(wrapper, cache_None=False, per_cpu=True)

    @staticmethod
    @Cache.cache_this_session(cache_None=False, until_new_objfile=True)
    def consts():
        # each property memoizes its own value on the returned object, so dropping the
        # object here drops every one of them
        if Kernel.version() is None:
            return None
        if is_x86_64():
            return KernelConstsX64()
        elif is_x86_32():
            return KernelConstsX86()
        elif is_arm64():
            return KernelConstsArm64()
        elif is_arm32():
            return KernelConstsArm32()
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_saved_command_line():
        # Do not use Ksym.get_addr since this function is used to discover KPTI,
        # because Ksym.get_addr uses a cache.

        kversion = Kernel.version()

        # plan 1 (available v2.6.28 or later)
        if kversion and "2.6.28" <= kversion:
            # This is OK since we are not looking for `saved_command_line` directly.
            addr = Ksym.get_addr("cmdline_proc_show")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                g = ()
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
                elif is_riscv32() or is_riscv64():
                    # auipc/lui + ld/lw, or a gp-relative load after linker relaxation
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_use(res, include_lui=True),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                    )
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_current_task():
        if not is_x86():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("current_task")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.1 or later)
        if kversion and "4.1" <= kversion:
            addr = Ksym.get_addr("common_cpu_up")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    # Some builds fold `per_cpu(current_task, cpu) = idle` into the store displacement
                    # instead of materializing `&current_task` first. The store is the more specific
                    # form, so try it before the plain constant (which may be a UBSAN descriptor).
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_disp_store(res),
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True),
                    )
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
            anchors = ["setup_arg_pages"]
            if is_x86_32():
                # gettid reads current without the stack canary load of setup_arg_pages on UP builds.
                anchors = ["__ia32_sys_gettid", "sys_gettid"] + anchors
            addrs = itertools.chain.from_iterable(Ksym.get_addrs(name, match="split") for name in anchors)
            for addr in addrs:
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 20)
                if is_x86_64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_ds(res),
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_gs(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_gs_rip_base(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res),
                    )
                elif is_x86_32():
                    # SMP reads `current` through %fs, and a later plain global (e.g. mmap_min_addr) is not it.
                    # UP has no %fs read, so the plain global is used.
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x86_dword_ptr_fs(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res),
                        KernelAddressHeuristicFinderUtil.x86_mov_noptr_ds(res),
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
    def dereference_current_task(current_task, cpu_base=None):
        if cpu_base is not None:
            current_task = AddressUtil.normalize_address(cpu_base + current_task)
        task = read_int_from_memory(current_task, safe=True)
        if task and is_valid_addr(task):
            return task
        return None

    @staticmethod
    @cpu_context_dependent
    def get_current_task_for_current_thread():
        if is_kgdb():
            cpu = KernelPerCpu.get_cpu_index(gdb.selected_thread())
            if cpu is not None:
                task = to_unsigned_long(gdb.parse_and_eval("kgdb_info[{:d}].task".format(cpu)))
                if task:
                    return task

        if is_arm32():
            # plan 1 (from special register)
            page_offset = KernelAddressHeuristicFinder.get_PAGE_OFFSET()
            if page_offset is None:
                return None
            r = get_register("$TPIDRURO")
            if r and r >= page_offset and is_valid_addr(r):
                return r
            r = get_register("$TPIDRURO_S")
            if r and r >= page_offset and is_valid_addr(r):
                return r

            # plan 2 (from stack top)
            # We need to consider the case where Linux and RTOS are running on different CPUs at the same time.
            # If the stack is not the address the kernel expects to use, it should not be interpreted as a task.

            # The kernel stack of the current task is banked to SVC mode. In the other modes `sp` is
            # either the user stack (USR, SYS) or the small per-CPU exception stack that cpu_init()
            # allocates in the kernel .data (FIQ, IRQ, ABT, UND, MON), so it is not a thread_info.
            cpsr = get_register(runtime.current_arch.flag_register)
            if cpsr is not None and (cpsr & 0b11111) != 0b10011:
                return None

            """
            struct thread_info {
                unsigned long flags;
                int preempt_count;
                mm_segment_t addr_limit; // ~v5.14
                struct task_struct *task; // ~v5.17
                ...
            }
            """
            kversion = Kernel.version()
            if kversion and kversion < "5.15":
                offset_task = runtime.current_arch.ptrsize * 3
            elif kversion and kversion < "5.18":
                offset_task = runtime.current_arch.ptrsize * 2
            else:
                return None

            # THREAD_SIZE is 8 KiB, or 16 KiB if CONFIG_KASAN=y (v5.11 or later). A candidate is accepted only if
            # its task links back to it by `task_struct.stack`. 8 KiB goes first, since the 16 KiB mask on an
            # 8 KiB stack may hit the thread_info of the neighbor task, which also links back.
            for thread_size in [0x2000, 0x4000]:
                current_thread_info = runtime.current_arch.sp & ~(thread_size - 1)
                # check if valid kernel address or not
                if current_thread_info < page_offset:
                    return None
                try:
                    v = read_int_from_memory(current_thread_info + offset_task)
                    if not v or v < page_offset or not is_valid_addr(v):
                        continue
                    # `stack` follows `state` at the top of task_struct, unless the layout is randomized.
                    head = slice_unpack(read_memory(v, runtime.current_arch.ptrsize * 0x10), runtime.current_arch.ptrsize)
                except gdb.MemoryError:
                    # In some threads, $sp points to an invalid address.
                    return None
                if current_thread_info in head:
                    return v
        elif is_riscv32() or is_riscv64():
            # plan 1 (from tp or sscratch)
            # The kernel keeps the current task in tp, and in sscratch while the hart is in U-mode.
            # Around the swap at the exception entry, either of them may hold the user tp or 0.
            priv = get_register("priv")
            if priv == 1:
                candidates = [get_register("$tp"), get_register("$sscratch")]
            elif priv == 0:
                candidates = [get_register("$sscratch")]
            else:
                return None
            for r in candidates:
                if not r:
                    continue
                if is_riscv64() and not AddressUtil.is_msb_on(r):
                    continue
                # PAGE_OFFSET is fixed to 0xc0000000 on RV32
                if is_riscv32() and r < 0xc000_0000:
                    continue
                # A U-mode hart cannot reach the kernel pages, so it is not validated by reading.
                if priv == 0 or is_valid_addr(r):
                    return r
        elif is_arm64():
            if not is_in_kernel():
                return None
            kversion = Kernel.version()
            if kversion and kversion < "4.5":
                sp = runtime.current_arch.sp
                if kversion < "3.11":
                    thread_size = 0x2000
                else:
                    thread_size = 0x4000
                if sp is not None:
                    r = sp & ~(thread_size - 1)
                else:
                    r = None
            else:
                r = get_register("$SP_EL0")
            if not r or not AddressUtil.is_msb_on(r) or not is_valid_addr(r):
                return None
            if kversion and kversion < "4.10":
                offset_task = GefUtil.offsetof("thread_info", "task")
                if offset_task is None:
                    offset_task = runtime.current_arch.ptrsize * 2
                task = read_int_from_memory(r + offset_task, safe=True)
                if not task or not AddressUtil.is_msb_on(task) or not is_valid_addr(task):
                    return None
                offset_stack = GefUtil.offsetof("task_struct", "stack")
                if offset_stack is not None and read_int_from_memory(task + offset_stack, safe=True) != r:
                    return None
                return task
            return r
        return None

    @staticmethod
    @cpu_context_dependent
    @switch_to_intel_syntax
    def get_init_task():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("init_task")
            if x:
                return x

        kversion = Kernel.version()

        # Detecting `init_task` is very difficult.
        # This is because `init_task` itself is rarely used, while `init_task.tasks` is used in most cases.
        # On x86/x64, only one case has been found where detection is stable.
        # However, there appear to be cases where it cannot be detected.

        def looks_like_init_task(task):
            # Only `init_task` has comm == "swapper/0" (or "swapper" when CONFIG_SMP=n),
            # so this rejects another statically allocated object in the same section.
            # For example, `task_struct.scx.tasks_node` (v6.12 or later) also links every task
            # and its head `scx_tasks` is in the kernel .data section, but it is located
            # before `tasks`, so it is found first.
            # init_task also points to itself through real_parent, parent and group_leader.
            data = read_memory(task, get_pagesize(), safe=True)
            if data is None:
                return False
            return (b"swapper/0\0" in data or b"swapper\0" in data) \
                and slice_unpack(data, runtime.current_arch.ptrsize).count(task) >= 3

        # plan 2 (available v3.4 or later)
        if kversion and "3.4" <= kversion:
            if is_x86_64() or is_x86_32():
                for addr in Ksym.get_addrs("do_exit", match="split"):
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 600)
                    if is_x86_64():
                        g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res)
                    elif is_x86_32():
                        g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res)
                    for x in KernelAddressHeuristicFinderUtil.filter_in_kernel_image(g):
                        # `do_exit` also compares against `&init_mm` and `&init_pid_ns`, so the
                        # candidates must be told apart by what they are, not by their contents.
                        # `init_mm` starts with the live refcount `mm_count` (v6.12 or later),
                        # which is temporarily not 2 right after boot.
                        if not is_valid_addr(x):
                            continue
                        if not looks_like_init_task(x):
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

        def get_offset_tasks(current_task, require_init_task=False):
            # search for init_task->tasks
            # On CPU1, the task list is doubly linked, but on others it is not.
            # For example:
            #   CPU1: cpu1_current_task <-> task1 <-> task2 <-> ... <-> cpu1_current_task
            #   CPU2: cpu2_current_task  -> task1 <-> task2 <-> ... <-> cpu1_current_task
            # Therefore, we should read one element at a time and verify the linkage.
            if require_init_task:
                klayout = Kernel.layout()
            else:
                klayout = None
            for i in range(0x200):
                offset_tasks = runtime.current_arch.ptrsize * i
                current_task_tasks = current_task + offset_tasks
                if not is_valid_addr(current_task_tasks):
                    return None
                if require_init_task and klayout.rw_base and klayout.rw_size:
                    task_list = KernelTask.get_task_list(current_task, offset_tasks)
                    rw_end = klayout.rw_base + klayout.rw_size
                    has_init_task = len(task_list) > 5 and any(
                        (klayout.rw_base <= task < rw_end
                         or (is_64bit() and task >= klayout.rw_base))
                        and looks_like_init_task(task)
                        for task in task_list
                    )
                    if has_init_task:
                        return offset_tasks
                    continue
                task1 = read_int_from_memory(current_task_tasks)
                if is_double_link_list(task1, min_len=5):
                    return offset_tasks
            return None

        def get_init_task_from_current(current):
            if current is None:
                return None
            klayout = Kernel.layout()
            # `init_task` may sit below `rw_base` (e.g. `.data..init_task` placed before `.data`),
            # so accept `current` on the boot CPU whenever it is in the image and its comm matches.
            if KernelAddressHeuristicFinderUtil.is_in_kernel_image(current) and looks_like_init_task(current):
                return current

            offset_tasks = get_offset_tasks(current, require_init_task=True)
            if offset_tasks:
                # `current` itself is also a task, so it is included.
                task_list = KernelTask.get_task_list(current, offset_tasks)
                min_distance_task = (None, 0xffff_ffff_ffff_ffff)
                for task in task_list:
                    # Only `init_task` is statically allocated. The others are on the slab.
                    if not KernelAddressHeuristicFinderUtil.is_in_kernel_image(task):
                        continue
                    distance = abs((klayout.rw_base or klayout.text_base) - task)
                    if min_distance_task[1] > distance:
                        min_distance_task = (task, distance)
                if min_distance_task[0] is not None:
                    return min_distance_task[0]
            return None

        # plan 3 (from current)
        current = None
        if is_arm64() or is_arm32() or is_riscv32() or is_riscv64():
            current = KernelAddressHeuristicFinder.get_current_task_for_current_thread()
        elif is_x86_64() or is_x86_32():
            current_task = KernelAddressHeuristicFinder.get_current_task()
            if current_task:
                p = KernelAddressHeuristicFinder.get_per_cpu_offset()
                if p and is_valid_addr(p):
                    cpu_base = read_int_from_memory(p)
                    current = KernelAddressHeuristicFinder.dereference_current_task(current_task, cpu_base)
                elif KernelAddressHeuristicFinderUtil.is_kernel_space(current_task) and is_valid_addr(current_task):
                    current = KernelAddressHeuristicFinder.dereference_current_task(current_task)

        init_task = get_init_task_from_current(current)
        if init_task is not None:
            return init_task

        # On ARM and RISC-V, another CPU may have a readable current task and a complete task list.
        if is_arm64() or is_arm32() or is_riscv32() or is_riscv64():
            orig_thread = gdb.selected_thread()
            threads = (thread for thread in KernelPerCpu.get_cpu_threads() if thread != orig_thread)
            with ContextManager.threads(threads) as threads:
                for _thread in threads:
                    current = KernelAddressHeuristicFinder.get_current_task_for_current_thread()
                    init_task = get_init_task_from_current(current)
                    if init_task is not None:
                        break
            if init_task is not None:
                return init_task

        # plan 4 (from init_task.comm and init_thread_union on arm32)
        # Before v5.15, thread_info is stored at the bottom of the kernel stack and
        # contains a backlink to task_struct.  This also works when every CPU is in
        # user mode and no current kernel stack is visible through $sp.
        if is_arm32() and kversion and kversion < "5.15":
            klayout = Kernel.layout()
            if klayout.rw_base and klayout.rw_size:
                rw_data = read_memory(klayout.rw_base, min(klayout.rw_size, 0x100_0000), safe=True) or b""

                page_offset = KernelAddressHeuristicFinder.get_PAGE_OFFSET()
                pos = -1
                while page_offset:
                    pos = rw_data.find(b"swapper/0\0", pos + 1)
                    if pos == -1:
                        break

                    comm = klayout.rw_base + pos
                    start = max(0, pos - 0x2000)
                    task_data = rw_data[start:pos]
                    for i in range(0, len(task_data) - runtime.current_arch.ptrsize + 1, runtime.current_arch.ptrsize):
                        stack = u32(task_data[i:i + runtime.current_arch.ptrsize])
                        if stack < page_offset or stack & 0x1fff:
                            continue
                        task = read_int_from_memory(stack + runtime.current_arch.ptrsize * 3, safe=True)
                        if task is None:
                            continue
                        if not klayout.rw_base + start <= task < comm:
                            continue

                        offset_tasks = get_offset_tasks(task)
                        if offset_tasks is None:
                            continue

                        # Verify the inferred comm offset against several tasks so a
                        # coincidental aligned pointer cannot be accepted as init_task.
                        offset_comm = comm - task
                        task_pos = task + offset_tasks
                        try:
                            for _ in range(5):
                                name_addr = task_pos - offset_tasks + offset_comm
                                name = read_memory(name_addr, 16).split(b"\0", 1)[0]
                                if not name or any(c < 0x20 or c >= 0x7f for c in name):
                                    break
                                task_pos = read_int_from_memory(task_pos)
                            else:
                                return task
                        except gdb.MemoryError:
                            continue

        # plan 5 (from the self-references in init_task)
        # `real_parent`, `parent` and `group_leader` of `init_task` all point to `init_task`
        # itself, so its own address appears at least 3 times inside the object, while the
        # self-pointing list_heads (children, sibling, thread_group, ...) hit only twice.
        # Only the pointers stored after the address they hold are counted. That drops both
        # the structures that are merely pointed at from the objects in front of them and
        # the `next` of a self-pointing list_head, which sits at the address it holds.
        # This needs no `current`, so it also works when every CPU is halted outside the
        # kernel (user mode, or the secure world on OP-TEE targets).
        klayout = Kernel.layout()
        # `init_task` is statically allocated just after .rodata, so the search area is the
        # detected RW range plus, as a fallback, the writable tail of the image starting at
        # the end of .rodata. The latter is needed when the RW range is missing (an old
        # single RWX image) or when it sits above `init_task` (the .rodata->.data gap).
        scan_regions = []
        if klayout.rw_base and klayout.rw_size:
            scan_regions.append((klayout.rw_base, min(klayout.rw_size, 0x100_0000)))
        ro_end = None
        if klayout.ro_base and klayout.ro_size:
            ro_end = klayout.ro_base + klayout.ro_size
        elif klayout.text_base and klayout.text_size:
            ro_end = klayout.text_base + klayout.text_size
        if ro_end is not None and not any(base <= ro_end < base + size for base, size in scan_regions):
            scan_regions.append((ro_end, 0x100_0000))

        unpack = GefUtil.get_unpack()
        for scan_base, scan_size in scan_regions:
            data = GefUtil.read_memory_padded(scan_base, scan_size, chunk_size=0x1_0000)

            for needle in [b"swapper/0\0", b"swapper\0"]:
                pos = -1
                while True:
                    pos = data.find(needle, pos + 1)
                    if pos == -1:
                        break

                    # `comm` is in the latter half of task_struct, so the object starts
                    # somewhere in the window right before it.
                    start = max(0, pos - 0x2000)
                    start += -(scan_base + start) % runtime.current_arch.ptrsize
                    counter = collections.Counter()
                    for i in range(start, pos - runtime.current_arch.ptrsize + 1, runtime.current_arch.ptrsize):
                        v = unpack(data[i:i + runtime.current_arch.ptrsize])
                        if scan_base + start <= v < scan_base + i:
                            counter[v] += 1

                    for task in sorted(counter):
                        if counter[task] < 3:
                            continue
                        if get_offset_tasks(task) is not None:
                            return task
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_init_cred():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("init_cred")
            if x:
                return x

        # plan 2 (from ktask metadata)
        res = gdb.execute("ktask --meta --no-pager", to_string=True)
        m = re.search(r"offsetof\(task_struct, cred\): (0x\w+)", res)
        task_match = re.search(r"init_task: (0x\w+)", res)
        if m and task_match:
            cred_offset = int(m.group(1), 16)
            task = int(task_match.group(1), 16)
            return read_int_from_memory(task + cred_offset)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_init_net():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("init_net")
            if x:
                return x

        kversion = Kernel.version()
        candidate = None

        def looks_like_init_net(x):
            if not KernelAddressHeuristicFinderUtil.is_in_kernel_image(x):
                return False
            if candidate is not None and not x <= candidate < x + get_pagesize():
                return False
            net_namespace_list = Ksym.get_addr("net_namespace_list")
            if net_namespace_list is None:
                return True
            first_net = read_int_from_memory(net_namespace_list)
            if first_net == net_namespace_list:
                return True
            return x <= first_net < x + get_pagesize()

        # plan 2 (available v2.6.35 or later)
        if kversion and "2.6.35" <= kversion:
            for addr in Ksym.get_addrs("net_initial_ns", match="split"):
                # `net_initial_ns` is only 3 instructions long, so the window reaches the neighbors
                # and `aarch64_adrp_add` pairs the adrp of this function with their add.
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 20)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res)
                for x in g:
                    if looks_like_init_net(x):
                        if Ksym.get_addr("net_namespace_list") is not None:
                            return x
                        # Newer net_initial_ns() returns &init_net.ns; prefer a base reference.
                        candidate = x

        # plan 3 (available v2.6.24 or later)
        if kversion and "2.6.24" <= kversion:
            addr = Ksym.get_addr("netdev_boot_base")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res)
                for x in g:
                    if not is_valid_addr(x):
                        continue
                    if read_cstring_from_memory(x) == "%s%d":
                        continue
                    if looks_like_init_net(x):
                        return x

        # plan 4 (available v2.6.35 or later)
        if kversion and "2.6.35" <= kversion:
            for addr in Ksym.get_addrs("alloc_netdev_mqs", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 200)
                if is_x86_64() or is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res)
                for x in g:
                    if looks_like_init_net(x):
                        return x

        # plan 5 (exported symbol, absolute or PREL32)
        for addr in Ksym.get_addrs("__ksymtab_init_net", match="split"):
            x = read_int_from_memory(addr, safe=True)
            if x is not None and looks_like_init_net(x):
                return x
            offset = read_int32_from_memory(addr, signed=True, safe=True)
            if offset is not None:
                x = AddressUtil.normalize_address(addr + offset)
                if looks_like_init_net(x):
                    return x
        return candidate

    @staticmethod
    @switch_to_intel_syntax
    def get_init_user_ns():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("init_user_ns")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.6.39 or later)
        # has_capability() is inlined since v6.15, so prefer has_capability_noaudit()
        # which loads &init_user_ns the same way and is always present in kallsyms.
        if kversion and "2.6.39" <= kversion:
            for sym in ("has_capability_noaudit", "has_capability"):
                addr = Ksym.get_addr(sym)
                if not addr:
                    continue
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res)
                for x in g:
                    return x
        return None

    @staticmethod
    def get_init_ipc_ns():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("init_ipc_ns")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v3.8 or later)
        # init_task.nsproxy is init_nsproxy, whose uts, ipc and pid namespaces are all in the kernel image,
        # and the initial ipc namespace has the fixed inode number.
        if kversion and "3.8" <= kversion:
            init_task = KernelAddressHeuristicFinder.get_init_task()
        else:
            init_task = None
        if init_task:
            is_in_kernel_image = KernelAddressHeuristicFinderUtil.is_in_kernel_image
            members = dict(KernelTask.get_nsproxy_members())
            data = KernelNamespace.read_object(init_task, 0x4000)
            for x in KernelAddressHeuristicFinderUtil.filter_in_kernel_image(slice_unpack(data, runtime.current_arch.ptrsize)):
                namespaces = [
                    read_int_from_memory(x + members[name], safe=True) for name in ["uts_ns", "ipc_ns", "pid_ns_for_children"]
                ]
                if not all(ns and is_in_kernel_image(ns) for ns in namespaces):
                    continue
                ipc_ns = namespaces[1]
                if KernelNamespace.INIT_INUMS["ipc"] in slice_unpack(KernelNamespace.read_object(ipc_ns, 0x1000), 4):
                    return ipc_ns
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_modules():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("modules")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (find_module was replaced by find_module_all in v3.7.5)
        if kversion:
            symbol = "find_module_all" if "3.7.5" <= kversion else "find_module"
            for addr in Ksym.get_addrs(symbol, match="split"):
                # KCOV builds interleave __sanitizer_cov_trace_* calls, pushing &modules past 40 insns
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 60)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    # &modules is not always folded into the ldr displacement; newer gcc
                    # materializes it with adrp + add (+ add) and loads with no displacement
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                    )
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_use(res)
                else:
                    g = []
                for x in g:
                    # modules is a list_head, so it passes even when no module is loaded
                    if is_double_link_list(x):
                        return x
                    # ARM32-LPAE may leave a part of the module area unmapped in the halted context,
                    # so the readable neighbors must link back to the head instead of the whole list
                    ptrsize = runtime.current_arch.ptrsize
                    neighbors = [read_int_from_memory(x + i * ptrsize, safe=True) for i in range(2)]
                    if None in neighbors or any(y & (ptrsize - 1) for y in neighbors):
                        continue
                    links = [
                        read_int_from_memory(y + (1 - i) * ptrsize, safe=True) == x
                        for i, y in enumerate(neighbors) if is_valid_addr(y)
                    ]
                    if links and all(links):
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_chrdevs():

        def is_chrdevs(x):
            # Each of the 255 buckets is NULL or a chain of char_device_struct hashed by major % 255.
            try:
                if not is_valid_addr(x):
                    return False
                found = False
                for i in range(255):
                    v = read_int_from_memory(x + runtime.current_arch.ptrsize * i)
                    seen = set()
                    while v:
                        if v in seen or not is_valid_addr(v):
                            return False
                        seen.add(v)
                        if read_int32_from_memory(v + runtime.current_arch.ptrsize) % 255 != i:
                            return False
                        found = True
                        v = read_int_from_memory(v)
                return found
            except gdb.MemoryError:
                return False

        def get_candidates(res):
            if is_x86_64():
                return itertools.chain(
                    KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res),
                    KernelAddressHeuristicFinderUtil.x64_lea_array_base(res),
                    KernelAddressHeuristicFinderUtil.x64_qword_ptr_disp_load(res),
                    KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res),
                )
            elif is_x86_32():
                return itertools.chain(
                    KernelAddressHeuristicFinderUtil.x86_dword_ptr_array4_base(res),
                    KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res),
                )
            elif is_arm64():
                # gcc splits the page offset into two adds in some builds
                return itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                )
            elif is_arm32():
                return itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                    # Older ARM32 kernels load a section anchor 8 bytes before chrdevs.
                    (x + 8 for x in KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res)),
                )
            return []

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("chrdevs")
            if x:
                return x
            # the address from the debug information is not relocated by KASLR
            try:
                x = Symbol.resolve_address("chrdevs")
                if x is not None and is_chrdevs(x):
                    return x
            except gdb.error:
                pass

        kversion = Kernel.version()

        # plan 2 (available v2.6.16.12 or later, if CONFIG_PROC_FS=y)
        tried = set()
        if kversion and "2.6.17" <= kversion:
            addr = Ksym.get_addr("chrdev_show")
            if addr:
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                for x in get_candidates(res):
                    if x in tried:
                        continue
                    tried.add(x)
                    if is_chrdevs(x):
                        return x

        # plan 3 (available v2.6.x or later)
        # Unlike chrdev_show, the registration functions exist even when CONFIG_PROC_FS=n.
        anchors = [
            "__register_chrdev_region", "__unregister_chrdev_region", "find_dynamic_major",
            "register_chrdev_region", "alloc_chrdev_region", "unregister_chrdev_region",
        ]
        for anchor in anchors:
            for addr in Ksym.get_addrs(anchor, match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 200)
                for x in get_candidates(res):
                    if x in tried:
                        continue
                    tried.add(x)
                    if is_chrdevs(x):
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_cdev_map():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("cdev_map")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.5.70 or later)
        if kversion and "2.5.70" <= kversion:
            addr = Ksym.get_addr("cdev_del")
            if addr:
                if is_arm32():
                    # KASAN pushes the cdev_map load beyond the first 30 instructions.
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 100)
                else:
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
    def get_devices_kset():

        def is_devices_kset(x):
            # *x is a kset, and its embedded kobject is named "devices".
            # spinlock_t before the kobject is empty on UP kernels.
            try:
                kset = read_int_from_memory(x)
                if not is_valid_addr(kset):
                    return False
                for i in range(2, 0x20):
                    name = read_int_from_memory(kset + runtime.current_arch.ptrsize * i)
                    if is_valid_addr(name) and read_cstring_from_memory(name) == "devices":
                        return True
            except gdb.MemoryError:
                return False
            return False

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("devices_kset")
            if x:
                return x
            # the address from the debug information is not relocated by KASLR
            try:
                x = Symbol.resolve_address("devices_kset")
                if x is not None and is_devices_kset(x):
                    return x
            except gdb.error:
                pass

        # plan 2 (available v2.6.25 or later)
        for anchor in ["device_initialize", "devices_kset_move_last"]:
            addr = Ksym.get_addr(anchor)
            if not addr:
                continue
            res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 30)
            if is_x86_64():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res),
                    KernelAddressHeuristicFinderUtil.x64_qword_ptr_ds(res),
                )
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
            elif is_arm64():
                # devices_kset may be loaded from the address of its neighbor (e.g., `add x20, x20, #0x1c0; ldr x2, [x20, #8]`)
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res),
                )
            elif is_arm32():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                )
            else:
                g = []
            for x in g:
                if is_devices_kset(x):
                    return x
        return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    @switch_to_intel_syntax
    def get_sys_call_table_x64():
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("sys_call_table")
            if x:
                return x

        kversion = Kernel.version()

        if kversion and "6.6.26" <= kversion:
            # On x64, each entry is embedded in `x64_sys_call` as call instruction.
            # So sys_call_table is no longer in use, but it still remains.
            # We won't return yet because we may be able to detect this in plan 5.
            pass

        # plan 2 (available v4.6 ~ v6.6.26)
        if kversion and "4.6" <= kversion < "6.6.26":
            for addr in Ksym.get_addrs("do_syscall_64", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 40)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res)
                for x in g:
                    return x

        # plan 3 (available v4.2 ~ v4.13)
        if kversion and "4.2" <= kversion < "4.14":
            addr = Ksym.get_addr("entry_SYSCALL_64_fastpath")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res)
                for x in g:
                    return x

        # plan 4 (available v2.6.27 ~ v4.1)
        if kversion and "2.6.27" <= kversion < "4.2":
            addr = Ksym.get_addr("system_call_fastpath")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res)
                for x in g:
                    return x

        # KGDB uses the symbols of vmlinux, so the table is absent here, and reading the image is too slow.
        if is_kgdb():
            return None

        # plan 5 (search for the memory)
        sys_read = Ksym.get_addr("__x64_sys_read")
        sys_write = Ksym.get_addr("__x64_sys_write")
        sys_open = Ksym.get_addr("__x64_sys_open")
        sys_close = Ksym.get_addr("__x64_sys_close")
        if None not in [sys_read, sys_write, sys_open, sys_close]:
            seq_to_find = p64(sys_read) + p64(sys_write) + p64(sys_open) + p64(sys_close)
            klayout = Kernel.layout()
            if klayout.ro_base:
                ro_data = read_memory(klayout.ro_base, klayout.ro_size)
                sys_call_table_offset = ro_data.find(seq_to_find)
                if sys_call_table_offset >= 0:
                    return klayout.ro_base + sys_call_table_offset
        return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    @switch_to_intel_syntax
    def get_sys_call_table_x32():
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("x32_sys_call_table")
            if x:
                return x

        kversion = Kernel.version()

        if kversion and kversion < "5.4":
            # Not introduced
            return None

        # x32_sys_call_table was replaced by the `x32_sys_call` switch in mainline v6.9
        # (backported to stable trees from v6.6.26), but non-LTS branches such as v6.7
        # still keep the array. Do not gate on the version: plan 2 disassembles
        # do_syscall_64 and only matches when the array actually exists.

        # plan 2 (available v5.4 or later)
        if kversion and "5.4" <= kversion:
            for addr in Ksym.get_addrs("do_syscall_64", match="split"):
                # The x32 dispatch (2nd array-base access) follows the 64-bit one and
                # the possibly inlined exit-work path, so disassemble the whole function
                # to reach it without spilling into the next symbol.
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 200)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res, skip=1)
                for x in g:
                    return x
        return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    @switch_to_intel_syntax
    def get_sys_call_table_x86():
        if not is_x86():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            if is_x86_64():
                x = Ksym.get_addr("ia32_sys_call_table")
            elif is_x86_32():
                x = Ksym.get_addr("sys_call_table")
            if x:
                return x

        kversion = Kernel.version()

        if kversion and "6.6.26" <= kversion:
            if is_x86_64():
                # ia32_sys_call_table was replaced by the `ia32_sys_call` switch in
                # mainline v6.9 (backported to stable trees from v6.6.26), but non-LTS
                # branches such as v6.7 still keep the array. Fall through to plan 3,
                # which only matches when the array actually exists.
                pass
            else:
                # On i386, each entry is embedded in `ia32_sys_call` as call instruction.
                # So sys_call_table is no longer in use, but it still remains.
                # We won't return yet because we may be able to detect this in plan 3.
                pass

        # plan 2 (available v2.6.24 ~ v6.6.26)
        if kversion and "6.6.7" <= kversion < "6.6.26":
            if is_x86_64():
                # ia32_sys_call_table is still used, but no detection logic.
                addrs = []
            else:
                addrs = Ksym.get_addrs("do_int80_syscall_32", match="split")
        elif kversion and "4.6" <= kversion < "6.6.7":
            addrs = Ksym.get_addrs("do_int80_syscall_32", match="split")
        elif kversion and "4.4" <= kversion < "4.6":
            if is_x86_64():
                addrs = Ksym.get_addrs("do_syscall_32_irqs_off", match="split")
            else:
                addrs = Ksym.get_addrs("do_syscall_32_irqs_on", match="split")
        elif kversion and "2.6.24" <= kversion < "4.4":
            addrs = Ksym.get_addrs("syscall_call", match="split")
        else:
            addrs = []
        for addr in addrs:
            res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_array4_base(res)
            for x in g:
                return x

        # KGDB uses the symbols of vmlinux, so the table is absent here, and reading the image is too slow.
        if is_kgdb():
            return None

        # plan 3 (search for the memory)
        # Since v4.17, syscall wrappers use the __ia32_sys_* names.  Keep the
        # legacy sys_* sequence as a fallback for older kernels.
        symbol_sequences = [
            ("__ia32_sys_restart_syscall", "__ia32_sys_exit", "__ia32_sys_fork", "__ia32_sys_read"),
            ("sys_restart_syscall", "sys_exit", "sys_fork", "sys_read"),
        ]
        address_sequences = []
        for symbol_sequence in symbol_sequences:
            syscall_addrs = [Ksym.get_addr(symbol) for symbol in symbol_sequence]
            if None not in syscall_addrs:
                address_sequences.append(syscall_addrs)
        if not address_sequences:
            return None

        klayout = Kernel.layout()
        if klayout.ro_base:
            ro_data = read_memory(klayout.ro_base, klayout.ro_size)
            if is_x86_64():
                pack = p64
            else:
                pack = p32
            for syscall_addrs in address_sequences:
                seq_to_find = b"".join(pack(addr) for addr in syscall_addrs)
                sys_call_table_offset = ro_data.find(seq_to_find)
                if sys_call_table_offset >= 0:
                    return klayout.ro_base + sys_call_table_offset
        return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_sys_call_table_arm32():
        if not is_arm32():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("sys_call_table")
            if x:
                return x

        # KGDB uses the symbols of vmlinux, so the table is absent here, and reading the image is too slow.
        if is_kgdb():
            return None

        # plan 2 (search for the memory)
        sys_restart_syscall = Ksym.get_addr("sys_restart_syscall")
        sys_exit = Ksym.get_addr("sys_exit")
        sys_forks = (Ksym.get_addr("sys_fork"), Ksym.get_addr("sys_fork_wrapper"))
        sys_read = Ksym.get_addr("sys_read")
        if None not in (sys_restart_syscall, sys_exit, sys_read) and any(addr is not None for addr in sys_forks):
            klayout = Kernel.layout()
            # `sys_call_table` is embedded in the .text area even if `CONFIG_KALLSYMS_ALL=n`
            if klayout.text_base:
                text_data = read_memory(klayout.text_base, klayout.text_size)
                for sys_fork in sys_forks:
                    if sys_fork is None:
                        continue
                    for thumb_bit in (0, 1):
                        seq_to_find = b"".join(p32(addr & ~1 | thumb_bit) for addr in (
                            sys_restart_syscall, sys_exit, sys_fork, sys_read))
                        sys_call_table_offset = text_data.find(seq_to_find)
                        if sys_call_table_offset >= 0:
                            return klayout.text_base + sys_call_table_offset
        return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_sys_call_table_arm64():
        if not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("sys_call_table")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v3.7 or later)
        if kversion and "5.6" <= kversion:
            addr = Ksym.get_addr("do_el0_svc")
        elif kversion and "4.18" <= kversion < "5.6":
            addr = Ksym.get_addr("el0_svc_handler")
        elif kversion and "3.7" <= kversion < "4.18":
            addr = Ksym.get_addr("el0_svc")
        else:
            addr = None
        if addr:
            res = gdb.execute("x/100i {:#x}".format(addr), to_string=True)
            g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, read_valid=True)
            for x in g:
                return x

        # KGDB uses the symbols of vmlinux, so the table is absent here, and reading the image is too slow.
        if is_kgdb():
            return None

        # plan 3 (search for the memory)
        sys_io_setup = Ksym.get_addr("__arm64_sys_io_setup")
        sys_io_destroy = Ksym.get_addr("__arm64_sys_io_destroy")
        sys_io_submit = Ksym.get_addr("__arm64_sys_io_submit")
        sys_io_cancel = Ksym.get_addr("__arm64_sys_io_cancel")
        if None not in [sys_io_setup, sys_io_destroy, sys_io_submit, sys_io_cancel]:
            seq_to_find = p64(sys_io_setup) + p64(sys_io_destroy) + p64(sys_io_submit) + p64(sys_io_cancel)
            klayout = Kernel.layout()
            if klayout.ro_base:
                ro_data = read_memory(klayout.ro_base, klayout.ro_size)
                sys_call_table_offset = ro_data.find(seq_to_find)
                if sys_call_table_offset >= 0:
                    return klayout.ro_base + sys_call_table_offset
        return None

    @staticmethod
    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_sys_call_table_arm64_compat():
        if not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("compat_sys_call_table")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v3.7 or later)
        if kversion and "5.6" <= kversion:
            addr = Ksym.get_addr("do_el0_svc_compat")
        elif kversion and "4.18" <= kversion < "5.6":
            addr = Ksym.get_addr("el0_svc_compat_handler")
        elif kversion and "3.7" <= kversion < "4.18":
            addr = Ksym.get_addr("el0_svc_compat")
        else:
            addr = None
        if addr:
            res = gdb.execute("x/100i {:#x}".format(addr), to_string=True)
            g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, read_valid=True)
            for x in g:
                return x

        # KGDB uses the symbols of vmlinux, so the table is absent here, and reading the image is too slow.
        if is_kgdb():
            return None

        # plan 3 (search for the memory)
        sys_restart_syscall = Ksym.get_addr("__arm64_sys_restart_syscall")
        sys_exit = Ksym.get_addr("__arm64_sys_exit")
        sys_fork = Ksym.get_addr("__arm64_sys_fork")
        sys_read = Ksym.get_addr("__arm64_sys_read")
        sys_write = Ksym.get_addr("__arm64_sys_write")
        sys_open = Ksym.get_addr("__arm64_compat_sys_open")
        if None not in [sys_restart_syscall, sys_exit, sys_fork, sys_read, sys_write, sys_open]:
            seq_to_find = p64(sys_restart_syscall) + p64(sys_exit) + p64(sys_fork) + p64(sys_read) + p64(sys_write) + p64(sys_open)
            klayout = Kernel.layout()
            if klayout.ro_base:
                ro_data = read_memory(klayout.ro_base, klayout.ro_size)
                sys_call_table_offset = ro_data.find(seq_to_find)
                if sys_call_table_offset >= 0:
                    return klayout.ro_base + sys_call_table_offset
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_per_cpu_offset():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("__per_cpu_offset")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v3.0 or later)
        if kversion and "3.0" <= kversion:
            addr = Ksym.get_addr("nr_iowait_cpu")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                g = ()
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
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res, include_lui=True)
                for x in g:
                    if not is_valid_addr(x):
                        continue
                    cpu0 = read_int_from_memory(x)
                    if cpu0 and (cpu0 & 0xfff) == 0:
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def find_per_cpu_static_range(offsets):
        """Return (`__per_cpu_start`, `__per_cpu_end`), or (None, None) if they are unknown.
        Both are data symbols, so a CONFIG_KALLSYMS_ALL=n kernel keeps neither, but
        `__is_kernel_percpu_address` (`is_kernel_percpu_address` before v4.14) materializes
        both of them as constants:
            static_size = __per_cpu_end - __per_cpu_start;
            base = __addr_to_pcpu_ptr(pcpu_base_addr); // folds to `__per_cpu_start`
            for_each_possible_cpu(cpu) { start = base + __per_cpu_offset[cpu]; ... }
        `__per_cpu_start` is page aligned, and `__per_cpu_end` is the nearest
        completed address above it, which is enough to tell them apart.
        CONFIG_SMP=n compiles the body away to `return false`, so nothing is found.
        `offsets` is `__per_cpu_offset[]`, which the caller already has."""
        # the static area never fills a whole unit, and 1MB covers every kernel of the corpus
        limit = 0x10_0000
        if len(offsets) >= 2:
            unit_size = AddressUtil.normalize_address(offsets[1] - offsets[0])
            if 0 < unit_size < limit:
                limit = unit_size

        for name in ["__is_kernel_percpu_address", "is_kernel_percpu_address"]:
            for anchor in Ksym.get_addrs(name, match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(anchor, 60)
                if is_x86_64() or is_x86_32():
                    # x86-64 links the section at 0 before v6.15, so the usual msb filter
                    # would throw both constants away
                    g = (int(m.group(1), 16)
                         for m in re.finditer(r"(?:mov|sub)\s+\w+\s*,\s*(0x\w+)\s*$", res, re.MULTILINE))
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = list(KernelAddressHeuristicFinderUtil.arm32_movw_movt(res))
                    zero_regs = set(re.findall(r"\bmovw\s+(\w+),\s*#0[ \t]*$", res, re.MULTILINE))
                    g.extend(int(m.group(2)) << 16 for m in re.finditer(r"\bmovt\s+(\w+),\s*#(\d+)", res)
                             if m.group(1) in zero_regs)
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res, include_lui=is_riscv32())
                else:
                    g = []
                consts = sorted({AddressUtil.normalize_address(x) for x in g})
                starts = set(consts)
                if is_riscv32():
                    starts.update(AddressUtil.normalize_address(int(m.group(1), 16) << 12)
                                  for m in re.finditer(r"\blui\s+\w+,\s*(0x[0-9a-f]+)\s*$", res, re.MULTILINE))

                for start in sorted(starts):
                    if start % 0x1000: # `__per_cpu_start` is `. = ALIGN(PAGE_SIZE)` in the linker script
                        continue
                    if start == 0:
                        if not is_x86_64():
                            continue
                    elif not KernelAddressHeuristicFinderUtil.is_in_kernel_image(start):
                        continue
                    end = next((x for x in consts if 0x1000 <= x - start <= limit), None)
                    if end is None:
                        continue
                    # `__per_cpu_start + __per_cpu_offset[cpu]` is the base of the unit of `cpu`,
                    # so a wrong candidate points at nothing
                    bases = [AddressUtil.normalize_address(start + off) for off in offsets or [0]]
                    if not all(is_valid_addr(base) for base in bases):
                        continue
                    return start, end
        return None, None

    @staticmethod
    def get_cpu_possible_mask(percpu=None):
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = KernelAddressHeuristicFinder.get_cpu_mask_directly("possible")
            if x:
                return x

        # plan 2 (available v3.0 or later)
        return KernelAddressHeuristicFinder.find_cpu_mask("possible", ["init_cpu_possible"], percpu)

    @staticmethod
    def get_cpu_present_mask():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = KernelAddressHeuristicFinder.get_cpu_mask_directly("present")
            if x:
                return x

        # plan 2 (available v3.2 or later)
        return KernelAddressHeuristicFinder.find_cpu_mask("present", ["init_cpu_present"])

    @staticmethod
    def get_cpu_online_mask():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = KernelAddressHeuristicFinder.get_cpu_mask_directly("online")
            if x:
                return x

        # plan 2 (available v3.2 or later)
        # `init_cpu_online()` is gone since v6.16, while `set_cpu_online()` is out of line
        # before v4.5 and since v5.6
        return KernelAddressHeuristicFinder.find_cpu_mask("online", ["init_cpu_online", "set_cpu_online"])

    @staticmethod
    def get_cpu_mask_directly(kind):
        """Return the address of the cpu mask bitmap of `kind` from the symbols, or None."""
        # v4.5~: `struct cpumask __cpu_possible_mask`
        # ~v4.4: `static DECLARE_BITMAP(cpu_possible_bits, CONFIG_NR_CPUS)`
        for name in ["__cpu_{:s}_mask", "cpu_{:s}_bits"]:
            x = Ksym.get_addr(name.format(kind))
            if x:
                return x
        # ~v4.4: `const struct cpumask *const cpu_possible_mask = to_cpumask(cpu_possible_bits)`,
        # where the static bitmap may be missing from kallsyms
        x = Ksym.get_addr("cpu_{:s}_mask".format(kind))
        if x:
            x = read_int_from_memory(x, safe=True)
            if x and is_valid_addr(x):
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def find_cpu_mask(kind, anchors, percpu=None):
        """Return the address of the cpu mask bitmap of `kind` found in the code of `anchors`, or None.
        `init_cpu_possible()`, `init_cpu_present()` and `init_cpu_online()` are
        `cpumask_copy(&__cpu_<kind>_mask, src)` (`cpu_<kind>_bits` before v4.5), and
        `set_cpu_online()` sets or clears a bit of it, so the bitmap is the first word-sized datum
        they access. A kernel with a large NR_CPUS reads `nr_cpu_ids` for the length first, which
        is an int, so the helpers below skip the int-sized accesses. A candidate is verified as
        a bitmap too: the boot cpu is always cpu0, `nr_cpu_ids` is the last possible cpu + 1,
        and the other masks are subsets of the possible one."""
        if percpu is None:
            percpu = Kernel.per_cpu()
        possible = None
        if kind != "possible":
            possible = percpu.read_cpu_mask(KernelAddressHeuristicFinder.get_cpu_possible_mask())

        for name in anchors:
            for anchor in Ksym.get_addrs(name):
                try:
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(anchor, 40)
                except gdb.error:
                    continue
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ref(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_ds_absolute(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_use(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_const_use(res)
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_use(res)
                else:
                    g = []
                for x in KernelAddressHeuristicFinderUtil.filter_in_kernel_image(g):
                    if x % runtime.current_arch.ptrsize:
                        continue
                    cpus = percpu.read_cpu_mask(x)
                    if not cpus:
                        continue
                    # cpu0 can be offline, but never absent
                    if kind != "online" and 0 not in cpus:
                        continue
                    if (kind == "possible" and percpu.is_smp and percpu.nr_cpu_ids is not None
                            and max(cpus) != percpu.nr_cpu_ids - 1):
                        continue
                    if possible is not None and not cpus <= possible:
                        continue
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_slab_caches():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("slab_caches")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.9 or later)
        if kversion and "4.9" <= kversion:
            addr = Ksym.get_addr("slub_cpu_dead")
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
                for x in KernelAddressHeuristicFinderUtil.filter_in_kernel_image(g):
                    if is_double_link_list(x):
                        return x

        # plan 3 (available v5.9 or later)
        if kversion and "5.9" <= kversion:
            for addr in Ksym.get_addrs("find_mergeable", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 50)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_cmp_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_add(res)
                for x in KernelAddressHeuristicFinderUtil.filter_in_kernel_image(g):
                    if is_double_link_list(x):
                        return x

        # plan 4 (available v4.10 or before and CONFIG_MEMCG=y)
        if kversion and kversion < "4.11":
            addr = Ksym.get_addr("memcg_update_all_caches")
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
                for x in KernelAddressHeuristicFinderUtil.filter_in_kernel_image(g):
                    if is_double_link_list(x):
                        return x

        # plan 5 (available v3.11 ~ v4.10 and CONFIG_SLABINFO=y)
        if kversion and "3.11" <= kversion < "4.11":
            addr = Ksym.get_addr("slab_next")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in KernelAddressHeuristicFinderUtil.filter_in_kernel_image(g):
                    if is_double_link_list(x):
                        return x

        # plan 6 (available if CONFIG_SLAB=y)
        addr = Ksym.get_addr("cache_reap")
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
            for x in KernelAddressHeuristicFinderUtil.filter_in_kernel_image(g):
                if is_double_link_list(x):
                    return x

        # plan 7 (available v2.6.24 ~ v3.10 and CONFIG_SLABINFO=y)
        if kversion and "2.6.24" <= kversion < "3.11":
            addrs = Ksym.get_addrs("s_next")
            if addrs:
                for s_next in addrs:
                    res = gdb.execute("x/20i {:#x}".format(s_next), to_string=True)
                    if is_x86_64():
                        g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, read_valid=True)
                    elif is_x86_32():
                        g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, read_valid=True)
                    elif is_arm64():
                        g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                    elif is_arm32():
                        g = itertools.chain(
                            KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                            KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                        )
                    for x in KernelAddressHeuristicFinderUtil.filter_in_kernel_image(g):
                        if is_double_link_list(x):
                            return x

        # plan 8 (available v4.11 ~ v6.11)
        if kversion and "4.11" <= kversion < "6.12":
            addr = Ksym.get_addr("slab_caches_to_rcu_destroy_workfn")
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
                for slab_mutex in KernelAddressHeuristicFinderUtil.filter_in_kernel_image(g):
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
            x = Ksym.get_addr("slab_kset")
            if x:
                return x

        # plan 2
        for addr in Ksym.get_addrs("sysfs_slab_add", match="split"):
            res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 100)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res)
            elif is_arm64():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res),
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("modprobe_path")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.modprobe")
            if KernelAddressHeuristicFinderUtil.is_in_kernel_image(x):
                return x

        # plan 3 (from a referencing function; used when register_sysctl is inlined away so ksysctl cannot start)
        # call_modprobe() reads modprobe_path as argv[0]; it is inlined into __request_module in some builds.
        # Only x86 has a byte-selective pattern here; on other arches the array base is indistinguishable
        # from unrelated globals, so plan 3 is skipped and ksysctl (plan 2) is relied upon.
        if is_x86():
            for name in ["call_modprobe", "__request_module"]:
                for addr in Ksym.get_addrs(name, match="split"):
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 40)
                    if is_x86_64():
                        g = KernelAddressHeuristicFinderUtil.x64_byte_ptr_rip_base(res)
                    elif is_x86_32():
                        g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                    for x in g:
                        if KernelAddressHeuristicFinderUtil.is_in_kernel_image(x):
                            return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_poweroff_cmd():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("poweroff_cmd")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.poweroff_cmd")
            if KernelAddressHeuristicFinderUtil.is_in_kernel_image(x):
                return x

        # plan 3 (from a referencing function; used when register_sysctl is inlined away so ksysctl cannot start)
        # __orderly_poweroff() runs poweroff_cmd via run_cmd(); when run_cmd is inlined it appears as
        # `mov reg, poweroff_cmd` inside poweroff_work_func. Only x86 loads the array base as an immediate;
        # poweroff_cmd points at a command-line string, so it is picked out by the ASCII-string check.
        if is_x86():
            for name in ["poweroff_work_func", "__orderly_poweroff"]:
                for addr in Ksym.get_addrs(name, match="split"):
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 60)
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                    for x in g:
                        if KernelAddressHeuristicFinderUtil.is_in_kernel_image(x) and is_ascii_string(x):
                            return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_core_pattern():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("core_pattern")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.core_pattern")
            if KernelAddressHeuristicFinderUtil.is_in_kernel_image(x):
                return x

        # plan 3 (from a referencing function; used when register_sysctl is inlined away so ksysctl cannot start)
        # format_corename() parses core_pattern; it is inlined into do_coredump in some builds, where the
        # reference sits deep in the function, so use a wider window for the fallback. Only x86 has a
        # byte-selective pattern here; on other arches the array base is indistinguishable from unrelated
        # globals, so plan 3 is skipped and ksysctl (plan 2) is relied upon.
        if is_x86():
            for name, n in [("format_corename", 30), ("do_coredump", 200)]:
                addr = Ksym.get_addr(name)
                if addr is None:
                    continue
                res = gdb.execute("x/{:d}i {:#x}".format(n, addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_byte_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                for x in g:
                    if KernelAddressHeuristicFinderUtil.is_in_kernel_image(x):
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_phys_base():
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("phys_base")
            if x:
                return read_int_from_memory(x)

        kversion = Kernel.version()

        # plan 2 (available v2.6.24 or later)
        if kversion and "2.6.24" <= kversion:
            addr = Ksym.get_addr("secondary_startup_64")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                for x in g:
                    return read_int_from_memory(x)

        # plan 3 (available v2.6.25 ~ v5.5)
        if kversion and "2.6.25" <= kversion < "5.5":
            addr = Ksym.get_addr("arch_crash_save_vmcoreinfo")
            if addr:
                res = gdb.execute("x/10i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                for x in g:
                    s = read_cstring_from_memory(x)
                    if not s:
                        return read_int_from_memory(x)

        # plan 4 (available v3.9 or later)
        if kversion and "3.9" <= kversion:
            for addr in Ksym.get_addrs("__virt_addr_valid", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 50)
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                for x in g:
                    return read_int_from_memory(x)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_PAGE_OFFSET_base():
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("page_offset_base")
            if x:
                return x

        # plan 2 (from pagewalk)
        klayout = Kernel.layout()
        if not klayout.maps or not klayout.ro_base or not klayout.ro_size:
            return None
        page_offset_base_raw = klayout.maps[0].vstart
        ro_data = read_memory(klayout.ro_base, klayout.ro_size)
        ro_data = slice_unpack(ro_data, runtime.current_arch.ptrsize)
        # ~v4.15 keeps page_offset_base in .data, and the same value may be elsewhere in .rodata.
        # vmalloc_base or vmemmap_base (aligned to 1 GiB) is next to the real one.
        areas = [(klayout.ro_base, ro_data)]
        if klayout.rw_base and klayout.rw_size:
            try:
                rw_data = read_memory(klayout.rw_base, klayout.rw_size)
                areas.append((klayout.rw_base, slice_unpack(rw_data, runtime.current_arch.ptrsize)))
            except gdb.MemoryError:
                pass
        for base, data in areas:
            for index, value in enumerate(data):
                if value != page_offset_base_raw:
                    continue
                neighbors = data[max(index - 1, 0):index] + data[index + 1:index + 2]
                if any(x > page_offset_base_raw and x & 0x3fff_ffff == 0 for x in neighbors):
                    return base + index * runtime.current_arch.ptrsize
        try:
            index = ro_data.index(page_offset_base_raw)
            return klayout.ro_base + index * runtime.current_arch.ptrsize
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
        if is_x86_64():
            # plan 1 (fixed address)
            kversion = Kernel.version()
            if kversion and kversion < "4.8":
                # kASLR and Level5 pagetable is unsupported, so fixed address
                return 0xffff_8800_0000_0000

            # plan 2 (from get_PAGE_OFFSET_base)
            page_offset_base = KernelAddressHeuristicFinder.get_PAGE_OFFSET_base()
            if page_offset_base:
                return read_int_from_memory(page_offset_base)

            # plan 3 (from pagewalk)
            klayout = Kernel.layout()
            if klayout.maps:
                page_offset_base_raw = klayout.maps[0].vstart
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            vmalloc_base = Ksym.get_addr("vmalloc_base")
            if vmalloc_base:
                return read_int_from_memory(vmalloc_base)

        kversion = Kernel.version()
        vmalloc_start = None
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
                    vmalloc_start = page_offset_base_b
                elif page_offset_base_0 < page_offset_base_a:
                    vmalloc_start = page_offset_base_a

                # vmemmap_base may be adjacent to page_offset_base instead.  If
                # the used vmap tree is available, make sure it is contained in
                # the candidate vmalloc range before accepting the candidate.
                if vmalloc_start is not None:
                    res = gdb.execute("vmalloc-dump --quiet --no-pager --only-used", to_string=True)
                    if res:
                        res = Color.remove_color(res)
                        lines = res.splitlines()
                        if len(lines) >= 2:
                            _, _, vrange, _, *_ = lines[1].split()
                            s, _ = vrange.split("-")
                            s = int(s, 16)
                            vmalloc_size_tb = KernelAddressHeuristicFinder.consts().VMALLOC_SIZE_TB
                            if vmalloc_size_tb is not None:
                                vmalloc_size = vmalloc_size_tb << 40
                                if vmalloc_start <= s < vmalloc_start + vmalloc_size:
                                    return vmalloc_start
                                vmalloc_start = None

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
        if kversion:
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
                    klayout = Kernel.layout()
                    prev = None
                    for entry in klayout.maps:
                        if entry.vstart == s:
                            break
                        prev = entry.vstart

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
        if is_x86_64():
            return vmalloc_start
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
        if is_x86_64():
            # plan 1 (fixed address)
            kversion = Kernel.version()
            if kversion and kversion < "4.8":
                # kASLR and Level5 pagetable is unsupported, so fixed address
                return 0xffff_ea00_0000_0000

            # plan 2 (directly)
            if KernelAddressHeuristicFinder.USE_DIRECTLY:
                vmemmap_base = Ksym.get_addr("vmemmap_base")
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
                    # this is called from page2virt, and slub-dump calls page2virt again to warm it up.
                    # `--skip-page2virt` is needed here, the same as in `Kernel.get_page_virt_pair()`,
                    # otherwise page2virt recurses into itself dozens of times.
                    ret = gdb.execute(
                        "{:s} --simple --no-pager --quiet --skip-page2virt kmalloc-{:d}".format(command, n),
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
        if not is_x86() and not is_arm64():
            return

        kversion = Kernel.version()

        # plan 1 (available v2.6.27 ~)
        if is_x86():
            if kversion and "2.6.27" <= kversion:
                for addr in Ksym.get_addrs("__native_set_fixmap", match="split"):
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 20)
                    m = re.search(r"\bcmp\s+\w+,\s*(0x\w+)\s*\n[^\n]*\b(jae|jbe|ja|jb)\b", res)
                    if m:
                        return int(m.group(1), 16) + int(m.group(2) in ("ja", "jbe"))

        # plan 2 (available v3.19 ~)
        if is_arm64():
            if kversion and "3.19" <= kversion:
                addr = Ksym.get_addr("__set_fixmap")
                if addr:
                    res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                    g = KernelAddressHeuristicFinderUtil.aarch64_cmp_const(res, skip_msb_check=True)
                    for x in g:
                        if x <= 1:
                            continue
                        return x
        return None

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    @switch_to_intel_syntax
    def get_end_of_permanent_fixed_addresses():
        if not is_x86():
            return None

        # plan 1 (from type information)
        end = GefUtil.enum_value("enum fixed_addresses", "__end_of_permanent_fixed_addresses")
        if end is not None:
            return end

        kversion = Kernel.version()

        # plan 2 (available v2.6.30 ~)
        if is_x86_32() and kversion and "2.6.30" <= kversion:
            for addr in Ksym.get_addrs("__virt_addr_valid", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 30)
                # `x >= FIXADDR_START` loads `__FIXADDR_TOP` and subtracts `FIXADDR_SIZE` from it
                for load in re.finditer(r"\bmov\s+(\w+),\s*(?:DWORD PTR )?ds:(0x\w+)", res):
                    m = re.search(r"\bsub\s+" + load.group(1) + r",\s*(0x\w+)", res[load.end():])
                    if not m:
                        continue
                    top = read_int32_from_memory(int(load.group(2), 16), safe=True)
                    size = int(m.group(1), 16)
                    if top and size and (top | size) % get_pagesize() == 0:
                        return size // get_pagesize()

        # plan 3 (available v4.14.10 ~, needs CONFIG_PTDUMP_CORE)
        if is_x86_64():
            top = KernelAddressHeuristicFinder.consts().FIXADDR_TOP
            klayout = Kernel.layout(use_iomem=False)
            if top and klayout.ro_base and klayout.ro_size and klayout.rw_base and klayout.rw_size:
                if is_valid_addr(klayout.ro_base) and is_valid_addr(klayout.rw_base):
                    try:
                        ro_data = read_memory(klayout.ro_base, klayout.ro_size)
                        rw_data = read_memory(klayout.rw_base, min(klayout.rw_size, 0x100_0000))
                    except gdb.MemoryError:
                        ro_data = rw_data = b""
                    pos = -1
                    while True:
                        pos = ro_data.find(b"Fixmap Area\x00", pos + 1)
                        if pos == -1:
                            break
                        name_ptr = p64(klayout.ro_base + pos)
                        pos2 = -1
                        while True:
                            pos2 = rw_data.find(name_ptr, pos2 + 1)
                            if pos2 == -1:
                                break
                            if pos2 % 8 or not 8 <= pos2 <= len(rw_data) - 32:
                                continue
                            # address_markers[] ends with {FIXADDR_START, "Fixmap Area", 0} and {-1, NULL, 0}
                            start, name, max_lines, end_start, end_name = slice_unpack(rw_data[pos2 - 8:pos2 + 32], 8)
                            if max_lines != 0 or end_start != 0xffff_ffff_ffff_ffff or end_name != 0:
                                continue
                            size = top - start
                            if 0 < size and size % get_pagesize() == 0:
                                return size // get_pagesize()

            # plan 4 (from the last permanent fixmap users)
            setters = {addr for name in ("native_set_fixmap", "__native_set_fixmap", "__set_fixmap")
                       for addr in Ksym.get_addrs(name, match="split")}
            if not setters:
                return None
            for name in ("ghes_ioremap_pfn_nmi", "text_poke"):
                if name == "text_poke":
                    if not kversion or kversion < "4.14.9" or Ksym.get_addrs("ghes_init", match="split"):
                        return None
                indices = set()
                for addr in Ksym.get_addrs(name, match="split"):
                    try:
                        res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 300)
                    except gdb.error:
                        continue
                    index = None
                    for line in res.splitlines():
                        load = re.search(r"\bmov\s+edi,\s*(0x\w+)\b", line)
                        call = re.search(r"\b(?:call|jmp)\s+(0x\w+)\b", line)
                        if load:
                            index = int(load.group(1), 16)
                        elif call:
                            if index is not None and int(call.group(1), 16) in setters:
                                indices.add(index)
                            index = None
                        elif re.search(r"\b(?:call|j\w+|ret)\b|\b\w+\s+(?:rdi|edi|di|dil)\b", line):
                            index = None
                if name == "ghes_ioremap_pfn_nmi" and len(indices) == 1:
                    return indices.pop() + 1
                if name == "text_poke" and len(indices) == 2 and max(indices) - min(indices) == 1:
                    return max(indices) + 1 + bool(Ksym.get_addrs("vrtc_set_mmss", match="split"))
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_cpu_entry_area_base():
        if not is_x86_32():
            return None

        kversion = Kernel.version()
        if kversion and "4.14.10" <= kversion:
            addr = Ksym.get_addr("get_cpu_entry_area")
            if addr:
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 40)
                for load in re.finditer(r"\bmov\s+(\w+),\s*(?:DWORD PTR )?ds:(0x\w+)", res):
                    reg = load.group(1)
                    code = res[load.end():]
                    patterns = (
                        r"\blea\s+(\w+),\s*\[" + reg + r"-(0x\w+)\]",
                        r"\bsub\s+(" + reg + r"),\s*(0x\w+)",
                    )
                    for pattern in patterns:
                        offset = re.search(pattern, code)
                        if not offset:
                            continue
                        mask = re.search(r"\band\s+" + offset.group(1) + r",\s*(0xff[ce]00000)\b",
                                         code[offset.end():])
                        if not mask:
                            continue
                        top = read_int32_from_memory(int(load.group(2), 16), safe=True)
                        if top is not None:
                            return (top - int(offset.group(2), 16)) & int(mask.group(1), 16)
        return None

    @staticmethod
    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def get_arm64_sparsemem():
        configs = runtime.CommandRegistry.instances["kconfig"].get_configs()
        if configs and configs.get("CONFIG_SPARSEMEM_VMEMMAP") == "y":
            return None
        pair = Kernel.get_page_virt_pair()
        if not pair:
            return None
        page, virt = pair
        phys = AddrMap.v2p(virt)
        flags = read_int_from_memory(page, safe=True)
        if phys is None or flags is None:
            return None
        consts = KernelAddressHeuristicFinder.consts()
        pfn = phys >> consts.PAGE_SHIFT
        sizeof_page = GefUtil.sizeof("page")
        if sizeof_page:
            page_sizes = [sizeof_page]
        else:
            page_sizes = range(32, 257, runtime.current_arch.ptrsize)
        sizeof_section = GefUtil.sizeof("mem_section")
        if sizeof_section:
            section_sizes = [sizeof_section]
        else:
            section_sizes = [16, 32]
        if not sizeof_section and configs:
            section_sizes = [32 if configs.get("CONFIG_PAGE_EXTENSION") == "y" else 16]
        candidates = []
        section_strides = set()
        section_pgshifts = set()
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            addr = Ksym.get_addr("mem_section")
            if addr:
                candidates.append(addr)
        for name in ("__get_free_pages", "free_pages", "__free_pages"):
            addr = Ksym.get_addr(name)
            if not addr:
                continue
            code = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 100)
            if name == "__get_free_pages":
                shifts = [int(shift) for shift in re.findall(r"(?:ubfx|lsr)\s+x\d+,\s*x\d+,\s*#(\d+)", code)]
                shifts = [shift for shift in shifts if 32 <= shift < 64]
                if shifts:
                    section_pgshifts.add(min(shifts))
            candidates.extend(KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(code, allow_add=True))
            candidates.extend(KernelAddressHeuristicFinderUtil.aarch64_adrp_add(code))
            for shift in re.findall(r"add\s+x\d+,\s*x\d+,\s*x\d+,\s*lsl\s*#(4|5)\b", code):
                section_strides.add(1 << int(shift))
        if not sizeof_section and not configs and section_strides:
            section_sizes = sorted(section_strides)
        layouts = []
        for section_bits in (27, 29, 30):
            section_id = phys >> section_bits
            section_shift = section_bits - consts.PAGE_SHIFT
            map_mask = AddressUtil.normalize_address(-1 << min(section_shift, consts.PAGE_SHIFT))
            pa_bits = (configs or {}).get("CONFIG_ARM64_PA_BITS")
            if pa_bits:
                shifts = [64 - (int(pa_bits) - section_bits)]
            else:
                shifts = [shift for shift in range(1, 64) if section_id and flags >> shift == section_id]
            if len(shifts) != 1 or flags >> shifts[0] != section_id:
                continue
            section_pgshift = shifts[0]
            if section_pgshifts and section_pgshift not in section_pgshifts:
                continue
            for addr in dict.fromkeys(candidates):
                for extreme in ((configs.get("CONFIG_SPARSEMEM_EXTREME") == "y",) if configs else (False, True)):
                    if extreme:
                        tables = [addr, read_int_from_memory(addr, safe=True)]
                    else:
                        tables = [addr]
                    for table in tables:
                        if not table:
                            continue
                        for size in section_sizes:
                            if extreme:
                                per_root = consts.PAGE_SIZE // size
                            else:
                                per_root = 1
                            if extreme:
                                root = read_int_from_memory(
                                    table + section_id // per_root * runtime.current_arch.ptrsize, safe=True,
                                )
                                if not root:
                                    continue
                                section = root + section_id % per_root * size
                            else:
                                section = table + section_id * size
                            encoded = read_int_from_memory(section, safe=True)
                            if encoded is None or not encoded & 2:
                                continue
                            biased_map = encoded & map_mask
                            for page_size in page_sizes:
                                if AddressUtil.normalize_address(biased_map + pfn * page_size) != page:
                                    continue
                                layouts.append({
                                    "mem_section": table, "sizeof_mem_section": size, "sections_per_root": per_root,
                                    "sizeof_struct_page": page_size, "SECTIONS_PGSHIFT": section_pgshift,
                                    "SECTIONS_MASK": (1 << (64 - section_pgshift)) - 1, "SECTION_MAP_MASK": map_mask,
                                    "SECTION_HAS_MEM_MAP": 2, "PFN_SECTION_SHIFT": section_shift,
                                    "NR_MEM_SECTIONS": 1 << (64 - section_pgshift), "mode": "SPARSEMEM",
                                })
        unique = [layout for index, layout in enumerate(layouts) if layout not in layouts[:index]]
        if len(unique) == 1:
            return unique[0]
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_mem_section():
        if not is_x86_32() and not is_arm32():
            return None

        # Since mem_map and mem_section are mutually exclusive, make sure that mem_map is not being used
        if KernelAddressHeuristicFinder.get_mem_map() is not None:
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            addr = Ksym.get_addr("mem_section")
            if addr:
                return addr

        kversion = Kernel.version()

        # plan 2 (available v2.4.0 or later)
        if kversion and "2.4" <= kversion:
            for addr in Ksym.get_addrs("free_pages", match="split"):
                try:
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 40)
                except gdb.MemoryError:
                    return None
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
                    v = read_int_from_memory(x, safe=True)
                    if v is None:
                        continue
                    if v and not is_valid_addr(v):
                        continue
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_mem_map():
        if not is_x86_32() and not is_arm32():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            addr = Ksym.get_addr("mem_map")
            if addr:
                v = read_int_from_memory(addr, safe=True)
                if v is None:
                    return None
                if v != 0:
                    return v
                return None

        kversion = Kernel.version()

        # plan 2 (available v2.4.0 or later)
        if kversion and "2.4" <= kversion:
            for addr in Ksym.get_addrs("free_pages", match="split"):
                try:
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 40)
                except gdb.MemoryError:
                    return None
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
                        # The literal must be dereferenced; a bare `ldr rX, [pc, #N]` in a slow path
                        # just materializes an unrelated pointer (e.g. a __FILE__ string).
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                    )
                for x in g:
                    v = read_int_from_memory(x, safe=True)
                    if v is None:
                        continue
                    if v != 0 and is_valid_addr(v):
                        return v
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_page_address_htable():
        if not is_x86_32() and not is_arm32():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("page_address_htable")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.5.41 or later)
        if kversion and "2.5.41" <= kversion:
            # page_address() refers to no list_head-like object but the table. set_page_address() also refers to
            # page_address_pool (~v3.7) or page_address_maps[] (v3.8~), and ~v3.7 refer to the table after 100+ insns.
            for name in ("page_address", "set_page_address"):
                addr = Ksym.get_addr(name)
                if not addr:
                    continue
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 300)
                if is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    # PA_HASH_ORDER is 7
                    if KernelAddressHeuristicFinderUtil.get_list_head_array_stride(x, 2 ** 7):
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_clocksource_tsc():
        if not is_x86():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("clocksource_tsc")
            if x:
                return x

        def looks_like_clocksource_tsc(addr):
            for offset in range(0, 0x80, runtime.current_arch.ptrsize):
                if not is_valid_addr(addr + offset):
                    return False
                name_addr = read_int_from_memory(addr + offset)
                if not is_valid_addr(name_addr):
                    continue
                if read_cstring_from_memory(name_addr, safe=True) == "tsc":
                    return True
            return False

        # plan 2
        # The compiler-split bodies may hold the actual clocksource_tsc reference.
        # `&clocksource_tsc` is passed after the pr_info() call and after
        # `&clocksource_tsc_early`, so the position of the candidate is not stable.
        # Tell them apart by the `name` member instead.
        for addr in Ksym.get_addrs("mark_tsc_unstable", match="split"):
            res = gdb.execute("x/40i {:#x}".format(addr), to_string=True)
            for x in KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res):
                if looks_like_clocksource_tsc(x):
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_clocksource_list():

        ptrsize = runtime.current_arch.ptrsize
        if is_x86_32():
            base_mask_offsets = (4, 8)
        elif is_arm32():
            base_mask_offsets = (8, 4)
        elif is_riscv32():
            base_mask_offsets = (8,)
        else:
            base_mask_offsets = (ptrsize,)
        mask_offsets = tuple(dict.fromkeys(
            offset for base in base_mask_offsets for offset in (base, base + 8)
        ))

        def looks_like_clocksource(current, i, offset_mask):
            clocksource = current - ptrsize * i
            read = read_int_from_memory(clocksource, safe=True)
            if not is_valid_addr(read):
                return False
            mask = read_int64_from_memory(clocksource + offset_mask, safe=True)
            mult = read_int32_from_memory(clocksource + offset_mask + 8, safe=True)
            shift = read_int32_from_memory(clocksource + offset_mask + 12, safe=True)
            if not mask or mask & (mask + 1) or not mult or shift is None or shift > 64:
                return False
            name_addr = read_int_from_memory(current - ptrsize, safe=True)
            if is_valid_addr(name_addr):
                name = read_cstring_from_memory(name_addr, safe=True)
            else:
                name = None
            return bool(name and len(name) <= 64 and name.isprintable())

        def looks_like_clocksource_list(addr):
            if not is_double_link_list(addr, min_len=1):
                return False

            nodes = []
            current = read_int_from_memory(addr)
            while current != addr:
                nodes.append(current)
                current = read_int_from_memory(current)

            # A corrupted node is tolerated only when the other nodes agree on the layout,
            # since a single node of an unrelated list (e.g., kobject.entry) may look like a clocksource.
            if len(nodes) >= 2:
                tolerance = 1
            else:
                tolerance = 0
            for i in range(5, 64):
                for offset_mask in mask_offsets:
                    failed = 0
                    for current in nodes:
                        if not looks_like_clocksource(current, i, offset_mask):
                            failed += 1
                            if failed > tolerance:
                                break
                    else:
                        return True
            return False

        def is_empty_clocksource_list(addr):
            return (
                read_int_from_memory(addr, safe=True) == addr
                and read_int_from_memory(addr + runtime.current_arch.ptrsize, safe=True) == addr
            )

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("clocksource_list")
            if x:
                try:
                    if is_empty_clocksource_list(x) or looks_like_clocksource_list(x):
                        return x
                    first = read_int_from_memory(x, safe=True)
                    last = read_int_from_memory(x + ptrsize, safe=True)
                    if (first and is_valid_addr(first) and read_int_from_memory(first + ptrsize, safe=True) == x
                            or last and is_valid_addr(last) and read_int_from_memory(last, safe=True) == x):
                        return x
                except gdb.MemoryError:
                    pass

        kversion = Kernel.version()

        # plan 2 (available v2.6.21 or later / v2.6.32 or later)
        if kversion and "2.6.21" <= kversion:
            for addr in (Ksym.get_addrs("clocksource_enqueue", match="split")
                         or Ksym.get_addrs("clocksource_resume", match="split")):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 20)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    # the section anchor is followed by a second add for &clocksource_list
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                    )
                elif is_arm32():
                    # the section anchor is often used as `ldr r3, [r5, #off]!`
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv32() or is_riscv64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                    )
                else:
                    g = []
                for x in g:
                    if is_x86():
                        if looks_like_clocksource_list(x):
                            return x
                        continue
                    if looks_like_clocksource_list(x):
                        return x
                    if is_riscv32() or is_riscv64():
                        continue

                    # ARM compilers may materialize a nearby base address and use an immediate offset for
                    # clocksource_list. Recover the actual list head instead of returning the unadjusted base.
                    for offset in range(runtime.current_arch.ptrsize, 0x1000, runtime.current_arch.ptrsize):
                        for candidate in (x + offset, x - offset):
                            if candidate > 0 and looks_like_clocksource_list(candidate):
                                return candidate
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_current_clocksource(clocksource_addresses):
        """Return the clocksource `curr_clocksource` points to."""
        clocksource_addresses = set(clocksource_addresses)
        if not clocksource_addresses:
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            addr = Ksym.get_addr("curr_clocksource")
            if addr:
                current = read_int_from_memory(addr, safe=True)
                if current in clocksource_addresses:
                    return current

        def pointer_locations(res):
            if is_x86_64():
                return KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
            if is_x86_32():
                return itertools.chain(
                    KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res),
                    KernelAddressHeuristicFinderUtil.x86_noptr_ds(res),
                )
            if is_arm64():
                return itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                )
            if is_arm32():
                return itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                )
            if is_riscv32() or is_riscv64():
                return itertools.chain(
                    KernelAddressHeuristicFinderUtil.riscv_load(res, mnemonic="ld" if is_riscv64() else "lw", include_lui=True),
                    KernelAddressHeuristicFinderUtil.riscv_auipc_use(res, include_lui=True),
                    KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                )
            return []

        def first_listed_clocksource(res):
            seen = set()
            for location in pointer_locations(res):
                if location in seen:
                    continue
                seen.add(location)
                current = read_int_from_memory(location, safe=True)
                if current is None:
                    continue
                if current in clocksource_addresses:
                    return current
            return None

        # plan 2: functions that dereference `curr_clocksource` itself.
        # `current_clocksource_show()` prints `curr_clocksource->name`, so the pointer is the
        # first global it loads. It is named `sysfs_show_current_clocksources()` before v5.9 and
        # both need CONFIG_SYSFS. `__clocksource_watchdog_kthread()` (v5.13 or later, needs
        # CONFIG_CLOCKSOURCE_WATCHDOG) also loads it first, for the per-cpu skew check.
        for name in ("current_clocksource_show", "sysfs_show_current_clocksources",
                     "__clocksource_watchdog_kthread"):
            # These are small, so a fixed window would spill into the next symbol.
            for addr in Ksym.get_addrs(name, match="split"):
                try:
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 200)
                except gdb.error:
                    continue
                current = first_listed_clocksource(res)
                if current is not None:
                    return current

        # plan 3: timekeeping_notify() compares its argument with timekeeper.tkr_mono.clock.
        # Recover that referenced pointer and only accept it when it points to an entry in
        # clocksource_list. timekeeping is switched over after `curr_clocksource` is updated,
        # so while the selector is still moving (refined-jiffies -> tsc-early -> tsc during
        # boot) this lags behind plan 1/2. Keep it last for kernels without the anchors above.
        addr = Ksym.get_addr("timekeeping_notify")
        if not addr:
            return None
        try:
            res = gdb.execute("x/80i {:#x}".format(addr), to_string=True)
        except gdb.error:
            return None
        return first_listed_clocksource(res)

    @staticmethod
    @switch_to_intel_syntax
    def get_capability_hooks():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("capability_hooks")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (search for the memory; available v4.2 or later)
        # `capability_hooks` is referenced only from `capability_init()`, which is __init and
        # already freed, so there is no instruction to follow. Search the data area for the
        # `hook` members instead. The head of the array is always these 3 entries.
        if kversion and "4.2" <= kversion:
            hooks = ["cap_capable", "cap_settime", "cap_ptrace_access_check"]
            hooks = [Ksym.get_addr(x) for x in hooks]
            image_range = KernelAddressHeuristicFinderUtil.get_kernel_image_range()
            klayout = Kernel.layout(use_iomem=False)
            start = klayout.ro_base or klayout.text_base # `capability_hooks` is never in .text
            if all(hooks) and start:
                if image_range and start < image_range[1]:
                    end = image_range[1]
                else:
                    # An old (=RWX) kernel has no detectable .data range. Scan a bounded area
                    # following .rodata, where `capability_hooks` is defined.
                    end = (klayout.ro_end or start) + 0x1000000
                ptrsize = runtime.current_arch.ptrsize
                if ptrsize == 4:
                    pack = p32
                else:
                    pack = p64
                hooks = [pack(x) for x in hooks]
                chunk_size = 0x100000
                # The area has unmapped holes, so read it chunk by chunk and pad the
                # unreadable pages with zero to keep the offset of the readable pages.
                for addr in range(start, end, chunk_size - ptrsize * 40):
                    size = min(chunk_size, end - addr)
                    data = GefUtil.read_memory_padded(addr, size)
                    pos = -1
                    while True:
                        pos = data.find(hooks[0], pos + 1)
                        if pos == -1:
                            break
                        if pos % ptrsize:
                            continue
                        # sizeof(security_hook_list) is 3 pointers from v6.12 (`scalls`, `hook`,
                        # `lsmid`), otherwise 4 pointers or more (`list`, `head`, `hook`,
                        # optional `lsm` and padding), so detect it from the array itself.
                        for stride in range(ptrsize * 3, ptrsize * 17, ptrsize):
                            if data[pos + stride:pos + stride + ptrsize] != hooks[1]:
                                continue
                            if data[pos + stride * 2:pos + stride * 2 + ptrsize] != hooks[2]:
                                continue
                            if stride == ptrsize * 3:
                                offset_hook = ptrsize
                            else:
                                offset_hook = ptrsize * 3
                            return addr + pos - offset_hook
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_n_tty_ops():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("n_tty_ops")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.6 or later)
        if kversion and "4.6" <= kversion:
            addr = Ksym.get_addr("n_tty_inherit_ops")
            if addr:
                # KASAN/KCOV builds interleave instrumentation, pushing &n_tty_ops past 20 insns
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 40)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_x86_dword_ptr_src(res),
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res),
                    )
                elif is_arm64():
                    # &n_tty_ops may be built as adrp + add + add
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                    )
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_tty_ldiscs():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("tty_ldiscs")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.6.37 or later)
        if kversion and "2.6.37" <= kversion:
            addr = Ksym.get_addr("tty_register_ldisc")
            if addr:
                if is_x86_64():
                    instruction_count = 40
                else:
                    instruction_count = 20
                res = gdb.execute("x/{:d}i {:#x}".format(instruction_count, addr), to_string=True)
                if is_x86_64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_array_base(res),
                        KernelAddressHeuristicFinderUtil.x64_lea_array_base(res),
                    )
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
                    # a small displacement (e.g. `[rax*8-0x28]`) normalizes to an unreadable address
                    if not is_valid_addr(x):
                        continue
                    for i in range(2):
                        v = read_int_from_memory(x + runtime.current_arch.ptrsize * i)
                        if not is_valid_addr(v):
                            continue
                        if kversion < "5.13":
                            w = read_int32_from_memory(v)
                            if w == 0x00005403: # magic
                                return x + runtime.current_arch.ptrsize * i
                        else:
                            w = read_int_from_memory(v)
                            if not is_valid_addr(w):
                                continue
                            s = read_cstring_from_memory(w) # name
                            if s and len(s) > 2:
                                return x + runtime.current_arch.ptrsize * i
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sysctl_table_root():

        def is_sysctl_table_root(x):
            # Since v3.4, default_set (the first member) has dir.header.root and dir.header.set in a row,
            # and both point back to the root. Slot 0 (is_seen) is skipped so that an empty list_head does not pass.
            data = read_memory(x, 0x80, safe=True)
            if data is None:
                return False
            values = slice_unpack(data, runtime.current_arch.ptrsize)
            return any(a == b == x for a, b in zip(values[1:], values[2:]))

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("sysctl_table_root")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.6.25 or later)
        # register_sysctl() is added in v3.4, and register_sysctl_paths() passes the same root until v3.3.
        if kversion:
            if "3.4" <= kversion:
                addr = Ksym.get_addr("register_sysctl") or Ksym.get_addr("register_sysctl_sz")
            else:
                addr = Ksym.get_addr("register_sysctl_paths")
            if addr:
                # register_sysctl() is a short wrapper, and the next function builds other addresses with adrp + add + add
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 20)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rdi")
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "e[a-d]x")
                elif is_arm64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res, include_lui=is_riscv32())
                else:
                    g = []
                for x in g:
                    if kversion < "3.4" or is_sysctl_table_root(x):
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_selinux_state():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("selinux_state")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.19 ~ v6.3, while the callee still takes &selinux_state as 1st arg)
        # show_sid() is a plain static helper and is inlined away in some builds, but
        # selinux_capset() is an LSM hook whose address is taken, so it always stays a symbol.
        if kversion and "4.19" <= kversion < "6.4":
            for name in ["show_sid", "selinux_capset"]:
                addr = Ksym.get_addr(name)
                if addr is None:
                    continue
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

        # plan 3 (available v6.4 or later)
        # v6.4 dropped the `struct selinux_state *` argument, so show_sid() no longer holds the
        # address. avc_denied() reads `selinux_state.enforcing` (= offset 0) via enforcing_enabled().
        if kversion and "6.4" <= kversion:
            for addr in Ksym.get_addrs("avc_denied", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 32)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_any_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldrb(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    # `enforcing` and the following `initialized` are bool, so reject other globals.
                    if (read_int8_from_memory(x, safe=True) in [0, 1]
                            and read_int8_from_memory(x + 1, safe=True) in [0, 1]):
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_apparmor_enabled():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("apparmor_enabled")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.12 or later)
        # `apparmor_enabled` is bool before v5.1, so ARM loads it by `ldrb`.
        if kversion and "4.12" <= kversion:
            addr = Ksym.get_addr("param_get_aauint")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_any_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64() and kversion < "5.1":
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldrb(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32() and kversion < "5.1":
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res, mnemonic="ldrb")
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res)
                for x in g:
                    return x

        # plan 3 (param_get_aauint has no apparmor_enabled check before v4.12)
        addr = Ksym.get_addr("param_get_mode")
        if addr:
            res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_any_ptr_rip_base(res)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
            elif is_arm64() and kversion and kversion < "5.1":
                g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldrb(res)
            elif is_arm64():
                g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
            elif is_arm32() and kversion and kversion < "5.1":
                g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res, mnemonic="ldrb")
            elif is_arm32():
                g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res)
            for x in g:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_apparmor_initialized():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("apparmor_initialized")
            # `apparmor_initialized` is __initdata and freed after boot before v4.12,
            # so a symbol landing in the freed init region is not a usable runtime target.
            if x and not KernelAddressHeuristicFinderUtil.is_in_freed_init_region(x):
                return x

        # plan 2
        # This is not gated on v4.12. A distro kernel backports the apparmor rework, so a v4.4
        # can keep `apparmor_initialized` live and reference it from this parameter handler too.
        # What the older layout actually produces is a candidate in the freed init region,
        # so reject that instead of the version.
        kversion = Kernel.version()
        addr = Ksym.get_addr("param_get_aauint")
        if addr:
            res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
            g = ()
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_any_ptr_rip_base(res, skip=1)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res, skip=1)
            elif is_arm64() and kversion and kversion < "5.1":
                # the preceding `apparmor_enabled` is bool and loaded by `ldrb`
                g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
            elif is_arm64():
                g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, skip=1)
            elif is_arm32():
                g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, skip=1)
            for x in g:
                if KernelAddressHeuristicFinderUtil.is_in_freed_init_region(x):
                    continue
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_kernel_locked_down():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("kernel_locked_down")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v5.4 or later)
        if kversion and "5.4" <= kversion:
            for addr in Ksym.get_addrs("lock_kernel_down", match="split"):
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

        # plan 3 (lock_kernel_down is fully inlined in some builds, but the LSM hook always remains)
        if kversion and "5.4" <= kversion:
            for addr in Ksym.get_addrs("lockdown_is_locked_down", match="split"):
                # KCOV builds interleave __sanitizer_cov_trace_* calls, pushing the load past 10 insns
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 20)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_any_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                for x in g:
                    return x

        # plan 4 (before v5.4, distro backports export __kernel_is_locked_down instead)
        for addr in Ksym.get_addrs("__kernel_is_locked_down", match="split"):
            res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 10)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_any_ptr_rip_base(res)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
            elif is_arm64():
                g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldrb(res)
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
            x = Ksym.get_addr("tomoyo_enabled")
            if x:
                return x

        def get_from_check_profile():
            """Handle builds that keep `tomoyo_enabled` outside the hook array."""
            if not is_x86_64():
                return None
            for addr in Ksym.get_addrs("tomoyo_check_profile", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 20)

                # Some v5.3 builds put a 32-byte slot for tomoyo_enabled between the
                # io-buffer list and tomoyo_ss instead of next to tomoyo_hooks[].
                for ss in KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res):
                    x = ss - 0x20
                    try:
                        if (read_int32_from_memory(x) in [0, 1]
                                and read_memory(x + 4, 0x1C) == b"\0" * 0x1C
                                and is_double_link_list(x - 0x20)):
                            return x
                    except (gdb.MemoryError, MemoryError):
                        pass

                # Before DEFINE_LSM(tomoyo), tomoyo_enabled follows tomoyo_last_pid and
                # precedes the tomoyo_policy_loaded byte written by this function.
                kversion = Kernel.version()
                if kversion and kversion < "5.1":
                    policy_loads = KernelAddressHeuristicFinderUtil.x64_byte_ptr_rip_base(res)
                    for policy_loaded in policy_loads:
                        x = policy_loaded - 8
                        try:
                            if (read_int32_from_memory(x) in [0, 1]
                                    and read_memory(x + 4, 4) == b"\0" * 4):
                                return x
                        except (gdb.MemoryError, MemoryError):
                            pass
            return None

        # plan 2 (search for the memory; available v5.1 or later)
        # `tomoyo_enabled` is held only by DEFINE_LSM(tomoyo) in `.lsm_info.init` and read only
        # by tomoyo_interface_init(), both freed by free_initmem(), so no instruction points at
        # it. It is emitted next to `tomoyo_hooks[]` and `tomoyo_blob_sizes`, so search around
        # `tomoyo_blob_sizes`, which tomoyo_task() still materializes, for the array and take
        # the slot next to it. It holds 0 whenever TOMOYO is not the active LSM, so the value
        # cannot tell the slot apart from the padding.
        anchor = None
        for name in ["tomoyo_task_free", "tomoyo_task_alloc", "tomoyo_cred_prepare"]:
            addr = Ksym.get_addr(name)
            if addr is None:
                continue
            res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
            elif is_arm64():
                # `lbs_task` is an `int` used as an offset, so it can be loaded either way
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_ldrsw(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res),
                )
            elif is_arm32():
                g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res)
            elif is_riscv32() or is_riscv64():
                g = KernelAddressHeuristicFinderUtil.riscv_load(res, mnemonic="lwu" if is_riscv64() else "lw")
            else:
                return get_from_check_profile()
            anchor = next(iter(g), None)
            if anchor is not None:
                break
        ret = Ksym.get_kallsyms()
        if anchor is None or ret is None:
            return get_from_check_profile()
        kallsyms, _kallsyms_map = ret
        hooks = {a for a, name, typ in kallsyms if name.startswith("tomoyo_") and typ in "tT"}

        ptrsize = runtime.current_arch.ptrsize
        unpack = GefUtil.get_unpack(ptrsize)
        window = 0x8000 # the whole `.data..ro_after_init` block of tomoyo.c fits in this
        base = (anchor & ~(ptrsize - 1)) - window # keep the window aligned to the pointer slots
        data = GefUtil.read_memory_padded(base, window * 2)
        found = {base + i for i in range(0, len(data) - ptrsize, ptrsize) if unpack(data[i:i + ptrsize]) in hooks}

        # sizeof(security_hook_list) is 3 pointers from v6.12 (`scalls`, `hook`, `lsmid`),
        # otherwise 4 pointers or more (`list`, `head`, `hook`, optional `lsm` and padding),
        # so detect it from the array itself. `tomoyo_operations` also holds tomoyo functions,
        # so adopt the longest run to avoid mistaking a file_operations for the array.
        entries, stride = [], None
        for step in [ptrsize * n for n in [3, 4, 5]]:
            for head in found:
                if head - step in found:
                    continue
                run = [head]
                while run[-1] + step in found:
                    run.append(run[-1] + step)
                if len(run) > len(entries):
                    entries, stride = run, step
        if len(entries) < 8:
            return get_from_check_profile()
        if stride == ptrsize * 3:
            offset_hook = ptrsize
        else:
            offset_hook = ptrsize * 3
        start = entries[0] - offset_hook
        end = entries[-1] - offset_hook + stride

        # How much padding is in front of the array depends on the alignment the compiler gives
        # it, which is 32 in most builds but not all. It is a build-wide property and the other
        # LSMs keep their hook array in the same section, so take the alignment all of them
        # satisfy. Only the `hook` member of an entry points into .text, so drop the neighbors
        # of a text pointer to skip the plain function tables, then the arrays are the runs
        # left at the same stride.
        klayout = Kernel.layout()
        pointers = {base + i for i in range(0, len(data) - ptrsize, ptrsize)
                       if klayout.text_base <= unpack(data[i:i + ptrsize]) < klayout.text_end}
        pointers = {x for x in pointers if x - ptrsize not in pointers and x + ptrsize not in pointers}
        align = 0x20
        for head in pointers:
            if head - stride in pointers:
                continue
            count = 1
            while head + count * stride in pointers:
                count += 1
            if count >= 8:
                array_base = head - offset_hook
                align = min(align, array_base & -array_base)

        # The compiler is free to order the 3 objects, and `tomoyo_enabled` is 4 bytes, so it
        # takes whichever slot the other two leave next to the array.
        try:
            if start - 0x20 <= anchor < start:
                # `tomoyo_blob_sizes` is in front of the array. `tomoyo_enabled` only fits there
                # when `lbs_task` is its last member, which ends the struct 4 bytes early.
                if anchor == start - 8:
                    x = start - 4
                else:
                    x = end
                if read_int32_from_memory(x) in [0, 1]:
                    return x
            else:
                # `tomoyo_blob_sizes` is behind the array, so `tomoyo_enabled` heads the block
                # and the alignment padding of the array follows it. The value is 0 whenever
                # TOMOYO is not the active LSM, so only the padding tells the slot apart.
                x = start - align
                if read_int32_from_memory(x) in [0, 1]:
                    if read_memory(x + 4, align - 4) == b"\0" * (align - 4):
                        return x
        except (gdb.MemoryError, MemoryError):
            pass
        return get_from_check_profile()

    @staticmethod
    @switch_to_intel_syntax
    def get_mmap_min_addr():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("mmap_min_addr")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.6.26 or later)
        # mmap_min_addr_handler() is the only non-init writer of mmap_min_addr, so the
        # store destination tells it apart from the dac_mmap_min_addr it loads first.
        addr = Ksym.get_addr("mmap_min_addr_handler")
        if addr:
            res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 100)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base_store(res)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_noptr_ds_store(res)
            elif is_arm64():
                g = KernelAddressHeuristicFinderUtil.aarch64_adrp_str(res)
            elif is_arm32():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt_str(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_str(res),
                )
            for x in g:
                return x

        # plan 3 (available v4.19.27 or later, but not on the 4.20 branch before v4.20.14)
        # expand_downwards() also loads stack_guard_gap, so a build without the inlined
        # mmap_min_addr check yields that instead. Keep this behind the exact store above.
        if kversion and "4.19.27" <= kversion:
            addr = Ksym.get_addr("expand_downwards")
            if addr:
                # KASAN/KCOV builds interleave instrumentation, pushing &mmap_min_addr past 80 insns
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 200)
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
    def get_dac_mmap_min_addr():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("dac_mmap_min_addr")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("vm.mmap_min_addr")
            if x:
                return x

        # plan 3 (available v2.6.26 or later)
        # A kernel built without CONFIG_SYSCTL has no sysctl tree at all, so plan 2 can never
        # answer. update_mmap_min_addr() is inlined into mmap_min_addr_handler(), where
        # dac_mmap_min_addr is the load source and mmap_min_addr the store destination.
        addr = Ksym.get_addr("mmap_min_addr_handler")
        if addr:
            res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 100)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                stored = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base_store(res)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                stored = KernelAddressHeuristicFinderUtil.x86_noptr_ds_store(res)
            elif is_arm64():
                g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                stored = KernelAddressHeuristicFinderUtil.aarch64_adrp_str(res)
            elif is_arm32():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                )
                stored = itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt_str(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_str(res),
                )
            stored = set(stored)
            for x in g:
                if x not in stored:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sysctl_unprivileged_userfaultfd():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("sysctl_unprivileged_userfaultfd")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("vm.unprivileged_userfaultfd")
            if x:
                return x

        kversion = Kernel.version()

        # plan 3 (available v5.2 or later)
        # A kernel built without CONFIG_SYSCTL has no sysctl tree at all, so plan 2 can never
        # answer. The userfaultfd(2) entry is the only non-init reader. Its body lands either in
        # `__se_sys_userfaultfd` or, when that is inlined, in the arch syscall wrapper.
        if kversion and "5.2" <= kversion:
            anchors = ["__do_sys_userfaultfd", "__se_sys_userfaultfd", "__x64_sys_userfaultfd",
                       "__ia32_sys_userfaultfd", "__arm64_sys_userfaultfd", "sys_userfaultfd"]
            for name in anchors:
                for addr in Ksym.get_addrs(name, match="split"):
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 60)
                    if is_x86_64():
                        g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                    elif is_x86_32():
                        g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                    elif is_arm64():
                        g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, allow_add=True)
                    elif is_arm32():
                        g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res)
                    for x in g:
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sysctl_unprivileged_bpf_disabled():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("sysctl_unprivileged_bpf_disabled")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.unprivileged_bpf_disabled")
            if x:
                return x

        kversion = Kernel.version()

        # plan 3 (available v4.9.91 ~ v5.18.19)
        if kversion and "4.9.91" <= kversion < "5.19":
            addr = Ksym.get_addr("__do_sys_bpf")
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("kptr_restrict")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.kptr_restrict")
            if x:
                return x

        kversion = Kernel.version()

        # plan 3 (available v4.15 or later)
        if kversion and "4.15" <= kversion:
            addr = Ksym.get_addr("kallsyms_show_value")
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("sysctl_perf_event_paranoid")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.perf_event_paranoid")
            if x:
                return x

        kversion = Kernel.version()

        # plan 3 (available v4.15 or later)
        if kversion and "4.15" <= kversion:
            addr = Ksym.get_addr("kallsyms_show_value")
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("dmesg_restrict")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.dmesg_restrict")
            if x:
                return x

        kversion = Kernel.version()

        # plan 3 (available v3.11 or later)
        # syslog_action_restricted() reads dmesg_restrict; it is usually inlined into
        # check_syslog_permissions. On some x86 builds that function is split into a
        # `check_syslog_permissions.part.0` (no plain symbol) and the read stays in do_syslog,
        # which needs a wide window because the reference sits well after the fast-path return.
        if kversion and "3.11" <= kversion:
            anchors = [("check_syslog_permissions", 40)]
            if is_x86():
                anchors.append(("do_syslog", 80))
            for name, n in anchors:
                for addr in Ksym.get_addrs(name, match="split"):
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, n)
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("kexec_load_disabled")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.kexec_load_disabled")
            if x:
                return x

        # plan 3 (available v3.17 or later)
        # A kernel built without CONFIG_SYSCTL has no sysctl tree at all, so plan 2 can never
        # answer. kexec_load_permitted() holds the check since v6.3; before that it is open coded
        # in both syscall entries, and CONFIG_KEXEC=n leaves kexec_load(2) as an -ENOSYS stub
        # while CONFIG_KEXEC_FILE=y keeps kexec_file_load(2). With CONFIG_CFI the arch wrapper
        # only shuffles the arguments, so the body stays in `__se_sys_*`.
        anchors = ["kexec_load_permitted", "kexec_load_check",
                   "__do_sys_kexec_load", "__se_sys_kexec_load", "__x64_sys_kexec_load",
                   "__ia32_sys_kexec_load", "__arm64_sys_kexec_load", "sys_kexec_load",
                   "__do_sys_kexec_file_load", "__se_sys_kexec_file_load",
                   "__x64_sys_kexec_file_load", "__ia32_sys_kexec_file_load",
                   "__arm64_sys_kexec_file_load", "sys_kexec_file_load"]
        for name in anchors:
            for addr in Ksym.get_addrs(name, match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 60)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, allow_add=True)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res)
                for x in g:
                    # `kexec_load_disabled` is 0 or 1. Some builds materialize the syscall accounting
                    # index at the entry of the syscall, which is a plain load of a global too.
                    if read_int32_from_memory(x, safe=True) in [0, 1]:
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_loadpin_enabled():
        # plan 1 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.loadpin.enabled")
            if x:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_loadpin_enforce():
        # plan 1 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.loadpin.enforce")
            if x:
                return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_ptrace_scope():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("ptrace_scope")
            if x:
                return x

        # plan 2 (from ksysctl)
        if KernelAddressHeuristicFinder.USE_KSYSCTL:
            x = KernelSysctl.get("kernel.yama.ptrace_scope")
            if x:
                return x

        # plan 3 (available v3.4 or later)
        # A kernel built without CONFIG_SYSCTL has no sysctl tree at all, so plan 2 can never
        # answer. Both Yama hooks read `ptrace_scope` before touching any other global, except
        # `__stack_chk_guard` that ARM loads first with CONFIG_STACKPROTECTOR.
        anchors = ["yama_ptrace_access_check", "yama_ptrace_traceme"]
        for name in anchors:
            for addr in Ksym.get_addrs(name, match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 60)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, allow_add=True)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res)
                for x in g:
                    # `ptrace_scope` is 0 to 3 (YAMA_SCOPE_NO_ATTACH)
                    if read_int32_from_memory(x, safe=True) in [0, 1, 2, 3]:
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_vdso_image_64():
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("vdso_image_64")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.2 or later)
        if kversion and "4.2" <= kversion:
            addr = Ksym.get_addr("arch_setup_additional_pages")
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
        if not is_x86_64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("vdso_image_x32")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.2 or later)
        if kversion and "4.2" <= kversion:
            addr = Ksym.get_addr("compat_arch_setup_additional_pages")
            if addr:
                # Both vdso_image_32 and vdso_image_x32 are loaded here; their branch
                # order varies, so use a window long enough to reach the later one.
                res = gdb.execute("x/40i {:#x}".format(addr), to_string=True)
                g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rdi", read_valid=True)
                for x in g:
                    v = read_int_from_memory(x)
                    if read_memory(v, 4) == b"\x7fELF" and read_memory(v + 0x12, 1) == b"\x3e": # Elf.Machine
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_vdso_image_32():
        if not is_x86():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("vdso_image_32")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.2 or later)
        if kversion and "4.2" <= kversion:
            if is_x86_64():
                addr = Ksym.get_addr("compat_arch_setup_additional_pages")
                if addr:
                    # Both vdso images are loaded here in version-dependent order,
                    # so use a window long enough to reach the later one.
                    res = gdb.execute("x/40i {:#x}".format(addr), to_string=True)
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, "rdi", read_valid=True)
                    for x in g:
                        v = read_int_from_memory(x)
                        if read_memory(v, 4) == b"\x7fELF" and read_memory(v + 0x12, 1) == b"\x03": # Elf.Machine
                            return x
            elif is_x86_32():
                addr = Ksym.get_addr("arch_setup_additional_pages")
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
        if not is_arm64():
            return None

        def looks_like_vdso_info(addr):
            if addr % runtime.current_arch.ptrsize != 0 or not is_valid_addr(addr):
                return False
            try:
                name = read_int_from_memory(addr)
                code_start = read_int_from_memory(addr + runtime.current_arch.ptrsize)
                return (is_valid_addr(name)
                        and read_cstring_from_memory(name) == "vdso"
                        and code_start % get_pagesize() == 0
                        and is_valid_addr(code_start)
                        and read_memory(code_start, 4) == b"\x7fELF")
            except (gdb.MemoryError, MemoryError):
                return False

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("vdso_info")
            if x:
                return x

        kversion = Kernel.version()

        # vdso_info is introduced from v5.8
        if kversion is None or kversion < "5.8":
            return None

        # plan 2 (available v5.8 or later)
        if kversion and "5.8" <= kversion:
            for addr in Ksym.get_addrs("__vdso_init", match="split"):
                try:
                    res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                except gdb.MemoryError:
                    res = None
                if res:
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                    for x in g:
                        if looks_like_vdso_info(x):
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
        klayout = Kernel.layout()
        if klayout.ro_base and klayout.ro_size:
            ro_data = read_memory(klayout.ro_base, klayout.ro_size)
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
                    vdso_addr_byteseq = p32(klayout.ro_base + pos)
                else:
                    vdso_addr_byteseq = p64(klayout.ro_base + pos)

                # search for it from .rodata again
                pos2 = -1
                while True:
                    pos2 = ro_data.find(vdso_addr_byteseq, pos2 + 1)
                    if pos2 == -1:
                        break
                    if pos2 % runtime.current_arch.ptrsize != 0:
                        continue
                    maybe_vdso_info = klayout.ro_base + pos2
                    maybe_vdso_info -= runtime.current_arch.ptrsize
                    name = read_int_from_memory(maybe_vdso_info)
                    if not is_valid_addr(name):
                        continue
                    if read_cstring_from_memory(name) == "vdso":
                        return maybe_vdso_info
        return None

    @staticmethod
    def get_vdso_lookup():
        if not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("vdso_lookup")
            if x:
                return x

        kversion = Kernel.version()

        # vdso_info is introduced until v5.8
        if kversion and (kversion < "5.3" or "5.8" <= kversion):
            return None

        # plan 2 (available v5.3 or later)
        if kversion and "5.3" <= kversion:
            for addr in Ksym.get_addrs("__vdso_init", match="split"):
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
        klayout = Kernel.layout()
        if klayout.ro_base and klayout.ro_size:
            ro_data = read_memory(klayout.ro_base, klayout.ro_size)
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
                    vdso_addr_byteseq = p32(klayout.ro_base + pos)
                else:
                    vdso_addr_byteseq = p64(klayout.ro_base + pos)

                # search for it from .rodata again
                pos2 = -1
                while True:
                    pos2 = ro_data.find(vdso_addr_byteseq, pos2 + 1)
                    if pos2 == -1:
                        break
                    if pos2 % runtime.current_arch.ptrsize != 0:
                        continue
                    maybe_vdso_lookup = klayout.ro_base + pos2
                    maybe_vdso_lookup -= runtime.current_arch.ptrsize
                    name = read_int_from_memory(maybe_vdso_lookup)
                    if not is_valid_addr(name):
                        continue
                    if read_cstring_from_memory(name) == "vdso":
                        return maybe_vdso_lookup
        return None

    @staticmethod
    def get_vdso_start():
        if not is_arm32() and not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("vdso_start")
            if x:
                return x

        kversion = Kernel.version()

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
        klayout = Kernel.layout()
        if klayout.ro_base and klayout.ro_size:
            ro_data = read_memory(klayout.ro_base, klayout.ro_size)
            pos = -1
            while True:
                # search for aligned ELF header from .rodata
                pos = ro_data.find(b"\x7fELF", pos + 1)
                if pos == -1:
                    break
                if pos % get_pagesize() == 0:
                    return klayout.ro_base + pos
        return None

    @staticmethod
    def get_vdso32_start():
        if not is_arm64():
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("vdso32_start")
            if x:
                return x

        kversion = Kernel.version()

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
    def file_system_type_link_offset(kversion):
        # name, padded fs_flags, mount, kill_sb, owner
        if kversion < "5.1":
            return runtime.current_arch.ptrsize * 5
        # v5.1 added init_fs_context and parameters
        if kversion < "6.20":
            return runtime.current_arch.ptrsize * 7
        # v6.20 removed mount
        return runtime.current_arch.ptrsize * 6

    @staticmethod
    @switch_to_intel_syntax
    def get_file_systems():

        def looks_like_file_systems(addr):
            try:
                first_node = read_int_from_memory(addr)
                if not is_valid_addr(first_node):
                    return False
                fs_type = first_node
                if "7.2" <= kversion:
                    if read_int_from_memory(first_node + runtime.current_arch.ptrsize) != addr:
                        return False
                    fs_type -= KernelAddressHeuristicFinder.file_system_type_link_offset(kversion)
                name_addr = read_int_from_memory(fs_type)
                return is_valid_addr(name_addr) and bool(read_cstring_from_memory(name_addr))
            except gdb.MemoryError:
                pass
            return False

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("file_systems")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.5.7 or later)
        if kversion and "2.5.7" <= kversion:
            anchors = (("unregister_filesystem", 20), ("register_filesystem", 60))
            for symbol, instruction_count in anchors:
                addr = Ksym.get_addr(symbol)
                if not addr:
                    continue
                try:
                    res = gdb.execute("x/{:d}i {:#x}".format(instruction_count, addr), to_string=True)
                except gdb.MemoryError:
                    continue
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
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_use(res, read_valid=True)
                else:
                    continue
                for x in g:
                    if looks_like_file_systems(x):
                        return x
        return None

    @staticmethod
    def get_log_buffer(buf_len, buffer_pointer_address=None):
        """Find the storage currently used by the legacy log_buf ring."""
        kversion = Kernel.version()
        if kversion and "5.10" <= kversion:
            return False

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            addr = Ksym.get_addr("log_buf")
            if addr:
                x = read_int_from_memory(addr, safe=True)
                if x and is_valid_addr(x):
                    return x

        # plan 2 (from the resolved log_buf pointer)
        if buffer_pointer_address:
            try:
                x = read_int_from_memory(buffer_pointer_address)
                if x and is_valid_addr(x):
                    read_memory(x, min(buf_len, 16))
                    return x
            except gdb.error:
                pass

        # plan 3 (from log_buf_len)
        addr = KernelAddressHeuristicFinder.get_log_buf_len()
        if addr:
            pattern = tuple(dict.fromkeys((runtime.current_arch.ptrsize, 4, -runtime.current_arch.ptrsize, -4)))
            for diff in pattern:
                try:
                    x = read_int_from_memory(addr + diff)
                    if x and is_valid_addr(x):
                        read_memory(x, min(buf_len, 16))
                        return x
                except gdb.error:
                    continue

        # plan 4 (from __log_buf)
        x = KernelAddressHeuristicFinder.get___log_buf()
        if x and is_valid_addr(x):
            return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_printk_text_ring_symbols():
        """Find text ring metadata through symbols or emit_log_char."""
        log_end = None
        buf_len = None
        buffer_pointer = None
        source = "symbols"

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            log_end = Ksym.get_addr("log_end")
            buf_len = Ksym.get_addr("log_buf_len")
            buffer_pointer = Ksym.get_addr("log_buf")
            if log_end and buf_len:
                return log_end, buf_len, buffer_pointer, source

        # plan 2 (available before v3.5)
        for addr in Ksym.get_addrs("emit_log_char", match="split"):
            try:
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 80)
            except gdb.error:
                continue
            if is_x86_64():
                pointer_refs = list(KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res))
                data_refs = list(KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res))
                stores = []
                for line in res.splitlines():
                    match = re.search(r"DWORD PTR \[rip\+0x\w+\],[^#]*#\s*(0x\w+)", line)
                    if match:
                        stores.append(AddressUtil.normalize_address(int(match.group(1), 16)))
            elif is_x86_32():
                pointer_refs = list(KernelAddressHeuristicFinderUtil.x86_noptr_ds(res))
                data_refs = pointer_refs
                stores = list(KernelAddressHeuristicFinderUtil.x86_noptr_ds_store(res))
            elif is_arm64():
                pointer_refs = list(itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, allow_add=True),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res),
                ))
                data_refs = pointer_refs
                stores = list(KernelAddressHeuristicFinderUtil.aarch64_adrp_str(res))
            elif is_arm32():
                pointer_refs = list(itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                ))
                data_refs = pointer_refs
                stores = list(itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt_str(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_str(res),
                ))
            else:
                continue

            if not buffer_pointer:
                for x in dict.fromkeys(pointer_refs):
                    try:
                        v = read_int_from_memory(x)
                        if v and is_valid_addr(v):
                            read_memory(v, 16)
                            buffer_pointer = x
                            break
                    except gdb.error:
                        continue

            if not buf_len:
                length_candidates = []
                if buffer_pointer:
                    for offset in (runtime.current_arch.ptrsize, -runtime.current_arch.ptrsize, 4, -4):
                        length_candidates.append(buffer_pointer + offset)
                length_candidates.extend(data_refs)
                for x in dict.fromkeys(length_candidates):
                    try:
                        v = read_int32_from_memory(x)
                        if 0x1000 <= v <= 1 << 30 and v & (v - 1) == 0:
                            buf_len = x
                            break
                    except gdb.error:
                        continue

            if not log_end:
                for x in itertools.chain(stores, data_refs):
                    if x in (buf_len, buffer_pointer):
                        continue
                    if buffer_pointer and abs(x - buffer_pointer) <= runtime.current_arch.ptrsize + 4:
                        continue
                    try:
                        read_int32_from_memory(x)
                        log_end = x
                        break
                    except gdb.error:
                        continue

            if log_end and buf_len:
                source = "emit_log_char heuristic"
                return log_end, buf_len, buffer_pointer, source
        return log_end, buf_len, buffer_pointer, source

    @staticmethod
    @switch_to_intel_syntax
    def get_printk_ring_candidates():
        """Collect candidate addresses for the active descriptor ring."""
        candidates = []

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            addr = Ksym.get_addr("prb")
            if addr:
                try:
                    candidates.append((read_int_from_memory(addr), "prb"))
                except gdb.error:
                    pass

        # plan 2 (available v5.10 or later)
        for name in ("kmsg_dump_rewind", "kmsg_dump_rewind_nolock"):
            addr = Ksym.get_addr(name)
            if not addr:
                continue
            try:
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 80)
            except gdb.error:
                continue
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res, read_valid=True)
            elif is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res, read_valid=True)
            elif is_arm64():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, read_valid=True),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res, read_valid=True),
                )
            elif is_arm32():
                g = KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res, read_valid=True)
            elif is_riscv64() or is_riscv32():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.riscv_auipc_use(res, read_valid=True),
                    KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                )
            else:
                continue
            for x in g:
                try:
                    candidates.append((read_int_from_memory(x), "heuristic"))
                except gdb.error:
                    continue

        result = []
        seen = set()
        for address, source in candidates:
            if address and address not in seen:
                result.append((address, source))
                seen.add(address)
        return result

    @staticmethod
    @switch_to_intel_syntax
    def get_log_first_idx():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("log_first_idx")
            if x:
                return x

        kversion = Kernel.version()

        # this is old dmesg structure
        if kversion and "5.10" <= kversion:
            return False

        # plan 2 (available v3.5 or later)
        if kversion and "3.5" <= kversion:
            for addr in Ksym.get_addrs("devkmsg_open", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 80)
                if is_x86_64():
                    seqs = set(KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res))
                    refs = list(KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res))
                    g = [x for x in refs if x + runtime.current_arch.ptrsize in seqs]
                    if not g and len(refs) == 1:
                        g = refs
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_mov_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                    )
                elif is_riscv64() or is_riscv32():
                    stores = KernelAddressHeuristicFinderUtil.riscv_load_store(res)
                    idx_offset = GefUtil.member_offset("struct devkmsg_user", "idx")
                    seq_offset = GefUtil.member_offset("struct devkmsg_user", "seq")
                    if idx_offset is None:
                        idx_offset = 8
                    else:
                        idx_offset = idx_offset
                    if seq_offset is None:
                        seq_offset = 0
                    else:
                        seq_offset = seq_offset
                    width = runtime.current_arch.ptrsize
                    g = set()
                    for (base, offset, size), source in stores.items():
                        if offset != idx_offset or size != 4 or base in ("sp", "gp", "tp"):
                            continue
                        if (base, seq_offset, width) not in stores:
                            continue
                        if width == 4 and (base, seq_offset + 4, 4) not in stores:
                            continue
                        g.add(source)
                    if len(g) != 1:
                        continue
                    x = g.pop()
                    length_addr = KernelAddressHeuristicFinder.get_log_buf_len()
                    if length_addr:
                        length = read_int32_from_memory(length_addr, safe=True)
                    else:
                        length = None
                    value = read_int32_from_memory(x, safe=True)
                    if value is not None and length and value < length:
                        return x
                    continue
                else:
                    return None
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("log_next_idx")
            if x:
                return x

        kversion = Kernel.version()

        # this is old dmesg structure
        if kversion and "5.10" <= kversion:
            return False

        # plan 2 (available v3.5 or later)
        if kversion and "3.5" <= kversion:
            addr = Ksym.get_addr("kmsg_dump_rewind_nolock")
            if addr:
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(
                    addr, 40 if is_riscv64() or is_riscv32() else 20,
                )
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
                elif is_riscv64() or is_riscv32():
                    stores = KernelAddressHeuristicFinderUtil.riscv_load_store(res, base_register="a0")
                    offset = GefUtil.member_offset("struct kmsg_dumper", "next_idx")
                    if offset is None:
                        offset = align(runtime.current_arch.ptrsize * 3 + 6, 4) + 4
                    x = stores.get(("a0", offset, 4))
                    length_addr = KernelAddressHeuristicFinder.get_log_buf_len()
                    if length_addr:
                        length = read_int32_from_memory(length_addr, safe=True)
                    else:
                        length = None
                    if x:
                        value = read_int32_from_memory(x, safe=True)
                    else:
                        value = None
                    if value is not None and length and value < length:
                        return x
                    else:
                        return None
                else:
                    return None
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("__log_buf")
            if x:
                return x

        kversion = Kernel.version()

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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("log_buf_len")
            if x:
                return x

        kversion = Kernel.version()

        # this is old dmesg structure
        if kversion and "5.10" <= kversion:
            return False

        # plan 2 (available v3.17 or later)
        if kversion and "3.17" <= kversion:
            addr = Ksym.get_addr("log_buf_len_get")
            if addr:
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 10)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                    )
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_load(res)
                else:
                    return None
                for x in g:
                    v = read_int32_from_memory(x)
                    if v and (v & 0xfff) == 0:
                        return x

        # plan 3 (available v3.5 or later)
        if kversion and "3.5" <= kversion:
            for addr in Ksym.get_addrs("do_syslog", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 300)
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
                elif is_riscv64() or is_riscv32():
                    g = KernelAddressHeuristicFinderUtil.riscv_load(res)
                else:
                    return None
                for x in g:
                    v = read_int32_from_memory(x)
                    if v and (v & 0xfff) == 0:
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_idt_base():
        if is_x86():
            base, _ = GefUtil.get_x86_descriptor_table_register("idtr")
            return base
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_gdt_base():
        if is_x86():
            base, _ = GefUtil.get_x86_descriptor_table_register("gdtr")
            return base
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_tss_base():
        if is_x86():
            if is_qemu_system():
                res = gdb.execute("monitor info registers", to_string=True)
                tr = QemuMonitor.parse_x86_system_segment(res, "TR")
                if tr and not tr["base_truncated"]:
                    return tr["base"]
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_ldt_base():
        if is_x86():
            if is_qemu_system():
                res = gdb.execute("monitor info registers", to_string=True)
                ldtr = QemuMonitor.parse_x86_system_segment(res, "LDT")
                if ldtr and not ldtr["base_truncated"]:
                    return ldtr["base"]
            elif is_vmware():
                # `monitor r ldtr` is buggy
                return None
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_node_data():
        # when CONFIG_NUMA=y (maybe)

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("node_data")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.6.17 or later)
        if kversion and "2.6.17" <= kversion:
            addr = Ksym.get_addr("first_online_pgdat")
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
                    # A small displacement (e.g. `[rbx+rdx*8-0x28]`) normalizes to
                    # 0xffffffffffffffXX, which passes the MSB check but is not readable.
                    v = next((node for index, node in GefUtil.iter_kernel_node_pointers(x, "node_data")), None)
                    if v is None:
                        continue
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

        kversion = Kernel.version()

        # plan 1 (available v2.6.17 or later)
        if kversion and "2.6.17" <= kversion:
            addr = Ksym.get_addr("first_online_pgdat")
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
                    # the candidate itself may be unreadable (e.g. a sign-extended small constant)
                    v = read_int_from_memory(x, safe=True)
                    if v is None:
                        continue
                    if v and is_valid_addr(v):
                        continue
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_prog_idr():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("prog_idr")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.13 or later)
        if kversion and "4.13" <= kversion:
            candidates = KernelAddressHeuristicFinderUtil.collect_idr_candidates("bpf_prog_free_id")
            if not candidates:
                # bpf_prog_free_id() is inlined into its only caller in some builds
                candidates = KernelAddressHeuristicFinderUtil.collect_idr_candidates("__bpf_prog_put")
            if candidates:
                return KernelAddressHeuristicFinderUtil.select_idr(candidates)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_map_idr():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("map_idr")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.13 or later)
        if kversion and "4.13" <= kversion:
            candidates = KernelAddressHeuristicFinderUtil.collect_idr_candidates("bpf_map_free_id")
            if not candidates:
                # bpf_map_free_id() is inlined into its only caller in some builds
                candidates = KernelAddressHeuristicFinderUtil.collect_idr_candidates("__bpf_map_put")
            if candidates:
                return KernelAddressHeuristicFinderUtil.select_idr(candidates)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_vmap_area_list():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("vmap_area_list")
            if x:
                return x

        kversion = Kernel.version()
        if "6.9" <= kversion:
            return None

        fallback = None

        # plan 2 (available v4.7~)
        if kversion and "4.7" <= kversion:
            addr = Ksym.get_addr("register_vmap_purge_notifier")
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
                            fallback = a
                            break

        # plan 3 (available v3.10 ~ v6.3: vread, v6.4~: vread_iter)
        if kversion and "3.17" <= kversion:
            addr = Ksym.get_addr("vread") or Ksym.get_addr("vread_iter")
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
            addrs = Ksym.get_addrs("s_next")
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
            addr = Ksym.get_addr("__insert_vmap_area")
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
        return fallback

    @staticmethod
    @switch_to_intel_syntax
    def get_vmap_nodes_busy_head():
        kversion = Kernel.version()
        if kversion is None or kversion < "6.9":
            return None

        def busy_head(node, min_len):
            # `struct vmap_node` starts with `pool[MAX_VA_SIZE_PAGES]`, then `pool_lock` and
            # `skip_populate`, then `busy.root` and `busy.head`. The gap before `busy` depends
            # on `sizeof(spinlock_t)`, which grows with the lock debug options (0x90 on PREEMPT_RT with LOCK_STAT).
            base = node + runtime.current_arch.ptrsize * 3 * 256
            for i in range(32):
                head = base + runtime.current_arch.ptrsize * i
                if is_double_link_list(head, min_len=min_len):
                    return head
            return None

        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("vmap_nodes")
            if x:
                return busy_head(read_int_from_memory(x), 0)

        def indirect_heads(sources):
            # `nr_vmap_nodes` is materialized before `vmap_nodes` in every build seen, so draining
            # a source before trying the next one lets the neighbors of `nr_vmap_nodes` answer
            # first. Sweep slot by slot, which gives an exact candidate the first word.
            sources = list(sources)
            for i in range(128):
                for source in sources:
                    node_addr = source + runtime.current_arch.ptrsize * i
                    if not is_valid_addr(node_addr):
                        continue
                    vmap_nodes = read_int_from_memory(node_addr)
                    if is_valid_addr(vmap_nodes):
                        head = busy_head(vmap_nodes, 5)
                        if head:
                            yield head

        for addr in Ksym.get_addrs("find_vmap_area", match="split"):
            res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 100)
            direct_heads = ()
            if is_x86_64():
                # Static vmap_nodes[]: find_vmap_area reads busy.root.rb_node directly.
                direct_heads = (
                    root + runtime.current_arch.ptrsize
                    for root in KernelAddressHeuristicFinderUtil.x64_qword_ptr_disp_load(res, read_valid=True)
                )
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res, read_valid=True),
                    KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, read_valid=True),
                )
            elif is_x86_32():
                # Static vmap_nodes[]: find_vmap_area reads busy.root.rb_node directly,
                # or via the node base made by `lea` (e.g., `lea edi,[eax-0x3d88b8c0]` for `single`).
                direct_heads = itertools.chain(
                    (
                        root + runtime.current_arch.ptrsize
                        for root in KernelAddressHeuristicFinderUtil.x64_x86_dword_ptr_src(res, read_valid=True)
                    ),
                    filter(None, (
                        busy_head(node, 5)
                        for node in KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res, read_valid=True)
                    )),
                )
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.x86_dword_ptr_ds(res, read_valid=True),
                    KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, read_valid=True),
                )
            elif is_arm64():
                # some builds never materialize the address of `vmap_nodes`: they `ldr` it off an
                # `adrp` page, or off an `adrp`+`add` base that belongs to a neighboring symbol
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add_ldr(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res),
                )
            elif is_arm32():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                )
            for head in itertools.chain(direct_heads, indirect_heads(g)):
                if is_double_link_list(head, min_len=5):
                    return head
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_free_vmap_area_list():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("free_vmap_area_list")
            if x:
                return x

        kversion = Kernel.version()
        if kversion is None or kversion < "5.2":
            return None

        # plan 2 (a function that is handed `&free_vmap_area_list` materializes it directly)
        # The scan of plan 3 has two blind spots this plan does not have: `purge_vmap_area_list`
        # also sits between `vmap_area_list` and `free_vmap_area_list` and is counted whenever it
        # is not empty, and v7.1 may place `vmap_notify_list` and `free_vmap_area_list` in
        # different sections, which puts the latter out of reach of a forward scan.
        for name in ("insert_vmap_area_augment", "free_vmap_area"):
            for addr in Ksym.get_addrs(name, match="split"):
                # ARM keeps the constant in a literal pool and reads it ~210 instructions in (~600 with KASAN)
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 1000)
                if is_x86_64() or is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_arm64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    if is_double_link_list(x, min_len=3):
                        return x

        # plan 3 (available v4.7~; here, always True)
        addr = Ksym.get_addr("register_vmap_purge_notifier")
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
                    if kversion and kversion < "6.9":
                        count = 2
                    else:
                        count = 1
                else:
                    count = 1
                for i in range(128):
                    a = x + runtime.current_arch.ptrsize * i
                    if is_double_link_list(a, min_len=3):
                        count -= 1
                    if count == 0:
                        return a

        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_vmap_purge_list():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("vmap_purge_list")
            if x:
                return x

        kversion = Kernel.version()
        if kversion is None or not "4.7" <= kversion < "5.11":
            return None

        llist_add_batch = Ksym.get_addr("llist_add_batch")
        if llist_add_batch is None:
            return None

        # plan 2 (available v4.7~v5.10)
        # `llist_add(&va->purge_list, &vmap_purge_list)` passes the head to llist_add_batch as the third argument.
        # ARM64 keeps it in the register across the call of an out-of-line LL/SC atomic, so registers are
        # tracked without dropping them at calls.
        if is_x86_64():
            target = "rdx"
        elif is_x86_32():
            target = "ecx"
        elif is_arm64():
            target = "x2"
        elif is_arm32():
            target = "r2"
        else:
            return None

        call = re.compile(r"\b(?:call|bl)\s+{:#x}\b".format(llist_add_batch))
        non_writer = re.compile(r"(?:st|cmp|cmn|tst|teq|test|push|pld|prfm|cb|tb|call|j|b(?!ic|fi))")
        for name in ("free_vmap_area_noflush", "free_unmap_vmap_area", "free_vmap_block", "vm_unmap_ram"):
            for addr in Ksym.get_addrs(name, match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 100)
                regs = {}
                for line in res.splitlines():
                    if call.search(line):
                        x = regs.get(target)
                        if x and is_single_link_list(x):
                            return x
                        continue
                    m = re.search(r":\s*(\w+)\s+(\w+)\s*,\s*(.*)", line)
                    if not m:
                        continue
                    mnemonic, dst, src = m.groups()
                    dst = re.sub(r"^w(\d+)$", r"x\1", dst)
                    if dst in ("edx", "dx", "dl") and target == "rdx":
                        dst = "rdx"
                    v = None
                    if mnemonic == "mov" and src in regs:
                        v = regs[src]
                    elif mnemonic == "mov" and is_x86() and re.fullmatch(r"0x\w+", src):
                        v = int(src, 16)
                    elif mnemonic == "lea" and is_x86() and re.search(r"#\s*0x\w+", src):
                        v = int(re.search(r"#\s*(0x\w+)", src).group(1), 16)
                    elif mnemonic in ("adrp", "movw") and re.search(r"0x\w+", src):
                        v = int(re.search(r"0x\w+", src).group(0), 16)
                    elif mnemonic == "movt" and dst in regs and re.search(r"0x\w+", src):
                        v = (regs[dst] & 0xffff) | (int(re.search(r"0x\w+", src).group(0), 16) << 16)
                    elif mnemonic in ("add", "sub") and re.fullmatch(r"(\w+),\s*#(\w+)", src):
                        # ARM32 may derive the head from a neighbor (e.g., `sub r2, r2, #16` from `vmap_lazy_nr`)
                        base, imm = re.fullmatch(r"(\w+),\s*#(\w+)", src).groups()
                        if base in regs:
                            if mnemonic == "add":
                                imm = int(imm, 0)
                            else:
                                imm = -int(imm, 0)
                            v = AddressUtil.normalize_address(regs[base] + imm)
                    elif mnemonic == "ldr" and re.match(r"\[pc,\s*#(\d+)\]", src):
                        pc = int(re.match(r"\s*(?:=>)?\s*(0x[0-9a-f]+)", line).group(1), 16)
                        v = read_int_from_memory(pc + 8 + int(re.match(r"\[pc,\s*#(\d+)\]", src).group(1)), safe=True)
                    if v is not None:
                        regs[dst] = v
                    elif mnemonic in ("stxr", "stlxr", "strex", "stlex") or not non_writer.match(mnemonic):
                        regs.pop(dst, None)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_purge_vmap_area_list():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("purge_vmap_area_list")
            if x:
                return x

        kversion = Kernel.version()
        if kversion is None or not "5.11" <= kversion < "6.9":
            return None

        # plan 2 (available v5.11~v6.8)
        # free_vmap_area_noflush() adds an area to the list, and __purge_vmap_area_lazy() detaches it.
        # The latter also hands the areas to free_vmap_area_list, the only other list_head they touch.
        free_vmap_area_list = KernelAddressHeuristicFinder.get_free_vmap_area_list()
        for name in ("free_vmap_area_noflush", "__purge_vmap_area_lazy"):
            for addr in Ksym.get_addrs(name, match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 300)
                if is_x86_64() or is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_arm64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                for x in g:
                    if x != free_vmap_area_list and is_double_link_list(x):
                        return x
        return None

    @staticmethod
    def get_workqueues():

        def looks_like_workqueues(address):
            try:
                image_range = KernelAddressHeuristicFinderUtil.get_kernel_image_range()
                if image_range is None:
                    klayout = Kernel.layout()
                    image_start = klayout.text_base
                    image_end = max(klayout.text_end, klayout.ro_end) + max(klayout.text_size * 2, 0x100_0000)
                    if not image_start <= address < image_end:
                        return False
                elif not image_range[0] <= address < image_range[1]:
                    return False
                if not is_double_link_list(address, min_len=3):
                    return False
                node = read_int_from_memory(address)
                workqueue = node - runtime.current_arch.ptrsize * 2
                if Kernel.version() >= "3.10":
                    return is_double_link_list(workqueue)
                flags = read_int32_from_memory(workqueue)
                cpu_wq = read_int_from_memory(workqueue + runtime.current_arch.ptrsize)
                return flags < 0x10_0000 and cpu_wq != 0 and not cpu_wq & (runtime.current_arch.ptrsize - 1)
            except gdb.MemoryError:
                return False

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("workqueues")
            if x:
                return x

        # plan 2 (available v2.6.36 or later)
        # `system_wq` is exported while the list head is static. Every workqueue has its
        # `list` member at +2 pointers, so walking from system_wq reaches the only node in
        # the kernel image: the `workqueues` head itself.
        system_wq_ptr = Ksym.get_addr("system_wq")
        if system_wq_ptr:
            try:
                system_wq = read_int_from_memory(system_wq_ptr)
                if is_valid_addr(system_wq):
                    start = system_wq + runtime.current_arch.ptrsize * 2
                    current = read_int_from_memory(start)
                    seen = {start}
                    while current not in seen:
                        if looks_like_workqueues(current):
                            return current
                        if not is_valid_addr(current):
                            break
                        seen.add(current)
                        current = read_int_from_memory(current)
            except gdb.MemoryError:
                pass

        # plan 3: alloc_workqueue() links the new object into the static list.
        for anchor in (
                "alloc_workqueue", "__alloc_workqueue", "__alloc_workqueue_key",
                "show_workqueue_state", "show_all_workqueues", "show_freezable_workqueues",
                "freeze_workqueues_begin", "freeze_workqueues_busy", "thaw_workqueues"):
            for address in Ksym.get_addrs(anchor, match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(address, 500)
                if is_x86_64() or is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_arm64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv32() or is_riscv64():
                    # `workqueues.next` may be loaded directly (e.g. `auipc a5, ...` then `lw s0, ...(a5)`)
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_use(res),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                    )
                else:
                    g = []
                for x in g:
                    if looks_like_workqueues(x):
                        return x
                    if (is_arm32() or is_arm64()) and KernelAddressHeuristicFinderUtil.is_in_kernel_image(x):
                        for offset in range(-0x400, 0x404, runtime.current_arch.ptrsize):
                            if looks_like_workqueues(x + offset):
                                return x + offset
        return None

    @staticmethod
    def find_timer_base_clk(timer_base, cpu):
        """Check the layout invariants of `struct timer_base`, and return the offset of `clk`."""
        layout = KernelAddressHeuristicFinder.find_timer_base_layout(timer_base, cpu)
        if layout is None:
            return None
        return layout[0]

    @staticmethod
    def check_timer_wheel(timer_base, offset_pending, offset_vectors, wheel_size):
        """Return (the number of the mismatches with `pending_map`, the number of the non-empty buckets)
        of the timer wheel, or None if a bucket is broken.
        The bit of `pending_map` is set exactly when the bucket is not empty, except for the bucket
        being moved under the lock."""
        ptrsize = runtime.current_arch.ptrsize
        bits = ptrsize * 8
        try:
            pending = slice_unpack(read_memory(timer_base + offset_pending, wheel_size // 8), ptrsize)
            vectors = slice_unpack(read_memory(timer_base + offset_vectors, wheel_size * ptrsize), ptrsize)
        except gdb.MemoryError:
            return None

        mismatch = nonempty = 0
        for i, first in enumerate(vectors):
            if bool(first) != bool((pending[i // bits] >> (i % bits)) & 1):
                mismatch += 1
            if first == 0:
                continue
            head = timer_base + offset_vectors + i * ptrsize
            if not is_valid_addr(first) or read_int_from_memory(first + ptrsize, safe=True) != head:
                return None
            nonempty += 1
        return mismatch, nonempty

    @staticmethod
    def find_timer_base_layout(timer_base, cpu):
        """Check the layout invariants of `struct timer_base`.
        Return (offset of `clk`, [(offset of `vectors`, WHEEL_SIZE), ...]), or None.
        Both WHEEL_SIZEs are returned for an empty wheel, since it cannot tell them apart."""
        ptrsize = runtime.current_arch.ptrsize
        unpack = GefUtil.get_unpack(ptrsize)
        kversion = Kernel.version()

        header = read_memory(timer_base, 0x200, safe=True)
        if header is None:
            return None

        # Fields inserted by lockdep and PREEMPT_RT move `clk`, so find the stable tail:
        #   unsigned long clk, next_expiry;
        #   unsigned int cpu;
        #   bool next_expiry_recalc, is_idle, timers_pending;
        #   unsigned long pending_map[];
        #   struct hlist_head vectors[WHEEL_SIZE];
        for offset_clk in range(0, len(header) - ptrsize * 2 - 8, ptrsize):
            clk = unpack(header[offset_clk:offset_clk + ptrsize])
            next_expiry = unpack(header[offset_clk + ptrsize:offset_clk + ptrsize * 2])
            offset_cpu = offset_clk + ptrsize * 2
            if u32(header[offset_cpu:offset_cpu + 4]) != cpu:
                continue
            if any(x > 1 for x in header[offset_cpu + 4:offset_cpu + 7]):
                continue
            if clk == 0:
                continue

            # Since v5.14 an empty base can refresh `next_expiry` from current jiffies while
            # `clk` stays stale. `next_expiry` is invalid while recalculation is pending.
            bits = ptrsize * 8
            if next_expiry and (not kversion or kversion < "5.14"
                                or (not header[offset_cpu + 4] and header[offset_cpu + 6])):
                diff = u2i(next_expiry - clk, bits)
                if abs(diff) > (1 << 30) - 1:
                    continue

            # Since the v4.8 timer-wheel rewrite WHEEL_SIZE is 512 or 576, depending on HZ.
            # A 576-bucket wheel whose last `pending_map` word is 0 also passes the check of
            # the heads as a 512-bucket one shifted by a word, so `pending_map` decides it.
            found = []
            for wheel_size in (512, 576):
                offset_vectors = offset_cpu + 8 + wheel_size // 8
                result = KernelAddressHeuristicFinder.check_timer_wheel(timer_base, offset_cpu + 8, offset_vectors, wheel_size)
                if result is not None and result[0] <= 1:
                    found.append((result[0], offset_vectors, wheel_size))
            if found:
                best = min(found)[0]
                return offset_clk, [(offset_vectors, wheel_size) for mismatch, offset_vectors, wheel_size in found if mismatch == best]
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_timer_bases():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("timer_bases")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v4.8 or later)
        if kversion and "4.8" <= kversion:
            for addr in Ksym.get_addrs("run_timer_softirq", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(
                    addr, 40 if is_riscv32() or is_riscv64() else 20,
                )
                if is_arm32() or is_riscv32() or is_riscv64():
                    # v6.19: `run_timer_softirq()` only passes the index to `__run_timer_base()`,
                    # so `timer_bases` is referenced in the callee.
                    # 0xc04052ec <run_timer_softirq+4>: mov r0,#0
                    # 0xc04052f0 <run_timer_softirq+8>: bl  0xc0405264 <__run_timer_base>
                    # 0xffffffff800bf74e <run_timer_softirq+8>:  li  a0,0
                    # 0xffffffff800bf750 <run_timer_softirq+10>: jal 0xffffffff800bf6de <__run_timer_base>
                    m = re.search(r"\b(?:bl|jal)\s+(0x\w+)", res)
                    if m:
                        res += gdb.execute("x/20i {:s}".format(m.group(1)), to_string=True)
                if is_x86_64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_x86_add_reg_const(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res, skip_msb_check=True),
                    )
                    g2 = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res),
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res),
                    )
                elif is_x86_32():
                    # v7.x: 0xc1193ef6 <run_timer_softirq+38>: lea ebx,[eax-0x3d8a8b20] <-- timer_bases (0xc27574e0)
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res, skip_msb_check=True),
                    )
                    g2 = KernelAddressHeuristicFinderUtil.x64_x86_dword_ptr_src(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, skip_msb_check=True)
                    g2 = []
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                    g2 = []
                elif is_riscv32() or is_riscv64():
                    # the per-cpu symbol is a linked address, which is also `&timer_bases` with CONFIG_SMP=n
                    g = list(itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res, skip_msb_check=True, include_lui=True),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                    ))
                    g2 = g
                else:
                    g, g2 = [], []
                g, g2 = list(g), list(g2)

                # pattern3: 32-bit
                # x86_64 / arm64 link the per-cpu section outside the mapped area, so a per-cpu
                # candidate is detectable by `not is_valid_addr(x)` (pattern1). 32-bit kernels
                # put it in the kernel image, so every candidate is a valid address and cannot
                # be told apart. `timer_bases` and `hrtimer_bases` are both in the per-cpu
                # section and are always close to each other (0x1080-0x3e40 in the test corpus),
                # so use `hrtimer_bases` as a landmark.
                # 0xc03cd3e8 <run_timer_softirq+4>: movw r0,#0x5740
                # 0xc03cd3ec <run_timer_softirq+8>: movt r0,#0xc1a5    <-- timer_bases
                # 0xc116cfa1 <run_timer_softirq+1>: mov eax,0xc2c09a00 <-- timer_bases (not per_cpu)
                if is_32bit():
                    hrtimer_bases = KernelAddressHeuristicFinder.get_hrtimer_bases()
                    if hrtimer_bases:
                        for x in itertools.chain(g, g2):
                            if abs(x - hrtimer_bases) < 0x10000:
                                return x

                cpu_offset = Kernel.per_cpu().offsets
                if cpu_offset:
                    # pattern1: per_cpu
                    # pattern1-a:
                    # 0xffffffff8cf25b05 <run_timer_softirq+5>:  mov rdi,0x24b40 <-- timer_bases
                    # pattern1-b:
                    # 0xffffffffa440831e <run_timer_softirq+46>: lea rbx,[rax+0x22400]
                    # `run_timer_softirq()` walks `timer_bases[]` from the tail on some versions,
                    # so scan the candidates in ascending order to get the head of the array.
                    # 0xffffffffad545e60 <run_timer_softirq+96>: add rdi,0x1f540 <-- timer_bases[2]
                    # 0xffffffffad545e1a <run_timer_softirq+26>: lea rax,[rdi+0x1d040] <-- timer_bases
                    for x in sorted(g):
                        if x & (runtime.current_arch.ptrsize - 1):
                            continue
                        cpu_addrs = Kernel.per_cpu().possible_addrs_of(x)
                        if cpu_addrs and all(
                            KernelAddressHeuristicFinder.find_timer_base_clk(addr, cpu) is not None
                            for cpu, addr in cpu_addrs
                        ):
                            return x
                else:
                    # pattern2: not per_cpu
                    # 0xffffffff8aa6e450 <run_timer_softirq>:    mov rax,QWORD PTR [rip+0x7cfba9] # 0xffffffff8b23e000 <jiffies_64>
                    # 0xffffffff8aa6e457 <run_timer_softirq+7>:  cmp rax,QWORD PTR [rip+0x7ce92a] # 0xffffffff8b23cd88 <timer_bases+8>
                    # 0xffffffff8aa6e474 <run_timer_softirq+36>: mov rdx,QWORD PTR [rip+0x7cfb85] # 0xffffffff8b23e000 <jiffies_64>
                    # 0xffffffff8aa6e47b <run_timer_softirq+43>: mov rax,QWORD PTR [rip+0x7ce906] # 0xffffffff8b23cd88 <timer_bases+8>
                    # `__run_timers()` is usually inlined, so only the members are referenced and
                    # `&timer_bases[0]` itself may not appear at all. Snap a candidate back to the
                    # head via the offset of `clk`; `raw_spinlock_t` is an empty struct here
                    # because this pattern means CONFIG_SMP=n, so `clk` follows `running_timer`
                    # at the very head of the structure.
                    # When it is not inlined, each `&timer_bases[i]` is passed as an absolute
                    # immediate instead, so the mov candidates are needed as well.
                    # 0xffffffff95ead669 <run_timer_softirq>:    mov rdi,0xffffffff96b39700 <-- timer_bases
                    # 0xffffffff95ead675 <run_timer_softirq+12>: mov rdi,0xffffffff96b3a980 <-- timer_bases[1]
                    bases = []
                    for x in sorted(set(g2)):
                        if x & (runtime.current_arch.ptrsize - 1) or not is_valid_addr(x):
                            continue
                        offset_clk = KernelAddressHeuristicFinder.find_timer_base_clk(x, 0)
                        if offset_clk is not None:
                            bases.append(x + offset_clk - runtime.current_arch.ptrsize)
                    if bases:
                        return min(bases)
        return None

    @staticmethod
    def find_tvec_base_layout(tvec_base, cpu):
        """Check the layout invariants of `struct tvec_base` used before v4.8.
        Return (offset of `tv1`, the number of the buckets, True if they are hlist_head), or None.

        struct tvec_base {
            spinlock_t lock;
            struct timer_list *running_timer;
            unsigned long timer_jiffies;
            unsigned long next_timer;
            unsigned long active_timers; // v3.6~
            unsigned long all_timers;    // v3.16~
            int cpu;                     // v3.17~
            bool migration_enabled;      // v4.2~
            bool nohz_active;            // v4.2~
            struct tvec_root tv1;        // TVR_SIZE (256, or 64 with CONFIG_BASE_SMALL=y) buckets
            struct tvec tv2;             // TVN_SIZE (64, or 16 with CONFIG_BASE_SMALL=y) buckets
            struct tvec tv3;
            struct tvec tv4;
            struct tvec tv5;
        } ____cacheline_aligned;

        The bucket is `struct list_head` (~v4.1) or `struct hlist_head` (v4.2~).
        """
        ptrsize = runtime.current_arch.ptrsize
        header = read_memory(tvec_base, 0x100, safe=True)
        if header is None:
            return None
        words = slice_unpack(header, ptrsize)

        for nr_buckets in (512, 128):
            # ~v4.1: even an empty list_head is linked (to itself)
            for i in range(len(words)):
                offset = i * ptrsize
                heads = read_memory(tvec_base + offset, nr_buckets * ptrsize * 2, safe=True)
                if heads is None:
                    break
                heads = slice_unpack(heads, ptrsize)
                for j in range(nr_buckets):
                    head = tvec_base + offset + j * ptrsize * 2
                    next_entry, prev_entry = heads[j * 2], heads[j * 2 + 1]
                    if next_entry == head and prev_entry == head:
                        continue
                    if not is_valid_addr(next_entry) or not is_valid_addr(prev_entry):
                        break
                    if (read_int_from_memory(next_entry + ptrsize, safe=True) != head or
                            read_int_from_memory(prev_entry, safe=True) != head):
                        break
                else:
                    return offset, nr_buckets, False

            # v4.2~: an empty hlist_head is NULL, so `cpu` and the flags anchor the position,
            # and `all_timers` is the number of the timers linked from the buckets.
            # `cpu` follows 5 words, and the struct is ____cacheline_aligned (16 bytes or more).
            if tvec_base & 0xf:
                continue
            for offset_cpu in range(ptrsize * 5, len(header) - 8, ptrsize):
                if u32(header[offset_cpu:offset_cpu + 4]) != cpu:
                    continue
                if any(x > 1 for x in header[offset_cpu + 4:offset_cpu + 6]):
                    continue
                if words[offset_cpu // ptrsize - 4] == 0: # timer_jiffies
                    continue
                all_timers = words[offset_cpu // ptrsize - 1]
                offset = align(offset_cpu + 6, ptrsize)
                heads = read_memory(tvec_base + offset, nr_buckets * ptrsize, safe=True)
                if heads is None:
                    continue
                heads = slice_unpack(heads, ptrsize)
                count = 0
                for j, first in enumerate(heads):
                    link = tvec_base + offset + j * ptrsize
                    node = first
                    while node and count <= all_timers + 1:
                        if not is_valid_addr(node) or read_int_from_memory(node + ptrsize, safe=True) != link:
                            break
                        count += 1
                        link = node
                        node = read_int_from_memory(node, safe=True)
                    if node:
                        break
                else:
                    # one may be being moved under the lock
                    if count and abs(count - all_timers) <= 1:
                        return offset, nr_buckets, True
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_tvec_bases():
        """Return the per-cpu `tvec_bases` used before v4.8.
        It is a pointer to `struct tvec_base` (~v4.1), or the struct itself (v4.2~)."""

        def is_tvec_bases(x):
            slot = Kernel.per_cpu().addr_of(x, 0)
            if slot is None or slot & (runtime.current_arch.ptrsize - 1):
                return False
            base = read_int_from_memory(slot, safe=True)
            if base and is_valid_addr(base) and KernelAddressHeuristicFinder.find_tvec_base_layout(base, 0):
                return True
            return KernelAddressHeuristicFinder.find_tvec_base_layout(slot, 0) is not None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("tvec_bases")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.6.x ~ v4.7)
        if kversion and kversion < "4.8":
            for addr in Ksym.get_addrs("run_timer_softirq", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 100)
                if is_x86_64() or is_x86_32():
                    # 0xffffffff8106ab4d <run_timer_softirq+13>: mov rbx,QWORD PTR gs:0xd780 <-- tvec_bases (~v4.1)
                    # 0xffffffff810913e1 <run_timer_softirq+17>: mov rbx,QWORD PTR gs:[rip+0x7ef7bf97] # 0xd380
                    # 0xffffffff810b7e13 <run_timer_softirq+3>:  mov rbx,0xe740                <-- tvec_bases (v4.2~)
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_x86_any_const(res, skip_msb_check=True),
                        (int(v, 16) for v in re.findall(r"(?:fs|gs):0x([0-9a-fA-F]+)", res)),
                        (int(v, 16) for v in re.findall(r"(?:fs|gs):\[rip[+-]0x[0-9a-fA-F]+\].*#\s*(0x[0-9a-fA-F]+)", res)),
                    )
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, skip_msb_check=True)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv32() or is_riscv64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                    )
                else:
                    g = []
                for x in g:
                    if is_tvec_bases(x):
                        return x
        return None

    @staticmethod
    def find_clock_base_anchor(hrtimer_cpu_base):
        """Find `clock_base[]` by the back-pointer `clock_base[i].cpu_base`.
        Return (offset of clock_base[0], sizeof(struct hrtimer_clock_base), real
        `&hrtimer_cpu_base`). The offset is measured from the argument, which may point at
        a member instead of the head (see `get_hrtimer_bases()`).
        """
        ptrsize = runtime.current_arch.ptrsize
        hrtimer_cpu_base &= ~(ptrsize - 1)

        # Collect every pointer that points back into `hrtimer_cpu_base` itself. With
        # CONFIG_DEBUG_LOCK_ALLOC these are not only `clock_base[i].cpu_base`: `lock.dep_map.key`
        # is a lockdep self-reference placed before `clock_base[]`, and `clock_base[i].seq.lock`
        # points to `&cpu_base->lock` inside every element. So the first hit is not necessarily
        # `clock_base[0].cpu_base`, and the repeat of a same pointer is not necessarily the stride.
        candidates = []
        for i in range(0x400 // ptrsize):
            v = read_int_from_memory(hrtimer_cpu_base + ptrsize * i, safe=True)
            if v is None:
                return None
            if abs(v - hrtimer_cpu_base) < 0x40:
                candidates.append((ptrsize * i, v))

        # `clock_base[i].index == i` (HRTIMER_BASE_MONOTONIC, _REALTIME, _BOOTTIME, _TAI, ...)
        # tells the real head and stride apart from the lockdep pointers. Every supported
        # version has 3 clock bases or more (HRTIMER_BASE_TAI is added at v3.10).
        for (offset, v), (next_offset, next_v) in itertools.combinations(candidates, 2):
            if v != next_v:
                continue
            size = next_offset - offset
            try:
                index = [u32(read_memory(hrtimer_cpu_base + offset + size * n + ptrsize, 4)) for n in range(3)]
                third = read_int_from_memory(hrtimer_cpu_base + offset + size * 2)
            except gdb.MemoryError:
                continue
            if index == [0, 1, 2] and third == v:
                return offset, size, v
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_hrtimer_bases():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("hrtimer_bases")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v3.0 or later)
        if kversion and "3.0" <= kversion:
            for addr in Ksym.get_addrs("hrtimer_run_queues", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 20)
                if is_x86_64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_x86_add_reg_const(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_x86_byte_ptr(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res, skip_msb_check=True),
                    )
                    g2 = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x86_ds_absolute(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.x64_lea_reg_const(res, skip_msb_check=True),
                    )
                    g2 = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, skip_msb_check=True)
                    g2 = []
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, skip_msb_check=True),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                    g2 = []
                elif is_riscv32() or is_riscv64():
                    g = list(itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res, skip_msb_check=True, include_lui=True),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                    ))
                    g2 = g
                else:
                    g, g2 = [], []
                g, g2 = list(g), list(g2)

                # pattern3: 32-bit
                # 32-bit kernels put the per-cpu section in the kernel image, so every candidate
                # is a valid address and pattern1 cannot tell it apart (see `get_timer_bases()`).
                # Verify each candidate by reading it as a `struct hrtimer_cpu_base` instead.
                # 0xc0408740 <hrtimer_run_queues+4>: movw r3,#0xec0
                # 0xc0408744 <hrtimer_run_queues+8>: movt r3,#0xc267           <-- hrtimer_bases
                # 0xc116f770 <hrtimer_run_queues>:   test BYTE PTR ds:0xc2c0cbec,0x1
                #                                              <-- hrtimer_bases+0xc (not per_cpu)
                if is_32bit():
                    percpu = Kernel.per_cpu()
                    for x in itertools.chain(g, g2):
                        addr_cpu0 = percpu.addr_of(x, 0)
                        anchor = KernelAddressHeuristicFinder.find_clock_base_anchor(addr_cpu0)
                        if anchor:
                            return AddressUtil.normalize_address(x - (addr_cpu0 - anchor[2]))

                cpu_offset = Kernel.per_cpu().offsets
                if cpu_offset:
                    cpu_masks = Kernel.per_cpu().get_cpu_masks()
                    ready_cpus = cpu_masks["online"] or cpu_masks["present"]
                    # pattern1: per_cpu
                    # pattern1-a:
                    # 0xffffffff9b127acb: mov rbx,0x27040 <-- hrtimer_bases
                    # pattern1-b:
                    # 0xffffffffa440b87d <hrtimer_run_queues+13>: test BYTE PTR [rax+0x25b90],0x1
                    # The exact value is 0x25b80. Such a candidate points at a member, so it is
                    # snapped back to the head by the `clock_base[i].cpu_base` back-pointer.
                    # pattern1-c:
                    # 0xffffffff818f57b5 <hrtimer_run_queues+21>: lea rbx,[rax+0x1df00]
                    for x in g:
                        # v7.1 accesses via a register, so the displacement of the BYTE PTR is
                        # the offset in the structure. It is too small to be `hrtimer_bases`.
                        # 0xffffffffb5f81a48 <hrtimer_run_queues+24>: lea rbx,[rax-0x471d1540]
                        # 0xffffffffb5f81a4f <hrtimer_run_queues+31>: movzx eax,BYTE PTR [rbx+0x10]
                        if x < 0x1000 or not cpu_offset:
                            continue
                        addr_cpu0 = Kernel.per_cpu().addr_of(x, 0)
                        anchor = KernelAddressHeuristicFinder.find_clock_base_anchor(addr_cpu0)
                        if anchor and all(
                            KernelAddressHeuristicFinder.find_clock_base_anchor(addr)
                            for cpu, addr in Kernel.per_cpu().possible_addrs_of(x)
                            if cpu and (ready_cpus is None or cpu in ready_cpus)
                        ):
                            return AddressUtil.normalize_address(x - (addr_cpu0 - anchor[2]))
                else:
                    # pattern2: not per_cpu
                    # 0xffffffffbb8668bc <hrtimer_run_queues+12>: mov rdx,0xffffffffbc046138
                    # 0xffffffffbb8668c3 <hrtimer_run_queues+19>: mov rcx,0xffffffffbc046178
                    # 0xffffffffbb8668ca <hrtimer_run_queues+26>: mov rsi,0xffffffffbc0460f8
                    # 0xffffffffbb8668d1 <hrtimer_run_queues+33>: mov rdi,0xffffffffbc046048 <-- hrtimer_bases+8
                    # Newer x86_64 compilers keep the structure in memory instead, and then the
                    # only candidates are rip-relative operands.
                    # 0xffffffff9cedbb5c <hrtimer_run_queues+92>: mov rax,QWORD PTR [rip+0xe57795] # 0xffffffff9dd332f8
                    if is_x86_64():
                        g2 = itertools.chain(
                            g2,
                            KernelAddressHeuristicFinderUtil.x64_byte_ptr_rip_base(res),
                            KernelAddressHeuristicFinderUtil.x64_dword_ptr_rip_base(res),
                            KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res),
                        )
                    for x in sorted({x for x in g2 if is_valid_addr(x)}):
                        anchor = KernelAddressHeuristicFinder.find_clock_base_anchor(x)
                        if anchor:
                            return anchor[2]
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_jiffies():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("jiffies")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.6.18 or later)
        if kversion and "2.6.18" <= kversion:
            addr = Ksym.get_addr("jiffies_read")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res)
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv32() or is_riscv64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_use(res, include_lui=is_riscv32()),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                    )
                else:
                    g = []
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_pci_root_buses():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("pci_root_buses")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v2.5.71 or later)
        if kversion and "2.5.71" <= kversion:
            for addr in Ksym.get_addrs("pci_find_next_bus", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 30)
                if is_x86_64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res),
                        KernelAddressHeuristicFinderUtil.x64_x86_any_const(res),
                    )
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x86_noptr_ds(res)
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res, read_valid=True)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res, read_valid=True)
                elif is_riscv32() or is_riscv64():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res, read_valid=True)
                else:
                    g = []
                for x in g:
                    if KernelAddressHeuristicFinderUtil.is_in_kernel_image(x) and is_double_link_list(x):
                        return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_ioport_resource():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("ioport_resource")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2
        if kversion:
            for anchor in ("pci_scan_bus", "pci_scan_bus_parented"):
                addr = Ksym.get_addr(anchor)
                if not addr:
                    continue
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, r"r\w+")
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res, r"e\w+")
                elif is_arm64():
                    g = KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res)
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                elif is_riscv32() or is_riscv64():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res)
                else:
                    g = []
                for x in g:
                    layout = KernelResourceLayout.get_layout(x, "PCI IO", 0x100)
                    if layout:
                        return x

        # plan 3 (from .rodata)
        klayout = Kernel.layout(use_iomem=False)
        if klayout.ro_base and klayout.ro_size and is_valid_addr(klayout.ro_base):
            ro_data = read_memory(klayout.ro_base, klayout.ro_size)
            rw_ranges = [(klayout.ro_base, ro_data)]
            if klayout.rw_base and klayout.rw_size:
                rw_ranges.append((klayout.rw_base, read_memory(klayout.rw_base, min(klayout.rw_size, 0x1000000))))
            if klayout.ro_end and klayout.maps:
                rw_end = klayout.ro_end
                for entry in klayout.maps:
                    if entry.vstart <= rw_end < entry.vend or entry.vstart == rw_end:
                        rw_end = max(rw_end, entry.vend)
                    elif entry.vstart > rw_end:
                        break
                rw_size = min(rw_end - klayout.ro_end, 0x1000000)
                if rw_size:
                    rw_ranges.append((klayout.ro_end, read_memory(klayout.ro_end, rw_size)))
            pos = -1
            while True:
                # search for aligned string from .rodata
                pos = ro_data.find(b"PCI IO\x00", pos + 1)
                if pos == -1:
                    break

                # calc address of ELF header
                if is_32bit():
                    addr_byteseq = p32(klayout.ro_base + pos)
                else:
                    addr_byteseq = p64(klayout.ro_base + pos)

                for rw_base, rw_data in rw_ranges:
                    pos2 = -1
                    while True:
                        pos2 = rw_data.find(addr_byteseq, pos2 + 1)
                        if pos2 == -1:
                            break
                        if pos2 % runtime.current_arch.ptrsize != 0:
                            continue
                        name_addr = rw_base + pos2
                        candidates = []
                        for sizeof_resource_size_t in (8, 4):
                            maybe_ioport_resource = name_addr - sizeof_resource_size_t * 2
                            layout = KernelResourceLayout.get_layout(
                                maybe_ioport_resource, "PCI IO", 0x100, name_addr,
                            )
                            if not layout:
                                continue
                            # Without a child, both widths can pass (e.g., ARM without PCI has {0, 0, "PCI IO"}),
                            # but only the right one reads iomem_resource next to it correctly.
                            if KernelResourceLayout.find_iomem_resource(maybe_ioport_resource, layout):
                                return maybe_ioport_resource
                            candidates.append(maybe_ioport_resource)
                        if candidates:
                            return candidates[0]
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_iomem_resource():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("iomem_resource")
            if x:
                return x

        # plan 2 (from ioport_resource)
        x = KernelAddressHeuristicFinder.get_ioport_resource()
        if x:
            layout = KernelResourceLayout.get_layout(x, "PCI IO", 0x100)
            if layout:
                return KernelResourceLayout.find_iomem_resource(x, layout)
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_db_list():
        # need DMA_SHARED_BUFFER=y

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("db_list")
            if x:
                return x

        kversion = Kernel.version()
        if kversion and "6.10" <= kversion:
            return None

        # plan 2 (available v3.17 or later)
        # v5.7 moved the list_del out of `dma_buf_release()` into `dma_buf_file_release()`,
        # but some v5.4 stable trees carry that split too, so try both anchors in order
        # instead of picking one by version.
        if kversion:
            for anchor in ("dma_buf_file_release", "dma_buf_release"):
                addr = Ksym.get_addr(anchor)
                if addr is None:
                    continue
                # KASAN builds push &db_list.lock past the 30th instruction
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 60)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv32() or is_riscv64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("debugfs_list")
            if x:
                return x

        kversion = Kernel.version()

        # plan 2 (available v6.10 or later, until `dmabuf_list` replaces `debugfs_list`)
        if kversion and "6.10" <= kversion and not Ksym.get_addr("dma_buf_iter_begin"):
            # Some x64 builds place debugfs_list before debugfs_list_mutex, while others place it
            # after the mutex. dma_buf_debug_show() references the list head itself when iterating.
            if is_x86_64():
                for addr in Ksym.get_addrs("dma_buf_debug_show", match="split"):
                    res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 100)
                    for x in KernelAddressHeuristicFinderUtil.x64_x86_any_const(res):
                        if is_double_link_list(x):
                            return x

            for addr in Ksym.get_addrs("dma_buf_file_release", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 30)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv32() or is_riscv64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("dmabuf_list")
            if x:
                return x

        # `dmabuf_list` replaced `debugfs_list` together with the exported iterator. Mainline did
        # that in v6.16, but a tree based on v6.15 can carry it already, so the iterator itself
        # tells the two layouts apart where the version does not.
        has_iterator = bool(Ksym.get_addr("dma_buf_iter_begin"))

        # plan 2 (available since the dmabuf iterator was added)
        if has_iterator:
            for anchor in ("dma_buf_iter_begin", "dma_buf_iter_next"):
                addr = Ksym.get_addr(anchor)
                if addr is None:
                    continue
                res = gdb.execute("x/30i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
                elif is_arm64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv32() or is_riscv64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                    )
                # x64/x86 embeds &dmabuf_list itself as an immediate,
                # so it works even if dmabuf_list_mutex is placed far away in .bss.
                # ARM forms the head of the loop in `dma_buf_iter_begin()` with a pre-indexed
                # load, which leaves no constant to pick up; `dma_buf_iter_next()` compares
                # against the same head with a plain add / literal, so try both anchors.
                for x in g:
                    if is_double_link_list(x):
                        return x

        # plan 3 (available since the dmabuf iterator was added)
        if has_iterator:
            for addr in Ksym.get_addrs("dma_buf_file_release", match="split"):
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 30)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                    )
                elif is_arm32():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv32() or is_riscv64():
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res),
                        KernelAddressHeuristicFinderUtil.riscv_gp_relative(res),
                    )
                direction = TlsCommand.get_direction()
                # x64/x86:
                #   dmabuf_list
                #   dmabuf_list_mutex
                # arm64/arm32:
                #   dmabuf_list_mutex
                #   dmabuf_list
                for x in g:
                    if is_x86():
                        count = 1
                    else:
                        count = 2
                    for i in range(2, 30):
                        v = x + runtime.current_arch.ptrsize * direction * i
                        # here, x points &dmabuf_list_mutex
                        if is_double_link_list(v):
                            count -= 1
                            if count == 0:
                                return v
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_irq_desc_tree():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("irq_desc_tree")
            if x:
                return x

        kversion = Kernel.version()

        if kversion and "6.5" <= kversion:
            return False

        # plan 2 (available v2.6.37 ~ v6.4)
        if kversion and "2.6.37" <= kversion < "6.5":
            addr = Ksym.get_addr("irq_to_desc")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    res = re.split(r"\bret\b", res, maxsplit=1)[0]
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                    )
                elif is_arm32():
                    g = KernelAddressHeuristicFinderUtil.arm32_movw_movt(res)
                elif is_riscv32() or is_riscv64():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res, include_lui=is_riscv32())
                else:
                    g = []
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_sparse_irqs():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("sparse_irqs")
            if x:
                return x

        kversion = Kernel.version()

        if kversion and kversion < "6.5":
            return False

        # plan 2 (available v6.5 or later)
        if kversion and "6.5" <= kversion:
            addr = Ksym.get_addr("irq_to_desc")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
                if is_x86_64():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_x86_32():
                    g = KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res)
                elif is_arm64():
                    # irq_to_desc() is only a few instructions long, so cut the disassembly at
                    # its end. Otherwise the next function (irq_lock_sparse) offers
                    # &sparse_irq_lock as a candidate.
                    res = re.split(r"\bret\b", res, maxsplit=1)[0]
                    # &sparse_irqs may be built as adrp + add + add.
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                        KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                    )
                elif is_arm32():
                    # cut at the return or the tail call, for the same reason as arm64
                    res = re.split(r"\bb\s+0x|\bbx\s+lr\b|\b(?:pop|ldm)\w*\b[^\n]*\bpc\b", res, maxsplit=1)[0]
                    g = itertools.chain(
                        KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                        KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                    )
                elif is_riscv32() or is_riscv64():
                    g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res)
                else:
                    g = []
                for x in g:
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_irq_desc():
        """Return the static `irq_desc[NR_IRQS]` of CONFIG_SPARSE_IRQ=n, or None."""

        def is_irq_desc_array(address):
            # early_irq_init() sets irq_desc[i].irq_data.irq = i for every descriptor.
            words = read_memory(address, 0x2000, safe=True)
            if words is None:
                return False
            words = slice_unpack(words, 4)
            for offset in range(0, 0x100 // 4):
                if words[offset] != 0:
                    continue
                for stride in range(0x20 // 4, 0x800 // 4):
                    if offset + stride * 3 >= len(words):
                        break
                    if all(words[offset + stride * i] == i for i in range(1, 4)):
                        return True
            return False

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("irq_desc")
            if x:
                return x

        # plan 2 (from irq_to_desc)
        # `return (irq < NR_IRQS) ? irq_desc + irq : NULL;` computes the address of the array.
        addr = Ksym.get_addr("irq_to_desc")
        if addr:
            res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 20)
            if is_x86_64() or is_x86_32():
                g = KernelAddressHeuristicFinderUtil.x64_x86_any_const(res)
            elif is_arm64():
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add_add(res),
                    KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
                )
            elif is_arm32():
                # the range check makes the load conditional (e.g. `ldrls r3, [pc, #12]`)
                res = re.sub(r"\bldr(?:eq|ne|cs|hs|cc|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le)\b", "ldr", res)
                g = itertools.chain(
                    KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                    KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
                )
            elif is_riscv32() or is_riscv64():
                g = KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res)
            else:
                g = []
            for x in g:
                if is_irq_desc_array(x):
                    return x
        return None

    @staticmethod
    @switch_to_intel_syntax
    def get_slub_tlbflush_queue():
        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("slub_tlbflush_queue")
            if x:
                return x

        # plan 2 (from slub_tlbflush_worker)
        addr = Ksym.get_addr("slub_tlbflush_worker")
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
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            x = Ksym.get_addr("slub_addr_base")
            if x:
                return x

        kversion = Kernel.version()
        if not kversion:
            return None

        if kversion < "6.6":
            # plan 2 (available in 6.1-based from `alloc_slab_pv_page`)
            # bruteforces all accesses into global variables in `alloc_slab_pv_page`
            # In source, `slub_addr_base` is referenced only by `alloc_slab_meta`, but
            # compiler seems to inline this function (because calls once, maybe)
            addr = Ksym.get_addr("alloc_slab_pv_page")
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
            addr = Ksym.get_addr("vaddr_ranges_debug_start")
            if addr:
                res = gdb.execute("x/20i {:#x}".format(addr), to_string=True)
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
        if Kernel.version() < "6.6":
            return None

        # plan 1 (directly)
        if KernelAddressHeuristicFinder.USE_DIRECTLY:
            addr = Ksym.get_addr("slub_addr_current")
            if addr:
                return addr

        # plan 2 (from vaddr_ranges_first_valid_slab or vaddr_ranges_debug_start)
        anchors = (
            ("vaddr_ranges_first_valid_slab", 10, 0),
            ("vaddr_ranges_debug_start", 20, 1),
        )
        for symbol, instruction_count, skip in anchors:
            addr = Ksym.get_addr(symbol)
            if not addr:
                continue
            res = gdb.execute("x/{:d}i {:#x}".format(instruction_count, addr), to_string=True)
            if is_x86_64():
                g = KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res, skip=skip)
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
