"""Unicorn / Keystone / Capstone architecture-translation helpers (Layer 1).

`UnicornKeystoneCapstone` is a `@staticmethod` collection that maps GEF's
current architecture onto the arch/mode constants of the
capstone/keystone/unicorn trinity, plus the unicorn register map helper and
the keystone assembly wrapper.

`UnicornEmulator` is the in-process Unicorn wrapper used by the `unicorn-emulate`
family of commands (Phase 2.2): it maps memory on demand and emulates a linear
run of instructions from the current inferior context.

Reads of the mutable global `current_arch` go through `runtime.current_arch`.
References to `gef.core.process` (arch predicates) and the not-yet-extracted
`timeout` helper are late-imported inside the referencing method.
`UnicornEmulator` additionally late-imports `KernelAddressHeuristicFinder`
(`gef.core.pagewalk`), `X86` (`gef.arch.x86`), `ContextCodeCommand`
(`gef.commands.debugging.context`) and `KernelCurrentCommand`
(`gef.commands.kernel.basic`), because importing them at module level would
either create an import cycle (`gef.core.utils` imports this module) or reach
the not-yet-extracted command layer.
"""
import binascii
import collections
import re
import sys

import gdb

from gef.core import runtime
from gef.core.address import AddressUtil, Endian, Permission
from gef.core.color import Color, err, gef_print
from gef.core.exec import ExecSyscall
from gef.core.memory import is_valid_addr, read_memory
from gef.core.process import (
    ProcessMap,
    get_pagesize,
    is_64bit,
    is_arm32,
    is_arm64,
    is_in_kernel,
    is_kgdb,
    is_qemu_system,
    is_vmware,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import get_register
from gef.core.strings import String
from gef.core.symbols import ModuleLoader, Symbol
from gef.core.syscall import Syscall


class UnicornKeystoneCapstone:
    """A collection of utility functions that are related to unicorn, keystone, and capstone."""

    @staticmethod
    def get_generic_arch(module, prefix, arch, mode, big_endian, to_string):
        """Retrieve architecture and mode from the arguments for use for the holy
        capstone/keystone/unicorn trinity."""
        if isinstance(mode, tuple):
            modes = list(mode)
        else:
            modes = [mode]

        if big_endian:
            modes.append("BIG_ENDIAN")
        else:
            modes.append("LITTLE_ENDIAN")

        if to_string:
            # arch
            arch = "{:s}.{:s}_ARCH_{:s}".format(module.__name__, prefix, arch)
            # mode
            tmp = []
            for m in modes:
                if not m:
                    tmp.append("0")
                else:
                    tmp.append("{:s}.{:s}_MODE_{:s}".format(module.__name__, prefix, m))
            mode = " + ".join(tmp)
        else:
            # arch
            arch = getattr(module, "{:s}_ARCH_{:s}".format(prefix, arch))
            # mode
            mode = 0
            for m in modes:
                if m:
                    mode |= getattr(module, "{:s}_MODE_{:s}".format(prefix, m))
        return arch, mode

    @staticmethod
    @ModuleLoader.load_unicorn
    def get_unicorn_arch(arch=None, mode=None, endian=None, to_string=False):
        if (arch, mode, endian) == (None, None, None):
            arch = runtime.current_arch.arch
            mode = runtime.current_arch.mode
            endian = Endian.is_big_endian()
        if arch is None:
            arch = runtime.current_arch.arch
        if (arch, mode) == ("RISCV", "32"):
            mode = "RISCV32"
        elif (arch, mode) == ("RISCV", "64"):
            mode = "RISCV64"
        elif (arch, mode) == ("PPC", "32"):
            mode = "PPC32"
        elif (arch, mode) == ("PPC", "64"):
            mode = "PPC64"
        elif (arch, mode) == ("SPARC", "32"):
            mode = "SPARC32"
        elif (arch, mode) == ("SPARC", "32PLUS"):
            mode = "SPARC32"
        elif (arch, mode) == ("SPARC", "64"):
            mode = "SPARC64"
        elif (arch, mode) == ("MIPS", "32"):
            mode = "MIPS32"
        elif (arch, mode) == ("MIPS", "64"):
            mode = "MIPS64"
        elif arch == "S390X":
            mode = None
        elif arch == "M68K":
            mode = None
        return UnicornKeystoneCapstone.get_generic_arch(
            sys.modules["unicorn"], "UC", arch, mode, endian, to_string,
        )

    @staticmethod
    @ModuleLoader.load_capstone
    def get_capstone_arch(arch=None, mode=None, endian=None, to_string=False):
        if (arch, mode, endian) == (None, None, None):
            arch = runtime.current_arch.arch
            mode = runtime.current_arch.mode
            endian = Endian.is_big_endian()
        if arch is None:
            arch = runtime.current_arch.arch
        # hacky patch for applying to capstone's mode
        if arch == "ARM64":
            if sys.modules["capstone"].cs_version()[0] == 6:
                arch = "AARCH64"
        elif (arch, mode) == ("RISCV", "32"):
            mode = ("RISCV32", "RISCVC")
        elif (arch, mode) == ("RISCV", "64"):
            mode = ("RISCV64", "RISCVC")
        elif (arch, mode) == ("SPARC", "32"):
            mode = ""
        elif (arch, mode) == ("SPARC", "32PLUS"):
            mode = ""
        elif (arch, mode) == ("SPARC", "64"):
            mode = "V9"
        elif (arch, mode) == ("MIPS", "32"):
            mode = "MIPS32"
        elif (arch, mode) == ("MIPS", "64"):
            mode = "MIPS64"
        elif arch == "S390X":
            if sys.modules["capstone"].cs_version()[0] == 6:
                arch, mode = "SYSTEMZ", None
            else:
                arch, mode = "SYSZ", None
        elif arch == "M68K":
            mode = "M68K_060"
        elif (arch, mode) == ("LOONGARCH", "64"): # capstone v6.x~
            mode = "LOONGARCH64"
        elif (arch, mode) == ("LOONGARCH", "32"): # capstone v6.x~
            mode = "LOONGARCH32"
        elif arch == "ALPHA": # capstone v6.x~
            mode = None
        elif (arch, mode) == ("HPPA", "64"): # capstone v6.x~
            mode = "HPPA_20"
        elif (arch, mode) == ("HPPA", "32"): # capstone v6.x~
            mode = "HPPA_11"
        return UnicornKeystoneCapstone.get_generic_arch(
            sys.modules["capstone"], "CS", arch, mode, endian, to_string,
        )

    @staticmethod
    @ModuleLoader.load_keystone
    def get_keystone_arch(arch=None, mode=None, endian=None, to_string=False):
        if (arch, mode, endian) == (None, None, None):
            arch = runtime.current_arch.arch
            mode = runtime.current_arch.mode
            endian = Endian.is_big_endian()
        if arch is None:
            arch = runtime.current_arch.arch
        # hacky patch for applying to capstone's mode
        if arch == "ARM64":
            mode = None
        elif (arch, mode) == ("PPC", "32"):
            mode = "PPC32"
        elif (arch, mode) == ("PPC", "64"):
            mode = "PPC64"
        elif (arch, mode) == ("SPARC", "32"):
            mode = "SPARC32"
        elif (arch, mode) == ("SPARC", "32PLUS"):
            mode = "SPARC32"
        elif (arch, mode) == ("SPARC", "64"):
            mode = "SPARC64"
        elif (arch, mode) == ("MIPS", "32"):
            mode = "MIPS32"
        elif (arch, mode) == ("MIPS", "64"):
            mode = "MIPS64"
        elif arch == "S390X":
            arch, mode = "SYSTEMZ", None
        return UnicornKeystoneCapstone.get_generic_arch(
            sys.modules["keystone"], "KS", arch, mode, endian, to_string,
        )

    @staticmethod
    @ModuleLoader.load_unicorn
    def get_unicorn_registers(to_string=False, add_sse=False):
        "Return a dict matching the Unicorn identifier for a specific register."
        from gef.core.process import is_arm32, is_arm64, is_x86
        unicorn = sys.modules["unicorn"]
        regs = {}

        if runtime.current_arch is not None:
            arch = runtime.current_arch.arch.lower()
        else:
            raise OSError("Oops")

        const = getattr(unicorn, "{}_const".format(arch))

        extra_regs = []
        if add_sse:
            if is_x86():
                extra_regs = ["$xmm{:d}".format(i) for i in range(16)]
        if is_arm64():
            extra_regs = ["$tpidr_el0"] # for tls
        if is_arm32():
            extra_regs = ["$c13_c0_3"] # for tls

        for reg in runtime.current_arch.all_registers + extra_regs:
            if arch == "ppc" and reg.startswith("$r"):
                regname = "UC_{:s}_REG_{:s}".format(arch.upper(), reg.lstrip("$r").upper())
            elif arch == "arm64" and reg == "$cpsr":
                regname = "UC_ARM64_REG_PSTATE"
            else:
                regname = "UC_{:s}_REG_{:s}".format(arch.upper(), reg.lstrip("$").upper())
            try:
                getattr(const, regname)
            except AttributeError:
                continue
            if to_string:
                regs[reg] = "{:s}.{:s}".format(const.__name__, regname)
            else:
                regs[reg] = getattr(const, regname)
        return regs

    @staticmethod
    @ModuleLoader.load_keystone
    def keystone_assemble(code, arch, mode, *args, **kwargs):
        """Assembly encoding function based on keystone."""
        import multiprocessing
        from gef.core.utils import timeout
        keystone = sys.modules["keystone"]
        code = String.str2bytes(code)
        addr = kwargs.get("addr", 0x1000)

        # `asm "[]"` returns no response
        @timeout(duration=1)
        def ks_asm(code, addr):
            return ks.asm(code, addr)

        try:
            ks = keystone.Ks(arch, mode)
            enc, cnt = ks_asm(code, addr)
        except keystone.KsError as e:
            err("Keystone assembler error: {!s}".format(e))
            return None
        except multiprocessing.TimeoutError:
            err("Keystone assembler timeout error")
            return None

        if cnt == 0:
            return ""

        enc = bytearray(enc)
        if "raw" not in kwargs:
            s = binascii.hexlify(enc)
            enc = b"\\x" + b"\\x".join([s[i : i + 2] for i in range(0, len(s), 2)])
            enc = enc.decode("utf-8")

        return enc


class UnicornEmulator:
    """Namespace holding the shared Unicorn `Emulator`."""

    class Node:
        """A node in the future-calls tree."""

        def __init__(self, address, insn_address=None, kind="call", label=None):
            """Create a tree node for a call, return, or root entry."""
            self.address = address
            self.insn_address = insn_address
            self.kind = kind
            self.label = label
            self.children = []
            self.truncated = False
            self.error = None
            return

        @staticmethod
        def format_address(address):
            """Format an address with the best symbol information available."""
            if address is None:
                return "UNKNOWN"
            try:
                addr = ProcessMap.lookup_address(address)
                sym = Symbol.get_symbol_string(addr.value, nosymbol_string=" <NO_SYMBOL>")
                return "{!s}{:s}".format(addr, sym)
            except Exception:
                return "{:#x} <NO_SYMBOL>".format(address)

        @staticmethod
        def reason_color(reason):
            """Return the display color for a stop or truncation reason."""
            warnings = (
                "depth limit reached",
                "instruction limit reached",
                "loop detected",
                "node limit reached",
            )
            return "yellow" if reason in warnings else "red"

        @staticmethod
        def color_reason(reason):
            """Colorize a reason string for terminal output."""
            return Color.colorify(reason, "bold {:s}".format(
                UnicornEmulator.Node.reason_color(reason),
            ))

        def lines(self):
            """Render this node and its children as tree lines."""
            text = self.label or self.format_address(self.address)
            if self.kind == "ret":
                text = "ret" if self.address is None else "ret -> {:s}".format(text)
            if self.insn_address is not None:
                tag = "at" if self.kind == "ret" else "from"
                text += " [{:s} {:s}]".format(tag, self.format_address(self.insn_address))
            if self.truncated:
                text += " " + Color.colorify("[truncated]", "bold yellow")
            if self.error:
                color = self.reason_color(self.error)
                text += " " + Color.colorify("[{:s}]".format(self.error), "bold {:s}".format(color))

            lines = [text]
            for i, child in enumerate(self.children):
                child_lines = child.lines()
                lines.append("+- " + child_lines[0])
                prefix = "   " if i == len(self.children) - 1 else "|  "
                lines.extend(prefix + line for line in child_lines[1:])
            return lines

    class Emulator:
        """In-process Unicorn wrapper that maps memory on demand and emulates a linear run."""

        # safety cap for `-t`/`-n` runs that would otherwise loop forever
        MAX_INSNS = 100000

        def __init__(self, kwargs):
            """Initialize Unicorn state from the current inferior context."""
            from gef.core.pagewalk import KernelAddressHeuristicFinder
            self.kwargs = kwargs
            self.unicorn = sys.modules["unicorn"]
            capstone = sys.modules["capstone"]
            self.page_size = get_pagesize()
            self.page_mask = ~(self.page_size - 1)
            self.ptrsize = AddressUtil.ptr_width()
            if Endian.is_big_endian():
                raise OSError("Big endian is not supported")
            self.endian = "little"
            self.regs = UnicornKeystoneCapstone.get_unicorn_registers(add_sse=kwargs["add_sse"])
            # ordered register set used for the register dump (matches unicorn-emulate)
            self.registers = collections.OrderedDict(
                UnicornKeystoneCapstone.get_unicorn_registers(add_sse=kwargs["add_sse"]),
            )
            if is_arm64():
                try:
                    const = self.unicorn.arm64_const
                    for reg, name in (
                        ("$sp_el0", "UC_ARM64_REG_SP_EL0"),
                        ("$tpidr_el0", "UC_ARM64_REG_TPIDR_EL0"),
                        ("$tpidrro_el0", "UC_ARM64_REG_TPIDRRO_EL0"),
                        ("$tpidr_el1", "UC_ARM64_REG_TPIDR_EL1"),
                    ):
                        uc_reg = getattr(const, name, None)
                        if uc_reg is not None:
                            self.regs.setdefault(reg, uc_reg)
                except AttributeError:
                    pass
            self.pc_reg = next((self.regs[r] for r in ("$pc", "$rip", "$eip", "$ip") if r in self.regs), None)
            if self.pc_reg is None:
                raise OSError("Unsupported program counter register")
            arch, mode = UnicornKeystoneCapstone.get_unicorn_arch()
            self.emu = self.unicorn.Uc(arch, mode)

            # capstone for the displayed instruction trace (disassembled from emulator memory)
            cs_arch, cs_mode = UnicornKeystoneCapstone.get_capstone_arch()
            if is_arm32():
                # unicorn can handle thumb automatically, capstone can't; handle it manually
                self.cs_arm = capstone.Cs(cs_arch, cs_mode)
                self.cs_thumb = capstone.Cs(cs_arch, (cs_mode & ~capstone.CS_MODE_ARM) | capstone.CS_MODE_THUMB)
                self.cs = None
            else:
                self.cs_arm = None
                self.cs_thumb = None
                self.cs = capstone.Cs(cs_arch, cs_mode)

            self.mapped = set()
            self.aliases = {}
            self.alias_base = 0x10_0000_0000 if is_64bit() else 0x1000_0000
            self.alias_window = 0x1_0000_0000 if is_64bit() else 0x1000_0000
            self.alias_stride = 0x4_0000_0000 if is_64bit() else 0x2000_0000
            self.use_alias = is_64bit() and (is_in_kernel() or is_qemu_system() or is_kgdb() or is_vmware())
            self.start_address = kwargs["start_insn"]
            self.fs_base = None
            self.gs_base = None
            self.current_segment = None
            self.per_cpu_bases = None
            self.last_fault = None
            self.last_map_error = None
            self.last_map_source = None
            # instruction trace counter and tracked memory changes (for the diff dump)
            self.count = 0
            self.changed_mem = {}
            self.failed = None        # set by run(): the reason string when emulation stops abnormally (else None)
            self.last_syscall = None  # set by handle_syscall(): the first syscall number encountered (else None)
            hook = getattr(self.unicorn, "UC_HOOK_MEM_INVALID", None)
            if hook is None:
                hook = self.unicorn.UC_HOOK_MEM_READ_INVALID | self.unicorn.UC_HOOK_MEM_WRITE_INVALID
                hook |= getattr(self.unicorn, "UC_HOOK_MEM_FETCH_INVALID", 0)
            self.emu.hook_add(hook, self.mem_hook)
            self.emu.hook_add(self.unicorn.UC_HOOK_MEM_WRITE, self.mem_write_hook)
            self.map_page(self.start_address, translate=False)
            sp = self.read_gdb_register("$sp") or self.read_gdb_register("$rsp") or self.read_gdb_register("$esp")
            if sp:
                self.map_page(sp, zero_fill=True)
            if is_x86_32() or is_x86_64():
                for segment in ("fs", "gs"):
                    base = None
                    name = "${:s}_base".format(segment)
                    base = self.read_gdb_register(name)
                    if base is None:
                        getter = getattr(runtime.current_arch, "get_{:s}".format(segment), None)
                        if callable(getter):
                            try:
                                base = getter()
                            except Exception:
                                base = None
                    if segment == "fs":
                        self.fs_base = base
                    else:
                        self.gs_base = base
                if self.fs_base is None and is_x86_64():
                    self.fs_base = runtime.current_arch.get_tls()
                if self.gs_base is None and is_x86_32():
                    self.gs_base = runtime.current_arch.get_tls()
                fs_base = self.fs_base
                gs_base = self.gs_base
                if is_x86_64():
                    if self.use_alias:
                        fs_base = 0 if fs_base is not None else None
                        gs_base = 0
                    elif fs_base is None:
                        fs_base = runtime.current_arch.get_tls() or 0x2000
                if is_x86_32() and gs_base is None:
                    gs_base = runtime.current_arch.get_tls() or 0x2000
                try:
                    const = self.unicorn.x86_const
                    scratch_pages = (0xf000, 0x10000, 0x20000, 0x30000)
                    for msr, value in ((0xc0000100, fs_base), (0xc0000101, gs_base)):
                        if value is None:
                            continue
                        value = AddressUtil.normalize_address(value)
                        opcodes = b"\x0f\x30" # wrmsr
                        for scratch in scratch_pages:
                            scratch &= self.page_mask
                            mapped_here = False
                            if scratch in self.mapped:
                                continue
                            try:
                                self.emu.mem_map(scratch, self.page_size, Permission.ALL)
                                mapped_here = True
                                self.emu.mem_write(scratch, opcodes)
                                if is_x86_64():
                                    self.emu.reg_write(const.UC_X86_REG_RAX, value & 0xffff_ffff)
                                    self.emu.reg_write(const.UC_X86_REG_RDX, (value >> 32) & 0xffff_ffff)
                                    self.emu.reg_write(const.UC_X86_REG_RCX, msr & 0xffff_ffff)
                                else:
                                    self.emu.reg_write(const.UC_X86_REG_EAX, value & 0xffff_ffff)
                                    self.emu.reg_write(const.UC_X86_REG_EDX, (value >> 32) & 0xffff_ffff)
                                    self.emu.reg_write(const.UC_X86_REG_ECX, msr & 0xffff_ffff)
                                self.emu.emu_start(scratch, scratch + len(opcodes), count=1)
                                self.last_map_error = None
                                break
                            except self.unicorn.UcError as e:
                                self.last_map_error = "set_msr {:#x}: {!s}".format(msr, e)
                            finally:
                                if mapped_here:
                                    try:
                                        self.emu.mem_unmap(scratch, self.page_size)
                                    except self.unicorn.UcError:
                                        pass
                except AttributeError:
                    pass
            if is_arm32() or is_arm64():
                self.write_reg("$cpsr", self.read_gdb_register("$cpsr"))
            if is_arm32():
                current = None
                if is_in_kernel() or is_qemu_system() or is_kgdb() or is_vmware():
                    try:
                        current = KernelAddressHeuristicFinder.get_current_task_for_current_thread()
                    except Exception:
                        current = None
                tls = self.read_gdb_register("$TPIDRURO") or self.read_gdb_register("$TPIDRURO_S")
                if tls is None:
                    try:
                        tls = runtime.current_arch.get_tls()
                    except Exception:
                        tls = None
                if tls is None:
                    tls = current
                self.arm32_c13_c0 = {
                    2: self.read_gdb_register("$TPIDRURW") or self.read_gdb_register("$c13_c0_2"),
                    3: tls or self.read_gdb_register("$c13_c0_3"),
                    4: (
                        self.read_gdb_register("$TPIDRPRW")
                        or self.read_gdb_register("$c13_c0_4")
                        or current
                    ),
                }
                # also preset the CP15 register, so it is shown by the register dump
                if "$c13_c0_3" in self.regs and self.arm32_c13_c0[3] is not None:
                    try:
                        self.emu.reg_write(self.regs["$c13_c0_3"], AddressUtil.normalize_address(self.arm32_c13_c0[3]))
                    except self.unicorn.UcError:
                        pass
            if is_arm64():
                for reg, names in (
                    ("$sp_el0", ("$sp_el0", "$SP_EL0")),
                    ("$tpidr_el0", ("$tpidr_el0", "$TPIDR_EL0", "$tpidr")),
                    ("$tpidrro_el0", ("$tpidrro_el0", "$TPIDRRO_EL0")),
                    ("$tpidr_el1", ("$tpidr_el1", "$TPIDR_EL1")),
                ):
                    value = None
                    for name in names:
                        value = self.read_gdb_register(name)
                        if value is not None:
                            break
                    if value is None and reg == "$tpidr_el0" and not is_in_kernel():
                        try:
                            value = runtime.current_arch.get_tls()
                        except Exception:
                            value = None
                    self.write_reg(reg, value)

            for reg in runtime.current_arch.all_registers:
                if self.skip_register(reg):
                    continue
                self.write_reg(reg, self.read_gdb_register(reg))

            # XMM registers (x86 only); written directly to avoid pointer normalization
            if kwargs["add_sse"] and is_x86():
                lines = Color.remove_color(gdb.execute("xmm", to_string=True))
                for reg in ["$xmm{:d}".format(i) for i in range(16)]:
                    if reg not in self.regs:
                        continue
                    found = re.findall("\\" + reg + r" +: (0x\S+)", lines)
                    if found:
                        try:
                            self.emu.reg_write(self.regs[reg], int(found[0], 16))
                        except self.unicorn.UcError:
                            pass

            # syscall table entries used by the optional mmap/munmap/brk emulation (-E)
            self.mmap_entry = None
            self.munmap_entry = None
            self.brk_entry = None
            self.current_brk = None
            if kwargs["emulate_mmap"]:
                name_table = Syscall.get_syscall_table().name_table
                self.mmap_entry = name_table["mmap2"] if (is_x86_32() or is_arm32()) else name_table["mmap"]
                self.munmap_entry = name_table["munmap"]
                self.brk_entry = name_table["brk"]
                self.current_brk = ExecSyscall(
                    self.brk_entry.nr, [0x0],
                ).exec_code()["reg"][self.brk_entry.ret_regs[0]]
            return

        def read_gdb_register(self, name):
            """Read a register from GDB, using monitor access when needed."""
            try:
                extra = is_in_kernel() or is_qemu_system() or is_kgdb() or is_vmware()
                return get_register(name, use_mbed_exec=extra, use_monitor=extra)
            except Exception:
                return None

        def anchor(self, address):
            """Return the address anchor used for kernel aliasing."""
            if not self.use_alias:
                return None
            address = AddressUtil.normalize_address(address)
            if is_64bit():
                return address & 0xffff_ffff_0000_0000 if address >> 56 == 0xff else None
            return address & 0xf000_0000 if address >= 0x8000_0000 else None

        def arm64_kernel_address_candidates(self, address, allow_low=False):
            """Build possible AArch64 kernel addresses from a truncated pointer."""
            if not (is_arm64() and self.use_alias and is_in_kernel()):
                return []
            address = AddressUtil.normalize_address(address)
            if (not allow_low and address < 0x1_0000_0000) or self.anchor(address) is not None:
                return []

            anchors = []
            for anchor in self.aliases:
                if anchor not in anchors:
                    anchors.append(anchor)
            start_anchor = self.anchor(self.start_address)
            if start_anchor is not None and start_anchor not in anchors:
                anchors.append(start_anchor)

            candidates = []
            offset = address & 0xffff_ffff
            for anchor in anchors:
                candidate = AddressUtil.normalize_address(anchor + offset)
                if candidate != address and candidate not in candidates:
                    candidates.append(candidate)
            return candidates

        def to_emu(self, address, create=True):
            """Translate a GDB address into the Unicorn address space."""
            address = AddressUtil.normalize_address(address)
            anchor = self.anchor(address)
            if anchor is None:
                return address
            if anchor not in self.aliases:
                if not create:
                    return address
                self.aliases[anchor] = self.alias_base + len(self.aliases) * self.alias_stride
            return self.aliases[anchor] + address - anchor

        def from_emu(self, address):
            """Translate a Unicorn address back into the GDB address space."""
            address = AddressUtil.normalize_address(address)
            for anchor, base in self.aliases.items():
                if base <= address < base + self.alias_window:
                    return anchor + address - base
                if self.use_alias and is_x86_64():
                    overflow = base + self.alias_window
                    if overflow <= address < overflow + self.alias_window:
                        return address - overflow
            if self.use_alias and is_x86_64() and address & (1 << 47):
                address |= 0xffff_0000_0000_0000
            return AddressUtil.normalize_address(address)

        def translate_pointers(self, data):
            """Rewrite pointer-sized values in mapped data for Unicorn."""
            if not self.use_alias:
                return data
            data = bytearray(data)
            for i in range(0, len(data) - self.ptrsize + 1, self.ptrsize):
                value = int.from_bytes(data[i:i + self.ptrsize], self.endian)
                if self.anchor(value) is not None:
                    value = self.to_emu(value)
                    data[i:i + self.ptrsize] = int(value).to_bytes(self.ptrsize, self.endian)
                    continue
                for candidate in self.arm64_kernel_address_candidates(value):
                    try:
                        if is_valid_addr(candidate):
                            value = self.to_emu(candidate)
                            data[i:i + self.ptrsize] = int(value).to_bytes(self.ptrsize, self.endian)
                            break
                    except Exception:
                        pass
            return bytes(data)

        def mem_hook(self, emu, access, address, size, value, _user_data):
            """Map memory on demand when Unicorn reports an invalid access."""
            from gef.commands.kernel.basic import KernelCurrentCommand
            from gef.core.pagewalk import KernelAddressHeuristicFinder
            try:
                pc = self.from_emu(emu.reg_read(self.pc_reg))
            except Exception:
                pc = None
            access_text = str(access)
            for name in (
                "UC_MEM_READ_UNMAPPED", "UC_MEM_WRITE_UNMAPPED", "UC_MEM_FETCH_UNMAPPED",
                "UC_MEM_READ_PROT", "UC_MEM_WRITE_PROT", "UC_MEM_FETCH_PROT",
                "UC_MEM_READ", "UC_MEM_WRITE", "UC_MEM_FETCH",
            ):
                if getattr(self.unicorn, name, None) == access:
                    access_text = name
                    break
            is_write = access in (
                getattr(self.unicorn, "UC_MEM_WRITE_UNMAPPED", -1),
                getattr(self.unicorn, "UC_MEM_WRITE_PROT", -1),
            )
            is_fetch = access in (
                getattr(self.unicorn, "UC_MEM_FETCH_UNMAPPED", -1),
                getattr(self.unicorn, "UC_MEM_FETCH_PROT", -1),
            )
            self.last_fault = {
                "pc": pc, "access": access_text, "address": self.from_emu(address),
                "size": size, "value": self.from_emu(value) if value else value,
            }
            if address == 0:
                return False

            mapped = None
            offset = self.from_emu(address)
            # gs-segment per-cpu access: the classic `gs:[off]` form carries a small per-cpu
            # offset, while the RIP-relative `gs:[rip + disp]` form (emitted by recent kernels)
            # resolves to a full anchored kernel address, so route anchored offsets through
            # gs_base/per-cpu base as well instead of treating them as a raw mapping.
            if is_x86_64() and self.use_alias and self.current_segment == "gs" and (offset < self.alias_window or self.anchor(offset) is not None):
                self.last_map_error = None
                self.last_map_source = None
                emu_page = AddressUtil.normalize_address(address) & self.page_mask
                offset_page = self.from_emu(emu_page) & self.page_mask
                if emu_page in self.mapped:
                    mapped = True
                else:
                    bases = []
                    if self.gs_base is not None:
                        bases.append(("gs_base", self.gs_base))
                    if self.per_cpu_bases is None:
                        self.per_cpu_bases = []
                        try:
                            per_cpu_offset = KernelAddressHeuristicFinder.get_per_cpu_offset()
                            if per_cpu_offset:
                                self.per_cpu_bases = KernelCurrentCommand.get_each_cpu_offset(per_cpu_offset)
                        except Exception:
                            self.per_cpu_bases = []
                    if self.per_cpu_bases:
                        try:
                            cpu = max(0, gdb.selected_thread().num - 1)
                        except Exception:
                            cpu = 0
                        if cpu >= len(self.per_cpu_bases):
                            per_cpu_bases = self.per_cpu_bases
                        else:
                            per_cpu_bases = self.per_cpu_bases[cpu:cpu + 1]
                            per_cpu_bases += self.per_cpu_bases[:cpu] + self.per_cpu_bases[cpu + 1:]
                        bases.extend(("per_cpu", base) for base in per_cpu_bases)
                    errors = []
                    for name, base in bases:
                        source_page = AddressUtil.normalize_address(base + offset_page) & self.page_mask
                        data, error = self.read_page(source_page)
                        if data is None:
                            errors.append(error)
                            continue
                        try:
                            self.emu.mem_map(emu_page, self.page_size, Permission.ALL)
                        except self.unicorn.UcError as e:
                            self.last_map_error = "mem_map {:#x}: {!s}".format(emu_page, e)
                            mapped = False
                            break
                        self.mapped.add(emu_page)
                        try:
                            data = self.translate_pointers(data) if not is_fetch else data
                            self.emu.mem_write(emu_page, data)
                        except self.unicorn.UcError as e:
                            self.last_map_error = "mem_write {:#x}: {!s}".format(emu_page, e)
                            self.emu.mem_unmap(emu_page, self.page_size)
                            self.mapped.discard(emu_page)
                            mapped = False
                            break
                        self.last_map_source = "{:s}+{:#x}->{:#x}".format(name, offset_page, source_page)
                        mapped = True
                        break
                    if mapped is None and bases:
                        self.last_map_error = "; ".join(x for x in errors if x) or "per-cpu page not found"
                        mapped = False
            if mapped is None:
                mapped = self.map_page(address, zero_fill=is_write, translate=not is_fetch, emu_address=True)
            self.last_fault["mapped"] = mapped
            if self.last_map_error:
                self.last_fault["map_error"] = self.last_map_error
            if self.last_map_source:
                self.last_fault["map_source"] = self.last_map_source
            return mapped

        def read_page(self, page):
            """Read one page from GDB, falling back to partial chunks."""
            try:
                return read_memory(page, self.page_size), None
            except gdb.MemoryError:
                data = bytearray(b"\x00" * self.page_size)
                ok = False
                for off in range(0, self.page_size, 0x100):
                    try:
                        chunk = read_memory(page + off, min(0x100, self.page_size - off))
                        data[off:off + len(chunk)] = chunk
                        ok = True
                    except gdb.MemoryError:
                        pass
                if ok:
                    return bytes(data), None
            return None, "read_memory {:#x}-{:#x} failed".format(page, page + self.page_size)

        def map_page(self, address, zero_fill=False, translate=True, emu_address=False):
            """Map a GDB or Unicorn page into the emulator."""
            self.last_map_error = None
            self.last_map_source = None
            if address is None:
                self.last_map_error = "address is None"
                return False
            emu_page = (AddressUtil.normalize_address(address) if emu_address else self.to_emu(address)) & self.page_mask
            page = self.from_emu(emu_page) & self.page_mask
            if emu_page in self.mapped:
                return True
            try:
                self.emu.mem_map(emu_page, self.page_size, Permission.ALL)
            except self.unicorn.UcError as e:
                self.last_map_error = "mem_map {:#x}: {!s}".format(emu_page, e)
                return False
            self.mapped.add(emu_page)

            data, error = self.read_page(page)
            if data is None:
                errors = [error] if error else []
                for candidate in self.arm64_kernel_address_candidates(page, allow_low=True):
                    source_page = candidate & self.page_mask
                    data, source_error = self.read_page(source_page)
                    if data is not None:
                        self.last_map_source = "aarch64_kernel+{:#x}->{:#x}".format(
                            page & 0xffff_ffff, source_page,
                        )
                        break
                    if source_error:
                        errors.append(source_error)
                if data is None:
                    if not zero_fill:
                        self.last_map_error = "; ".join(errors) if errors else error
                        self.emu.mem_unmap(emu_page, self.page_size)
                        self.mapped.discard(emu_page)
                        return False
                    data = b"\x00" * self.page_size

            try:
                self.emu.mem_write(emu_page, self.translate_pointers(data) if translate else data)
            except self.unicorn.UcError as e:
                self.last_map_error = "mem_write {:#x}: {!s}".format(emu_page, e)
                self.emu.mem_unmap(emu_page, self.page_size)
                self.mapped.discard(emu_page)
                return False
            return True

        def write_reg(self, name, value):
            """Write a GDB register value into Unicorn after translation."""
            if value is None or name not in self.regs:
                return
            value = AddressUtil.normalize_address(value)
            for candidate in self.arm64_kernel_address_candidates(value):
                try:
                    if is_valid_addr(candidate):
                        value = candidate
                        break
                except Exception:
                    pass
            translated = self.to_emu(value, create=False)
            if translated != value:
                value = translated
            elif self.anchor(value) is not None:
                try:
                    value = self.to_emu(value) if is_valid_addr(value) else value
                except Exception:
                    pass
            try:
                self.emu.reg_write(self.regs[name], value)
            except self.unicorn.UcError:
                pass
            return

        def skip_register(self, reg):
            """Return whether a register should be skipped by bulk operations."""
            from gef.arch.x86 import X86
            if reg not in self.regs:
                return True
            if is_x86_64() and reg in ("$fs", "$gs", "$fs_base", "$gs_base"):
                return True
            if is_x86_32() and reg in X86.special_registers:
                return True
            if is_arm32() and reg.startswith("$c13_c0_"):
                return True
            if (is_arm32() or is_arm64()) and reg == "$cpsr":
                return True
            return False

        def write_pc(self, address):
            """Write the program counter in the Unicorn address space."""
            value = self.to_emu(address)
            # ARM: writing an even PC clears the cpsr T bit (dropping Thumb mode), so
            # keep bit 0 set when currently in Thumb to preserve the mode.
            if is_arm32():
                try:
                    if self.emu.reg_read(self.regs["$cpsr"]) & 0x20:
                        value |= 1
                except self.unicorn.UcError:
                    pass
            self.emu.reg_write(self.pc_reg, value)
            return

        def mem_write_hook(self, emu, _access, address, size, value, _user_data):
            """Record memory changes (before/after) for the modified-memory dump."""
            if self.kwargs["only_insns"]:
                return
            try:
                before = emu.mem_read(address, size)
            except self.unicorn.UcError:
                return
            for i in range(size):
                accessed = address + i
                if accessed not in self.changed_mem:
                    self.changed_mem[accessed] = {}
                    self.changed_mem[accessed]["before"] = before[i]
                self.changed_mem[accessed]["after"] = (value >> (8 * i)) & 0xff
                self.changed_mem[accessed]["type"] = "modified"
            return

        def read_code(self, pc):
            """Read up to one instruction worth of bytes from emulator memory."""
            out = bytearray()
            addr = pc
            while len(out) < 16:
                if not self.map_page(addr, translate=False):
                    break
                emu_addr = self.to_emu(addr)
                page_off = emu_addr & (self.page_size - 1)
                n = min(16 - len(out), self.page_size - page_off)
                try:
                    out += bytes(self.emu.mem_read(emu_addr, n))
                except self.unicorn.UcError:
                    break
                addr += n
            return bytes(out)

        def disasm(self, code, addr):
            """Disassemble a single instruction, handling ARM thumb manually."""
            if is_arm32():
                try:
                    thumb = self.emu.reg_read(self.regs["$cpsr"]) & 0x20
                except Exception:
                    thumb = 0
                cs = self.cs_thumb if thumb else self.cs_arm
            else:
                cs = self.cs
            for insn in cs.disasm(code, addr):
                return insn
            return None

        def show_insn(self, real_pc, code, insn):
            """Print one line of the instruction trace (and registers if verbose)."""
            if not self.kwargs["quiet"]:
                if self.kwargs["verbose"]:
                    self.print_regs()
                code_hex = bytes(code[:insn.size]).hex()
                gef_print(">>> {:d} {:#x}: {:24s} {:s} {:s}".format(
                    self.count, real_pc, code_hex, insn.mnemonic, insn.op_str,
                ))
            self.count += 1
            return

        def print_regs(self):
            """Print the register dump in the unicorn-emulate layout."""
            if self.kwargs["only_insns"]:
                return
            items = list(self.registers.items())
            line = ""
            for i, (name, uc_reg) in enumerate(items):
                value = self.emu.reg_read(uc_reg)
                if name.startswith("$xmm"):
                    line += "{:7s} = {:#034x}  ".format(name, value)
                    if (i % 2 == 1) or (i == len(items) - 1):
                        gef_print(line)
                        line = ""
                else:
                    if self.use_alias:
                        value = self.from_emu(value)
                    line += "{:7s} = {:#0{:d}x}  ".format(name, value, runtime.current_arch.ptrsize * 2 + 2)
                    if (i % 4 == 3) or (i == len(items) - 1):
                        gef_print(line)
                        line = ""
            if line:
                gef_print(line)
            return

        def print_mems(self):
            """Print the modified-memory diff (before | after) in the unicorn-emulate layout."""
            if self.kwargs["only_insns"]:
                return
            aligned_addrs = {x & ~0xf for x in self.changed_mem.keys()}
            for aligned_addr in aligned_addrs:
                for pad_addr in range(aligned_addr, aligned_addr + 0x10):
                    if pad_addr in self.changed_mem:
                        continue
                    try:
                        byte = self.emu.mem_read(pad_addr, 1)[0]
                    except self.unicorn.UcError:
                        byte = 0
                    self.changed_mem[pad_addr] = {"before": byte, "after": byte, "type": None}
            sorted_data = sorted(self.changed_mem.items())
            sliced = [sorted_data[i:i + 16] for i in range(0, len(sorted_data), 16)]
            prev_address = None
            for chunk in sliced:
                address = chunk[0][0]
                prefix = "{:#0{:d}x}".format(self.from_emu(address), runtime.current_arch.ptrsize * 2 + 2)
                before = ""
                after = ""
                for i in range(16 // runtime.current_arch.ptrsize):
                    atmp = []
                    btmp = []
                    for j in range(runtime.current_arch.ptrsize):
                        idx = i * runtime.current_arch.ptrsize + j
                        a = chunk[idx][1]["after"]
                        b = chunk[idx][1]["before"]
                        if a == b:
                            if chunk[idx][1]["type"] is None:
                                btmp.append("{:02x}".format(b))
                                atmp.append("{:02x}".format(a))
                            else:
                                btmp.append("\033[2m{:02x}\033[0m".format(b))
                                atmp.append("\033[2m{:02x}\033[0m".format(a))
                        else:
                            btmp.append("\033[2m\033[1m{:02x}\033[0m".format(b))
                            atmp.append("\033[2m\033[1m{:02x}\033[0m".format(a))
                    before += "0x" + "".join(btmp[::-1]) + " "
                    after += "0x" + "".join(atmp[::-1]) + " "
                line = "{:s} | {:s}| {:s}|".format(prefix, before, after)
                if prev_address is not None and prev_address + 0x10 != address:
                    gef_print("*")
                gef_print(line)
                prev_address = address
            gef_print("\033[2m00\033[0m: write accessed, \033[2m\033[1m00\033[0m: value changes")
            return

        def patch_got(self):
            """Patch GOT entries to avoid avx/neon optimized functions Unicorn can't emulate."""
            if is_x86_64():
                re_opt = re.compile(r"^(?:\*ABS\*|__str|__mem|str|mem).* \| .+ \| (0x\S+) \| (0x\S+) <(__(\w+)_avx2?.*)>")
            elif is_arm32():
                re_opt = re.compile(r"^(?:\*ABS\*|__str|__mem|str|mem).* \| .+ \| (0x\S+) \| (0x\S+) <(__(\w+)_neon.*)>")
            else:
                return

            res = gdb.execute("got-all --no-pager", to_string=True)
            for line in res.splitlines():
                line = Color.remove_color(line)
                m = re_opt.search(line)
                if not m:
                    continue
                try:
                    got = int(m.group(1), 16)
                    base_func_name = m.group(4)
                except ValueError:
                    continue

                # get original function (e.g., __memmove_avx_unaligned_erms -> __memmove)
                try:
                    base_func_addr = int(gdb.parse_and_eval("&{:s}".format(base_func_name)))
                except (gdb.error, ValueError):
                    try:
                        base_func_name = "__" + base_func_name # e.g., __memmove_chk
                        base_func_addr = int(gdb.parse_and_eval("&{:s}".format(base_func_name)))
                    except (gdb.error, ValueError):
                        continue

                if not self.map_page(got):
                    continue
                try:
                    self.emu.mem_write(
                        self.to_emu(got),
                        AddressUtil.normalize_address(base_func_addr).to_bytes(self.ptrsize, self.endian),
                    )
                except self.unicorn.UcError:
                    pass
            return

        def is_syscall_insn(self, insn):
            """Return whether the instruction triggers a syscall handled by this command."""
            mnemonic = insn.mnemonic.lower()
            if is_x86_64():
                return mnemonic == "syscall"
            if is_x86_32():
                return mnemonic == "int" and insn.op_str.strip() == "0x80"
            if is_arm64():
                return mnemonic == "svc"
            if is_arm32():
                return mnemonic in ("svc", "swi")
            return False

        def handle_syscall(self, insn):
            """Emulate (or report) a syscall; return None to continue or a reason to stop."""
            syscall_register = runtime.current_arch.syscall_register
            if syscall_register in self.regs:
                sysno = self.emu.reg_read(self.regs[syscall_register])
            else:
                sysno = None
            if sysno is not None and self.last_syscall is None:
                self.last_syscall = sysno
            if self.kwargs["emulate_mmap"] and sysno is not None:
                for emulate in (self.emulate_mmap, self.emulate_munmap, self.emulate_brk):
                    if emulate(sysno):
                        self.write_pc(insn.address + insn.size)
                        return None
            gef_print("  --> syscall={!s} (not emulated)".format(sysno))
            return "syscall {!s} not emulated".format(sysno)

        def emulate_mmap(self, sysno):
            """Best-effort emulation of an anonymous private mmap (for main_arena expansion)."""
            entry = self.mmap_entry
            if sysno != entry.nr:
                return False
            a1 = self.emu.reg_read(self.regs[entry.arg_regs[0]])
            if a1 != 0:
                return False
            a2 = self.emu.reg_read(self.regs[entry.arg_regs[1]])
            if a2 == 0 or (a2 & 0xfff) != 0:
                return False
            if a2 > 0x1000_0000: # heuristic value (0x800_0000 is used to create thread arena)
                return False
            a3 = self.emu.reg_read(self.regs[entry.arg_regs[2]]) & 7
            a4 = self.emu.reg_read(self.regs[entry.arg_regs[3]])
            if a4 != 0x22: # MAP_ANONYMOUS|MAP_PRIVATE
                return False
            a5 = self.emu.reg_read(self.regs[entry.arg_regs[4]])
            if a5 != 0xffff_ffff:
                return False
            a6 = self.emu.reg_read(self.regs[entry.arg_regs[5]])

            regions = [(None, 0, None)] + list(self.emu.mem_regions())
            regions = regions[::-1]
            map_start = None
            for (mr1, mr2) in zip(regions[:-1], regions[1:]):
                if is_64bit() and mr1[0] >= 0x8000_0000_0000_0000: # avoid around [vsyscall]
                    continue
                if mr1[0] - mr2[1] >= a2:
                    map_start = mr1[0] - a2
                    break
            if map_start is None:
                return False # not found space
            try:
                self.emu.mem_map(map_start, a2, a3)
                self.emu.reg_write(self.regs[entry.ret_regs[0]], map_start)
            except Exception:
                return False
            self.mapped.add(map_start & self.page_mask)
            gef_print("  --> syscall={:d} (emulated)".format(sysno))
            gef_print("    --> {:#x} = mmap({:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x})".format(
                map_start, a1, a2, a3, a4, a5, a6,
            ))
            return True

        def emulate_munmap(self, sysno):
            """Best-effort emulation of munmap."""
            entry = self.munmap_entry
            if sysno != entry.nr:
                return False
            a1 = self.emu.reg_read(self.regs[entry.arg_regs[0]])
            a2 = self.emu.reg_read(self.regs[entry.arg_regs[1]])
            if a2 == 0 or (a2 & 0xfff) != 0:
                return False
            try:
                self.emu.mem_unmap(a1, a2)
                self.emu.reg_write(self.regs[entry.ret_regs[0]], 0)
            except Exception:
                return False
            for page in range(a1 & self.page_mask, a1 + a2, self.page_size):
                self.mapped.discard(page)
            gef_print("  --> syscall={:d} (emulated)".format(sysno))
            gef_print("    --> munmap({:#x}, {:#x})".format(a1, a2))
            return True

        def emulate_brk(self, sysno):
            """Best-effort emulation of brk (for main_arena expansion)."""
            entry = self.brk_entry
            if sysno != entry.nr:
                return False
            a1 = self.emu.reg_read(self.regs[entry.arg_regs[0]])

            if a1 == 0 or a1 == self.current_brk:
                self.emu.reg_write(self.regs[entry.ret_regs[0]], self.current_brk)
                gef_print("  --> syscall={:d} (emulated)".format(sysno))
                gef_print("    --> {:#x} = brk({:#x})".format(self.current_brk, a1))
                return True

            if a1 > self.current_brk:
                map_perm = None
                for r in self.emu.mem_regions(): # get the permission of current brk region
                    if r[1] + 1 == self.current_brk:
                        map_perm = r[2]
                        break
                if map_perm is None:
                    return False # something is wrong
                try:
                    self.emu.mem_map(self.current_brk, a1 - self.current_brk, map_perm)
                except Exception:
                    return False
                for page in range(self.current_brk & self.page_mask, a1, self.page_size):
                    self.mapped.add(page)
            else:
                try:
                    self.emu.mem_unmap(a1, self.current_brk - a1)
                except Exception:
                    return False
                for page in range(a1 & self.page_mask, self.current_brk, self.page_size):
                    self.mapped.discard(page)

            self.emu.reg_write(self.regs[entry.ret_regs[0]], a1)
            gef_print("  --> syscall={:d} (emulated)".format(sysno))
            gef_print("    --> {:#x} = brk({:#x})".format(a1, a1))
            self.current_brk = a1
            return True

        def is_arm64_atomic(self, mnemonic):
            """Return True for an AArch64 LSE atomic memory op that Unicorn cannot emulate."""
            return re.match(
                r"^(?:cas|swp|ld(?:add|clr|eor|set|smax|smin|umax|umin)"
                r"|st(?:add|clr|eor|set|smax|smin|umax|umin))(?:al|a|l)?(?:b|h)?$",
                mnemonic,
            ) is not None

        def arm64_atomic_op(self, op, mem_val, src_val, width):
            """Return the value an AArch64 ld<op>/st<op> atomic writes back to memory."""
            if op == "add":
                return mem_val + src_val
            if op == "clr":
                return mem_val & ~src_val
            if op == "eor":
                return mem_val ^ src_val
            if op == "set":
                return mem_val | src_val
            # signed min/max sign-extend both values at the access width before comparing
            bits = width * 8
            if op in ("smax", "smin"):
                a = mem_val - (1 << bits) if mem_val >> (bits - 1) else mem_val
                b = src_val - (1 << bits) if src_val >> (bits - 1) else src_val
            else:
                a, b = mem_val, src_val
            return max(a, b) if op in ("smax", "umax") else min(a, b)

        def emulate_arm64_atomic(self, insn):
            """Emulate AArch64 LSE atomics (cas/swp/ld<op>/st<op>), which Unicorn does not support."""
            decoded = re.match(
                r"^(cas|swp|ld(add|clr|eor|set|smax|smin|umax|umin)"
                r"|st(add|clr|eor|set|smax|smin|umax|umin))(?:al|a|l)?(b|h)?$",
                insn.mnemonic.lower(),
            )
            if decoded is None:
                return "unsupported atomic {:s}".format(insn.mnemonic)
            base = decoded.group(1) # cas, swp, or the ld<op>/st<op> base mnemonic
            op = decoded.group(2) or decoded.group(3) # the <op> for ld<op>/st<op>, else None
            size = decoded.group(4) # "b"/"h" for byte/halfword variants, else None
            # cas/swp/ld<op> use "Rs, Rt, [Xn]"; st<op> uses "Rs, [Xn]" (no destination Rt)
            match = re.search(
                r"([xw](?:\d+|zr))(?:, ([xw](?:\d+|zr)))?, \[(x\d+|sp)\]",
                (insn.op_str if hasattr(insn, "op_str") else ", ".join(insn.operands)).lower(),
            )
            if not match:
                return "unsupported {:s} operand".format(insn.mnemonic)
            # a b/h suffix forces a 1/2-byte access, otherwise the register width applies
            width = 1 if size == "b" else 2 if size == "h" else (8 if match.group(1)[0] == "x" else 4)
            src_reg = None if match.group(1).endswith("zr") else "$x" + match.group(1)[1:]
            dst_reg = None if match.group(2) is None or match.group(2).endswith("zr") else "$x" + match.group(2)[1:]
            base_reg = "$sp" if match.group(3) == "sp" else "$" + match.group(3)
            for reg in (base_reg, src_reg, dst_reg):
                if reg is not None and reg not in self.regs:
                    return "unsupported {:s} register {:s}".format(insn.mnemonic, reg)
            try:
                mem_addr = self.emu.reg_read(self.regs[base_reg])
                if not self.map_page(mem_addr, emu_address=True):
                    detail = " ({:s})".format(self.last_map_error) if self.last_map_error else ""
                    return "cannot map {:#x}{:s}".format(self.from_emu(mem_addr), detail)
                mask = (1 << (width * 8)) - 1
                mem_val = int.from_bytes(bytes(self.emu.mem_read(mem_addr, width)), "little")
                src_val = (self.emu.reg_read(self.regs[src_reg]) & mask) if src_reg is not None else 0
                if base == "cas":
                    # compare Rs with memory and store Rt only when they are equal
                    store_val = (self.emu.reg_read(self.regs[dst_reg]) & mask) if dst_reg is not None else 0
                    if src_val == mem_val:
                        self.emu.mem_write(mem_addr, int(store_val).to_bytes(width, "little"))
                    # cas always loads the original memory value into Rs
                    if src_reg is not None:
                        self.emu.reg_write(self.regs[src_reg], mem_val)
                else:
                    # swp stores Rs as-is; ld<op>/st<op> store mem <op> Rs
                    store_val = src_val if base == "swp" else self.arm64_atomic_op(op, mem_val, src_val, width) & mask
                    self.emu.mem_write(mem_addr, int(store_val).to_bytes(width, "little"))
                    # swp/ld<op> load the original memory value into Rt (st<op> has none)
                    if dst_reg is not None:
                        self.emu.reg_write(self.regs[dst_reg], mem_val)
                self.write_pc(insn.address + 4)
                return None
            except self.unicorn.UcError as e:
                return str(e)

        def emulate_arm32_mrc(self, insn):
            """Proactively emulate `mrc p15, 0, Rt, c13, c0, {2,3,4}` (TLS); used for kernel too.

            Returns "skip" when the instruction is not such an mrc, None when handled, or
            an error string otherwise."""
            rt = None
            opc2 = None
            opcodes = bytes(insn.bytes)
            if len(opcodes) == 4:
                word = int.from_bytes(opcodes, "little")
                opc1 = (word >> 21) & 0x7
                crn = (word >> 16) & 0xf
                coproc = (word >> 8) & 0xf
                crm = word & 0xf
                is_mrc = (word & 0x0f10_0010) == 0x0e10_0010
                if is_mrc and opc1 == 0 and crn == 13 and coproc == 15 and crm == 0:
                    rt = (word >> 12) & 0xf
                    opc2 = (word >> 5) & 0x7
            if opc2 is None and insn.mnemonic == "mrc":
                operands = insn.op_str.lower()
                match = re.search(
                    r"p15,\s*#?(?:0x)?0,\s*r(\d+),\s*c13,\s*c0,\s*#?(?:0x)?([234])",
                    operands,
                )
                if match:
                    rt = int(match.group(1))
                    opc2 = int(match.group(2), 16 if match.group(2).startswith("0x") else 10)
            if opc2 is None:
                return "skip"
            value = self.arm32_c13_c0.get(opc2)
            dst = "$r{:d}".format(rt)
            if value is None:
                return "unsupported mrc p15, #0, {:s}, c13, c0, #{:d}".format(dst[1:], opc2)
            if rt == 15:
                self.write_pc(insn.address + 4)
                return None
            if dst not in self.regs:
                return "unsupported mrc destination {:s}".format(dst)
            try:
                self.emu.reg_write(self.regs[dst], AddressUtil.normalize_address(value))
                self.write_pc(insn.address + 4)
                return None
            except self.unicorn.UcError as e:
                return str(e)

        def step_one(self, insn):
            """Emulate one instruction; return None on success or a reason string on stop."""
            self.last_fault = None
            self.last_map_error = None
            self.current_segment = None
            mnemonic = insn.mnemonic.lower()
            op_str = insn.op_str.lower()
            if is_x86_32() or is_x86_64():
                if "gs:" in op_str:
                    self.current_segment = "gs"
                elif "fs:" in op_str:
                    self.current_segment = "fs"
            # arm32 TLS access via mrc p15 (handled directly for userland and kernel)
            if is_arm32():
                reason = self.emulate_arm32_mrc(insn)
                if reason != "skip":
                    return reason
            # arm64 LSE atomic instructions Unicorn cannot emulate (handled in-process)
            if is_arm64() and self.is_arm64_atomic(mnemonic):
                return self.emulate_arm64_atomic(insn)
            # syscalls
            if self.is_syscall_insn(insn):
                return self.handle_syscall(insn)
            # default: single-step in Unicorn
            start = self.to_emu(insn.address)
            # End bound from the real address; must stay strictly above `start` even when
            # the instruction is a single byte at an odd address (common on x86), otherwise
            # Unicorn stops immediately without executing anything.
            end = start + max(1, insn.size)
            self.write_pc(insn.address)
            # ARM: emu_start selects Thumb mode from bit 0 of the start address, so it
            # must be set when single-stepping Thumb code (otherwise Unicorn drops to ARM
            # mode and clears the cpsr T bit, breaking the rest of the run).
            if is_arm32() and (self.emu.reg_read(self.regs["$cpsr"]) & 0x20):
                start |= 1
            try:
                self.emu.emu_start(start, end, count=1)
            except self.unicorn.UcError as e:
                detail = str(e)
                if self.last_fault is not None:
                    address = self.last_fault.get("address")
                    if address is not None:
                        detail += " (access={:s}, addr={:#x}".format(self.last_fault.get("access", "?"), address)
                        if self.last_fault.get("map_error"):
                            detail += ", {:s}".format(self.last_fault["map_error"])
                        detail += ")"
                return detail
            finally:
                self.current_segment = None
            return None

        def run(self, kwargs):
            """Drive the linear emulation and print the unicorn-emulate style output."""
            start = kwargs["start_insn"]
            end = kwargs["end_insn"]
            nb_gadget = kwargs["nb_gadget"]

            if not kwargs["only_insns"]:
                gef_print("========================= Initial registers =========================")
                self.print_regs()
                gef_print("========================= Starting emulation =========================")

            self.write_pc(start)
            failed = None
            try:
                while True:
                    pc = self.from_emu(self.emu.reg_read(self.pc_reg))
                    if nb_gadget is None:
                        if end is not None and pc == end:
                            break
                        # safety cap so `-t`/`-n` runs cannot loop forever (e.g., when the
                        # target is never reached, such as emulating an unresolved PLT).
                        if self.count >= self.MAX_INSNS:
                            failed = "instruction limit reached ({:d})".format(self.MAX_INSNS)
                            break
                    elif self.count >= nb_gadget:
                        break
                    if not self.map_page(pc, translate=False):
                        detail = " ({:s})".format(self.last_map_error) if self.last_map_error else ""
                        failed = "cannot map {:#x}{:s}".format(pc, detail)
                        break
                    code = self.read_code(pc)
                    insn = self.disasm(code, pc)
                    if insn is None:
                        failed = "cannot disassemble {:#x}".format(pc)
                        break
                    self.show_insn(pc, code, insn)
                    reason = self.step_one(insn)
                    if reason is not None:
                        failed = reason
                        break
            except KeyboardInterrupt:
                failed = "interrupted"
            self.failed = failed

            if failed is not None and not kwargs["quiet"]:
                gef_print("========================= Emulation failed =========================")
                gef_print("  --> {:s}".format(failed))

            if not kwargs["only_insns"]:
                gef_print("========================= Final registers =========================")
                self.print_regs()
                gef_print("========================= Modified memories (before | after) =========================")
                self.print_mems()
            return

        def step(self, insn):
            """Emulate one instruction and return a reason string on failure."""
            from gef.commands.debugging.context import ContextCodeCommand
            self.last_fault = None
            self.last_map_error = None
            self.last_map_source = None
            self.current_segment = None
            if is_x86_32() or is_x86_64():
                operands = " ".join(insn.operands).lower()
                if "gs:" in operands:
                    self.current_segment = "gs"
                elif "fs:" in operands:
                    self.current_segment = "fs"
            if not self.map_page(insn.address, translate=False):
                detail = " ({:s})".format(self.last_map_error) if self.last_map_error else ""
                return "cannot map {:#x}{:s}".format(insn.address, detail)
            start = self.to_emu(insn.address)
            self.write_pc(insn.address)
            if is_arm32():
                rt = None
                opc2 = None
                if len(insn.opcodes) == 4:
                    word = int.from_bytes(bytes(insn.opcodes), "little")
                    opc1 = (word >> 21) & 0x7
                    crn = (word >> 16) & 0xf
                    coproc = (word >> 8) & 0xf
                    crm = word & 0xf
                    is_mrc = (word & 0x0f10_0010) == 0x0e10_0010
                    if is_mrc and opc1 == 0 and crn == 13 and coproc == 15 and crm == 0:
                        rt = (word >> 12) & 0xf
                        opc2 = (word >> 5) & 0x7
                if opc2 is None and insn.mnemonic == "mrc":
                    operands = ", ".join(insn.operands).lower()
                    match = re.search(
                        r"p15,\s*#?(?:0x)?0,\s*r(\d+),\s*c13,\s*c0,\s*#?(?:0x)?([234])",
                        operands,
                    )
                    if match:
                        rt = int(match.group(1))
                        opc2 = int(match.group(2), 16 if match.group(2).startswith("0x") else 10)
                if opc2 is not None:
                    value = self.arm32_c13_c0.get(opc2)
                    dst = "$r{:d}".format(rt)
                    if value is None:
                        return "unsupported mrc p15, #0, {:s}, c13, c0, #{:d}".format(dst[1:], opc2)
                    if rt == 15:
                        self.write_pc(insn.address + 4)
                        return None
                    if dst not in self.regs:
                        return "unsupported mrc destination {:s}".format(dst)
                    try:
                        self.emu.reg_write(self.regs[dst], AddressUtil.normalize_address(value))
                        self.write_pc(insn.address + 4)
                        return None
                    except self.unicorn.UcError as e:
                        return str(e)
            if is_arm64() and self.is_arm64_atomic(insn.mnemonic.lower()):
                return self.emulate_arm64_atomic(insn)
            try:
                self.emu.emu_start(start, start + max(1, len(insn.opcodes)), count=1)
            except self.unicorn.UcError as e:
                recovered_pc = None
                if is_x86_32() and self.last_fault is not None:
                    fault = self.last_fault.get("address")
                    access = self.last_fault.get("access")
                    try:
                        target = ContextCodeCommand.get_branch_addr(insn)
                    except Exception:
                        target = None
                    if access in ("UC_MEM_FETCH_UNMAPPED", "UC_MEM_FETCH_PROT") and fault is not None and target is not None:
                        fault = AddressUtil.normalize_address(fault)
                        target = AddressUtil.normalize_address(target)
                        if fault != target:
                            if fault <= 0xffff and (target & 0xffff) == fault:
                                recovered_pc = target
                            elif fault <= 0xfffff and (target & 0xfffff) == fault:
                                recovered_pc = target
                if recovered_pc is not None:
                    self.last_fault["recovered_pc"] = recovered_pc
                    self.write_pc(recovered_pc)
                    return None
                return str(e)
            finally:
                self.current_segment = None
            return None

        def skip_to(self, saved, address):
            """Restore saved registers and continue at the given address."""
            for reg, value in saved.items():
                if self.skip_register(reg):
                    continue
                try:
                    self.emu.reg_write(self.regs[reg], value)
                except self.unicorn.UcError:
                    pass
            self.write_pc(address)
            return
