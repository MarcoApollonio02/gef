"""Unicorn / Keystone / Capstone architecture-translation helpers (Layer 1).

`UnicornKeystoneCapstone` is a `@staticmethod` collection that maps GEF's
current architecture onto the arch/mode constants of the
capstone/keystone/unicorn trinity, plus the unicorn register map helper and
the keystone assembly wrapper.

Reads of the mutable global `current_arch` go through `runtime.current_arch`.
References to `gef.core.process` (arch predicates) and the not-yet-extracted
`timeout` helper are late-imported inside the referencing method.
"""
import binascii
import sys

from gef.core import runtime
from gef.core.address import Endian
from gef.core.color import err
from gef.core.strings import String
from gef.core.symbols import ModuleLoader


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


