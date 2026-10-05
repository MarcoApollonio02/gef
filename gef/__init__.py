"""GEF — Multi-Architecture GDB Enhanced Features (modular package).

This is the package form of the former monolithic gef.py. See
docs/ARCHITECTURE.md for the layout and layering rules.

The package contains the core domain, the architecture families, the command
implementations, and the bootstrap that discovers and registers them.

All public names are exposed lazily (PEP 562, ``__getattr__``) so that plain
``import gef`` and ``from gef import *`` work even outside a GDB session;
the underlying modules are imported on first attribute access (they need GDB's
embedded Python at runtime).
"""

_REEXPORTS = {
    "gef.core.address": ("Address", "AddressUtil", "Endian", "Permission", "Section"),
    "gef.core.arch_base": ("Architecture",),
    "gef.core.auxv": ("Auxv",),
    "gef.core.bitinfo": ("BitInfo",),
    "gef.core.cache": ("Cache",),
    "gef.core.color": ("Color", "err", "gef_print", "info", "ok", "titlify", "warn"),
    "gef.core.config": ("Config",),
    "gef.core.display": ("DisplayHook", "hexoff", "hexon"),
    "gef.core.elf": ("Checksec", "Elf"),
    "gef.core.errors": ("GefError", "show_last_exception"),
    "gef.core.events": ("EventHandler", "EventHooking", "only_if_events_supported"),
    "gef.core.highlight": ("highlight_text",),
    "gef.core.instruction": ("Disasm", "Instruction", "get_insn", "get_insn_next", "get_insn_prev"),
    "gef.core.memory": (
        "hexdump",
        "is_ascii_string", "is_double_link_list", "is_single_link_list",
        "is_valid_addr", "is_valid_addr_addr",
        "p8", "p16", "p32", "p64", "u8", "u16", "u32", "u64", "u128",
        "read_cstring_from_memory", "read_int8_from_memory", "read_int16_from_memory",
        "read_int32_from_memory", "read_int64_from_memory", "read_int_from_memory",
        "read_memory", "write_memory",
    ),
    "gef.core.pagewalk": ("KernelAddressHeuristicFinder", "KernelAddressHeuristicFinderUtil", "PageMap"),
    "gef.core.process": (
        "Pid", "Path", "ProcessMap",
        "get_arch", "get_pagesize", "get_pagesize_mask_high", "get_pagesize_mask_low",
        "is_alive", "is_alpha", "is_arc32", "is_arc64", "is_arm32", "is_arm32_cortex_m",
        "is_arm64", "is_attach", "is_container_attach", "is_cris", "is_csky",
        "is_emulated32", "is_hppa32", "is_hppa64", "is_in_kernel", "is_in_secure",
        "is_in_smm", "is_kdb", "is_kgdb", "is_kvm_enabled", "is_loongarch64",
        "is_m68k", "is_microblaze", "is_mips32", "is_mips64", "is_mipsn32",
        "is_nios2", "is_normal_run", "is_or1k", "is_over_serial", "is_pin",
        "is_ppc32", "is_ppc64", "is_qiling", "is_qemu", "is_qemu_system",
        "is_qemu_user", "is_remote_debug", "is_riscv32", "is_riscv64", "is_rr",
        "is_s390x", "is_sh4", "is_smp_enabled", "is_sparc32", "is_sparc32plus",
        "is_sparc64", "is_support_secure_world", "is_vmware", "is_wine",
        "is_x86", "is_x86_16", "is_x86_32", "is_x86_64", "is_xtensa",
        "is_32bit", "is_64bit", "kgdb_has_system_registers", "scan_smm_token_in_monitor",
        "set_arch",
    ),
    "gef.core.qemu": (
        "QemuMonitor", "disable_phys", "enable_phys", "is_supported_physmode",
        "read_physmem", "write_physmem",
    ),
    "gef.core.registers": ("get_register", "to_unsigned_long"),
    "gef.core.strings": ("String",),
    "gef.core.symbols": ("ModuleLoader", "Symbol"),
    "gef.core.types": ("GenericType", "GlibcHeap"),
    "gef.core.unicorn": ("UnicornKeystoneCapstone",),
    "gef.core.utils": (
        "GefUtil", "align_to_pagesize", "align_to_ptrsize", "align", "byteswap",
        "cperf", "get_libc_version", "perf", "rol", "ror", "slice_unpack", "slicer",
        "switch_to_intel_syntax", "timeout", "xor",
    ),
    "gef.bootstrap": ("Gef",),
}

_NAME_SOURCE = {name: module for module, names in _REEXPORTS.items() for name in names}

__all__ = sorted(_NAME_SOURCE)


class _LazyProxy:
    """Placeholder returned when a name is accessed outside a GDB session.

    The real module import is attempted on any actual use (attribute access or
    call); by then we must be running inside GDB's embedded Python.
    """

    def __init__(self, module, name):
        object.__setattr__(self, "_module", module)
        object.__setattr__(self, "_name", name)

    def _resolve(self):
        import importlib

        return getattr(importlib.import_module(object.__getattribute__(self, "_module")),
                       object.__getattribute__(self, "_name"))

    def __getattr__(self, item):
        return getattr(self._resolve(), item)

    def __call__(self, *args, **kwargs):
        return self._resolve()(*args, **kwargs)

    def __repr__(self):
        return f"<lazy gef.{object.__getattribute__(self, '_name')} (loads inside GDB)>"


def __getattr__(name):
    if name == "process":
        import importlib

        return importlib.import_module("gef.core.process")
    module = _NAME_SOURCE.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    import importlib

    try:
        return getattr(importlib.import_module(module), name)
    except ModuleNotFoundError as exc:
        if exc.name == "gdb":
            # Outside a GDB session: defer the real import until first use.
            return _LazyProxy(module, name)
        raise


def __dir__():
    return sorted(__all__ + ["process"])
