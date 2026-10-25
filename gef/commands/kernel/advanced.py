"""GEF kernel commands (category 06-g) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Linux Advanced: kernel module/device/config
inspection (kmod, kblockdevs, kchardevs, kops, ksysctl, kfilesystems,
kclocksource, ktimer, kpcidev, kconfig, kdmesg, syscall-table-view, kpipe,
kbpf, kipcs, kdevio, kdmabuf, kirq, knetdev). Auto-discovered by gef.bootstrap
via pkgutil.walk_packages.
"""
import argparse
import bisect
import collections
import itertools
import os
import re
import struct
import subprocess
import sys

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    only_if_in_kernel_or_kpti_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.cache import Cache
from gef.core.color import Color, err, info, titlify, warn
from gef.core.config import Config
from gef.core.instruction import Disasm, get_insn, get_insn_next
from gef.core.display import ProgressBar
from gef.core.kernel import (Kernel, KernelDevice, KernelListHead, KernelMapleTree, KernelNftables,
                             KernelRBTree, KernelRadixTree, KernelSlub, KernelTask, KernelVersion,
                             KernelXArray, Ksym)
from gef.core.memory import (
    hexdump,
    is_ascii_string,
    is_double_link_list,
    is_valid_addr,
    is_valid_addr_addr,
    read_cstring_from_memory,
    read_int16_from_memory,
    read_int32_from_memory,
    read_int64_from_memory,
    read_int8_from_memory,
    read_int_from_memory,
    read_memory,
    u16,
    u32,
    u64,
)
from gef.core.pagewalk import KernelAddressHeuristicFinder, KernelAddressHeuristicFinderUtil
from gef.core.process import (
    ProcessMap,
    get_pagesize,
    get_pagesize_mask_high,
    is_32bit,
    is_64bit,
    is_arm32,
    is_arm64,
    is_hppa32,
    is_hppa64,
    is_kgdb,
    is_m68k,
    is_qemu_system,
    is_riscv32,
    is_riscv64,
    is_sparc32,
    is_sparc32plus,
    is_sparc64,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import to_unsigned_long
from gef.core.strings import String
from gef.core.symbols import Symbol
from gef.core.syscall import Syscall
from gef.core.utils import (GEF_TEMP_DIR, GefUtil, align, align_to_ptrsize, slicer, slice_unpack,
                            switch_to_intel_syntax, u2i)


@register_command
class KernelModuleCommand(GenericCommand, BufferingOutput):
    """Display kernel module list."""

    _cmdline_ = "kmod"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("-s", "--resolve-symbol", action="store_true", help="try to resolve symbols.")
    group.add_argument("-a", "--apply-symbol", action="store_true",
                        help="try to apply symbol in the form 'module_name.symbol'.")
    parser.add_argument("--symbol-unsort", action="store_true",
                        help="print resolved symbols without sorting by address.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="REGEXP filter.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n.",
        "",
        "Simplified module structure:",
        "",
        "                   +-module------------------+",
        "+-modules-----+    | ...                     |",
        "| list_head   |--->| list                    |--->...",
        "+-------------+    | name[]                  |",
        "                   | ...                     |",
        "                   | mem[] (v6.4~)           |",
        "                   |     base                |",
        "                   |     size                |",
        "                   |     ...                 |",
        "                   | init_layout (v4.5~v6.4) |",
        "                   |     base                |",
        "                   |     size                |",
        "                   |     text_size           |",
        "                   |     ro_size             |",
        "                   |     ro_after_init_size  |",
        "                   |     ...                 |",
        "                   | module_core    (~v4.4)  |",
        "                   | init_size      (~v4.4)  |",
        "                   | core_size      (~v4.4)  |",
        "                   | init_text_size (~v4.4)  |  +-->+-mod_kallsyms---+",
        "                   | core_text_size (~v4.4)  |  |   | symtab         |",
        "                   | ...                     |  |   | num_symtab     |",
        "                   | kallsyms                |--+   | strtab         |",
        "                   | ...                     |      | typetab (v5.2~)|",
        "                   +-------------------------+      +----------------+",
        "",
        "Notes for -a option:",
        "- You can check the added symbols with the `symbols` command.",
        "- Added symbols are in the format `module_name.symbol` to avoid collisions.",
        "  When used from the command line, they must be enclosed in single quotes.",
        "  e.g., `p 'virtio_net.__this_module'`",
    ]
    _note_ = "\n".join(_note_)

    def get_modules_list(self, modules):
        # use cache
        if self.module_addrs:
            return self.module_addrs

        # slow path
        if modules is None:
            return None

        module_addrs = []
        current = modules
        while True:
            try:
                addr = read_int_from_memory(current)
            except gdb.MemoryError:
                return None
            if addr == modules:
                break
            module_addrs.append(addr - runtime.current_arch.ptrsize)
            current = addr
        return module_addrs

    def get_offset_name(self, module_addrs):
        # fast path
        try:
            return to_unsigned_long(gdb.parse_and_eval("&((struct module*)0).name"))
        except gdb.error:
            pass

        # slow_path
        for i in range(0x10):
            offset_name = i * runtime.current_arch.ptrsize
            valid = True
            for module in module_addrs:
                if not is_ascii_string(module + offset_name):
                    valid = False
                    break
                s = read_cstring_from_memory(module + offset_name)
                if len(s) < 2:
                    valid = False
                    break
            if valid:
                return offset_name

        return None

    def get_offset_mem(self, module_addrs): # v6.4~
        """
        ac3b43283923440900b4f36ca5f9f0b1ca43b70e changed the module layout information structure
        MOD_TEXT = 0,
        MOD_DATA,
        MOD_RODATA,
        MOD_RO_AFTER_INIT,
        MOD_INIT_TEXT,
        MOD_INIT_DATA,
        MOD_INIT_RODATA,

        struct module {
            enum module_state state;
            struct list_head list;
            char name[MODULE_NAME_LEN]; // 64 - sizeof(unsigned long) bytes
        #ifdef CONFIG_STACKTRACE_BUILD_ID
            unsigned char build_id[BUILD_ID_SIZE_MAX]; // 20 bytes
        #endif
            struct module_kobject mkobj;
            struct module_attribute *modinfo_attrs;
            const char *version;
            const char *srcversion;
            struct kobject *holders_dir;
            const struct kernel_symbol *syms;
            const s32 *crcs;
            unsigned int num_syms;
        #ifdef CONFIG_ARCH_USES_CFI_TRAPS
            s32 *kcfi_traps;
            s32 *kcfi_traps_end;
        #endif
        #ifdef CONFIG_SYSFS
            struct mutex param_lock;
        #endif
            struct kernel_param *kp;
            unsigned int num_kp;
            unsigned int num_gpl_syms;
            const struct kernel_symbol *gpl_syms;
            const s32 *gpl_crcs;
            bool using_gplonly_symbols;
        #ifdef CONFIG_MODULE_SIG
            bool sig_ok;
        #endif
            bool async_probe_requested;
            unsigned int num_exentries;
            struct exception_table_entry *extable;
            int (*init)(void);
            struct module_memory mem[MOD_MEM_NUM_TYPES] __module_memory_align;    <-- here
            struct mod_arch_specific arch;
            unsigned long taints;
        #ifdef CONFIG_GENERIC_BUG
            unsigned num_bugs;
            struct list_head bug_list;
            struct bug_entry *bug_table;
        #endif
        #ifdef CONFIG_KALLSYMS
            struct mod_kallsyms __rcu *kallsyms;
            struct mod_kallsyms core_kallsyms;
            struct module_sect_attrs *sect_attrs;
            struct module_notes_attrs *notes_attrs;
        #endif
        };

        struct module_memory {
            void *base;
            void *rw_copy; // v6.13~6.14
            bool is_rox;   // v6.13~
            unsigned int size;
        #ifdef CONFIG_MODULES_TREE_LOOKUP
            struct mod_tree_node mtn; (0x38)
        #endif
        };
        """
        # fast path
        try:
            offset_mem = to_unsigned_long(gdb.parse_and_eval("&((struct module*)0).mem"))
            offset_size = to_unsigned_long(gdb.parse_and_eval("&((struct module_memory*)0).size"))
            return offset_mem, offset_mem + offset_size
        except gdb.error:
            pass

        # slow_path
        MOD_TEXT = 0
        MOD_DATA = 1
        MOD_RODATA = 2
        MOD_RO_AFTER_INIT = 3 # noqa: F841
        MOD_INIT_TEXT = 4 # noqa: F841
        MOD_INIT_DATA = 5 # noqa: F841
        MOD_INIT_RODATA = 6 # noqa: F841
        MOD_MEM_NUM_TYPES = 7 # noqa: F841

        kversion = Kernel.kernel_version()
        if kversion < "6.13":
            offset_size = runtime.current_arch.ptrsize # void*
        elif "6.13" <= kversion < "6.15":
            offset_size = runtime.current_arch.ptrsize * 2 + 4 # void*, void*, bool
        else:
            offset_size = runtime.current_arch.ptrsize + 4 # void*, bool
        sizeof_module_memory_min = align_to_ptrsize(offset_size + 4)
        sizeof_mod_tree_node = runtime.current_arch.ptrsize * 7
        sizeof_module_memory_max = sizeof_module_memory_min + sizeof_mod_tree_node

        # TODO: only handles non init module type
        for i in range(300):
            offset_mem = i * runtime.current_arch.ptrsize
            for sizeof_module_memory in (sizeof_module_memory_min, sizeof_module_memory_max):
                valid = True
                for module in module_addrs:
                    for mem_type in (MOD_TEXT, MOD_DATA, MOD_RODATA):
                        mem_ptr = module + offset_mem + mem_type * sizeof_module_memory
                        # memory access check
                        if not is_valid_addr(mem_ptr):
                            valid = False
                            break
                        # base align check
                        cand_base = read_int_from_memory(mem_ptr)
                        if cand_base == 0 or cand_base & 0xfff:
                            valid = False
                            break
                        # size check
                        cand_size = read_int32_from_memory(mem_ptr + offset_size)
                        if cand_size == 0 or cand_size > 0x10_0000:
                            valid = False
                            break
                if valid:
                    return offset_mem, offset_mem + offset_size
        return None

    def get_offset_init_layout(self, module_addrs): # v4.5 ~ v6.4
        """
        struct module { // kernel v4.5~
            enum module_state state;
            struct list_head list;
            char name[MODULE_NAME_LEN]; // 64 - sizeof(unsigned long) bytes
        #ifdef CONFIG_STACKTRACE_BUILD_ID
            unsigned char build_id[BUILD_ID_SIZE_MAX]; // 20 bytes
        #endif
            struct module_kobject mkobj;
            struct module_attribute *modinfo_attrs;
            const char *version;
            const char *srcversion;
            struct kobject *holders_dir;
            const struct kernel_symbol *syms;
            const s32 *crcs;
            unsigned int num_syms;
        #ifdef CONFIG_CFI_CLANG
            cfi_check_fn cfi_check;
        #endif
        #ifdef CONFIG_SYSFS
            struct mutex param_lock;
        #endif
            struct kernel_param *kp;
            unsigned int num_kp;
            unsigned int num_gpl_syms;
            const struct kernel_symbol *gpl_syms;
            const s32 *gpl_crcs;
            bool using_gplonly_symbols;
        #ifdef CONFIG_MODULE_SIG
            bool sig_ok;
        #endif
            bool async_probe_requested;
            unsigned int num_exentries;
            struct exception_table_entry *extable;
            int (*init)(void);
            struct module_layout core_layout __module_layout_align;
            struct module_layout init_layout;                                     <-- here
        #ifdef CONFIG_ARCH_WANTS_MODULES_DATA_IN_VMALLOC
            struct module_layout data_layout;
        #endif
            struct mod_arch_specific arch;
            unsigned long taints;
        #ifdef CONFIG_GENERIC_BUG
            unsigned num_bugs;
            struct list_head bug_list;
            struct bug_entry *bug_table;
        #endif
        #ifdef CONFIG_KALLSYMS
            struct mod_kallsyms __rcu *kallsyms;
            struct mod_kallsyms core_kallsyms;
            struct module_sect_attrs *sect_attrs;
            struct module_notes_attrs *notes_attrs;
        #endif
            ...
        };

        struct module_layout {
            /* The actual code + data. */
            void *base;
            /* Total size. */
            unsigned int size;
            /* The size of the executable code.  */
            unsigned int text_size;
            /* Size of RO section of the module (text+rodata) */
            unsigned int ro_size;
            /* Size of RO after init section */
            unsigned int ro_after_init_size;
        #ifdef CONFIG_MODULES_TREE_LOOKUP
            struct mod_tree_node mtn;
        #endif
        };

        [Example arm32]
            gef> x/128xw 0x00000000bf22b084
            0xbf22b084:     0xbf1bb044      0xc1696530      0x00006773      0x00000000
            0xbf22b094:     0x00000000      0x00000000      0x00000000      0x00000000
            0xbf22b0a4:     0x00000000      0x00000000      0x00000000      0x00000000
            0xbf22b0b4:     0x00000000      0x00000000      0x00000000      0x00000000
            0xbf22b0c4:     0x00000000      0xc1ec2d00      0xc1a11d80      0xbf1bb08c
            0xbf22b0d4:     0xc1a11d8c      0xc1a11d80      0xc1628e38      0xc8e0b2c0
            0xbf22b0e4:     0x00000003      0x00000007      0xbf22b080      0x00000000
            0xbf22b0f4:     0xc8d4f380      0x00000000      0xc1e47400      0xc8f6d900
            0xbf22b104:     0xc8f6d080      0xc8004300      0x00000000      0x00000000
            0xbf22b114:     0x00000000      0x00000000      0x00000000      0x00000000
            0xbf22b124:     0xbf22b124      0xbf22b124      0xbf22a990      0x00000003
            0xbf22b134:     0x00000000      0x00000000      0x00000000      0x00000001
            0xbf22b144:     0x00000000      0x00000000      0x00000000      0x00000000
            0xbf22b154:     0x00000000      0xbf17e000      0x00000000      0x00000000
            0xbf22b164:     0x00000000      0x00000000      0x00000000      0x00000000
            0xbf22b174:     0x00000000      0x00000000      0x00000000      0xbf225000 <- init_layout.base
            0xbf22b184:     0x00008000      0x00005000      0x00006000      0x00006000
        """
        # fast path
        try:
            return to_unsigned_long(gdb.parse_and_eval("&((struct module*)0).init_layout"))
        except gdb.error:
            pass

        # slow_path
        for i in range(300):
            offset_init_layout = i * runtime.current_arch.ptrsize
            valid = True
            for module in module_addrs:
                # memory access check
                init_layout_ptr = module + offset_init_layout
                if not is_valid_addr(init_layout_ptr):
                    valid = False
                    break
                # base align check
                cand_base = read_int_from_memory(init_layout_ptr)
                if cand_base == 0 or cand_base & 0xfff:
                    valid = False
                    break
                # size check
                cand_size = read_int32_from_memory(init_layout_ptr + runtime.current_arch.ptrsize)
                if cand_size == 0 or cand_size > 0x20_0000:
                    valid = False
                    break
                # text_size check
                cand_text_size = read_int32_from_memory(init_layout_ptr + runtime.current_arch.ptrsize + 4 * 1)
                if cand_text_size == 0 or cand_text_size > 0x20_0000:
                    valid = False
                    break
                # ro_size check
                cand_ro_size = read_int32_from_memory(init_layout_ptr + runtime.current_arch.ptrsize + 4 * 2)
                if cand_ro_size == 0 or cand_ro_size > 0x20_0000:
                    valid = False
                    break
                # ro_after_init_size check
                cand_ro_after_init_size = read_int32_from_memory(init_layout_ptr + runtime.current_arch.ptrsize + 4 * 3)
                if cand_ro_after_init_size == 0 or cand_ro_after_init_size > 0x20_0000:
                    valid = False
                    break
            if valid:
                return offset_init_layout
        return None

    def get_offset_module_core(self, module_addrs): # ~v4.4
        """
        struct module { // ~v4.4
            enum module_state state;
            struct list_head list;
            char name[MODULE_NAME_LEN];
            struct module_kobject mkobj;
            struct module_attribute *modinfo_attrs;
            const char *version;
            const char *srcversion;
            struct kobject *holders_dir;
            const struct kernel_symbol *syms;
            const unsigned long *crcs;
            unsigned int num_syms;
        #ifdef CONFIG_SYSFS
            struct mutex param_lock;
        #endif
            struct kernel_param *kp;
            unsigned int num_kp;
            unsigned int num_gpl_syms;
            const struct kernel_symbol *gpl_syms;
            const unsigned long *gpl_crcs;
        #ifdef CONFIG_UNUSED_SYMBOLS
            const struct kernel_symbol *unused_syms;
            const unsigned long *unused_crcs;
            unsigned int num_unused_syms;
            unsigned int num_unused_gpl_syms;
            const struct kernel_symbol *unused_gpl_syms;
            const unsigned long *unused_gpl_crcs;
        #endif
        #ifdef CONFIG_MODULE_SIG
            bool sig_ok;
        #endif
            bool async_probe_requested;
            const struct kernel_symbol *gpl_future_syms;
            const unsigned long *gpl_future_crcs;
            unsigned int num_gpl_future_syms;
            unsigned int num_exentries;
            struct exception_table_entry *extable;
            int (*init)(void);
            void *module_init ____cacheline_aligned;
            /* Here is the actual code + data, vfree'd on unload. */
            void *module_core;                                                    <-- here
            /* Here are the sizes of the init and core sections */
            unsigned int init_size, core_size;
            /* The size of the executable code in each section. */
            unsigned int init_text_size, core_text_size;
        #ifdef CONFIG_MODULES_TREE_LOOKUP
            struct mod_tree_node mtn_core;
            struct mod_tree_node mtn_init;
        #endif
            unsigned int init_ro_size, core_ro_size;
            struct mod_arch_specific arch;
            unsigned int taints;
        #ifdef CONFIG_GENERIC_BUG
            unsigned num_bugs;
            struct list_head bug_list;
            struct bug_entry *bug_table;
        #endif
        #ifdef CONFIG_KALLSYMS
            struct mod_kallsyms *kallsyms;                                        <-- here
            struct mod_kallsyms core_kallsyms;
            struct module_sect_attrs *sect_attrs;
            struct module_notes_attrs *notes_attrs;
        #endif
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(gdb.parse_and_eval("&((struct module*)0).module_core"))
        except gdb.error:
            pass

        # slow_path
        for i in range(300):
            offset_module_core = i * runtime.current_arch.ptrsize
            valid = True
            for module in module_addrs:
                module_core_ptr = module + offset_module_core
                # memory access check
                if not is_valid_addr(module_core_ptr):
                    valid = False
                    break
                # module_core align check
                cand_module_core = read_int_from_memory(module_core_ptr)
                if cand_module_core == 0 or cand_module_core & 0xfff:
                    valid = False
                    break
                # init_size check
                cand_init_size = read_int32_from_memory(module_core_ptr + runtime.current_arch.ptrsize)
                if cand_init_size > 0x10_0000:
                    valid = False
                    break
                # core_size check
                cand_core_size = read_int32_from_memory(module_core_ptr + runtime.current_arch.ptrsize + 4 * 1)
                if cand_core_size == 0 or cand_core_size > 0x10_0000:
                    valid = False
                    break
                # init_text_size check
                cand_init_text_size = read_int32_from_memory(module_core_ptr + runtime.current_arch.ptrsize + 4 * 2)
                if cand_init_text_size > 0x10_0000:
                    valid = False
                    break
                # core_text_size check
                cand_core_text_size = read_int32_from_memory(module_core_ptr + runtime.current_arch.ptrsize + 4 * 3)
                if cand_core_text_size == 0 or cand_core_text_size > 0x10_0000:
                    valid = False
                    break
            if valid:
                return offset_module_core
        return None

    def get_offset_kallsyms(self, module_addrs):
        """
        struct mod_kallsyms {
            Elf_Sym *symtab;
            unsigned int num_symtab;
            char *strtab;
            char *typetab; // v5.2~
        };
        """
        # fast path
        try:
            return to_unsigned_long(gdb.parse_and_eval("&((struct module*)0).kallsyms"))
        except gdb.error:
            pass

        # slow_path
        kversion = Kernel.kernel_version()
        for i in range(300):
            offset_kallsyms = i * runtime.current_arch.ptrsize
            valid = True
            for module in module_addrs:
                kallsyms_ptr = module + offset_kallsyms
                # access check
                if not is_valid_addr(kallsyms_ptr):
                    valid = False
                    break
                # kallsyms access check
                cand_kallsyms = read_int_from_memory(kallsyms_ptr)
                if not is_valid_addr(cand_kallsyms):
                    valid = False
                    break
                # struct mod_kallsyms member access check
                cand_symtab = read_int_from_memory(cand_kallsyms)
                if not is_valid_addr(cand_symtab):
                    valid = False
                    break
                cand_num_symtab = read_int_from_memory(cand_kallsyms + runtime.current_arch.ptrsize * 1)
                if is_valid_addr(cand_num_symtab) or cand_num_symtab == 0:
                    valid = False
                    break
                cand_strtab = read_int_from_memory(cand_kallsyms + runtime.current_arch.ptrsize * 2)
                if not is_valid_addr(cand_strtab):
                    valid = False
                    break
                if "5.2" <= kversion:
                    cand_typetab = read_int_from_memory(cand_kallsyms + runtime.current_arch.ptrsize * 3)
                    if not is_valid_addr(cand_typetab):
                        valid = False
                        break
            if valid:
                return offset_kallsyms
        return None

    def initialize(self):
        if hasattr(self, "initialized"):
            return True

        kversion = Kernel.kernel_version()
        if kversion is None:
            self.quiet_err("Failed to resolve kernel version")
            return False

        # modules
        self.modules = KernelAddressHeuristicFinder.get_modules()
        if self.modules is None:
            self.quiet_err("Could not find modules (CONFIG_MODULES may not be set)")
            return False
        self.quiet_info("modules: {:#x}".format(self.modules))

        # modules list
        self.module_addrs = self.get_modules_list(self.modules)
        if self.module_addrs is None:
            return False
        if self.module_addrs == []:
            self.quiet_err("Could not find any modules")
            return False

        # module->name
        self.offset_name = self.get_offset_name(self.module_addrs)
        if self.offset_name is None:
            self.quiet_err("Could not find module->name[MODULE_NAME_LEN]")
            return False
        self.quiet_info("offsetof(module, name): {:#x}".format(self.offset_name))

        # modules->{mem,mem_size,module_core}
        if "6.4" <= kversion:
            ret = self.get_offset_mem(self.module_addrs)
            if ret is None:
                self.quiet_err("Could not find module->mem")
                return False
            self.offset_mem, self.offset_mem_size = ret
            self.quiet_info("offsetof(module, mem): {:#x}".format(self.offset_mem))
            self.quiet_info("offsetof(module, mem.size): {:#x}".format(self.offset_mem_size))
        elif "4.5" <= kversion:
            self.offset_init_layout = self.get_offset_init_layout(self.module_addrs)
            if self.offset_init_layout is None:
                self.quiet_err("Could not find module->init_layout")
                return False
            self.quiet_info("offsetof(module, init_layout): {:#x}".format(self.offset_init_layout))
        else: # kversion < v4.5
            self.offset_module_core = self.get_offset_module_core(self.module_addrs)
            if self.offset_module_core is None:
                self.quiet_err("Could not find module->module_core")
                return False
            self.quiet_info("offsetof(module, module_core): {:#x}".format(self.offset_module_core))

        # module->kallsyms
        self.offset_kallsyms = self.get_offset_kallsyms(self.module_addrs)
        if self.offset_kallsyms is None:
            self.quiet_err("Could not find module->kallsyms")
            return False
        self.quiet_info("offsetof(module, kallsyms): {:#x}".format(self.offset_kallsyms))

        self.initialized = True
        return True

    def parse_kallsyms(self, kallsyms):
        kversion = Kernel.kernel_version()

        symtab = read_int_from_memory(kallsyms + runtime.current_arch.ptrsize * 0)
        sizeof_symtab_entry = 24 if is_64bit() else 16
        num_symtab = read_int_from_memory(kallsyms + runtime.current_arch.ptrsize * 1)
        strtab = read_int_from_memory(kallsyms + runtime.current_arch.ptrsize * 2)
        strtab_pos = 0
        if "5.2" <= kversion:
            typetab = read_int_from_memory(kallsyms + runtime.current_arch.ptrsize * 3)

        #gef_print("symtab: {:#x}".format(symtab))
        #gef_print("sizeof_symtab_entry: {:#x}".format(sizeof_symtab_entry))
        #gef_print("num_symab: {:#x}".format(num_symtab))
        #gef_print("strtab: {:#x}".format(strtab))
        #if "5.2" <= kversion:
        #    gef_print("typetab: {:#x}".format(typetab))

        entries = []
        tqdm = GefUtil.get_tqdm(not self.args.quiet and not self.args.apply_symbol)
        for i in tqdm(range(num_symtab), leave=False):
            sym_addr = read_int_from_memory(symtab + sizeof_symtab_entry * i + runtime.current_arch.ptrsize)
            sym_name = read_cstring_from_memory(strtab + strtab_pos)
            strtab_pos += len(sym_name) + 1

            if "5.2" <= kversion:
                sym_type = chr(read_int8_from_memory(typetab + i))
            elif "5.0" <= kversion:
                # st_size
                if is_64bit():
                    sym_type = chr(read_int8_from_memory(symtab + sizeof_symtab_entry * i + 16))
                else:
                    sym_type = chr(read_int8_from_memory(symtab + sizeof_symtab_entry * i + 8))
            else:
                # st_info
                if is_64bit():
                    sym_type = chr(read_int8_from_memory(symtab + sizeof_symtab_entry * i + 4))
                else:
                    sym_type = chr(read_int8_from_memory(symtab + sizeof_symtab_entry * i + 12))
            entries.append([sym_addr, sym_type, sym_name])
        return entries

    def print_symbol(self, entries, symbol_unsort):
        self.out.append(titlify("module symbols"))
        # symbol_unsort is used for debugging.
        if not symbol_unsort:
            entries = sorted(entries)
        # add output
        for sym_addr, sym_type, sym_name in entries:
            self.out.append("{:#018x} {:s} {:s}".format(sym_addr, sym_type, sym_name))
        self.out.append(titlify(""))
        return

    def apply_symbol(self, module_name, text_base, entries):
        # remove old file
        from gef.commands.debugging.other import AddSymbolTemporaryCommand
        sym_elf_path = os.path.join(GEF_TEMP_DIR, "kmod-{:s}.elf".format(module_name))
        if os.path.exists(sym_elf_path):
            os.unlink(sym_elf_path)

        # make blank ELF
        text_base &= get_pagesize_mask_high()
        text_end = entries[-1][0]
        blank_elf = AddSymbolTemporaryCommand.create_blank_elf(text_base, text_end)
        if blank_elf is None:
            self.quiet_err("Failed to create blank ELF")
            return

        # create command
        cmd_string_arr = []
        for sym_addr, sym_type, sym_name in entries:
            if sym_addr < text_base:
                continue

            if sym_type in ["T", "t", "W", None]:
                type_flag = "function"
            else:
                type_flag = "object"
            if sym_type and sym_type in "abcdefghijklmnopqrstuvwxyz":
                global_flag = "local"
            else:
                global_flag = "global"

            # higher address needs relative
            relative_addr = sym_addr - text_base
            cmd_string_arr.append("--add-symbol")
            cmd_string_arr.append("{:s}.{:s}=.text:{:#x},{:s},{:s}".format(
                # modules often contain the same symbols, such as "__this_module".
                # to avoid collisions, register them in the form "module_name.symbol".
                module_name, sym_name, relative_addr, global_flag, type_flag,
            ))

        # embedding symbols
        objcopy = GefUtil.which(Config.get_gef_setting("gef.objcopy_command"))
        processed_count = 0
        for cmd_string_arr_sliced in slicer(cmd_string_arr, 10000 * 2):
            subprocess.check_output([objcopy] + cmd_string_arr_sliced + [blank_elf])
            processed_count += len(cmd_string_arr_sliced) // 2
        self.quiet_info("{:s}: {:d} entries were processed".format(module_name, processed_count))
        os.rename(blank_elf, sym_elf_path)

        # apply
        cmd = "add-symbol-file {!r} {:#x}".format(sym_elf_path, text_base)
        self.quiet_info("Execute `{:s}`".format(cmd))
        gdb.execute(cmd, to_string=True)
        return

    def parse_module(self):
        if not self.args.apply_symbol:
            if not self.args.quiet:
                fmt = "{:<18s} {:<24s} {:<18s} {:<18s}"
                legend = ["module", "module->name", "base", "size"]
                self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        kversion = Kernel.kernel_version()
        tqdm = GefUtil.get_tqdm(not self.args.quiet and not self.args.apply_symbol)
        for module in tqdm(self.module_addrs, leave=False):
            name_string = read_cstring_from_memory(module + self.offset_name)
            if self.args.filter:
                if not any(re_pattern.search(name_string) for re_pattern in self.args.filter):
                    continue

            if "6.4" <= kversion:
                base = read_int_from_memory(module + self.offset_mem)
                size = read_int32_from_memory(module + self.offset_mem_size)
            elif "4.5" <= kversion:
                base = read_int_from_memory(module + self.offset_init_layout)
                size = read_int32_from_memory(module + self.offset_init_layout + runtime.current_arch.ptrsize)
            else: # kversion < "4.5"
                base = read_int_from_memory(module + self.offset_module_core)
                size = read_int32_from_memory(module + self.offset_module_core + runtime.current_arch.ptrsize + 4)

            if not self.args.apply_symbol:
                self.out.append("{:#018x} {:<24s} {:#018x} {:#018x}".format(module, name_string, base, size))

            if self.args.resolve_symbol:
                kallsyms = read_int_from_memory(module + self.offset_kallsyms)
                entries = self.parse_kallsyms(kallsyms)
                self.print_symbol(entries, self.args.symbol_unsort)

            elif self.args.apply_symbol:
                kallsyms = read_int_from_memory(module + self.offset_kallsyms)
                entries = self.parse_kallsyms(kallsyms)
                self.apply_symbol(name_string, base, entries)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        # initialize
        self.module_addrs = None
        ret = self.initialize()
        if not ret:
            self.quiet_err("Failed to initialize")
            return

        # get module addrs
        if not self.module_addrs:
            self.module_addrs = self.get_modules_list(self.modules)
        if self.module_addrs is None:
            return
        if self.module_addrs == []:
            self.quiet_err("Could not find any modules")
            return
        self.quiet_info("Num of modules: {:#x}".format(len(self.module_addrs)))

        # parse modules
        self.out = []
        self.parse_module()
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelBlockDevicesCommand(GenericCommand, BufferingOutput):
    """Display block device list."""

    _cmdline_ = "kbdev"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "",
        "If the debug information has struct block_device, block devices are listed from the inodes of the bdev",
        "pseudo filesystem. Otherwise, the bdev_cache dump, which does not include full slabs, is supplemented with",
        "block devices referenced by mounted filesystems. The others are found by the layout measured with them,",
        "from the block devices in devices_kset (v5.11~) or from the inodes of the bdev pseudo filesystem (~v5.10).",
        "RISC-V is supported only with the debug information.",
        "",
        "The name is built from bd_disk->disk_name and the partition number, in the same way as the kernel.",
        "Before v5.11, bd_disk is set only while the block device is opened.",
        "If it cannot be resolved, the name is guessed from the major/minor number and marked as `(guessed)`.",
    ]
    _note_ = "\n".join(_note_)

    BLOCK_EXT_MAJOR = 259

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def initialize_dwarf(self):
        """Resolve the layout from the debug information. Return True if struct block_device is available."""
        offsetof = GefUtil.offsetof
        self.offset_bd_dev = offsetof("block_device", "bd_dev")
        self.offset_bd_disk = offsetof("block_device", "bd_disk")
        gendisk = [offsetof("gendisk", m) for m in ("major", "first_minor", "minors", "disk_name")]
        if self.offset_bd_dev is None or self.offset_bd_disk is None or None in gendisk:
            return False
        self.offset_gendisk = gendisk

        self.partno_kind = None
        self.offset_bd_partno = offsetof("block_device", "bd_partno")
        if self.offset_bd_partno is not None:
            self.partno_kind = "u8"
        else:
            self.offset_bd_partno = offsetof("block_device", "__bd_flags")
            if self.offset_bd_partno is not None:
                self.partno_kind = "flags"
            else:
                self.offset_bd_part = offsetof("block_device", "bd_part")
                self.offset_hd_partno = offsetof("hd_struct", "partno")
                if self.offset_bd_part is not None and self.offset_hd_partno is not None:
                    self.partno_kind = "part"

        self.meta.append((self.quiet_info, "layout source: debug information"))
        self.meta.append((self.quiet_info, "offsetof(block_device, bd_dev): {:#x}".format(self.offset_bd_dev)))
        self.meta.append((self.quiet_info, "offsetof(block_device, bd_disk): {:#x}".format(self.offset_bd_disk)))
        self.meta.append((self.quiet_info, "offsetof(gendisk, disk_name): {:#x}".format(self.offset_gendisk[3])))
        return True

    def get_bdev_list_from_inodes(self):
        """Walk blockdev_superblock->s_inodes. Each inode is embedded in struct bdev_inode with its block_device."""
        offsetof = GefUtil.offsetof
        offset_vfs_inode = offsetof("bdev_inode", "vfs_inode")
        offset_s_inodes = offsetof("super_block", "s_inodes")
        offset_s_type = offsetof("super_block", "s_type")
        offset_i_sb_list = offsetof("inode", "i_sb_list")
        if None in (offset_vfs_inode, offset_s_inodes, offset_s_type, offset_i_sb_list):
            return None

        blockdev_superblock = Ksym.get_addr("blockdev_superblock")
        if blockdev_superblock is None:
            blockdev_superblock = Symbol.resolve_address("blockdev_superblock")
        if blockdev_superblock is None:
            return None
        sb = read_int_from_memory(blockdev_superblock, safe=True)
        if not is_valid_addr(sb):
            return None
        # the address from the debug information is not relocated by KASLR, so check what it points to
        fst = read_int_from_memory(sb + offset_s_type, safe=True)
        if not is_valid_addr(fst) or read_cstring_from_memory(read_int_from_memory(fst), safe=True) != "bdev":
            return None
        self.meta.append((self.quiet_info, "blockdev_superblock: {:#x}".format(blockdev_superblock)))
        self.meta.append((self.quiet_info, "offsetof(bdev_inode, vfs_inode): {:#x}".format(offset_vfs_inode)))

        head = sb + offset_s_inodes
        bdevs = []
        seen = set()
        current = read_int_from_memory(head)
        while current != head:
            if current in seen or not is_valid_addr(current):
                self.meta.append((self.quiet_warn, "Stopped at broken s_inodes list: {:#x}".format(current)))
                break
            seen.add(current)
            bdevs.append(current - offset_i_sb_list - offset_vfs_inode)
            current = read_int_from_memory(current)
        return bdevs

    def get_bdev_list(self):
        allocator = Kernel.get_slab_type()
        if allocator == "SLUB":
            ret = gdb.execute("slub-dump --quiet --no-pager -vv bdev_cache", to_string=True)
        elif allocator == "SLUB_TINY":
            ret = gdb.execute("slub-tiny-dump --quiet --no-pager bdev_cache", to_string=True)
        elif allocator == "SLAB":
            ret = gdb.execute("slab-dump --quiet --no-pager bdev_cache", to_string=True)
        else:
            self.quiet_err("Unsupported: SLOB, Unknown allocator")
            return None

        bdevs = []
        for line in ret.splitlines():
            line = Color.remove_color(line)
            r = re.search(r"(0x\S+) \(in-use\)", line)
            if not r:
                continue
            bdev = int(r.group(1), 16)
            bdevs.append(bdev)
        return bdevs

    def get_mounted_bdev_candidates(self):
        """Get bdevs which the slab allocator lists cannot reach, as [(bdev, s_dev), ...] not yet verified.

        struct super_block {
            ...
            struct block_device *s_bdev;
            struct bdev_handle *s_bdev_handle; // v6.6.47~v6.8
            struct file *s_bdev_file; // v6.9~
            struct backing_dev_info *s_bdi;
            struct mtd_info *s_mtd;
            struct hlist_node s_instances;
            ...
        };
        """
        kversion = Kernel.version()
        if kversion < "3.3":
            return []
        kfs = Kernel.file_system()
        try:
            ret = kfs.initialize()
        except gdb.MemoryError:
            ret = None
        if not ret:
            self.meta.append((self.quiet_warn, "Could not resolve super_block; mounted block devices are not supplemented"))
            return []

        ptrsize = runtime.current_arch.ptrsize
        if kversion < "6.6.47":
            distances = (3, 4)
        else:
            distances = (4, 3)
        candidates = []
        seen = set()
        fst = read_int_from_memory(kfs.file_systems)
        if fst:
            fst -= kfs.offset_hlist_node
        while fst and fst not in seen and is_valid_addr(fst):
            seen.add(fst)
            s_instances = read_int_from_memory(fst + kfs.offset_fs_supers)
            while s_instances and s_instances not in seen and is_valid_addr(s_instances):
                seen.add(s_instances)
                s_dev = read_int32_from_memory(s_instances - kfs.offset_s_instances + kfs.offset_s_dev)
                if s_dev >> 20:
                    for distance in distances:
                        bdev = read_int_from_memory(s_instances - ptrsize * distance)
                        if is_valid_addr(bdev):
                            candidates.append((bdev, s_dev))
                s_instances = read_int_from_memory(s_instances)
            fst = read_int_from_memory(fst + kfs.offset_link)
            if fst:
                fst -= kfs.offset_hlist_node
        return candidates

    def read_gendisk(self, gendisk):
        """Return (major, first_minor, minors, disk_name) if `gendisk` looks like struct gendisk."""
        if gendisk in self.gendisk_cache:
            return self.gendisk_cache[gendisk]
        self.gendisk_cache[gendisk] = None
        if not gendisk or not is_valid_addr(gendisk):
            return None
        offset_major, offset_first_minor, offset_minors, offset_disk_name = self.offset_gendisk
        try:
            major = read_int32_from_memory(gendisk + offset_major)
            first_minor = read_int32_from_memory(gendisk + offset_first_minor)
            minors = read_int32_from_memory(gendisk + offset_minors)
            name = read_memory(gendisk + offset_disk_name, 32).split(b"\0")[0]
        except gdb.MemoryError:
            return None
        if not (0 < major < 4096 and first_minor < (1 << 20) and minors <= (1 << 20)):
            return None
        if not (0 < len(name) < 32 and all(0x21 <= c < 0x7f for c in name)):
            return None
        self.gendisk_cache[gendisk] = (major, first_minor, minors, name.decode())
        return self.gendisk_cache[gendisk]

    def is_disk_of(self, gd, dev):
        major, minor = dev >> 20, dev & ((1 << 20) - 1)
        if major == 0:
            return False
        if gd[0] == major and gd[1] <= minor < gd[1] + max(gd[2], 1):
            return True
        # partitions over the minors of the disk are numbered from BLOCK_EXT_MAJOR
        return major == self.BLOCK_EXT_MAJOR

    def resolve_layout(self, samples):
        """Resolve the offsets of bd_dev and bd_disk without the debug information.

        [~v5.10]
        struct block_device {
            dev_t bd_dev;
            ...
            struct gendisk *bd_disk;     // set while opened
            ...
        };

        [v5.11~]
        struct block_device {
            sector_t bd_start_sect;      // sector_t: u64
            sector_t bd_nr_sectors;      // sector_t: u64, v5.16~
            struct gendisk *bd_disk;     // v6.4~
            struct request_queue *bd_queue;  // v6.4~
            struct disk_stats __percpu *bd_stats;
            unsigned long bd_stamp;
            bool bd_read_only;           // ~v6.9
            u8 bd_partno;                // v6.4~v6.9
            bool bd_write_holder;        // v6.4~v6.9
            bool bd_has_submit_bio;      // v6.4~v6.9
            atomic_t __bd_flags;         // v6.10~, the lower 8 bits are the partition number
            dev_t bd_dev;
            ...
            struct gendisk *bd_disk;     // ~v6.3
            ...
        };
        """
        kversion = Kernel.version()
        ptrsize = runtime.current_arch.ptrsize
        self.offset_gendisk = [0, 4, 8, 12]

        # candidates of bd_dev in the order the version suggests. They are checked against bd_disk,
        # so a layout backported to another version is also found.
        offset_v64 = 8 * 2 + ptrsize * 4 + 4
        layouts = [0, 8 * 1 + ptrsize * 2 + 4, 8 * 2 + ptrsize * 2 + 4, offset_v64]
        if kversion < "5.11":
            index = 0
        elif kversion < "5.16":
            index = 1
        elif kversion < "6.4":
            index = 2
        else:
            index = 3
        layouts.insert(0, layouts.pop(index))

        # bd_disk is searched as the pointer to a gendisk which covers bd_dev
        scan_size = 0x800
        unpack = GefUtil.get_unpack(ptrsize)
        votes = {}
        for bdev in samples[:32]:
            data = read_memory(bdev, scan_size, safe=True)
            if data is None:
                continue
            for offset_disk in range(0, scan_size, ptrsize):
                gd = self.read_gendisk(unpack(data[offset_disk:offset_disk + ptrsize]))
                if gd is None:
                    continue
                for offset_dev in layouts:
                    if self.is_disk_of(gd, u32(data[offset_dev:offset_dev + 4])):
                        votes[offset_dev, offset_disk] = votes.get((offset_dev, offset_disk), 0) + 1

        if votes:
            self.offset_bd_dev, self.offset_bd_disk = max(votes, key=lambda k: (votes[k], -layouts.index(k[0]), -k[1]))
        else:
            self.offset_bd_dev, self.offset_bd_disk = layouts[0], (16 if layouts[0] == offset_v64 else None)

        # the partition number is also needed for partitions over the minors of the disk
        self.partno_kind = None
        if self.offset_bd_dev == offset_v64:
            if kversion < "6.10":
                self.partno_kind, self.offset_bd_partno = "u8", self.offset_bd_dev - 3
            else:
                self.partno_kind, self.offset_bd_partno = "flags", self.offset_bd_dev - 4

        self.meta.append((self.quiet_info, "layout source: heuristic"))
        self.meta.append((self.quiet_info, "offsetof(block_device, bd_dev): {:#x}".format(self.offset_bd_dev)))
        if self.offset_bd_disk is None:
            self.meta.append((self.quiet_warn, "Could not find offsetof(block_device, bd_disk)"))
        else:
            self.meta.append((self.quiet_info, "offsetof(block_device, bd_disk): {:#x}".format(self.offset_bd_disk)))
        return

    def get_partno(self, bdev, dev, gd):
        major, minor = dev >> 20, dev & ((1 << 20) - 1)
        if gd[0] == major and gd[1] <= minor < gd[1] + max(gd[2], 1):
            return minor - gd[1]
        if self.partno_kind == "u8":
            return read_int8_from_memory(bdev + self.offset_bd_partno, safe=True)
        if self.partno_kind == "flags":
            flags = read_int32_from_memory(bdev + self.offset_bd_partno, safe=True)
            if flags is None:
                return None
            return flags & 0xff
        if self.partno_kind == "part":
            part = read_int_from_memory(bdev + self.offset_bd_part, safe=True)
            if part and is_valid_addr(part):
                return read_int32_from_memory(part + self.offset_hd_partno, safe=True)
        return None

    def get_disk_name(self, bdev, dev, gendisk=None):
        """Return (gendisk, name) from bd_disk as the kernel names the block device, or (0, None)."""
        if gendisk is None:
            if self.offset_bd_disk is None:
                return 0, None
            gendisk = read_int_from_memory(bdev + self.offset_bd_disk, safe=True)
        gd = self.read_gendisk(gendisk)
        if gd is None or not self.is_disk_of(gd, dev):
            return 0, None
        partno = self.get_partno(bdev, dev, gd)
        if partno is None:
            return gendisk, None
        name = gd[3]
        if partno:
            name = "{:s}{:s}{:d}".format(name, "p" if name[-1].isdigit() else "", partno)
        return gendisk, "/dev/" + name

    @staticmethod
    def get_bdev_name(major, minor):
        # https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
        # https://github.com/lrs-lang/lib/blob/master/src/dev/lib.rs
        dev_name_list = {
            0: "???",
            4: "/dev/root",
            7: "/dev/loop{:d}",
            9: "/dev/md{:d}",
            11: "/dev/scd{0:d} (sr{0:d})",
            12: "/dev/dos_cd{:d}",
            15: "/dev/sonycd",
            16: "/dev/gscd",
            17: "/dev/optcd",
            18: "/dev/sjcd",
            20: "/dev/hitcd",
            23: "/dev/mcd",
            24: "/dev/cdu535",
            29: "/dev/aztcd",
            30: "/dev/cm205cd",
            32: "/dev/cm206cd",
            35: "/dev/slram",
            37: "/dev/z2ram",
            41: "/dev/bpcd",
            43: "/dev/nb{:d}",
            46: "/dev/pcd{:d}",
            47: "/dev/pf{:d}",
            59: "/dev/pda{:d}",
            92: "/dev/ppdd{:d}",
            97: "/dev/pktcdvd",
            99: "/dev/jsfd",
            103: "/dev/audit",
            115: "/dev/nwfs/v{:d}",
            147: "/dev/drbd{:d}",
            152: "/dev/etherd/{:d}",
            199: "/dev/vx/dsk/*/*",
            201: "/dev/vx/dmp/*/*",
            258: "/dev/blockrom{:d}",
        }

        if major in dev_name_list:
            return dev_name_list[major].format(minor)

        def common_pattern(kind_sep, kind_max, devstr, sym_start="a"):
            kind = minor // kind_sep
            num = minor % kind_sep
            if kind < kind_max:
                dev = "/dev/{:s}{:s}".format(devstr, chr(ord(sym_start) + kind))
                if num:
                    dev = "{:s}{:d}".format(dev, num)
                return dev
            return "???"

        def common_pattern_num_p(kind_sep, kind_max, devstr, kind_offset=0):
            kind = minor // kind_sep
            num = minor % kind_sep
            if kind_max is None or kind < kind_max:
                dev = "/dev/{:s}{:d}".format(devstr, kind + kind_offset)
                if num:
                    dev = "{:s}p{:d}".format(dev, num)
                return dev
            return "???"

        def iterate_pattern(kind_sep, kind_max, dev_str, sym_start):

            def gen():
                cs = "abcdefghijklmnopqrstuvwxyz"
                for c in cs:
                    yield c
                for c1 in cs:
                    for c2 in cs:
                        yield c1 + c2
                return

            name_list = list(gen())
            kind = minor // kind_sep
            num = minor % kind_sep
            if kind < (kind_max or len(name_list)):
                offset = name_list.index(sym_start)
                dev = "/dev/{:s}{:s}".format(dev_str, name_list[offset + kind])
                if num:
                    dev = "{:s}{:d}".format(dev, num)
                return dev
            return "???"

        if major == 1:
            if 0 <= minor < 250:
                return "/dev/ram{:d}".format(minor)
            elif minor == 250:
                return "/dev/initrd"
        elif major == 2:
            if 0 <= minor < 128:
                num = minor % 4
            elif 128 <= minor < 256:
                num = 4 + minor % 4
            else:
                return "???"
            fd_type = (minor % 128) & ~0b11
            type_dic = {
                0: "",
                4: "d360",
                8: "h1200",
                12: "u360",
                16: "u720",
                20: "h360",
                24: "h720",
                28: "u1440",
                32: "u2880",
                36: "CompaQ",
                40: "h1440",
                44: "u1680",
                48: "h410",
                52: "u820",
                56: "h1476",
                60: "u1722",
                64: "h420",
                68: "u830",
                72: "h1494",
                76: "u1743",
                80: "h880",
                84: "u1040",
                88: "u1120",
                92: "h1600",
                96: "u1760",
                100: "u1920",
                104: "u3200",
                108: "u3520",
                112: "u3840",
                116: "u1840",
                120: "u800",
                124: "u1600",
            }
            if fd_type in type_dic:
                return "/dev/fd{:d}{:s}".format(num, type_dic[fd_type])
        elif major == 3:
            return common_pattern(64, 2, "hd", sym_start="a")
        elif major == 8:
            return iterate_pattern(16, 16, "sd", sym_start="a")
        elif major == 13:
            return common_pattern(64, 4, "xd")
        elif major == 14:
            return common_pattern(64, 4, "dos_hd")
        elif major == 19:
            if 0 <= minor < 8:
                return "/dev/double{:d}".format(minor)
            elif 128 <= minor < 136:
                return "/dev/cdouble{:d}".format(minor - 128)
        elif major == 21:
            return common_pattern(64, 2, "mfm")
        elif major == 22:
            return common_pattern(64, 2, "hd", sym_start="c")
        elif 25 <= major < 28:
            if 0 <= minor < 4:
                return "/dev/sbpcd{:d}".format(minor + (major - 25) * 4)
        elif major == 28: # 28 are duplicates
            if is_m68k():
                return common_pattern(16, 16, "ad")
            else:
                if 0 <= minor < 4:
                    return "/dev/sbpcd{:d}".format(minor + (major - 25) * 4)
        elif major == 31:
            if 0 <= minor < 8:
                return "/dev/rom{:d}".format(minor)
            elif 8 <= minor < 16:
                return "/dev/rrom{:d}".format(minor - 8)
            elif 16 <= minor < 24:
                return "/dev/flash{:d}".format(minor - 16)
            elif 24 <= minor < 32:
                return "/dev/rflash{:d}".format(minor - 24)
        elif 33 <= major < 35:
            return common_pattern(64, 2, "hd", sym_start=["e", "g"][major - 33])
        elif major == 36:
            return common_pattern(64, 4, "ed")
        elif major == 40:
            if minor == 0:
                return "/dev/eza"
            elif 1 <= minor < 64:
                return "/dev/eza{:d}".format(minor)
        elif major == 44:
            return common_pattern(16, 16, "ftl")
        elif major == 45:
            return common_pattern(16, 4, "pd")
        elif 48 <= major < 56:
            return common_pattern_num_p(8, 32, "rd/c{:d}d".format(major - 48))
        elif 56 <= major < 58:
            return common_pattern(64, 2, "hd", sym_start=["i", "k"][major - 56])
        elif major == 64:
            if minor == 0:
                return "/dev/scramdisk/master"
            elif 1 <= minor:
                return "/dev/scramdisk/{:d}".format(minor)
        elif 65 <= major < 72:
            return iterate_pattern(16, 16, "sd", sym_start=["q", "ag", "aw", "bm", "cc", "cs", "di"][major - 65])
        elif 72 <= major < 80:
            return common_pattern_num_p(16, 16, "ida/c{:d}d".format(major - 72))
        elif 80 <= major < 88:
            return iterate_pattern(16, 16, "i2o/hd", sym_start=["a", "q", "ag", "aw", "bm", "cc", "cs", "di"][major - 80])
        elif 88 <= major < 92:
            return common_pattern(64, 2, "hd", sym_start=["m", "o", "q", "s"][major - 88])
        elif major == 93:
            return common_pattern(16, 16, "nftl")
        elif major == 94:
            return common_pattern(4, 26, "dasd")
        elif major == 96:
            return common_pattern(16, 16, "inftl")
        elif major == 98:
            return common_pattern(16, 26, "ubd")
        elif major == 101:
            return common_pattern_num_p(16, 16, "amiraid/ar")
        elif major == 102:
            return common_pattern(16, 16, "cbd/")
        elif 104 <= major < 112:
            return common_pattern_num_p(16, 16, "cciss/c{:d}d".format(major - 104))
        elif major == 112:
            return iterate_pattern(8, 64, "iseries/vd", sym_start="a")
        elif major == 113:
            return iterate_pattern(1, None, "iseries/vcd", sym_start="a")
        elif major == 114:
            return common_pattern_num_p(16, 16, "ataraid/d")
        elif major == 116:
            return common_pattern_num_p(16, 16, "umem/d")
        elif major == 117:
            if minor == 0:
                return "/dev/evms/block_device"
            elif 1 <= minor < 128:
                return "/dev/evms/legacyname{:d}".format(minor)
            elif 128 <= minor < 256:
                return "/dev/evms/EVMSname{:d}".format(256 - minor)
        elif 128 <= major < 136:
            return iterate_pattern(16, 16, "sd", sym_start=["dy", "eo", "fe", "fu", "gk", "ha", "hq", "ig"][major - 128])
        elif 136 <= major < 144:
            return common_pattern_num_p(16, 16, "rd/c{:d}d".format(major - 136 + 8))
        elif major == 153:
            return common_pattern_num_p(16, 16, "emd/")
        elif 160 <= major < 162:
            return common_pattern_num_p(32, 8, "carmel/", kind_offset=(major - 160) * 8) # codespell:ignore
        elif major == 179:
            return common_pattern_num_p(8, None, "mmcblk")
        elif major == 180:
            return common_pattern(8, 26, "ub")
        elif major == 202:
            return common_pattern(16, 16, "xvd")
        elif 240 <= major < 255: # LOCAL/EXPERIMENTAL USE, but maybe this is virtio when qemu-system
            return common_pattern(16, 16, "vd")
        elif major == 256:
            return common_pattern(16, 16, "rfd")
        elif major == 257:
            return common_pattern(8, 8, "ssfdc")
        return "???"

    def get_dev_num(self, bdev):
        dev = read_int32_from_memory(bdev + self.offset_bd_dev, safe=True)
        if dev is None:
            return 0, 0, 0
        return dev, dev >> 20, dev & ((1 << 20) - 1)

    def get_bdevs(self):
        self.gendisk_cache = {}
        self.device_names = {}

        dwarf = self.initialize_dwarf()
        if dwarf:
            bdevs = self.get_bdev_list_from_inodes()
            if bdevs is not None:
                self.meta.append((self.quiet_info, "bdev source: blockdev_superblock->s_inodes"))
                return bdevs

        if is_riscv32() or is_riscv64():
            self.meta.append((self.quiet_err, "Unsupported: RISC-V without the debug information of struct block_device"))
            return None

        self.meta.append((self.quiet_info, "bdev source: bdev_cache and mounted filesystems"))
        bdevs = self.get_bdev_list() or []
        candidates = self.get_mounted_bdev_candidates()
        if not dwarf:
            self.resolve_layout(bdevs + [bdev for bdev, _ in candidates])

        # the candidates next to s_bdev are verified with s_dev and bd_disk
        for bdev, s_dev in candidates:
            if self.get_dev_num(bdev)[0] != s_dev:
                continue
            if self.offset_bd_disk is not None and self.get_disk_name(bdev, s_dev)[0] == 0:
                continue
            bdevs.append(bdev)

        bdevs.extend(self.get_bdev_list_from_devices(bdevs))
        bdevs.extend(self.get_bdev_list_from_bd_inode(bdevs))
        return bdevs

    def get_bdev_list_from_bd_inode(self, samples):
        """Get the bdevs in full slabs before v5.11, which the slab dump cannot reach.
        Every inode of bdev_inode is on blockdev_superblock->s_inodes, and bdev->bd_inode points to the inode
        of itself. So the offset of inode->i_sb_list is measured with a known bdev, then the list is walked.

        [~v5.10]
        struct block_device {
            dev_t bd_dev;
            int bd_openers;
            struct inode *bd_inode;
            ...
        };

        struct bdev_inode {
            struct block_device bdev;
            struct inode vfs_inode;
        };
        """
        if Kernel.version() >= "5.11" or self.offset_bd_dev != 0:
            return []
        ptrsize = runtime.current_arch.ptrsize
        offset_bd_inode = 8

        def walk(start, offset_i_sb_list, offset_vfs_inode):
            # the list is circular through the list head in the super_block. The root inode of the bdev
            # pseudo filesystem is also on it, and they are the only non-bdev nodes.
            bdevs = []
            others = 0
            seen = {start}
            current = read_int_from_memory(start, safe=True)
            while current != start:
                if current in seen or not current or not is_valid_addr(current):
                    return None
                seen.add(current)
                inode = current - offset_i_sb_list
                bdev = inode - offset_vfs_inode
                if read_int_from_memory(bdev + offset_bd_inode, safe=True) == inode:
                    bdevs.append(bdev)
                else:
                    others += 1
                current = read_int_from_memory(current, safe=True)
            if others > 2 or not bdevs:
                return None
            return bdevs

        for sample in set(samples):
            inode = read_int_from_memory(sample + offset_bd_inode, safe=True)
            if not inode or not (0 < inode - sample < 0x1000) or not is_valid_addr(inode):
                continue
            offset_vfs_inode = inode - sample
            # other lists such as i_io_list may link a part of them, so the longest one is taken
            best = None
            for offset in range(0, 0x200, ptrsize):
                bdevs = walk(inode + offset, offset, offset_vfs_inode)
                if bdevs is not None and (best is None or len(bdevs) > len(best[1])):
                    best = (offset, bdevs)
            if best:
                self.meta.append((self.quiet_info, "offsetof(inode, i_sb_list): {:#x}".format(best[0])))
                return best[1]
        return []

    def get_bdev_list_from_devices(self, samples):
        """Get the bdevs in full slabs, which the slab dump cannot reach.
        Since v5.11, struct block_device embeds bd_device, which is in devices_kset as a device of the "block" class.
        Its offset is measured with the bdevs already found."""
        if Kernel.version() < "5.11" or not samples:
            return []
        kdev = KernelDevice()
        if not kdev.initialize():
            self.meta.extend(Kernel.export_meta(self, kdev.meta, demote_err=True))
            return []
        block_devices = {}
        for device, _name, devt, class_name in kdev.devices:
            if class_name == "block":
                block_devices.setdefault(devt, []).append(device)

        deltas = {}
        for bdev in set(samples):
            for device in block_devices.get(self.get_dev_num(bdev)[0], []):
                deltas[device - bdev] = deltas.get(device - bdev, 0) + 1
        if not deltas:
            self.meta.append((self.quiet_warn, "Could not find offsetof(block_device, bd_device)"))
            return []
        delta = max(deltas, key=deltas.get)
        self.meta.append((self.quiet_info, "offsetof(block_device, bd_device): {:#x}".format(delta)))

        bdevs = []
        for devt, devices in block_devices.items():
            for device in devices:
                if self.get_dev_num(device - delta)[0] == devt:
                    bdevs.append(device - delta)
        # the kobject of bd_device is named as the kernel names the block device
        self.device_names = {device - delta: name for device, name, _devt, class_name in kdev.devices if class_name == "block"}
        return bdevs

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        if Kernel.version() is None:
            self.quiet_err("Could not find Linux kernel")
            return

        self.meta = []
        bdevs = self.get_bdevs()
        if args.meta or bdevs is None:
            for func, line in self.meta:
                func(line)
        if bdevs is None or args.meta:
            return

        # ignore bdev if major is 0
        bdevs_with_info = []
        for bdev in set(bdevs):
            dev, major, minor = self.get_dev_num(bdev)
            if major == 0:
                continue
            gendisk, name = self.get_disk_name(bdev, dev)
            bdevs_with_info.append([major, minor, bdev, gendisk, name])

        # bd_disk may be unset (e.g., a partition not opened before v5.11), but a disk that another
        # block device refers to also covers it
        gendisks = {gendisk: self.read_gendisk(gendisk) for _, _, _, gendisk, _ in bdevs_with_info if gendisk}
        for entry in bdevs_with_info:
            major, minor, bdev, gendisk, name = entry
            if name is None:
                for gendisk, gd in gendisks.items():
                    if gd[0] == major and gd[1] <= minor < gd[1] + max(gd[2], 1):
                        entry[3:] = self.get_disk_name(bdev, major << 20 | minor, gendisk)
                        break
            if entry[4] is None and bdev in self.device_names:
                entry[4] = "/dev/" + self.device_names[bdev]
            if entry[4] is None:
                entry[4] = KernelBlockDevicesCommand.get_bdev_name(major, minor) + " (guessed)"

        if not bdevs_with_info:
            if bdevs:
                self.quiet_err("Could not find any bdev (after filtering major == 0)")
            else:
                self.quiet_err("Could not find any bdev")
            return

        self.out = []
        if not args.quiet:
            fmt = "{:<18s} {:<18s} {:<6s} {:<6s} {:s}"
            legend = ["bdev", "gendisk", "major", "minor", "name"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for major, minor, bdev, gendisk, name in sorted(bdevs_with_info):
            self.out.append("{:#018x} {:#018x} {:<6d} {:<6d} {:s}".format(bdev, gendisk, major, minor, name))

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelCharacterDevicesCommand(GenericCommand, BufferingOutput):
    """Display character device list."""

    _cmdline_ = "kcdev"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-N", "--nodes", action="store_true",
                        help="list the device nodes (struct device with devt) instead of the registered ranges.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -n",
        "{0:s} -n -v",
        "{0:s} -n --nodes",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "",
        "Simplified cdev structure:",
        "",
        "+-chrdevs[255]-+    +-char_device_struct-+",
        "| [0]          |--->| next               |--->...",
        "| ...          |    | major              |",
        "| [254]        |    | baseminor          |           +--->+-cdev--+  +-->+-kobject-+",
        "+--------------+    | minorct            |           |    | kobj  |--+   | name    |",
        "                    | name[64]           |           |    | ...   |      | ...     |",
        "                    | cdev               |-----------+    | ops   |      | parent  |",
        "                    +--------------------+           |    | ...   |      | ...     |",
        "                                                     |    | dev   |      +---------+",
        "+----------+    +-kobj_map----+    +-probe-+         |    | ...   |",
        "| cdev_map |--->| probes[0]   |--->| next  |--->...  |    +-------+",
        "+----------+    | ...         |    | dev   |         |",
        "                | probes[254] |    | ...   |         |",
        "                | lock        |    | data  |---------+",
        "                +-------------+    +-------+",
        "",
        "The character devices are managed at chrdevs[] and cdev_map.",
        "This command use each of them for getting structure information.",
        "",
        "Each line is a registered range of minors, not a device node.",
        "`name (guessed)` is guessed from the static major/minor table only when the range has a single minor.",
        "`-v` also shows the cdevs registered in the middle of a range (e.g., each tty port).",
        "`--nodes` lists the device nodes from devices_kset with their sysfs names and the cdev that serves each.",
        "Block devices are excluded from them.",
    ]
    _note_ = "\n".join(_note_)

    @staticmethod
    def guess_cdev_path(major, minor):
        """Guess a device path from the static major/minor allocation table."""
        # https://www.kernel.org/doc/Documentation/admin-guide/devices.txt
        # https://github.com/lrs-lang/lib/blob/master/src/dev/lib.rs
        dev_name_list = {
            (1, 0): "/dev/mem", # Undocumented, but it seems to be used
            (1, 1): "/dev/mem",
            (1, 2): "/dev/kmem",
            (1, 3): "/dev/null",
            (1, 4): "/dev/port",
            (1, 5): "/dev/zero",
            (1, 6): "/dev/core",
            (1, 7): "/dev/full",
            (1, 8): "/dev/random",
            (1, 9): "/dev/urandom",
            (1, 10): "/dev/aio",
            (1, 11): "/dev/kmsg",
            (1, 12): "/dev/oldmem",
            (5, 0): "/dev/tty",
            (5, 1): "/dev/console",
            (5, 2): "/dev/ptmx",
            (5, 3): "/dev/ttyprintk",
            (10, 0): "/dev/logibm",
            (10, 1): "/dev/psaux",
            (10, 2): "/dev/inportbm",
            (10, 3): "/dev/atibm",
            #(10, 4): "/dev/jbm", # duplicates
            (10, 4): "/dev/amigamouse",
            (10, 5): "/dev/atarimouse",
            (10, 6): "/dev/sunmouse",
            (10, 7): "/dev/amigamouse1",
            (10, 8): "/dev/smouse",
            (10, 9): "/dev/pc110pad",
            (10, 10): "/dev/adbmouse",
            (10, 11): "/dev/vrtpanel",
            (10, 13): "/dev/vpcmouse",
            (10, 14): "/dev/touchscreen/ucb1x00",
            (10, 15): "/dev/touchscreen/mk712",
            (10, 128): "/dev/beep",
            (10, 130): "/dev/watchdog",
            (10, 131): "/dev/temperature",
            (10, 132): "/dev/hwtrap",
            (10, 133): "/dev/exttrp",
            (10, 134): "/dev/apm_bios",
            (10, 135): "/dev/rtc",
            (10, 137): "/dev/vhci",
            (10, 139): "/dev/openprom",
            (10, 140): "/dev/relay8",
            (10, 141): "/dev/relay16",
            (10, 143): "/dev/pciconf",
            (10, 144): "/dev/nvram",
            (10, 145): "/dev/hfmodem",
            (10, 146): "/dev/graphics",
            (10, 147): "/dev/opengl",
            (10, 148): "/dev/gfx",
            (10, 149): "/dev/input/mouse",
            (10, 150): "/dev/input/keyboard",
            (10, 151): "/dev/led",
            (10, 152): "/dev/kpoll",
            (10, 153): "/dev/mergemem",
            (10, 154): "/dev/pmu",
            (10, 156): "/dev/lcd",
            (10, 157): "/dev/ac",
            (10, 158): "/dev/nwbutton",
            (10, 159): "/dev/nwdebug",
            (10, 160): "/dev/nwflash",
            (10, 161): "/dev/userdma",
            (10, 162): "/dev/smbus",
            (10, 163): "/dev/lik", # codespell:ignore
            (10, 164): "/dev/ipmo",
            (10, 165): "/dev/vmmon",
            (10, 166): "/dev/i2o/ctl",
            (10, 167): "/dev/specialix_sxctl",
            (10, 168): "/dev/tcldrv",
            (10, 169): "/dev/specialix_rioctl",
            (10, 170): "/dev/thinkpad/thinkpad",
            (10, 171): "/dev/srripc",
            (10, 172): "/dev/usemaclone",
            (10, 173): "/dev/ipmikcs",
            (10, 174): "/dev/uctrl",
            (10, 175): "/dev/agpgart",
            (10, 176): "/dev/gtrsc",
            (10, 177): "/dev/cbm",
            (10, 178): "/dev/jsflash",
            (10, 179): "/dev/xsvc",
            (10, 180): "/dev/vrbuttons",
            (10, 181): "/dev/toshiba",
            (10, 182): "/dev/perfctr",
            (10, 183): "/dev/hwrng",
            (10, 184): "/dev/cpu/microcode",
            (10, 186): "/dev/atomicps",
            (10, 187): "/dev/irnet",
            (10, 188): "/dev/smbusbios",
            (10, 189): "/dev/ussp_ctl",
            (10, 190): "/dev/crash",
            (10, 191): "/dev/pcl181",
            (10, 192): "/dev/nas_xbus",
            (10, 193): "/dev/d7s",
            (10, 194): "/dev/zkshim",
            (10, 195): "/dev/elographics/e2201",
            (10, 196): "/dev/vfio/vfio",
            (10, 197): "/dev/pxa3xx-gcu",
            (10, 198): "/dev/sexec",
            (10, 199): "/dev/scanners/cuecat",
            (10, 200): "/dev/net/tun",
            (10, 201): "/dev/button/gulpb",
            (10, 202): "/dev/emd/ctl",
            (10, 203): "/dev/cuse",
            (10, 204): "/dev/video/em8300",
            (10, 205): "/dev/video/em8300_mv",
            (10, 206): "/dev/video/em8300_ma",
            (10, 207): "/dev/video/em8300_sp",
            (10, 208): "/dev/compaq/cpqphpc",
            (10, 209): "/dev/compaq/cpqrid",
            (10, 210): "/dev/impi/bt",
            (10, 211): "/dev/impi/smic",
            (10, 212): "/dev/watchdogs/0",
            (10, 213): "/dev/watchdogs/1",
            (10, 214): "/dev/watchdogs/2",
            (10, 215): "/dev/watchdogs/3",
            (10, 216): "/dev/fujitsu/apanel",
            (10, 217): "/dev/ni/natmotn",
            (10, 218): "/dev/kchuid",
            (10, 219): "/dev/modems/mwave",
            (10, 220): "/dev/mptctl",
            (10, 221): "/dev/mvista/hssdsi",
            (10, 222): "/dev/mvista/hasi",
            (10, 223): "/dev/input/uinput",
            (10, 224): "/dev/tpm",
            (10, 225): "/dev/pps",
            (10, 226): "/dev/systrace",
            (10, 227): "/dev/mcelog",
            (10, 228): "/dev/hpet",
            (10, 229): "/dev/fuse",
            (10, 230): "/dev/midishare",
            (10, 231): "/dev/snapshot",
            (10, 232): "/dev/kvm",
            (10, 233): "/dev/kmview",
            (10, 234): "/dev/btrfs-control",
            (10, 235): "/dev/autofs",
            (10, 236): "/dev/mapper/control",
            (10, 237): "/dev/loop-control",
            (10, 238): "/dev/vhost-net",
            (10, 239): "/dev/uhid",
            (10, 240): "/dev/userio",
            (10, 241): "/dev/vhost-vsock",
            (10, 242): "/dev/rfkill",
            (12, 2): "/dev/ntpqic11",
            (12, 3): "/dev/tpqic11",
            (12, 4): "/dev/ntpqic24",
            (12, 5): "/dev/tpqic24",
            (12, 6): "/dev/ntpqic120",
            (12, 7): "/dev/tpqic120",
            (12, 8): "/dev/ntpqic150",
            (12, 9): "/dev/tpqic150",
            (14, 0): "/dev/mixer",
            (14, 1): "/dev/sequencer",
            (14, 2): "/dev/midi00",
            (14, 3): "/dev/dsp",
            (14, 4): "/dev/audio",
            (14, 7): "/dev/audioctl",
            (14, 8): "/dev/sequencer2",
            (14, 16): "/dev/mixer1",
            (14, 17): "/dev/patmgr0",
            (14, 18): "/dev/midi01",
            (14, 19): "/dev/dsp1",
            (14, 20): "/dev/audio1",
            (14, 33): "/dev/patmgr1",
            (14, 34): "/dev/midi02",
            (14, 50): "/dev/midi03",
            (30, 0): "/dev/socksys",
            (30, 1): "/dev/spx",
            (30, 32): "/dev/inet/ip",
            (30, 33): "/dev/inet/icmp",
            (30, 34): "/dev/inet/ggp",
            (30, 35): "/dev/inet/ipip",
            (30, 36): "/dev/inet/tcp",
            (30, 37): "/dev/inet/egp",
            (30, 38): "/dev/inet/pup",
            (30, 39): "/dev/inet/udp",
            (30, 40): "/dev/inet/idp",
            (30, 41): "/dev/inet/rawip",
            (31, 0): "/dev/mpu401data",
            (31, 1): "/dev/mpu401stat",
            (36, 0): "/dev/route",
            (36, 1): "/dev/skip",
            (36, 3): "/dev/fwmonitor",
            (70, 0): "/dev/apscfg",
            (70, 1): "/dev/apsauth",
            (70, 2): "/dev/apslog",
            (70, 3): "/dev/apsdbg",
            (70, 64): "/dev/apsisdn",
            (70, 65): "/dev/apsasync",
            (70, 128): "/dev/apsmon",
            (73, 0): "/dev/ip2ipl0",
            (73, 1): "/dev/ip2stat0",
            (73, 4): "/dev/ip2ipl1",
            (73, 5): "/dev/ip2stat1",
            (73, 8): "/dev/ip2ipl2",
            (73, 9): "/dev/ip2stat2",
            (73, 12): "/dev/ip2ipl3",
            (73, 13): "/dev/ip2stat",
            (95, 0): "/dev/ipl",
            (95, 1): "/dev/ipnat",
            (95, 2): "/dev/ipstate",
            (95, 3): "/dev/ipauth",
            (152, 0): "/dev/etherd/ctl",
            (152, 1): "/dev/etherd/err",
            (152, 2): "/dev/etherd/raw",
            (200, 0): "/dev/vx/config",
            (200, 1): "/dev/vx/trace",
            (200, 2): "/dev/vx/iod",
            (200, 3): "/dev/vx/info",
            (200, 4): "/dev/vx/task",
            (200, 5): "/dev/vx/taskmon",
            (207, 0): "/dev/cpqhealth/cpqw",
            (207, 1): "/dev/cpqhealth/crom",
            (207, 2): "/dev/cpqhealth/cdt",
            (207, 3): "/dev/cpqhealth/cevt",
            (207, 4): "/dev/cpqhealth/casr",
            (207, 5): "/dev/cpqhealth/cecc",
            (207, 6): "/dev/cpqhealth/cmca",
            (207, 7): "/dev/cpqhealth/ccsm",
            (207, 8): "/dev/cpqhealth/cnmi",
            (207, 9): "/dev/cpqhealth/css",
            (207, 10): "/dev/cpqhealth/cram",
            (207, 11): "/dev/cpqhealth/cpci",
        }
        if (major, minor) in dev_name_list:
            return dev_name_list[major, minor]

        dev_name_list2 = {
            0: "???",
            6: "/dev/lp{:d}",
            16: "/dev/gs4500",
            17: "/dev/ttyH{:d}",
            18: "/dev/cuh{:d}",
            19: "/dev/ttyC{:d}",
            20: "/dev/cub{:d}",
            21: "/dev/sg{:d}",
            22: "/dev/ttyD{:d}",
            23: "/dev/cud{:d}",
            24: "/dev/ttyE{:d}",
            25: "/dev/cue{:d}",
            26: "/dev/wvisfgrab",
            29: "/dev/fb{:d}",
            32: "/dev/ttyX{:d}",
            33: "/dev/cux{:d}",
            34: "/dev/scc{:d}",
            38: "/dev/mlanai{:d}",
            40: "/dev/mmetfgrab",
            41: "/dev/yamm",
            43: "/dev/ttyI{:d}",
            44: "/dev/cui{:d}",
            46: "/dev/ttyR{:d}",
            47: "/dev/cur{:d}",
            48: "/dev/ttyL{:d}",
            49: "/dev/cul{:d}",
            51: "/dev/bc{:d}",
            52: "/dev/dcbri{:d}",
            54: "/dev/holter{:d}",
            55: "/dev/dsp56k",
            56: "/dev/adb",
            57: "/dev/ttyP{:d}",
            58: "/dev/cup{:d}",
            59: "/dev/firewall",
            64: "/dev/enskip",
            66: "/dev/yppcpci{:d}",
            67: "/dev/cfs0",
            69: "/dev/ma16",
            71: "/dev/ttyF{:d}",
            72: "/dev/cuf{:d}",
            74: "/dev/SCI/{:d}",
            75: "/dev/ttyW{:d}",
            76: "/dev/cuw{:d}",
            77: "/dev/qng",
            78: "/dev/ttyM{:d}",
            79: "/dev/cum{:d}",
            80: "/dev/at200",
            82: "/dev/winradio{:d}",
            83: "/dev/mga_vid{:d}",
            84: "/dev/ihcp{:d}",
            86: "/dev/sch{:d}",
            87: "/dev/controla{:d}",
            88: "/dev/comx{:d}",
            89: "/dev/i2c-{:d}",
            91: "/dev/can{:d}",
            94: "/dev/dcxx{:d}",
            97: "/dev/pg{:d}",
            98: "/dev/comedi{:d}",
            99: "/dev/parport{:d}",
            100: "/dev/phone{:d}",
            102: "/dev/tlk{:d}",
            103: "/dev/nnpfs{:d}",
            105: "/dev/ttyV{:d}",
            106: "/dev/cuv{:d}",
            107: "/dev/3dfx",
            108: "/dev/ppp",
            110: "/dev/srnd{:d}",
            111: "/dev/av{:d}",
            112: "/dev/ttyM{:d}", # same 78
            113: "/dev/cum{:d}", # same 79
            119: "/dev/vnet{:d}",
            136: "/dev/pts/{:d}",
            137: "/dev/pts/{:d}",
            138: "/dev/pts/{:d}",
            139: "/dev/pts/{:d}",
            140: "/dev/pts/{:d}",
            141: "/dev/pts/{:d}",
            142: "/dev/pts/{:d}",
            143: "/dev/pts/{:d}",
            144: "/dev/pppox{:d}",
            146: "/dev/scramnet{:d}",
            147: "/dev/aureal{:d}",
            148: "/dev/ttyT{:d}",
            149: "/dev/cut{:d}",
            150: "/dev/rtf{:d}",
            151: "/dev/dpti{:d}",
            153: "/dev/spi{:d}",
            154: "/dev/ttySR{:d}",
            155: "/dev/cusr{:d}",
            158: "/dev/gfax{:d}",
            160: "/dev/gpib{:d}",
            166: "/dev/ttyACM{:d}",
            167: "/dev/cuacm{:d}",
            168: "/dev/ecsa{:d}",
            169: "/dev/ecsa8-{:d}",
            170: "/dev/megarac{:d}",
            174: "/dev/ttySI{:d}",
            175: "/dev/cusi{:d}",
            176: "/dev/nfastpci{:d}",
            178: "/dev/clanvi{:d}",
            179: "/dev/dvxirq{:d}",
            181: "/dev/pcfclock{:d}",
            182: "/dev/pethr{:d}",
            183: "/dev/ss5136dn{:d}",
            184: "/dev/pevss{:d}",
            185: "/dev/intermezzo{:d}",
            186: "/dev/obd{:d}",
            187: "/dev/deskey{:d}",
            188: "/dev/ttyUSB{:d}",
            189: "/dev/cuusb{:d}",
            190: "/dev/kctt{:d}",
            196: "/dev/tor/{:d}",
            198: "/dev/tpmp2/{:d}",
            199: "/dev/vx/rdsk/*/*",
            201: "/dev/vx/rdmp/*",
            202: "/dev/cpu/{:d}/msr",
            203: "/dev/cpu/{:d}/cpuid",
            208: "/dev/ttyU{:d}",
            209: "/dev/cuu{:d}",
            211: "/dev/addinum/cpci1500/{:d}",
            216: "/dev/rfcomm{:d}",
            217: "/dev/curf{:d}",
            218: "/dev/logicalco/bci/{:d}",
            219: "/dev/logicalco/dci1300/{:d}",
            224: "/dev/ttyY{:d}",
            225: "/dev/cuy{:d}",
            226: "/dev/dri/card{:d}",
            229: "/dev/hvc{:d}",
            256: "/dev/ttyEQ{:d}",
            257: "/dev/ptlsec",
            259: "/dev/icap{:d}",
            260: "/dev/osd{:d}",
            261: "/dev/accel/accel{:d}",
        }
        if major in dev_name_list2:
            return dev_name_list2[major].format(minor)

        def pty_tty_pattern(devstr):
            cs1 = "pqrstuvwxyzabcde"
            cs2 = "0123456789abcdef"
            return "/dev/{:s}{:s}{:s}".format(devstr, cs1[minor // 16], cs2[minor % 16])

        if major == 2:
            return pty_tty_pattern("pty")
        elif major == 3:
            return pty_tty_pattern("tty")
        elif major == 4:
            if 0 <= minor < 64:
                return "/dev/tty{:d}".format(minor)
            elif 64 <= minor < 256:
                return "/dev/ttyS{:d}".format(minor - 64)
        elif major == 5:
            if 64 <= minor < 256:
                return "/dev/cua{:d}".format(minor - 64)
        elif major == 7:
            if minor == 0:
                return "/dev/vcs"
            elif 1 <= minor < 64:
                return "/dev/vcs{:d}".format(minor)
            elif minor == 64:
                return "/dev/vcsu"
            elif 65 <= minor < 128:
                return "/dev/vcsu{:d}".format(minor - 64)
            elif minor == 128:
                return "/dev/vcsa"
            elif 129 <= minor < 192:
                return "/dev/vcsa{:d}".format(minor - 128)
        elif major == 9:
            if 0 <= minor < 32:
                return "/dev/st{:d}".format(minor)
            elif 32 <= minor < 64:
                return "/dev/st{:d}l".format(minor - 32)
            elif 64 <= minor < 96:
                return "/dev/st{:d}m".format(minor - 64)
            elif 96 <= minor < 128:
                return "/dev/st{:d}a".format(minor - 96)
            elif 128 <= minor < 160:
                return "/dev/nst{:d}".format(minor - 128)
            elif 160 <= minor < 192:
                return "/dev/nst{:d}l".format(minor - 160)
            elif 192 <= minor < 224:
                return "/dev/nst{:d}m".format(minor - 192)
            elif 224 <= minor < 256:
                return "/dev/nst{:d}a".format(minor - 224)
        elif major == 11: # 11 are duplicates
            if is_sparc32() or is_sparc32plus() or is_sparc64():
                return "/dev/kbd"
            elif is_hppa32() or is_hppa64():
                return "/dev/ttyB{:d}".format(minor)
        elif major == 13:
            if 0 <= minor < 32:
                return "/dev/input/js{:d}".format(minor)
            elif 32 <= minor < 63:
                return "/dev/input/mouse{:d}".format(minor - 32)
            elif minor == 63:
                return "/dev/input/mice"
            elif 64 <= minor < 96:
                return "/dev/input/event{:d}".format(minor - 64)
        elif major == 15:
            if 0 <= minor < 128:
                return "/dev/js{:d}".format(minor)
            elif 128 <= minor < 256:
                return "/dev/djs{:d}".format(minor - 128)
        elif major == 27:
            if 0 <= minor < 4:
                return "/dev/qft{:d}".format(minor)
            elif 4 <= minor < 8:
                return "/dev/nqft{:d}".format(minor - 4)
            elif 16 <= minor < 20:
                return "/dev/zqft{:d}".format(minor - 16)
            elif 20 <= minor < 24:
                return "/dev/nzqft{:d}".format(minor - 20)
            elif 32 <= minor < 36:
                return "/dev/rawqft{:d}".format(minor - 32)
            elif 36 <= minor < 40:
                return "/dev/nrawqft{:d}".format(minor - 36)
        elif major == 28: # 28 are duplicates
            if is_m68k():
                return "/dev/slm{:d}".format(minor)
            else:
                return "/dev/staliomem{:d}".format(minor)
        elif major == 35:
            if 0 <= minor < 4:
                return "/dev/midi{:d}".format(minor)
            elif 64 <= minor < 67:
                return "/dev/rmidi{:d}".format(minor - 64)
            elif 128 <= minor < 132:
                return "/dev/smpte{:d}".format(minor - 128)
        elif major == 36:
            if 16 <= minor < 32:
                return "/dev/tap{:d}".format(minor - 16)
        elif major == 37:
            if 0 <= minor < 128:
                return "/dev/ht{:d}".format(minor)
            elif 128 <= minor < 256:
                return "/dev/nht{:d}".format(minor - 128)
        elif major == 39:
            if 0 <= minor % 32 < 16:
                return "/dev/ml16p{:s}-a{:d}".format(chr(ord("a") + minor // 32), minor)
            elif minor % 32 == 16:
                return "/dev/ml16p{:s}-d".format(chr(ord("a") + minor // 32))
            elif 17 <= minor % 32 < 20:
                return "/dev/ml16p{:s}-c{:d}".format(chr(ord("a") + minor // 32), minor - 17)
        elif major == 45:
            if 0 <= minor < 64:
                return "/dev/isdn{:d}".format(minor)
            elif 64 <= minor < 128:
                return "/dev/isdncntl{:d}".format(minor - 64)
            elif 128 <= minor < 192:
                return "/dev/ippp{:d}".format(minor - 128)
            elif minor == 255:
                return "/dev/isdninfo"
        elif major == 53:
            if 0 <= minor < 3:
                return "/dev/pd_bdm{:d}".format(minor)
            elif 4 <= minor < 7:
                return "/dev/icd_bdm{:d}".format(minor)
        elif major == 65:
            if 0 <= minor < 4:
                return "/dev/plink{:d}".format(minor)
            elif 64 <= minor < 67:
                return "/dev/rplink{:d}".format(minor - 64)
            elif 128 <= minor < 132:
                return "/dev/plink{:d}d".format(minor - 128)
            elif 192 <= minor < 196:
                return "/dev/rplink{:d}d".format(minor - 192)
        elif major == 68:
            if minor == 0:
                return "/dev/capi20"
            elif 1 <= minor < 20:
                return "/dev/capi20.{:02d}".format(minor - 1)
        elif major == 81:
            if 0 <= minor < 64:
                return "/dev/video{:d}".format(minor)
            elif 64 <= minor < 128:
                return "/dev/radio{:d}".format(minor - 64)
            elif 128 <= minor < 192:
                return "/dev/swradio{:d}".format(minor - 128)
            elif 192 <= minor < 256:
                return "/dev/vbi{:d}".format(minor - 192)
        elif major == 85:
            if minor == 0:
                return "/dev/shmiq"
            elif 1 <= minor:
                return "/dev/qcntl{:d}".format(minor)
        elif major == 90:
            if 0 <= minor < 32:
                if minor % 2 == 0:
                    return "/dev/mtd{:d}".format(minor // 2)
                elif minor % 2 == 1:
                    return "/dev/mtdr{:d}".format(minor // 2)
        elif major == 93:
            if 0 <= minor < 128:
                return "/dev/iscc{:d}".format(minor)
            elif 128 <= minor < 256:
                return "/dev/isccctl{:d}".format(minor - 128)
        elif major == 96:
            if 0 <= minor < 128:
                return "/dev/pt{:d}".format(minor)
            elif 128 <= minor < 256:
                return "/dev/npt{:d}".format(minor - 128)
        elif major == 101:
            if minor == 0:
                return "/dev/mdspstat"
            elif 1 <= minor < 17:
                return "/dev/mdsp{:d}".format(minor)
        elif major == 114:
            if 0 <= minor < 128:
                return "/dev/ise{:d}".format(minor)
            elif 128 <= minor < 256:
                return "/dev/isex{:d}".format(minor - 128)
        elif major == 115:
            if 0 <= minor < 8:
                return "/dev/tipar{:d}".format(minor)
            elif 8 <= minor < 16:
                return "/dev/tiser{:d}".format(minor - 8)
            elif 16 <= minor < 48:
                return "/dev/tiusb{:d}".format(minor - 16)
        elif major == 117:
            return "/dev/cosa{:d}c{:d}".format(minor // 16, minor % 16)
        elif major == 118:
            if minor == 0:
                return "/dev/ica"
            elif 1 <= minor:
                return "/dev/ica{:d}".format(minor - 1)
        elif major == 145:
            if minor % 64 == 0:
                return "/dev/sam{:d}_mixer".format(minor // 64)
            elif minor % 64 == 1:
                return "/dev/sam{:d}_sequencer".format(minor // 64)
            elif minor % 64 == 2:
                return "/dev/sam{:d}_midi00".format(minor // 64)
            elif minor % 64 == 3:
                return "/dev/sam{:d}_dsp".format(minor // 64)
            elif minor % 64 == 4:
                return "/dev/sam{:d}_audio".format(minor // 64)
            elif minor % 64 == 6:
                return "/dev/sam{:d}_sndstat".format(minor // 64)
            elif minor % 64 == 18:
                return "/dev/sam{:d}_midi01".format(minor // 64)
            elif minor % 64 == 34:
                return "/dev/sam{:d}_midi02".format(minor // 64)
            elif minor % 64 == 50:
                return "/dev/sam{:d}_midi03".format(minor // 64)
        elif major == 156:
            return "/dev/ttySR{:d}".format(minor + 256)
        elif major == 157:
            return "/dev/cusr{:d}".format(minor + 256)
        elif major == 161:
            if 0 <= minor < 16:
                return "/dev/ircomm{:d}".format(minor)
            elif 16 <= minor < 32:
                return "/dev/irlpt{:d}".format(minor - 16)
        elif major == 162:
            if minor == 0:
                return "/dev/rawctl"
            elif 1 <= minor:
                return "/dev/raw/raw{:d}".format(minor)
        elif major == 164:
                return "/dev/ttyCH{:d}".format(minor)
        elif major == 165:
            if 0 <= minor < 64:
                return "/dev/cuch{:d}".format(minor)
        elif major == 172:
            if 0 <= minor < 128:
                return "/dev/ttyMX{:d}".format(minor)
            elif minor == 128:
                return "/dev/moxactl"
        elif major == 173:
            if 0 <= minor < 128:
                return "/dev/cumx{:d}".format(minor)
        elif major == 177:
            if 0 <= minor < 16:
                return "/dev/pcilynx/aux{:d}".format(minor)
            elif 16 <= minor < 32:
                return "/dev/pcilynx/rom{:d}".format(minor - 16)
            elif 32 <= minor < 48:
                return "/dev/pcilynx/ram{:d}".format(minor - 32)
        elif major == 180:
            if 0 <= minor < 16:
                return "/dev/usb/lp{:d}".format(minor)
            elif 48 <= minor < 64:
                return "/dev/usb/scanner{:d}".format(minor - 48)
            elif minor == 64:
                return "/dev/usb/rio500"
            elif minor == 65:
                return "/dev/usb/usblcd"
            elif minor == 66:
                return "/dev/usb/cpad0"
            elif 96 <= minor < 112:
                return "/dev/usb/hiddev{:d}".format(minor - 96)
            elif 112 <= minor < 128:
                return "/dev/usb/auer{:d}".format(minor - 112)
            elif 128 <= minor < 132:
                return "/dev/usb/brlvgr{:d}".format(minor - 128)
            elif minor == 132:
                return "/dev/usb/idmouse"
            elif 133 <= minor < 141:
                return "/dev/usb/sisusbvga{:d}".format(minor - 133 + 1)
            elif minor == 144:
                return "/dev/usb/lcd"
            elif 160 <= minor < 176:
                return "/dev/usb/legousbtower{:d}".format(minor - 160)
            elif 176 <= minor < 192:
                return "/dev/usb/usbtmc{:d}".format(minor - 176 + 1)
            elif 192 <= minor < 210:
                return "/dev/usb/yurex{:d}".format(minor - 192 + 1)
        elif major == 192:
            if minor == 0:
                return "/dev/profile"
            elif 1 <= minor:
                return "/dev/profile{:d}".format(minor - 1)
        elif major == 193:
            if minor == 0:
                return "/dev/trace"
            elif 1 <= minor:
                return "/dev/trace{:d}".format(minor - 1)
        elif major == 194:
            if minor % 16 == 0:
                return "/dev/mvideo/status{:d}".format(minor // 16)
            elif minor % 16 == 1:
                return "/dev/mvideo/stream{:d}".format(minor // 16)
            elif minor % 16 == 2:
                return "/dev/mvideo/frame{:d}".format(minor // 16)
            elif minor % 16 == 3:
                return "/dev/mvideo/rawframe{:d}".format(minor // 16)
            elif minor % 16 == 4:
                return "/dev/mvideo/codec{:d}".format(minor // 16)
            elif minor % 16 == 5:
                return "/dev/mvideo/video4linux{:d}".format(minor // 16)
        elif major == 195:
            if 0 <= minor < 255:
                return "/dev/nvidia{:d}".format(minor)
            elif minor == 255:
                return "/dev/nvidiactl"
        elif major == 197:
            if 0 <= minor < 128:
                return "/dev/tnf/t{:d}".format(minor)
            elif minor == 128:
                return "/dev/tnf/status"
            elif minor == 130:
                return "/dev/tnf/trace"
        elif major == 204:
            if 0 <= minor < 4:
                return "/dev/ttyLU{:d}".format(minor)
            elif minor == 4:
                return "/dev/ttyFB0"
            elif 5 <= minor < 8:
                return "/dev/ttySA{:d}".format(minor - 5)
            elif 8 <= minor < 12:
                return "/dev/ttySC{:d}".format(minor - 8)
            elif 12 <= minor < 16:
                return "/dev/ttyFW{:d}".format(minor - 12)
            elif 16 <= minor < 32:
                return "/dev/ttyAM{:d}".format(minor - 16)
            elif 32 <= minor < 40:
                return "/dev/ttyDB{:d}".format(minor - 32)
            elif minor == 40:
                return "/dev/ttySG0"
            elif 41 <= minor < 44:
                return "/dev/ttySMX{:d}".format(minor - 41)
            elif 44 <= minor < 46:
                return "/dev/ttyMM{:d}".format(minor - 44)
            elif 46 <= minor < 50:
                return "/dev/ttyCPM{:d}".format(minor - 46)
            elif 50 <= minor < 82:
                return "/dev/ttyIOC{:d}".format(minor - 50)
            elif 82 <= minor < 84:
                return "/dev/ttyVR{:d}".format(minor - 82)
            elif 84 <= minor < 116:
                return "/dev/ttyIOC{:d}".format(minor)
            elif 116 <= minor < 148:
                return "/dev/ttySIOC{:d}".format(minor - 116)
            elif 148 <= minor < 154:
                return "/dev/ttyPSC{:d}".format(minor - 148)
            elif 154 <= minor < 170:
                return "/dev/ttyAT{:d}".format(minor - 154)
            elif 170 <= minor < 186:
                return "/dev/ttyNX{:d}".format(minor - 170)
            elif minor == 186:
                return "/dev/ttyJ0"
            elif 187 <= minor < 190:
                return "/dev/ttyUL{:d}".format(minor - 187)
            elif minor == 191:
                return "/dev/xvc0"
            elif 192 <= minor < 196:
                return "/dev/ttyPZ{:d}".format(minor - 192)
            elif 196 <= minor < 204:
                return "/dev/ttyTX{:d}".format(minor - 196)
            elif 205 <= minor < 209:
                return "/dev/ttySC{:d}".format(minor - 205)
            elif 209 <= minor < 213:
                return "/dev/ttyMAX{:d}".format(minor - 209)
        elif major == 205:
            if 0 <= minor < 4:
                return "/dev/culu{:d}".format(minor)
            elif minor == 4:
                return "/dev/cufb0"
            elif 5 <= minor < 8:
                return "/dev/cusa{:d}".format(minor - 5)
            elif 8 <= minor < 12:
                return "/dev/cusc{:d}".format(minor - 8)
            elif 12 <= minor < 16:
                return "/dev/cufw{:d}".format(minor - 12)
            elif 16 <= minor < 32:
                return "/dev/cuam{:d}".format(minor - 16)
            elif 32 <= minor < 40:
                return "/dev/cudb{:d}".format(minor - 32)
            elif minor == 40:
                return "/dev/cusg0"
            elif 41 <= minor < 44:
                return "/dev/ttycusmx{:d}".format(minor - 41)
            elif 46 <= minor < 50:
                return "/dev/cucpm{:d}".format(minor - 46)
            elif 50 <= minor < 82:
                return "/dev/cuioc4{:d}".format(minor - 50)
            elif 82 <= minor < 84:
                return "/dev/cuvr{:d}".format(minor - 82)
        elif major == 206:
            if 0 <= minor < 32:
                return "/dev/osst{:d}".format(minor)
            elif 32 <= minor < 64:
                return "/dev/osst{:d}l".format(minor - 32)
            elif 64 <= minor < 96:
                return "/dev/osst{:d}m".format(minor - 64)
            elif 96 <= minor < 128:
                return "/dev/osst{:d}a".format(minor - 96)
            elif 128 <= minor < 160:
                return "/dev/nosst{:d}".format(minor - 128)
            elif 160 <= minor < 192:
                return "/dev/nosst{:d}l".format(minor - 160)
            elif 192 <= minor < 224:
                return "/dev/nosst{:d}m".format(minor - 192)
            elif 224 <= minor < 256:
                return "/dev/nosst{:d}a".format(minor - 224)
        elif major == 210:
            if minor % 10 == 0:
                return "/dev/sbei/wxcfg{:d}".format(minor // 10)
            elif minor % 10 == 1:
                return "/dev/sbei/dld{:d}".format(minor // 10)
            elif 2 <= minor % 10 < 6:
                return "/dev/sbei/wan{:d}{:d}".format(minor // 10, minor % 10)
            elif 6 <= minor % 10 < 10:
                return "/dev/sbei/wanc{:d}{:d}".format(minor // 10, minor % 10)
        elif major == 212:
            if minor % 64 % 9 == 0:
                return "/dev/dvb/adapter{:d}/video{:d}".format(minor // 64, minor % 64 // 9)
            elif minor % 64 % 9 == 1:
                return "/dev/dvb/adapter{:d}/audio{:d}".format(minor // 64, minor % 64 // 9)
            elif minor % 64 % 9 == 2:
                return "/dev/dvb/adapter{:d}/sec{:d}".format(minor // 64, minor % 64 // 9)
            elif minor % 64 % 9 == 3:
                return "/dev/dvb/adapter{:d}/frontend{:d}".format(minor // 64, minor % 64 // 9)
            elif minor % 64 % 9 == 4:
                return "/dev/dvb/adapter{:d}/demux{:d}".format(minor // 64, minor % 64 // 9)
            elif minor % 64 % 9 == 5:
                return "/dev/dvb/adapter{:d}/dvr{:d}".format(minor // 64, minor % 64 // 9)
            elif minor % 64 % 9 == 6:
                return "/dev/dvb/adapter{:d}/ca{:d}".format(minor // 64, minor % 64 // 9)
            elif minor % 64 % 9 == 7:
                return "/dev/dvb/adapter{:d}/net{:d}".format(minor // 64, minor % 64 // 9)
            elif minor % 64 % 9 == 8:
                return "/dev/dvb/adapter{:d}/osd{:d}".format(minor // 64, minor % 64 // 9)
        elif major == 220:
            if minor % 2 == 0:
                return "/dev/myricom/gm{:d}".format(minor // 2)
            elif minor % 2 == 1:
                return "/dev/myricom/gmp{:d}".format(minor // 2)
        elif major == 221:
            if 0 <= minor < 4:
                return "/dev/bus/vme/m{:d}".format(minor)
            elif 4 <= minor < 8:
                return "/dev/bus/vme/s{:d}".format(minor - 4)
            elif minor == 8:
                return "/dev/bus/vme/ctl"
        elif major == 227:
            if 1 <= minor:
                return "/dev/3270/tty{:d}".format(minor)
        elif major == 228:
            if minor == 0:
                return "/dev/3270/tub"
            elif 1 <= minor:
                return "/dev/3270/tub{:d}".format(minor)
        elif major == 230:
            if 0 <= minor < 32:
                return "/dev/iseries/vt{:d}".format(minor)
            elif 32 <= minor < 64:
                return "/dev/iseries/vt{:d}l".format(minor - 32)
            elif 64 <= minor < 96:
                return "/dev/iseries/vt{:d}m".format(minor - 64)
            elif 96 <= minor < 128:
                return "/dev/iseries/vt{:d}a".format(minor - 96)
            elif 128 <= minor < 160:
                return "/dev/iseries/nvt{:d}".format(minor - 128)
            elif 160 <= minor < 192:
                return "/dev/iseries/nvt{:d}l".format(minor - 160)
            elif 192 <= minor < 224:
                return "/dev/iseries/nvt{:d}m".format(minor - 192)
            elif 224 <= minor < 256:
                return "/dev/iseries/nvt{:d}a".format(minor - 224)
        elif major == 231:
            if 0 <= minor < 64:
                return "/dev/infiniband/umad{:d}".format(minor)
            elif 64 <= minor < 128:
                return "/dev/infiniband/issm{:d}".format(minor - 64)
            elif 192 <= minor < 224:
                return "/dev/infiniband/uverbs{:d}".format(minor - 192)
        elif major == 232:
            if minor % 10 == 0:
                return "/dev/biometric/sensor{:d}/fingerprint".format(minor // 10)
            elif minor % 10 == 1:
                return "/dev/biometric/sensor{:d}/iris".format(minor // 10)
            elif minor % 10 == 2:
                return "/dev/biometric/sensor{:d}/retina".format(minor // 10)
            elif minor % 10 == 3:
                return "/dev/biometric/sensor{:d}/voiceprint".format(minor // 10)
            elif minor % 10 == 4:
                return "/dev/biometric/sensor{:d}/facial".format(minor // 10)
            elif minor % 10 == 5:
                return "/dev/biometric/sensor{:d}/hand".format(minor // 10)
        elif major == 233:
            if minor == 0:
                return "/dev/ipath"
            elif 1 <= minor < 5:
                return "/dev/ipath{:d}".format(minor - 1)
            elif minor == 129:
                return "/dev/ipath_sma"
            elif minor == 130:
                return "/dev/ipath_diag"
        return "???"

    def get_chrdev_list(self): # [chrdev, chrdev, chrdev, ...]
        """
        #define CHRDEV_MAJOR_HASH_SIZE 255
        static struct char_device_struct {
            struct char_device_struct *next;
            unsigned int major;
            unsigned int baseminor;
            int minorct;
            char name[64];
            struct cdev *cdev;
        } *chrdevs[CHRDEV_MAJOR_HASH_SIZE];
        """
        chrdevs = KernelAddressHeuristicFinder.get_chrdevs()
        if chrdevs is None:
            self.quiet_err("Could not find chrdevs")
            return None
        self.quiet_info("chrdevs: {:#x}".format(chrdevs))

        chrdev_addrs = []
        chrdev_seen = set()
        for i in range(255):
            chrdevs_i = chrdevs + i * runtime.current_arch.ptrsize
            if not is_valid_addr(chrdevs_i):
                self.quiet_err("Memory read error")
                return None
            addr = read_int_from_memory(chrdevs_i)
            while addr:
                if addr in chrdev_seen:
                    self.quiet_warn("Incomplete chrdevs: cycle or duplicate at {:#x}".format(addr))
                    break
                if len(chrdev_seen) >= 0x10000:
                    self.quiet_warn("Incomplete chrdevs: traversal limit reached at {:#x}".format(addr))
                    return chrdev_addrs
                chrdev_addrs.append(addr)
                chrdev_seen.add(addr)
                if not is_valid_addr(addr):
                    self.quiet_err("Memory read error")
                    return None
                addr = read_int_from_memory(addr)
        return chrdev_addrs

    def get_cdev_list(self): # [[cdev, major, minor, range], [...] ...]
        """
        struct kobj_map {
            struct probe {
                struct probe *next;
                dev_t dev;
                unsigned long range;
                struct module *owner;
                kobj_probe_t *get;
                int (*lock)(dev_t, void *);
                void *data;  // -> cdev
            } *probes[255];
            struct mutex *lock;
        };
        static struct kobj_map *cdev_map;

        struct cdev {
            struct kobject kobj;
            struct module *owner;
            const struct file_operations *ops;
            struct list_head list;
            dev_t dev;
            unsigned int count;
        } __randomize_layout;

        struct kobject {
            const char *name;
            struct list_head entry;
            struct kobject *parent;
            struct kset *kset;
            const struct kobj_type *ktype;
            struct kernfs_node *sd;
            struct kref kref;
        #ifdef CONFIG_DEBUG_KOBJECT_RELEASE
            struct delayed_work release;
        #endif
            unsigned int state_initialized:1;
            unsigned int state_in_sysfs:1;
            unsigned int state_add_uevent_sent:1;
            unsigned int state_remove_uevent_sent:1;
            unsigned int uevent_suppress:1;
        };
        """
        cdev_map = KernelAddressHeuristicFinder.get_cdev_map()
        if cdev_map is None:
            self.quiet_err("Could not find cdev_map")
            return None
        self.quiet_info("cdev_map: {:#x}".format(cdev_map))

        try:
            cdev_map_ = read_int_from_memory(cdev_map)
            self.quiet_info("*cdev_map: {:#x}".format(cdev_map_))
        except Exception:
            self.quiet_err("cdev_map is not initialized")
            return None

        cdev_addrs = []
        seen = set()
        for i in range(255):
            addr = read_int_from_memory(cdev_map_ + i * runtime.current_arch.ptrsize)
            probe_seen = set()
            while addr:
                if addr in probe_seen:
                    self.quiet_warn("Incomplete cdev_map: probe cycle at {:#x} (bucket {:d})".format(addr, i))
                    break
                if len(probe_seen) >= 0x10000:
                    self.quiet_warn("Incomplete cdev_map: probe traversal limit at {:#x} (bucket {:d})".format(addr, i))
                    break
                probe_seen.add(addr)
                cdev = read_int_from_memory(addr + 6 * runtime.current_arch.ptrsize)
                dev = read_int32_from_memory(addr + runtime.current_arch.ptrsize)
                range_ = read_int_from_memory(addr + 2 * runtime.current_arch.ptrsize)
                major = dev >> 20
                minor = dev & ((1 << 20) - 1)
                if cdev and cdev not in seen:
                    cdev_addrs.append([cdev, major, minor, range_])
                    seen.add(cdev)
                addr = read_int_from_memory(addr)
        return cdev_addrs

    def is_file_operations(self, ops):
        """Check the owner and the function pointers of `ops`. Return None if it cannot be decided,
        because a kernel address is unreadable (e.g., the module region of ARM32 LPAE).
        The second member is `fop_flags` since v6.10, so a small value is also accepted there.
        All members but the owner may be NULL (e.g., portdev_fops of virtio_console)."""
        if not ops:
            return False
        if not is_valid_addr(ops):
            if KernelAddressHeuristicFinderUtil.is_kernel_space(ops):
                return None
            return False
        try:
            members = [read_int_from_memory(ops + runtime.current_arch.ptrsize * i) for i in range(20)]
        except gdb.MemoryError:
            return None
        if members[1] < 0x10000:
            members[1] = 0
        unknown = False
        for x in members:
            if not x or is_valid_addr(x):
                continue
            if not KernelAddressHeuristicFinderUtil.is_kernel_space(x):
                return False
            unknown = True
        if unknown:
            return None
        return True

    def get_offset_ops(self, cdevs):
        offset_ops = GefUtil.offsetof("cdev", "ops")
        if offset_ops is not None:
            self.quiet_info("offsetof(cdev, ops): {:#x}".format(offset_ops))
            return offset_ops

        # cdev->list follows cdev->ops, but its position depends on struct kobject
        # (e.g., CONFIG_DEBUG_KOBJECT_RELEASE adds a delayed_work), so it is searched widely.
        # Lists in kobject such as the release work entry are rejected by checking cdev->ops.
        for i in range(3, 0x100):
            offset_list = i * runtime.current_arch.ptrsize
            valid = True
            for cdev in cdevs:
                pos_next = cdev + offset_list
                pos_prev = cdev + offset_list + runtime.current_arch.ptrsize
                list_entry_next = [pos_next]
                list_entry_prev = [pos_prev]
                while valid:
                    # read check
                    try:
                        pos_next = read_int_from_memory(pos_next)
                        pos_prev = read_int_from_memory(pos_prev) + runtime.current_arch.ptrsize
                    except gdb.MemoryError: # memory read error
                        valid = False
                        break
                    # list validate
                    if pos_next in list_entry_next[1:]: # incomplete infinity loop detected
                        valid = False
                        break
                    if pos_prev in list_entry_prev[1:]: # incomplete infinity loop detected
                        valid = False
                        break
                    if pos_next == list_entry_next[0] and pos_prev == list_entry_prev[0]:
                        break
                    list_entry_next.append(pos_next)
                    list_entry_prev.append(pos_prev)
                if not valid:
                    break
            else:
                # for loop is finished until last element
                offset_ops = offset_list - runtime.current_arch.ptrsize
                checked = [self.is_file_operations(read_int_from_memory(cdev + offset_ops)) for cdev in cdevs]
                if False not in checked and True in checked:
                    self.quiet_info("offsetof(cdev, ops): {:#x}".format(offset_ops))
                    return offset_ops

        self.quiet_err("Could not find offsetof(cdev, ops)")
        return None

    def print_nodes(self, regions, cdev_addrs, off_ops):
        kdev = KernelDevice()
        ret = kdev.initialize()
        for func, line in Kernel.export_meta(self, kdev.meta):
            func(line)
        if not ret:
            return

        def find_region(major, minor):
            devt = major << 20 | minor
            for m in regions:
                start = m["major"] << 20 | m["minor"]
                if start <= devt < start + m["count"]:
                    return m["name"]
            return None

        def find_cdev(major, minor):
            # kobj_lookup() takes the narrowest range
            devt = major << 20 | minor
            found = [(range_, cdev) for cdev, ma, mi, range_ in cdev_addrs
                     if (ma << 20 | mi) <= devt < (ma << 20 | mi) + range_]
            if found:
                return min(found, key=lambda entry: entry[0])[1]
            return 0

        self.out = []
        if not self.args.quiet:
            fmt = "{:<18s} {:<20s} {:<12s} {:<6s} {:<6s} {:<18s} {:<18s} {:<s}"
            legend = ["device", "name (sysfs)", "class", "major", "minor", "chrdev name", "cdev", "cdev->ops"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for device, name, devt, class_name in sorted(kdev.devices, key=lambda x: (x[2], x[0])):
            major, minor = devt >> 20, devt & ((1 << 20) - 1)
            region_name = find_region(major, minor)
            cdev = find_cdev(major, minor)
            if class_name == "block":
                continue
            if class_name == "???" and region_name is None and cdev == 0:
                # the class is unknown, and the block devices are not in the registries of the character devices
                continue
            if cdev:
                ops = read_int_from_memory(cdev + off_ops)
            else:
                ops = 0
            self.out.append("{:#018x} {:<20s} {:<12s} {:<6d} {:<6d} {:<18s} {:#018x} {:s}".format(
                device, name, class_name, major, minor, region_name or "-", cdev,
                Symbol.format(ops, show_address=True, nocolor=True),
            ))
        self.print_output(check_terminal_size=True)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        chrdev_addrs = self.get_chrdev_list()
        if chrdev_addrs is None:
            return
        cdev_addrs = self.get_cdev_list()
        if cdev_addrs is None:
            return

        # merge chrdev (from chrdevs)
        merged = {}
        regions = []
        for chrdev in chrdev_addrs:
            major = read_int32_from_memory(chrdev + runtime.current_arch.ptrsize)
            minor = read_int32_from_memory(chrdev + runtime.current_arch.ptrsize + 4)
            count = read_int32_from_memory(chrdev + runtime.current_arch.ptrsize + 4 * 2)
            name_string = read_cstring_from_memory(chrdev + runtime.current_arch.ptrsize + 4 * 3) or "<None>"
            off = chrdev + runtime.current_arch.ptrsize + 4 * 3 + 64
            while off % runtime.current_arch.ptrsize: # align
                off += 1
            cdev = read_int_from_memory(off)
            merged[major, minor] = {"chrdev": chrdev, "name": name_string, "cdev": cdev, "count": count}
            regions.append({"major": major, "minor": minor, "count": count, "name": name_string})

        # merge cdev (from cdev_map)
        registered_ranges = sorted((m["major"] << 20 | m["minor"], m["count"]) for m in regions)
        for cdev, major, minor, range_ in cdev_addrs:
            kobj = read_int_from_memory(cdev)
            name_string = read_cstring_from_memory(kobj) or "<None>"

            if (major, minor) in merged:
                if merged[major, minor]["cdev"] == 0:
                    merged[major, minor]["cdev"] = cdev
                if merged[major, minor]["name"] == "<None>":
                    merged[major, minor]["name"] = name_string
            else:
                merged[major, minor] = {"chrdev": 0x0, "name": name_string, "cdev": cdev, "count": range_}

            # a cdev must be added in a range registered by register_chrdev_region() or its variants
            start = major << 20 | minor
            last = start + range_ - 1
            covered = start
            for region_start, count in registered_ranges:
                if region_start <= covered < region_start + count:
                    covered = region_start + count
                    if covered > last:
                        break
            if covered <= last:
                self.quiet_warn("cdev {:#x} ({:d}:{:d}-{:d}:{:d}) is not in any range of chrdevs".format(
                    cdev, major, minor, last >> 20, last & ((1 << 20) - 1)))

        # add ops info
        off_ops = self.get_offset_ops([v["cdev"] for k, v in merged.items() if v["cdev"]])
        if off_ops is None:
            return

        # cdev->dev and cdev->count are what cdev_add() registered to cdev_map
        offsetof = GefUtil.offsetof
        off_dev = offsetof("cdev", "dev")
        if off_dev is None:
            off_dev = off_ops + runtime.current_arch.ptrsize * 3
        off_count = offsetof("cdev", "count")
        if off_count is None:
            off_count = off_dev + 4
        for cdev, major, minor, range_ in cdev_addrs:
            dev = read_int32_from_memory(cdev + off_dev)
            count = read_int32_from_memory(cdev + off_count)
            if (dev, count) != (major << 20 | minor, range_):
                self.quiet_warn("cdev {:#x} ({:d}:{:d}, count {:d}) differs from cdev_map ({:d}:{:d}, range {:d})".format(
                    cdev, dev >> 20, dev & ((1 << 20) - 1), count, major, minor, range_,
                ))

        if args.nodes:
            self.print_nodes(regions, cdev_addrs, off_ops)
            return

        for k in merged.keys():
            if merged[k]["cdev"]:
                merged[k]["ops"] = read_int_from_memory(merged[k]["cdev"] + off_ops)
            else:
                merged[k]["ops"] = 0x0

        # add parent info
        off_parent = offsetof("cdev", "kobj.parent")
        if off_parent is None:
            off_parent = runtime.current_arch.ptrsize * 3
        for k in merged.keys():
            if merged[k]["cdev"]:
                parent = read_int_from_memory(merged[k]["cdev"] + off_parent)
                merged[k]["parent"] = parent
                if parent:
                    if not is_valid_addr(parent):
                        merged[k]["parent_name"] = "???"
                    else:
                        name = read_int_from_memory(parent)
                        if name:
                            merged[k]["parent_name"] = read_cstring_from_memory(name) or "<None>"
                        else:
                            merged[k]["parent_name"] = "<None>"
                else:
                    merged[k]["parent_name"] = "<None>"
            else:
                merged[k]["parent"] = 0x0
                merged[k]["parent_name"] = "<None>"

        # print
        self.out = []
        if not args.quiet:
            fmt = "{:<18s} {:<18s} {:<24s} {:<6s} {:<15s} {:<7s} {:<18s} {:<18s} {:18s} {:<s}"
            legend = [
                "chrdev", "name", "name (guessed)", "major", "minor", "count",
                "cdev", "cdev->kobj.parent", "parent_name", "cdev->ops",
            ]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for (major, minor), m in sorted(merged.items()):
            if not args.verbose:
                if m["chrdev"] == 0:
                    continue
            count = m["count"]
            if count == 1:
                minors = "{:d}".format(minor)
                guessed_name = KernelCharacterDevicesCommand.guess_cdev_path(major, minor)
            else:
                last = (major << 20 | minor) + count - 1
                if last >> 20 == major:
                    minors = "{:d}-{:d}".format(minor, last & ((1 << 20) - 1))
                else:
                    minors = "{:d}-{:d}:{:d}".format(minor, last >> 20, last & ((1 << 20) - 1))
                guessed_name = "-"
            self.out.append("{:#018x} {:<18s} {:<24s} {:<6d} {:<15s} {:<7d} {:#018x} {:#018x} {:<18s} {:s}".format(
                m["chrdev"], m["name"], guessed_name, major, minors, count,
                m["cdev"], m["parent"], m["parent_name"], Symbol.format(m["ops"], show_address=True, nocolor=True),
            ))

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelOperationsCommand(GenericCommand, BufferingOutput):
    """Display the members of commonly used function table (like struct file_operations) in the kernel."""

    _cmdline_ = "kops"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    types = [
        "address_space_operations",
        "ata_port_operations",
        "btf_kind_operations",
        "block_device_operations",
        "clk_ops",
        "configfs_item_operations",
        "configfs_group_operations",
        "damon_operations",
        "dentry_operations",
        "dev_pm_ops",
        "dma_buf_ops",
        "export_operations",
        "file_operations",
        "fs_context_operations",
        "inode_operations",
        "kobj_ns_type_operations",
        "media_entity_operations",
        "movable_operations",
        "net_device_ops",
        "page_ext_operations",
        "parport_operations",
        "pernet_operations",
        "pipe_buf_operations",
        "proc_ns_operations",
        "proc_ops",
        "regulator_ops",
        "seq_operations",
        "smp_operations", # ARM only
        "super_operations",
        "tty_ldisc_ops",
        "tty_operations",
        "tty_port_operations",
        "ucsi_operations",
        "vm_operations_struct",
    ]
    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("name", metavar="STRUCT_NAME", choices=types, help="the structure name.")
    parser.add_argument("address", metavar="ADDRESS", nargs="?", type=AddressUtil.parse_address,
                        help="the address interpreted as ops.")
    parser.add_argument("-V", "--version", help="use specific kernel version. (default: detected kernel version)")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} file_operations",
        "{0:s} -V 6.6.0 file_operations",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n.",
        "",
        "Currently it supports from 3.0 to 7,0-rc7.",
        "",
        "Supported structure:",
    ]
    for t_grp in slicer(types, 4):
        _note_.append("  " + ", ".join(t_grp) + ",")
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete="use_user_complete")
        return

    def complete(self, text, word): # noqa
        if text.strip() in self.types:
            # already matched
            return []

        if text == "":
            # no prefix: example: `kops TAB`
            return [s for s in self.types if ((word is None) or (s and word in s))]

        # finally, look for possible values for given prefix
        return [s for s in self.types if s and s.startswith(text.strip())]

    def initialize(self, kversion):
        if kversion.major < 3:
            err("Unsupported before v3.0")
            return False

        self.members = {}

        def adapt_to_kernel_version(ops):
            out = []
            for entry in ops:
                if len(entry) == 5:
                    typ, name, minver, maxver, enabled = entry
                    if not enabled:
                        continue
                else:
                    typ, name, minver, maxver = entry

                if minver and kversion < minver:
                    continue
                if maxver and maxver <= kversion:
                    continue
                out.append((typ, name))
            return out

        file_operations = [
            # type       name                                       minver     maxver
            ["ptr",      "owner",                                   None,      None],
            ["int",      "flags",                                   "6.10.0",  None],
            ["func_ptr", "llseek",                                  None,      None],
            ["func_ptr", "read",                                    None,      None],
            ["func_ptr", "write",                                   None,      None],
            ["func_ptr", "aio_read",                                None,      "4.1.0"],
            ["func_ptr", "aio_write",                               None,      "4.1.0"],
            ["func_ptr", "read_iter",                               "3.16.0",  None],
            ["func_ptr", "write_iter",                              "3.16.0",  None],
            ["func_ptr", "readdir",                                 None,      "3.11.0"],
            ["func_ptr", "iopoll",                                  "5.1.0",   None],
            ["func_ptr", "iterate",                                 "3.11.0",  "6.5.0"],
            ["func_ptr", "iterate_shared",                          "4.7.0",   None],
            ["func_ptr", "poll",                                    None,      None],
            ["func_ptr", "unlocked_ioctl",                          None,      None],
            ["func_ptr", "compat_ioctl",                            None,      None],
            ["func_ptr", "mmap",                                    None,      None],
            ["func_ptr", "mremap",                                  "3.19.0",  "4.3.0"],
            ["ulong",    "mmap_supported_flags",                    "4.15.0",  "6.10.0"],
            ["func_ptr", "open",                                    None,      None],
            ["func_ptr", "flush",                                   None,      None],
            ["func_ptr", "release",                                 None,      None],
            ["func_ptr", "fsync",                                   None,      None],
            ["func_ptr", "aio_fsync",                               None,      "4.9.0"],
            ["func_ptr", "fasync",                                  None,      None],
            ["func_ptr", "lock",                                    None,      None],
            ["func_ptr", "sendpage",                                None,      "6.5.0"],
            ["func_ptr", "get_unmapped_area",                       None,      None],
            ["func_ptr", "check_flags",                             None,      None],
            ["func_ptr", "flock",                                   None,      None],
            ["func_ptr", "splice_write",                            None,      None],
            ["func_ptr", "splice_read",                             None,      None],
            ["func_ptr", "splice_eof",                              "6.5.0",   None],
            ["func_ptr", "setlease",                                None,      None],
            ["func_ptr", "fallocate",                               None,      None],
            ["func_ptr", "show_fdinfo",                             "3.8.0",   None],
            ["func_ptr", "copy_file_range",                         "4.5.0",   None],
            ["func_ptr", "clone_file_range",                        None,      "4.19.289"],
            ["func_ptr", "dedupe_file_range",                       None,      "4.19.289"],
            ["func_ptr", "remap_file_range",                        "4.20.0",  None],
            ["func_ptr", "fadvise",                                 "4.19.0",  None],
            ["func_ptr", "uring_cmd",                               "5.19.0",  None],
            ["func_ptr", "uring_cmd_iopoll",                        "6.1.0",   None],
            ["func_ptr", "mmap_prepare",                            "6.16.0",  None],
        ]
        self.members["file_operations"] = adapt_to_kernel_version(file_operations)

        tty_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "lookup",                                  None,      None],
            ["func_ptr", "install",                                 None,      None],
            ["func_ptr", "remove",                                  None,      None],
            ["func_ptr", "open",                                    None,      None],
            ["func_ptr", "close",                                   None,      None],
            ["func_ptr", "shutdown",                                None,      None],
            ["func_ptr", "cleanup",                                 None,      None],
            ["func_ptr", "write",                                   None,      None],
            ["func_ptr", "put_char",                                None,      None],
            ["func_ptr", "flush_chars",                             None,      None],
            ["func_ptr", "write_room",                              None,      None],
            ["func_ptr", "chars_in_buffer",                         None,      None],
            ["func_ptr", "ioctl",                                   None,      None],
            ["func_ptr", "compat_ioctl",                            None,      None],
            ["func_ptr", "set_termios",                             None,      None],
            ["func_ptr", "throttle",                                None,      None],
            ["func_ptr", "unthrottle",                              None,      None],
            ["func_ptr", "stop",                                    None,      None],
            ["func_ptr", "start",                                   None,      None],
            ["func_ptr", "hangup",                                  None,      None],
            ["func_ptr", "break_ctl",                               None,      None],
            ["func_ptr", "flush_buffer",                            None,      None],
            ["func_ptr", "ldisc_ok",                                "6.1.0",   None],
            ["func_ptr", "set_ldisc",                               None,      None],
            ["func_ptr", "wait_until_sent",                         None,      None],
            ["func_ptr", "send_xchar",                              None,      None],
            ["func_ptr", "tiocmget",                                None,      None],
            ["func_ptr", "tiocmset",                                None,      None],
            ["func_ptr", "resize",                                  None,      None],
            ["func_ptr", "set_termiox",                             None,      "5.10.0"],
            ["func_ptr", "get_icount",                              None,      None],
            ["func_ptr", "get_serial",                              "4.19.0",  None],
            ["func_ptr", "set_serial",                              "4.19.0",  None],
            ["func_ptr", "show_fdinfo",                             "4.14.0",  None],
            ["func_ptr", "poll_init (CONFIG_CONSOLE_POLL=y)",       None,      None],
            ["func_ptr", "poll_get_char (CONFIG_CONSOLE_POLL=y)",   None,      None],
            ["func_ptr", "poll_put_char (CONFIG_CONSOLE_POLL=y)",   None,      None],
            ["func_ptr", "proc_show",                               "4.18.0",  None],
            ["ptr",      "proc_fops",                               None,      "4.18.0"],
        ]
        self.members["tty_operations"] = adapt_to_kernel_version(tty_operations)

        tty_ldisc_ops = [
            # type       name                                       minver     maxver      additional_flag
            ["int",      "magic",                                   None,      "5.13.0"],
            ["char*",    "name",                                    None,      None],
            ["int",      "num",                                     "5.16.0",  None],
            ["int",      "num",                                     None,      "5.15.121", is_32bit()],
            ["int",      "flags",                                   None,      "5.15.121", is_32bit()],
            ["int, int", "flags, num",                              None,      "5.15.121", is_64bit()],
            ["func_ptr", "open",                                    None,      None],
            ["func_ptr", "close",                                   None,      None],
            ["func_ptr", "flush_buffer",                            None,      None],
            ["func_ptr", "read",                                    None,      None],
            ["func_ptr", "write",                                   None,      None],
            ["func_ptr", "ioctl",                                   None,      None],
            ["func_ptr", "compat_ioctl",                            None,      None],
            ["func_ptr", "set_termios",                             None,      None],
            ["func_ptr", "poll",                                    None,      None],
            ["func_ptr", "hangup",                                  None,      None],
            ["func_ptr", "receive_buf",                             None,      None],
            ["func_ptr", "write_wakeup",                            None,      None],
            ["func_ptr", "dcd_change",                              None,      None],
            ["func_ptr", "fasync",                                  "3.11.0",  "4.6.0"],
            ["func_ptr", "receive_buf2",                            "3.12.0",  None],
            ["func_ptr", "lookahead_buf",                           "5.16.0",  None],
            ["ptr",      "owner",                                   None,      None],
            ["int",      "refcount",                                None,      "5.14.0"],
        ]
        self.members["tty_ldisc_ops"] = adapt_to_kernel_version(tty_ldisc_ops)

        seq_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "start",                                   None,      None],
            ["func_ptr", "stop",                                    None,      None],
            ["func_ptr", "next",                                    None,      None],
            ["func_ptr", "show",                                    None,      None],
        ]
        self.members["seq_operations"] = adapt_to_kernel_version(seq_operations)

        inode_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "lookup",                                  None,      None],
            ["func_ptr", "get_link",                                "4.5.0",   None],
            ["func_ptr", "follow_link",                             None,      "4.5.0"],
            ["func_ptr", "permission",                              None,      None],
            ["func_ptr", "get_inode_acl",                           "6.2.0",   None],
            ["func_ptr", "get_acl",                                 "3.1.0",   "6.1.39"],
            ["func_ptr", "check_acl",                               None,      "3.1.0"],
            ["func_ptr", "readlink",                                None,      None],
            ["func_ptr", "put_link",                                None,      "4.5.0"],
            ["func_ptr", "create",                                  None,      None],
            ["func_ptr", "link",                                    None,      None],
            ["func_ptr", "unlink",                                  None,      None],
            ["func_ptr", "symlink",                                 None,      None],
            ["func_ptr", "mkdir",                                   None,      None],
            ["func_ptr", "rmdir",                                   None,      None],
            ["func_ptr", "mknod",                                   None,      None],
            ["func_ptr", "rename",                                  None,      None],
            ["func_ptr", "truncate",                                None,      "3.8.0"],
            ["func_ptr", "rename2",                                 "3.15.0",  "4.9.0"],
            ["func_ptr", "setattr",                                 None,      None],
            ["func_ptr", "getattr",                                 None,      None],
            ["func_ptr", "setxattr",                                None,      "4.9.0"],
            ["func_ptr", "getxattr",                                None,      "4.9.0"],
            ["func_ptr", "listxattr",                               None,      None],
            ["func_ptr", "removexattr",                             None,      "4.9.0"],
            ["func_ptr", "fiemap",                                  None,      None],
            ["func_ptr", "update_time",                             "3.5.0",   None],
            ["func_ptr", "sync_lazytime",                           "7.0.0",   None],
            ["func_ptr", "atomic_open",                             "3.6.0",   None],
            ["func_ptr", "tmpfile",                                 "3.11.0",  None],
            ["func_ptr", "get_acl",                                 "6.2.0",   None],
            ["func_ptr", "set_acl",                                 "3.14.0",  None],
            ["func_ptr", "dentry_open",                             None,      "4.2.0"],
            ["func_ptr", "fileattr_set",                            "5.13.0",  None],
            ["func_ptr", "fileattr_get",                            "5.13.0",  None],
            ["func_ptr", "get_offset_ctx",                          "6.6.0",   None],
        ]
        self.members["inode_operations"] = adapt_to_kernel_version(inode_operations)

        pernet_operations = [
            # type       name                                       minver     maxver
            ["ptr",      "list.next",                               None,      None],
            ["ptr",      "list.prev",                               None,      None],
            ["func_ptr", "init",                                    None,      None],
            ["func_ptr", "pre_exit",                                "5.3.0",   None],
            ["func_ptr", "exit",                                    None,      None],
            ["func_ptr", "exit_batch",                              None,      None],
            ["func_ptr", "exit_batch_rtnl",                         "6.9.0",   "6.15.9"],
            ["func_ptr", "exit_rtnl",                               "6.16.0",  None],
            ["ptr",      "id",                                      None,      None],
            ["long",     "size",                                    None,      None],
        ]
        self.members["pernet_operations"] = adapt_to_kernel_version(pernet_operations)

        address_space_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "writepage",                               None,      "6.15.9"],
            ["func_ptr", "read_folio",                              "5.19.0",  None],
            ["func_ptr", "readpage",                                None,      "5.19.0"],
            ["func_ptr", "writepages",                              None,      None],
            ["func_ptr", "dirty_folio",                             "5.18.0",  None],
            ["func_ptr", "set_page_dirty",                          None,      "5.18.0"],
            ["func_ptr", "readpages",                               None,      "5.18.0"],
            ["func_ptr", "readahead",                               "5.8.0",   None],
            ["func_ptr", "write_begin",                             None,      None],
            ["func_ptr", "write_end",                               None,      None],
            ["func_ptr", "bmap",                                    None,      None],
            ["func_ptr", "invalidate_folio",                        "5.18.0",  None],
            ["func_ptr", "invalidatepage",                          None,      "5.18.0"],
            ["func_ptr", "release_folio",                           "5.19.0",  None],
            ["func_ptr", "releasepage",                             None,      "5.19.0"],
            ["func_ptr", "free_folio",                              "5.19.0",  None],
            ["func_ptr", "freepage",                                None,      "5.19.0"],
            ["func_ptr", "direct_IO",                               None,      None],
            ["func_ptr", "get_xip_mem",                             None,      "4.0.0"],
            ["func_ptr", "migrate_folio",                           "6.0.0",   None],
            ["func_ptr", "migratepage",                             None,      "5.20.0"],
            ["func_ptr", "isolate_page",                            "4.8.0",   "5.20.0"],
            ["func_ptr", "putback_page",                            "4.8.0",   "5.20.0"],
            ["func_ptr", "launder_folio",                           "5.18.0",  None],
            ["func_ptr", "launder_page",                            None,      "5.18.0"],
            ["func_ptr", "is_partially_uptodate",                   None,      None],
            ["func_ptr", "is_dirty_writeback",                      "3.11.0",  None],
            ["func_ptr", "error_remove_page",                       None,      "6.8.0"],
            ["func_ptr", "error_remove_folio",                      "6.8.0",   None],
            ["func_ptr", "swap_activate",                           "3.6.0",   None],
            ["func_ptr", "swap_deactivate",                         "3.6.0",   None],
            ["func_ptr", "swap_rw",                                 "5.19.0",  None],
        ]
        self.members["address_space_operations"] = adapt_to_kernel_version(address_space_operations)

        vm_operations_struct = [
            # type       name                                            minver     maxver
            ["func_ptr", "open",                                         None,      None],
            ["func_ptr", "close",                                        None,      None],
            ["func_ptr", "mapped",                                       "7.1.0",   None],
            ["func_ptr", "may_split",                                    "5.11.0",  None],
            ["func_ptr", "split",                                        "4.14.0",  "5.10.187"],
            ["func_ptr", "mremap",                                       "4.3.9",   None],
            ["func_ptr", "mprotect",                                     "5.11.0",  None],
            ["func_ptr", "fault",                                        None,      None],
            ["func_ptr", "huge_fault",                                   "4.11.0",  None],
            ["func_ptr", "pmd_fault",                                    "4.3.0",   "4.11.0"],
            ["func_ptr", "map_pages",                                    "3.15.0",  None],
            ["func_ptr", "pagesize",                                     "4.17.0",  None],
            ["func_ptr", "page_mkwrite",                                 None,      None],
            ["func_ptr", "pfn_mkwrite",                                  "4.1.0",   None],
            ["func_ptr", "access",                                       None,      None],
            ["func_ptr", "name",                                         "3.16.0",  None],
            ["func_ptr", "set_policy (CONFIG_NUMA=y)",                   None,      None],
            ["func_ptr", "get_policy (CONFIG_NUMA=y)",                   None,      None],
            ["func_ptr", "migrate (CONFIG_NUMA=y)",                      None,      "3.19.0"],
            ["func_ptr", "find_special_page",                            "4.0.0",   "6.17.8"],
            ["func_ptr", "find_normal_page (CONFIG_FIND_NORMAL_PAGE=y)", "6.18.0",  None],
            ["func_ptr", "remap_pages",                                  "3.17.0",  "4.0.0"],
            ["func_ptr", "remap_pages",                                  "3.7.0",   "3.16.59"],
            ["ptr",      "uffd_ops (CONFIG_USERFAULTFD=y)",              "7.1.0",   None],
        ]
        self.members["vm_operations_struct"] = adapt_to_kernel_version(vm_operations_struct)

        super_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "alloc_inode",                             None,      None],
            ["func_ptr", "destroy_inode",                           None,      None],
            ["func_ptr", "free_inode",                              "5.2.0",   None],
            ["func_ptr", "dirty_inode",                             None,      None],
            ["func_ptr", "write_inode",                             None,      None],
            ["func_ptr", "drop_inode",                              None,      None],
            ["func_ptr", "evict_inode",                             None,      None],
            ["func_ptr", "put_super",                               None,      None],
            ["func_ptr", "write_super",                             None,      "3.6.0"],
            ["func_ptr", "sync_fs",                                 None,      None],
            ["func_ptr", "freeze_super",                            "3.19.0",  None],
            ["func_ptr", "freeze_fs",                               None,      None],
            ["func_ptr", "thaw_super",                              "3.19.0",  None],
            ["func_ptr", "unfreeze_fs",                             None,      None],
            ["func_ptr", "statfs",                                  None,      None],
            ["func_ptr", "remount_fs",                              None,      "7.0.0"],
            ["func_ptr", "umount_begin",                            None,      None],
            ["func_ptr", "show_options",                            None,      None],
            ["func_ptr", "show_devname",                            None,      None],
            ["func_ptr", "show_path",                               None,      None],
            ["func_ptr", "show_stats",                              None,      None],
            ["func_ptr", "quota_read (CONFIG_QUOTA=y)",             None,      None],
            ["func_ptr", "quota_write (CONFIG_QUOTA=y)",            None,      None],
            ["func_ptr", "get_dquots (CONFIG_QUOTA=y)",             "3.19.0",  None],
            ["func_ptr", "bdev_try_to_free_page",                   None,      "5.14.0"],
            ["func_ptr", "nr_cached_objects",                       "3.1.0",   None],
            ["func_ptr", "free_cached_objects",                     "3.1.0",   None],
            ["func_ptr", "remove_bdev",                             "6.17.0",  None],
            ["func_ptr", "shutdown",                                "6.5.0",   None],
            ["func_ptr", "report_error",                            "7.0.0",   None],
        ]
        self.members["super_operations"] = adapt_to_kernel_version(super_operations)

        dentry_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "d_revalidate",                            None,      None],
            ["func_ptr", "d_weak_revalidate",                       "3.9.0",   None],
            ["func_ptr", "d_hash",                                  None,      None],
            ["func_ptr", "d_compare",                               None,      None],
            ["func_ptr", "d_delete",                                None,      None],
            ["func_ptr", "d_init",                                  "4.8.0",   None],
            ["func_ptr", "d_release",                               None,      None],
            ["func_ptr", "d_prune",                                 "3.2.0",   None],
            ["func_ptr", "d_iput",                                  None,      None],
            ["func_ptr", "d_dname",                                 None,      None],
            ["func_ptr", "d_automount",                             None,      None],
            ["func_ptr", "d_manage",                                None,      None],
            ["func_ptr", "d_select_inode",                          "4.1.0",   "4.8.0"],
            ["func_ptr", "d_real",                                  "4.4.0",   None],
            ["func_ptr", "d_select_inode",                          "3.18.23", "3.19.0"],
            ["func_ptr", "d_unalias_trylock",                       "6.14.0",  None],
            ["func_ptr", "d_unalias_unlock",                        "6.14.0",  None],
        ]
        self.members["dentry_operations"] = adapt_to_kernel_version(dentry_operations)

        block_device_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "submit_bio",                              "5.9.0",   None],
            ["func_ptr", "poll_bio",                                "5.18.0",  None],
            ["func_ptr", "open",                                    None,      None],
            ["func_ptr", "release",                                 None,      None],
            ["func_ptr", "rw_page",                                 None,      "6.3.0"],
            ["func_ptr", "ioctl",                                   None,      None],
            ["func_ptr", "compat_ioctl",                            None,      None],
            ["func_ptr", "direct_access",                           None,      "4.12.0"],
            ["func_ptr", "check_events",                            None,      None],
            ["func_ptr", "media_changed",                           None,      "5.9.0"],
            ["func_ptr", "unlock_native_capacity",                  None,      None],
            ["func_ptr", "revalidate_disk",                         None,      "5.13.0"],
            ["func_ptr", "getgeo",                                  None,      None],
            ["func_ptr", "set_read_only",                           "5.11.0",  None],
            ["func_ptr", "free_disk",                               "5.18.0",  None],
            ["func_ptr", "swap_slot_free_notify",                   None,      None],
            ["func_ptr", "report_zones",                            "4.20.0",  None],
            ["func_ptr", "devnode",                                 "5.7.0",   None],
            ["func_ptr", "get_unique_id",                           "5.16.0",  None],
            ["ptr",      "owner",                                   None,      None],
            ["ptr",      "pr_ops",                                  "4.4.0",   None],
            ["func_ptr", "alternative_gpt_sector",                  "5.15.0",  None],
        ]
        self.members["block_device_operations"] = adapt_to_kernel_version(block_device_operations)

        pipe_buf_operations = [
            # type       name                                       minver     maxver
            ["int",      "can_merge",                               None,      "5.1.0"],
            ["func_ptr", "map",                                     None,      "3.15.0"],
            ["func_ptr", "unmap",                                   None,      "3.15.0"],
            ["func_ptr", "confirm",                                 None,      None],
            ["func_ptr", "release",                                 None,      None],
            ["func_ptr", "try_steal",                               None,      None],
            ["func_ptr", "get",                                     None,      None],
        ]
        self.members["pipe_buf_operations"] = adapt_to_kernel_version(pipe_buf_operations)

        smp_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "smp_init_cpus (CONFIG_SMP=y)",            "3.7.0",   None],
            ["func_ptr", "smp_prepare_cpus (CONFIG_SMP=y)",         "3.7.0",   None],
            ["func_ptr", "smp_secondary_init (CONFIG_SMP=y)",       "3.7.0",   None],
            ["func_ptr", "smp_boot_secondary (CONFIG_SMP=y)",       "3.7.0",   None],
            ["func_ptr", "cpu_kill (CONFIG_HOTPLUG_CPU=y)",         "3.7.0",   None],
            ["func_ptr", "cpu_die (CONFIG_HOTPLUG_CPU=y)",          "3.7.0",   None],
            ["func_ptr", "cpu_can_disable (CONFIG_HOTPLUG_CPU=y)",  "4.3.0",   None],
            ["func_ptr", "cpu_disable (CONFIG_HOTPLUG_CPU=y)",      "3.7.0",   None],
        ]
        self.members["smp_operations"] = adapt_to_kernel_version(smp_operations)

        dma_buf_ops = [
            # type         name                                     minver     maxver
            ["bool",       "cache_sgt_mapping",                     "5.7.0",   "6.15.9"],
            ["bool, bool", "cache_sgt_mapping, dynamic_mapping",    "5.5.0",   "5.7.0"],
            ["bool",       "cache_sgt_mapping",                     "5.3.0",   "5.4.265"],
            ["func_ptr",   "attach",                                "3.2.0",   None],
            ["func_ptr",   "detach",                                "3.2.0",   None],
            ["func_ptr",   "pin",                                   "5.7.0",   None],
            ["func_ptr",   "unpin",                                 "5.7.0",   None],
            ["func_ptr",   "map_dma_buf",                           "3.2.0",   None],
            ["func_ptr",   "unmap_dma_buf",                         "3.2.0",   None],
            ["func_ptr",   "release",                               "3.2.0",   None],
            ["func_ptr",   "begin_cpu_access",                      "3.4.0",   None],
            ["func_ptr",   "end_cpu_access",                        "3.4.0",   None],
            ["func_ptr",   "mmap",                                  "5.3.0",   None],
            ["func_ptr",   "map_atomic",                            "4.12.0",  "4.19.0"],
            ["func_ptr",   "unmap_atomic",                          "4.12.0",  "4.19.0"],
            ["func_ptr",   "kmap_atomic",                           "3.4.0",   "4.12.0"],
            ["func_ptr",   "kunmap_atomic",                         "3.4.0",   "4.12.0"],
            ["func_ptr",   "map",                                   "4.12.0",  "5.6.0"],
            ["func_ptr",   "unmap",                                 "4.12.0",  "5.6.0"],
            ["func_ptr",   "kmap",                                  "3.4.0",   "4.12.0"],
            ["func_ptr",   "kunmap",                                "3.4.0",   "4.12.0"],
            ["func_ptr",   "mmap",                                  "3.5.0",   "5.3.0"],
            ["func_ptr",   "vmap",                                  "3.5.0",   None],
            ["func_ptr",   "vunmap",                                "3.5.0",   None],
        ]
        self.members["dma_buf_ops"] = adapt_to_kernel_version(dma_buf_ops)

        ata_port_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "qc_defer",                                None,      None],
            ["func_ptr", "check_atapi_dma",                         None,      None],
            ["func_ptr", "qc_prep",                                 None,      None],
            ["func_ptr", "qc_issue",                                None,      None],
            ["func_ptr", "qc_fill_rtf",                             None,      None],
            ["func_ptr", "qc_ncq_fill_rtf",                         "6.3.0",   None],
            ["func_ptr", "cable_detect",                            None,      None],
            ["func_ptr", "mode_filter",                             None,      None],
            ["func_ptr", "set_piomode",                             None,      None],
            ["func_ptr", "set_dmamode",                             None,      None],
            ["func_ptr", "set_mode",                                None,      None],
            ["func_ptr", "read_id",                                 None,      None],
            ["func_ptr", "dev_config",                              None,      None],
            ["func_ptr", "freeze",                                  None,      None],
            ["func_ptr", "thaw",                                    None,      None],
            ["func_ptr", "prereset",                                None,      "6.16.5"],
            ["func_ptr", "softreset",                               None,      "6.16.5"],
            ["func_ptr", "hardreset",                               None,      "6.16.5"],
            ["func_ptr", "postreset",                               None,      "6.16.5"],
            ["func_ptr", "reset.prereset",                          "6.17.0",  None],
            ["func_ptr", "reset.softreset",                         "6.17.0",  None],
            ["func_ptr", "reset.hardreset",                         "6.17.0",  None],
            ["func_ptr", "reset.postreset",                         "6.17.0",  None],
            ["func_ptr", "pmp_prereset",                            None,      "6.16.5"],
            ["func_ptr", "pmp_softreset",                           None,      "6.16.5"],
            ["func_ptr", "pmp_hardreset",                           None,      "6.16.5"],
            ["func_ptr", "pmp_postreset",                           None,      "6.16.5"],
            ["func_ptr", "pmp_reset.pmp_prereset",                  "6.17.0",  None],
            ["func_ptr", "pmp_reset.pmp_softreset",                 "6.17.0",  None],
            ["func_ptr", "pmp_reset.pmp_hardreset",                 "6.17.0",  None],
            ["func_ptr", "pmp_reset.pmp_postreset",                 "6.17.0",  None],
            ["func_ptr", "error_handler",                           None,      None],
            ["func_ptr", "lost_interrupt",                          None,      None],
            ["func_ptr", "post_internal_cmd",                       None,      None],
            ["func_ptr", "sched_eh",                                "3.6.0",   None],
            ["func_ptr", "end_eh",                                  "3.6.0",   None],
            ["func_ptr", "scr_read",                                None,      None],
            ["func_ptr", "scr_write",                               None,      None],
            ["func_ptr", "pmp_attach",                              None,      None],
            ["func_ptr", "pmp_detach",                              None,      None],
            ["func_ptr", "set_lpm",                                 None,      None],
            ["func_ptr", "port_suspend",                            None,      None],
            ["func_ptr", "port_resume",                             None,      None],
            ["func_ptr", "port_start",                              None,      None],
            ["func_ptr", "port_stop",                               None,      None],
            ["func_ptr", "host_stop",                               None,      None],
            ["func_ptr", "sff_dev_select (CONFIG_ATA_SFF=y)",       None,      None],
            ["func_ptr", "sff_set_devctl (CONFIG_ATA_SFF=y)",       None,      None],
            ["func_ptr", "sff_check_status (CONFIG_ATA_SFF=y)",     None,      None],
            ["func_ptr", "sff_check_altstatus (CONFIG_ATA_SFF=y)",  None,      None],
            ["func_ptr", "sff_tf_load (CONFIG_ATA_SFF=y)",          None,      None],
            ["func_ptr", "sff_tf_read (CONFIG_ATA_SFF=y)",          None,      None],
            ["func_ptr", "sff_exec_command (CONFIG_ATA_SFF=y)",     None,      None],
            ["func_ptr", "sff_data_xfer (CONFIG_ATA_SFF=y)",        None,      None],
            ["func_ptr", "sff_irq_on (CONFIG_ATA_SFF=y)",           None,      None],
            ["func_ptr", "sff_irq_check (CONFIG_ATA_SFF=y)",        None,      None],
            ["func_ptr", "sff_irq_clear (CONFIG_ATA_SFF=y)",        None,      None],
            ["func_ptr", "sff_drain_fifo (CONFIG_ATA_SFF=y)",       None,      None],
            ["func_ptr", "bmdma_setup (CONFIG_ATA_BMDMA=y)",        None,      None],
            ["func_ptr", "bmdma_start (CONFIG_ATA_BMDMA=y)",        None,      None],
            ["func_ptr", "bmdma_stop (CONFIG_ATA_BMDMA=y)",         None,      None],
            ["func_ptr", "bmdma_status (CONFIG_ATA_BMDMA=y)",       None,      None],
            ["func_ptr", "em_show",                                 None,      None],
            ["func_ptr", "em_store",                                None,      None],
            ["func_ptr", "sw_activity_show",                        None,      None],
            ["func_ptr", "sw_activity_store",                       None,      None],
            ["func_ptr", "transmit_led_message",                    "3.11.0",  None],
            ["func_ptr", "phy_reset",                               None,      "6.6.0"],
            ["func_ptr", "eng_timeout",                             None,      "6.6.0"],
            ["ptr",      "inherits",                                None,      None],
        ]
        self.members["ata_port_operations"] = adapt_to_kernel_version(ata_port_operations)

        media_entity_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "get_fwnode_pad",                          "4.13.0",  None],
            ["func_ptr", "link_setup",                              None,      None],
            ["func_ptr", "link_validate",                           "3.5.0",   None],
            ["func_ptr", "has_pad_interdep",                        "6.1.0",   None],
        ]
        self.members["media_entity_operations"] = adapt_to_kernel_version(media_entity_operations)

        configfs_item_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "release",                                 None,      None],
            ["func_ptr", "show_attribute",                          None,      "4.4.0"],
            ["func_ptr", "store_attribute",                         None,      "4.4.0"],
            ["func_ptr", "allow_link",                              None,      None],
            ["func_ptr", "drop_link",                               None,      None],
        ]
        self.members["configfs_item_operations"] = adapt_to_kernel_version(configfs_item_operations)

        configfs_group_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "make_item",                               None,      None],
            ["func_ptr", "make_group",                              None,      None],
            ["func_ptr", "commit_item",                             None,      "6.1.113"],
            ["func_ptr", "disconnect_notify",                       None,      None],
            ["func_ptr", "drop_item",                               None,      None],
            ["func_ptr", "is_visible",                              "6.11.0",  None],
            ["func_ptr", "is_bin_visible",                          "6.11.0",  None],
        ]
        self.members["configfs_group_operations"] = adapt_to_kernel_version(configfs_group_operations)

        fs_context_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "free",                                    "5.1.0",   None],
            ["func_ptr", "dup",                                     "5.1.0",   None],
            ["func_ptr", "parse_param",                             "5.1.0",   None],
            ["func_ptr", "parse_monolithic",                        "5.1.0",   None],
            ["func_ptr", "get_tree",                                "5.1.0",   None],
            ["func_ptr", "reconfigure",                             "5.1.0",   None],
        ]
        self.members["fs_context_operations"] = adapt_to_kernel_version(fs_context_operations)

        export_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "encode_fh",                               None,      None],
            ["func_ptr", "fh_to_dentry",                            None,      None],
            ["func_ptr", "fh_to_parent",                            None,      None],
            ["func_ptr", "get_name",                                None,      None],
            ["func_ptr", "get_parent",                              None,      None],
            ["func_ptr", "commit_metadata",                         None,      None],
            ["func_ptr", "get_uuid",                                "4.0.0",   None],
            ["func_ptr", "map_blocks",                              "4.0.0",   None],
            ["func_ptr", "commit_blocks",                           "4.0.0",   None],
            ["func_ptr", "fetch_iversion",                          "5.10.0",  "6.3.0"],
            ["func_ptr", "permission",                              "6.14.0",  None],
            ["func_ptr", "open",                                    "6.14.0",  None],
            ["long",     "flags",                                   "5.10.0",  None],
        ]
        self.members["export_operations"] = adapt_to_kernel_version(export_operations)

        dev_pm_ops = [
            # type       name                                       minver     maxver
            ["func_ptr", "prepare",                                 None,      None],
            ["func_ptr", "complete",                                None,      None],
            ["func_ptr", "suspend",                                 None,      None],
            ["func_ptr", "resume",                                  None,      None],
            ["func_ptr", "freeze",                                  None,      None],
            ["func_ptr", "thaw",                                    None,      None],
            ["func_ptr", "poweroff",                                None,      None],
            ["func_ptr", "restore",                                 None,      None],
            ["func_ptr", "suspend_late",                            "3.4.0",   None],
            ["func_ptr", "resume_early",                            "3.4.0",   None],
            ["func_ptr", "freeze_late",                             "3.4.0",   None],
            ["func_ptr", "thaw_early",                              "3.4.0",   None],
            ["func_ptr", "poweroff_late",                           "3.4.0",   None],
            ["func_ptr", "restore_early",                           "3.4.0",   None],
            ["func_ptr", "suspend_noirq",                           None,      None],
            ["func_ptr", "resume_noirq",                            None,      None],
            ["func_ptr", "freeze_noirq",                            None,      None],
            ["func_ptr", "thaw_noirq",                              None,      None],
            ["func_ptr", "poweroff_noirq",                          None,      None],
            ["func_ptr", "restore_noirq",                           None,      None],
            ["func_ptr", "runtime_suspend",                         None,      None],
            ["func_ptr", "runtime_resume",                          None,      None],
            ["func_ptr", "runtime_idle",                            None,      None],
        ]
        self.members["dev_pm_ops"] = adapt_to_kernel_version(dev_pm_ops)

        clk_ops = [
            # type       name                                       minver     maxver
            ["func_ptr", "prepare",                                 "3.4.0",   None],
            ["func_ptr", "unprepare",                               "3.4.0",   None],
            ["func_ptr", "is_prepared",                             "3.10.0",  None],
            ["func_ptr", "unprepare_unused",                        "3.10.0",  None],
            ["func_ptr", "init (CONFIG_SH_CLK_CPG_LEGACY=y)",       None,      "3.4.0"],
            ["func_ptr", "enable",                                  None,      None],
            ["func_ptr", "disable",                                 None,      None],
            ["func_ptr", "is_enabled",                              "3.4.0",   None],
            ["func_ptr", "disable_unused",                          "3.8.0",   None],
            ["func_ptr", "save_context",                            "4.20.0",  None],
            ["func_ptr", "restore_context",                         "4.20.0",  None],
            ["func_ptr", "recalc_rate",                             "3.4.0",   None],
            ["func_ptr", "recalc",                                  None,      "3.4.0"],
            ["func_ptr", "round_rate",                              "3.4.0",   "7.0.10"],
            ["func_ptr", "determine_rate",                          "3.12.0",  None],
            ["func_ptr", "set_parent",                              "3.4.0",   None],
            ["func_ptr", "get_parent",                              "3.4.0",   None],
            ["func_ptr", "set_rate",                                None,      None],
            ["func_ptr", "set_rate_and_parent",                     "3.14.0",  None],
            ["func_ptr", "set_parent",                              None,      "3.4.0"],
            ["func_ptr", "round_rate",                              None,      "3.4.0"],
            ["func_ptr", "recalc_accuracy",                         "3.14.0",  None],
            ["func_ptr", "get_phase",                               "3.18.0",  None],
            ["func_ptr", "set_phase",                               "3.18.0",  None],
            ["func_ptr", "get_duty_cycle",                          "4.19.0",  None],
            ["func_ptr", "set_duty_cycle",                          "4.19.0",  None],
            ["func_ptr", "init",                                    "3.4.0",   None],
            ["func_ptr", "terminate",                               "5.6.0",   None],
            ["func_ptr", "debug_init",                              "3.15.0",  None],
        ]
        self.members["clk_ops"] = adapt_to_kernel_version(clk_ops)

        parport_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "write_data",                              None,      None],
            ["func_ptr", "read_data",                               None,      None],
            ["func_ptr", "write_control",                           None,      None],
            ["func_ptr", "read_control",                            None,      None],
            ["func_ptr", "frob_control",                            None,      None],
            ["func_ptr", "read_status",                             None,      None],
            ["func_ptr", "enable_irq",                              None,      None],
            ["func_ptr", "disable_irq",                             None,      None],
            ["func_ptr", "data_forward",                            None,      None],
            ["func_ptr", "data_reverse",                            None,      None],
            ["func_ptr", "init_state",                              None,      None],
            ["func_ptr", "save_state",                              None,      None],
            ["func_ptr", "restore_state",                           None,      None],
            ["func_ptr", "epp_write_data",                          None,      None],
            ["func_ptr", "epp_read_data",                           None,      None],
            ["func_ptr", "epp_write_addr",                          None,      None],
            ["func_ptr", "epp_read_addr",                           None,      None],
            ["func_ptr", "ecp_write_data",                          None,      None],
            ["func_ptr", "ecp_read_data",                           None,      None],
            ["func_ptr", "ecp_write_addr",                          None,      None],
            ["func_ptr", "compat_write_data",                       None,      None],
            ["func_ptr", "nibble_read_data",                        None,      None],
            ["func_ptr", "byte_read_data",                          None,      None],
            ["ptr",      "owner",                                   None,      None],
        ]
        self.members["parport_operations"] = adapt_to_kernel_version(parport_operations)

        proc_ns_operations = [
            # type       name                                       minver     maxver
            ["char*",    "name",                                    None,      None],
            ["char*",    "real_ns_name",                            "4.12.0",  None],
            ["int",      "type",                                    None,      "6.17.8"],
            ["func_ptr", "get",                                     None,      None],
            ["func_ptr", "put",                                     None,      None],
            ["func_ptr", "install",                                 None,      None],
            ["func_ptr", "owner",                                   "4.9.0",   None],
            ["func_ptr", "get_parent",                              "4.9.0",   None],
            ["func_ptr", "inum",                                    "3.8.0",   "3.19.0"],
        ]
        self.members["proc_ns_operations"] = adapt_to_kernel_version(proc_ns_operations)

        net_device_ops = [
            # type       name                                                   minver     maxver
            ["func_ptr", "ndo_init",                                            None,      None],
            ["func_ptr", "ndo_uninit",                                          None,      None],
            ["func_ptr", "ndo_open",                                            None,      None],
            ["func_ptr", "ndo_stop",                                            None,      None],
            ["func_ptr", "ndo_start_xmit",                                      None,      None],
            ["func_ptr", "ndo_features_check",                                  "4.5.0",   None],
            ["func_ptr", "ndo_select_queue",                                    None,      None],
            ["func_ptr", "ndo_change_rx_flags",                                 None,      None],
            ["func_ptr", "ndo_set_rx_mode",                                     None,      None],
            ["func_ptr", "ndo_set_rx_mode_async",                               "7.1.0",   None],
            ["func_ptr", "ndo_set_multicast_list",                              None,      "3.2.0"],
            ["func_ptr", "ndo_set_mac_address",                                 None,      None],
            ["func_ptr", "ndo_validate_addr",                                   None,      None],
            ["func_ptr", "ndo_do_ioctl",                                        None,      None],
            ["func_ptr", "ndo_eth_ioctl",                                       "5.15.0",  None],
            ["func_ptr", "ndo_siocbond",                                        "5.15.0",  None],
            ["func_ptr", "ndo_siocwandev",                                      "5.15.0",  None],
            ["func_ptr", "ndo_siocdevprivate",                                  "5.15.0",  None],
            ["func_ptr", "ndo_set_config",                                      None,      None],
            ["func_ptr", "ndo_change_mtu",                                      None,      None],
            ["func_ptr", "ndo_neigh_setup",                                     None,      None],
            ["func_ptr", "ndo_tx_timeout",                                      None,      None],
            ["func_ptr", "ndo_get_stats64",                                     None,      None],
            ["func_ptr", "ndo_has_offload_stats",                               "4.9.0",   None],
            ["func_ptr", "ndo_get_offload_stats",                               "4.9.0",   None],
            ["func_ptr", "ndo_get_stats",                                       None,      None],
            ["func_ptr", "ndo_vlan_rx_register",                                None,      "3.1.0"],
            ["func_ptr", "ndo_vlan_rx_add_vid",                                 None,      None],
            ["func_ptr", "ndo_vlan_rx_kill_vid",                                None,      None],
            ["func_ptr", "ndo_poll_controller (CONFIG_NET_POLL_CONTROLLER=y)",  None,      None],
            ["func_ptr", "ndo_netpoll_setup (CONFIG_NET_POLL_CONTROLLER=y)",    None,      None],
            ["func_ptr", "ndo_netpoll_cleanup (CONFIG_NET_POLL_CONTROLLER=y)",  None,      None],
            ["func_ptr", "ndo_busy_poll (CONFIG_NET_RX_BUSY_POLL=y)",           "3.11.0",  "4.11.0"],
            ["func_ptr", "ndo_set_vf_mac",                                      None,      None],
            ["func_ptr", "ndo_set_vf_vlan",                                     None,      None],
            ["func_ptr", "ndo_set_vf_rate",                                     "3.16.0",  None],
            ["func_ptr", "ndo_set_vf_tx_rate",                                  None,      "3.16.0"],
            ["func_ptr", "ndo_set_vf_spoofchk",                                 "3.2.0",   None],
            ["func_ptr", "ndo_set_vf_trust",                                    "4.4.0",   None],
            ["func_ptr", "ndo_get_vf_config",                                   None,      None],
            ["func_ptr", "ndo_set_vf_link_state",                               "3.11.0",  None],
            ["func_ptr", "ndo_get_vf_stats",                                    "4.2.0",   None],
            ["func_ptr", "ndo_set_vf_port",                                     None,      None],
            ["func_ptr", "ndo_get_vf_port",                                     None,      None],
            ["func_ptr", "ndo_set_vf_rss_query_en",                             "3.18.21", "3.19.0"],
            ["func_ptr", "ndo_get_vf_guid",                                     "5.5.0",   None],
            ["func_ptr", "ndo_set_vf_guid",                                     "4.6.0",   None],
            ["func_ptr", "ndo_set_vf_rss_query_en",                             "4.1.0",   None],
            ["func_ptr", "ndo_setup_tc",                                        None,      None],
            ["func_ptr", "ndo_fcoe_enable (CONFIG_FCOE=y)",                     None,      None],
            ["func_ptr", "ndo_fcoe_disable (CONFIG_FCOE=y)",                    None,      None],
            ["func_ptr", "ndo_fcoe_ddp_setup (CONFIG_FCOE=y)",                  None,      None],
            ["func_ptr", "ndo_fcoe_ddp_done (CONFIG_FCOE=y)",                   None,      None],
            ["func_ptr", "ndo_fcoe_ddp_target CONFIG_FCOE=y)",                  None,      None],
            ["func_ptr", "ndo_fcoe_get_hbainfo (CONFIG_FCOE=y)",                "3.3.0",   None],
            ["func_ptr", "ndo_fcoe_get_wwn (CONFIG_LIBFCOE=y)",                 "3.2.0",   None],
            ["func_ptr", "ndo_fcoe_get_wwn (CONFIG_FCOE=y)",                    None,      "3.2.0"],
            ["func_ptr", "ndo_rx_flow_steer (CONFIG_RFS_ACCEL=y)",              None,      None],
            ["func_ptr", "ndo_add_slave",                                       None,      None],
            ["func_ptr", "ndo_del_slave",                                       None,      None],
            ["func_ptr", "ndo_get_xmit_slave",                                  "5.8.0",   None],
            ["func_ptr", "ndo_sk_get_lower_dev",                                "5.12.0",  None],
            ["func_ptr", "ndo_fix_features",                                    None,      None],
            ["func_ptr", "ndo_set_features",                                    None,      None],
            ["func_ptr", "ndo_neigh_construct",                                 "3.3.0",   None],
            ["func_ptr", "ndo_neigh_destroy",                                   "3.3.0",   None],
            ["func_ptr", "ndo_fdb_add",                                         "3.5.0",   None],
            ["func_ptr", "ndo_fdb_del",                                         "3.5.0",   None],
            ["func_ptr", "ndo_fdb_del_bulk",                                    "5.19.0",  None],
            ["func_ptr", "ndo_fdb_dump",                                        "3.5.0",   None],
            ["func_ptr", "ndo_fdb_get",                                         "5.0.0",   None],
            ["func_ptr", "ndo_mdb_add",                                         "6.4.0",   None],
            ["func_ptr", "ndo_mdb_del",                                         "6.4.0",   None],
            ["func_ptr", "ndo_mdb_del_bulk",                                    "6.8.0",   None],
            ["func_ptr", "ndo_mdb_dump",                                        "6.4.0",   None],
            ["func_ptr", "ndo_mdb_get",                                         "6.7.0",   None],
            ["func_ptr", "ndo_bridge_setlink",                                  "3.8.0",   None],
            ["func_ptr", "ndo_bridge_getlink",                                  "3.8.0",   None],
            ["func_ptr", "ndo_bridge_dellink",                                  "3.9.0",   None],
            ["func_ptr", "ndo_change_carrier",                                  "3.9.0",   None],
            ["func_ptr", "ndo_get_phys_port_id",                                "3.12.0",  None],
            ["func_ptr", "ndo_get_port_parent_id",                              "5.1.0",   None],
            ["func_ptr", "ndo_get_phys_port_name",                              "4.1.0",   None],
            ["func_ptr", "ndo_udp_tunnel_add",                                  "4.8.0",   "5.12.0"],
            ["func_ptr", "ndo_udp_tunnel_del",                                  "4.8.0",   "5.12.0"],
            ["func_ptr", "ndo_add_vxlan_port",                                  "3.12.0",  "4.8.0"],
            ["func_ptr", "ndo_del_vxlan_port",                                  "3.12.0",  "4.8.0"],
            ["func_ptr", "ndo_add_geneve_port",                                 "4.5.0",   "4.8.0"],
            ["func_ptr", "ndo_del_geneve_port",                                 "4.5.0",   "4.8.0"],
            ["func_ptr", "ndo_dfwd_add_station",                                "3.13.0",  None],
            ["func_ptr", "ndo_dfwd_del_station",                                "3.13.0",  None],
            ["func_ptr", "ndo_dfwd_start_xmit",                                 "3.13.0",  "4.13.0"],
            ["func_ptr", "ndo_get_lock_subclass",                               "3.14.5",  "5.4.0"],
            ["func_ptr", "ndo_features_check",                                  "3.18.4",  "4.5.0"],
            ["func_ptr", "ndo_gso_check",                                       "3.18.0",  "3.18.4"],
            ["func_ptr", "ndo_set_tx_maxrate",                                  "4.1.0",   None],
            ["func_ptr", "ndo_get_iflink",                                      "4.1.0",   None],
            ["func_ptr", "ndo_switch_parent_id_get (CONFIG_NET_SWITCHDEV=y)",   "3.19.0",  "4.1.0"],
            ["func_ptr", "ndo_switch_port_stp_update (CONFIG_NET_SWITCHDEV=y)", "3.19.0",  "4.1.0"],
            ["func_ptr", "ndo_change_proto_down",                               "4.3.0",   "5.17.0"],
            ["func_ptr", "ndo_fill_metadata_dst",                               "4.3.0",   None],
            ["func_ptr", "ndo_set_rx_headroom",                                 "4.6.0",   None],
            ["func_ptr", "ndo_bpf",                                             "4.15.0",  None],
            ["func_ptr", "ndo_xdp",                                             "4.8.0",   "4.15.0"],
            ["func_ptr", "ndo_xdp_xmit",                                        "4.14.0",  None],
            ["func_ptr", "ndo_xdp_get_xmit_slave",                              "5.15.0",  None],
            ["func_ptr", "ndo_xsk_wakeup",                                      "5.4.0",   None],
            ["func_ptr", "ndo_xsk_async_xmit",                                  "4.18.0",  "5.4.0"],
            ["func_ptr", "ndo_xdp_flush",                                       "4.14.0",  "4.18.0"],
            ["func_ptr", "ndo_get_devlink_port",                                "5.2.0",   "6.1.115"],
            ["func_ptr", "ndo_get_devlink",                                     "5.1.0",   "5.2.0"],
            ["func_ptr", "ndo_tunnel_ctl",                                      "5.8.0",   None],
            ["func_ptr", "ndo_get_peer_dev",                                    "5.10.0",  None],
            ["func_ptr", "ndo_fill_forward_path",                               "5.13.0",  None],
            ["func_ptr", "ndo_get_tstamp",                                      "5.19.0",  None],
            ["func_ptr", "ndo_hwtstamp_get",                                    "6.6.0",   None],
            ["func_ptr", "ndo_hwtstamp_set",                                    "6.6.0",   None],
            ["ptr",      "net_shaper_ops (CONFIG_NET_SHAPER=y)",                "6.12.0",  None],
        ]
        self.members["net_device_ops"] = adapt_to_kernel_version(net_device_ops)

        page_ext_operations = [
            # type       name                                       minver     maxver
            ["long",     "offset",                                  "4.9.0",   None],
            ["long",     "size",                                    "4.9.0",   None],
            ["func_ptr", "need",                                    "3.19.0",  None],
            ["func_ptr", "init",                                    "3.19.0",  None],
            ["bool",     "need_shared_flags",                       "6.3.0",   None],
        ]
        self.members["page_ext_operations"] = adapt_to_kernel_version(page_ext_operations)

        ucsi_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "read_version",                            "6.11.0",  None],
            ["func_ptr", "read_cci",                                "6.11.0",  None],
            ["func_ptr", "poll_cci",                                "6.14.0",  None],
            ["func_ptr", "read_message_in",                         "6.11.0",  None],
            ["func_ptr", "sync_control",                            "6.11.0",  None],
            ["func_ptr", "async_control",                           "6.11.0",  None],
            ["func_ptr", "read",                                    "5.4.0",   "6.11.0"],
            ["func_ptr", "sync_write",                              "5.4.0",   "6.11.0"],
            ["func_ptr", "async_write",                             "5.4.0",   "6.11.0"],
            ["func_ptr", "update_altmodes",                         "5.6.0",   None],
            ["func_ptr", "update_connector",                        "6.10.0",  None],
            ["func_ptr", "connector_status",                        "6.10.0",  None],
            ["func_ptr", "add_partner_altmodes",                    "7.0.0",   None],
            ["func_ptr", "remove_partner_altmodes",                 "7.0.0",   None],
        ]
        self.members["ucsi_operations"] = adapt_to_kernel_version(ucsi_operations)

        movable_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "isolate_page",                            "6.0.0",   None],
            ["func_ptr", "migrate_page",                            "6.0.0",   None],
            ["func_ptr", "pushback_page",                           "6.0.0",   None],
        ]
        self.members["movable_operations"] = adapt_to_kernel_version(movable_operations)

        damon_operations = [
            # type       name                                       minver     maxver
            ["int",      "id",                                      "5.18.0",  None],
            ["func_ptr", "init",                                    "5.18.0",  None],
            ["func_ptr", "update",                                  "5.18.0",  None],
            ["func_ptr", "prepare_access_checks",                   "5.18.0",  None],
            ["func_ptr", "check_accesses",                          "5.18.0",  None],
            ["func_ptr", "reset_aggregated",                        "5.18.0",  "6.15.0"],
            ["func_ptr", "get_scheme_score",                        "5.18.0",  None],
            ["func_ptr", "apply_scheme",                            "5.18.0",  None],
            ["func_ptr", "target_valid",                            "5.18.0",  None],
            ["func_ptr", "cleanup_target",                          "6.17.0",  None],
            ["func_ptr", "cleanup",                                 "5.18.0",  "7.0.0"],
        ]
        self.members["damon_operations"] = adapt_to_kernel_version(damon_operations)

        proc_ops = [
            # type       name                                       minver     maxver
            ["int",      "proc_flags",                              "5.7.0",   None],
            ["func_ptr", "proc_open",                               "5.6.0",   None],
            ["func_ptr", "proc_read",                               "5.6.0",   None],
            ["func_ptr", "proc_read_iter",                          "5.10.0",  None],
            ["func_ptr", "proc_write",                              "5.6.0",   None],
            ["func_ptr", "proc_lseek",                              "5.6.0",   None],
            ["func_ptr", "proc_release",                            "5.6.0",   None],
            ["func_ptr", "proc_poll",                               "5.6.0",   None],
            ["func_ptr", "proc_ioctl",                              "5.6.0",   None],
            ["func_ptr", "proc_compat_ioctl (CONFIG_COMPAT=y)",     "5.6.0",   None],
            ["func_ptr", "proc_mmap",                               "5.6.0",   None],
            ["func_ptr", "proc_get_unmapped_area",                  "5.6.0",   None],
        ]
        self.members["proc_ops"] = adapt_to_kernel_version(proc_ops)

        regulator_ops = [
            # type       name                                       minver     maxver
            ["func_ptr", "list_voltage",                            None,      None],
            ["func_ptr", "set_voltage",                             None,      None],
            ["func_ptr", "map_voltage",                             None,      None],
            ["func_ptr", "set_voltage_sel",                         None,      None],
            ["func_ptr", "get_voltage",                             None,      None],
            ["func_ptr", "get_voltage_sel",                         None,      None],
            ["func_ptr", "set_current_limit",                       None,      None],
            ["func_ptr", "get_current_limit",                       None,      None],
            ["func_ptr", "set_input_current_limit",                 "4.2.0",   None],
            ["func_ptr", "set_over_current_protection",             "4.3.0",   None],
            ["func_ptr", "set_over_voltage_protection",             "5.14.0",  None],
            ["func_ptr", "set_under_voltage_protection",            "5.14.0",  None],
            ["func_ptr", "set_thermal_protection",                  "5.14.0",  None],
            ["func_ptr", "set_active_discharge",                    "4.6.0",   None],
            ["func_ptr", "enable",                                  None,      None],
            ["func_ptr", "disable",                                 None,      None],
            ["func_ptr", "is_enabled",                              None,      None],
            ["func_ptr", "set_mode",                                None,      None],
            ["func_ptr", "get_mode",                                None,      None],
            ["func_ptr", "get_error_flags",                         "4.10.0",  None],
            ["func_ptr", "enable_time",                             None,      None],
            ["func_ptr", "set_ramp_delay",                          "3.6.0",   None],
            ["func_ptr", "set_voltage_time",                        "4.9.0",   None],
            ["func_ptr", "set_voltage_time_sel",                    None,      None],
            ["func_ptr", "set_soft_start",                          "4.2.0",   None],
            ["func_ptr", "get_status",                              None,      None],
            ["func_ptr", "get_optimum_mode",                        None,      None],
            ["func_ptr", "set_load",                                "4.1.0",   None],
            ["func_ptr", "set_bypass",                              "3.7.0",   None],
            ["func_ptr", "get_bypass",                              "3.7.0",   None],
            ["func_ptr", "set_suspend_voltage",                     None,      None],
            ["func_ptr", "set_suspend_enable",                      None,      None],
            ["func_ptr", "set_suspend_disable",                     None,      None],
            ["func_ptr", "set_suspend_mode",                        None,      None],
            ["func_ptr", "resume",                                  "4.19.0",  None],
            ["func_ptr", "resume_early",                            "4.16.0",  "4.19.0"],
            ["func_ptr", "set_pull_down",                           "4.2.0",   None],
        ]
        self.members["regulator_ops"] = adapt_to_kernel_version(regulator_ops)

        tty_port_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "carrier_raised",                          "5.15.0",  None],
            ["func_ptr", "dtr_rts",                                 "5.15.0",  None],
            ["func_ptr", "shutdown",                                "5.15.0",  None],
            ["func_ptr", "activate",                                "5.15.0",  None],
            ["func_ptr", "destruct",                                "5.15.0",  None],
        ]
        self.members["tty_port_operations"] = adapt_to_kernel_version(tty_port_operations)

        kobj_ns_type_operations = [
            # type       name                                       minver     maxver
            ["int",      "type",                                    None,      None],
            ["func_ptr", "current_may_mount",                       "3.12.0",  None],
            ["func_ptr", "grab_current_ns",                         None,      None],
            ["func_ptr", "netlink_ns",                              None,      None],
            ["func_ptr", "initial_ns",                              None,      None],
            ["func_ptr", "drop_ns",                                 None,      None],
        ]
        self.members["kobj_ns_type_operations"] = adapt_to_kernel_version(kobj_ns_type_operations)

        btf_kind_operations = [
            # type       name                                       minver     maxver
            ["func_ptr", "check_meta",                              "4.18.0",  None],
            ["func_ptr", "resolve",                                 "4.18.0",  None],
            ["func_ptr", "check_member",                            "4.18.0",  None],
            ["func_ptr", "check_kflag_member",                      "5.0.0",   None],
            ["func_ptr", "log_details",                             "4.18.0",  None],
            ["func_ptr", "show",                                    "5.10.0",  None],
            ["func_ptr", "seq_show",                                "4.18.0",  "5.10.0"],
        ]
        self.members["btf_kind_operations"] = adapt_to_kernel_version(btf_kind_operations)

        assert set(self.members.keys()) == set(self.types)
        return True

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        # parse version
        if args.version:
            r = re.search(r"(\d)\.(\d+)(?:\.(\d+))?", args.version)
            if r:
                major, minor, patch = int(r.group(1)), int(r.group(2)), int(r.group(3) or 0)
            else:
                err("Failed to parse version string")
                return
            kversion = KernelVersion(None, args.version, major, minor, patch)
        else:
            self.quiet_info("Wait for memory scan")
            kversion = Kernel.kernel_version()
            if kversion is None:
                err("Could not find Linux kernel")
                return
        self.quiet_info("Kernel version: {:d}.{:d}.{:d}".format(kversion.major, kversion.minor, kversion.patch))

        # initialize
        if self.initialize(kversion) is False:
            return

        # get member
        members = self.members[args.name]
        if not members:
            warn("Not defined in this version")
            return

        # print
        self.out = []
        if args.address:
            # show permission
            if not args.quiet:
                kinfo = Kernel.get_kernel_layout()
                for vaddr, size, perm in kinfo.maps:
                    if vaddr <= args.address and args.address < vaddr + size:
                        perm_str = perm
                        break
                else:
                    perm_str = "???"
                self.out.append("Address: {:#x} Permission: {:s}".format(args.address, perm_str))

            # get name width
            name_width = max(len(m[1]) for m in members)
            try:
                addrs = [read_int_from_memory(args.address + runtime.current_arch.ptrsize * i) for i in range(len(members))]
            except gdb.MemoryError:
                self.quiet_err("Memory read error")
                return

            # legend
            if not args.quiet:
                fmt = "{:5s} {:<10s} {:<{:d}s} {:s}"
                legend = ["Index", "Type", "Name", name_width, "Value"]
                self.out.append(GefUtil.make_legend(fmt.format(*legend)))

            # each entries
            width = AddressUtil.get_format_address_width()
            for idx, ((type_name, name), address) in enumerate(zip(members, addrs)):
                if type_name == "char*":
                    sym = " {!r}".format(read_cstring_from_memory(address))
                else:
                    sym = Symbol.get_symbol_string(address)
                self.out.append("{:<5d} {:10s} {:{:d}s} {:#0{:d}x}{:s}".format(
                    idx, type_name, name, name_width, address, width, sym,
                ))
        else:
            # legend
            if not args.quiet:
                fmt = "{:5s} {:<10s} {:s}"
                legend = ["Index", "Type", "Name"]
                self.out.append(GefUtil.make_legend(fmt.format(*legend)))

            # each entries
            for idx, (type_name, name) in enumerate(members):
                self.out.append("{:<5d} {:10s} {:s}".format(idx, type_name, name))

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelSysctlCommand(GenericCommand, BufferingOutput):
    """Dump the sysctl parameters."""

    _cmdline_ = "ksysctl"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="REGEXP filter.")
    parser.add_argument("-s", "--skip-symlink", action="store_true", help="do not follow symlink (net.* and user.*).")
    parser.add_argument("-e", "--exact", action="store_true", help="use exact match.")
    parser.add_argument("-d", "--decimal", action="store_true", help="display integer values in decimal.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-v", "--verbose", action="store_true", help="dump zero-sized entries and proc_handler too.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} --filter modprobe             # filter by parameter name",
        "{0:s} --filter kernel.modprobe -e   # exact match",
        "{0:s} -s                            # skip symlink (improves performance with many .net.* and user.* entries)",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "ParamValue is decoded as proc_handler (or the known handler it calls) reads it:",
        "strings, integer vectors in hex (decimal with -d), bit ranges of a bitmap, or `raw:` bytes if unknown.",
        "The unit is the one of the stored value (e.g., `jiffies`), not of /proc/sys. MaxLen of a bitmap is in bits.",
        "",
        "Simplified sysctl_table structure:",
        "",
        "   +-sysctl_table_root-+          +----->+-ctl_dir------+",
        "   | default_set       |          |      | header       |",
        "   |   ...             |          |      |   ctl_table  |---+",
        "   |   dir             |          |      |   ...        |   |",
        "   |     header        |          |      |   parent     |---|-->parent ctl_node",
        "   |       ctl_table   |          |      |   ...        |   |",
        "   |       ...         |          |      | root         |   |",
        "   |       parent      |          |      |   rb_node    |---|-->ctl_node",
        "   |       ...         |          |      +--------------+   |",
        "   |     root          |          |                         |",
        "   |       rb_node     |----+     |   +---------------------+",
        "   |   ...             |    |     |   |",
        "   +-------------------+    |     |   +->+-ctl_table(array)-+",
        "                            |     |      | procname         |-->name[]",
        "+---------------------------+     |      | data             |-->data[max_len]",
        "|                                 |      | maxlen           |",
        "+->+-ctl_node-----+               |      | mode             |",
        "   | rb_node      |               |      | proc_handler     |",
        "   |   color      |               |      +------------------+",
        "   |   right      |--->ctl_node   |      | procname         |-->name[]",
        "   |   left       |--->ctl_node   |      | data             |-->data[max_len]",
        "   | header       |---------------+      | maxlen           |",
        "   +--------------+                      | mode             |",
        "                                         | proc_handler     |",
        "                                         +------------------+",
        "                                         | ...              |",
        "                                         +------------------+",
    ]
    _note_ = "\n".join(_note_)

    def should_be_print(self, procname):
        if self.args.filter == []:
            return True

        if self.args.exact:
            for filt in self.args.filter:
                if filt.pattern == procname:
                    self.exact_found = True
                    return True
            return False

        else:
            for re_pattern in self.args.filter:
                if re_pattern.search(procname):
                    return True
            return False

    def get_data_value(self, data):
        if not data.address:
            return "-", "-"
        if not is_valid_addr(data.address):
            if not self.args.verbose:
                return None
            return "{:#018x}".format(data.address), "-"

        address = "{:#018x}".format(data.address)
        if data.maxlen == 0:
            if not self.args.verbose:
                return None
            return address, "-"
        try:
            value = self.decode_value(data, self.ksysctl.get_handler_type(data.handler))
        except gdb.MemoryError:
            value = "???"
        return address, value

    def decode_value(self, data, handler_type):
        from gef.commands.kernel.basic import KernelPerCpuCommand
        # some handlers take the net namespace as data (e.g., proc_fib_multipath_hash_seed)
        if data.address == self.ksysctl.init_net:
            return "-"
        maxlen = min(data.maxlen, 0x1000)
        if handler_type == "static_key":
            # the value is `enabled`, the first member of struct static_key
            handler_type, maxlen = (4, True, ""), 4
        if handler_type == "string":
            value = read_cstring_from_memory(data.address, max_length=maxlen)
            if value is not None:
                return "{!r}".format(value)
        elif handler_type == "wrapped-string":
            # data of a wrapper is a string only if it is printable text padded with NUL
            text = read_memory(data.address, maxlen).rstrip(b"\0")
            if 0 < len(text) < maxlen and all(chr(x) in String.STRING_PRINTABLE for x in text):
                return "{!r}".format(String.bytes2str(text))
        elif handler_type == "bitmap":
            # maxlen is the number of bits, and the data points to the bitmap since v3.16
            bitmap = data.address
            if "3.16" <= Kernel.version():
                bitmap = read_int_from_memory(bitmap)
            if not bitmap:
                return "-"
            nbits = data.maxlen
            word_bits = runtime.current_arch.ptrsize * 8
            raw = read_memory(bitmap, (nbits + word_bits - 1) // word_bits * runtime.current_arch.ptrsize)
            words = slice_unpack(raw, runtime.current_arch.ptrsize)
            bits = {i * word_bits + j for i, w in enumerate(words) if w for j in range(word_bits) if w >> j & 1}
            return KernelPerCpuCommand.format_cpus({x for x in bits if x < nbits})
        elif handler_type is not None:
            size, signed, unit = handler_type
            if size is None:
                size = maxlen
            elif size == 0:
                size = runtime.current_arch.ptrsize
            if size in [1, 2, 4, 8]:
                count = maxlen // size
            else:
                count = 0
            if count:
                max_count = 0x10
                raw = read_memory(data.address, min(count, max_count) * size)
                if self.args.decimal:
                    values = [str(u2i(x, size * 8) if signed else x) for x in slice_unpack(raw, size)]
                else:
                    values = ["{:#x}".format(x) for x in slice_unpack(raw, size)]
                if count > max_count:
                    values.append("...")
                if unit:
                    values.append(unit)
                return " ".join(values)
        raw = read_memory(data.address, min(maxlen, 0x10))
        return "raw:{:s}{:s}".format(raw.hex(), "..." if maxlen > 0x10 else "")

    def dump_data(self, entry):
        if not self.should_be_print(entry.path):
            return

        data = self.ksysctl.parse_entry(entry, include_namespace=self.args.verbose)
        value = self.get_data_value(data)
        if value is None:
            return
        data_addr_str, data_val = value

        handler_info = ""
        header_info = ""
        if self.args.verbose:
            handler_info = " " + Symbol.format(
                data.handler, ksym="prefer", missing="NO_SYMBOL", show_address=True, nocolor=True,
            )
            header_info = "{:#018x} {:#018x} {:<23s} ".format(entry.header, data.ctset, data.namespace)
            data_val = "{:<18s}".format(data_val)

        self.out.append("{:<56s} {:<18s} {:#07x} {:#010o} {:s}{:s}{:s}".format(
            entry.path, data_addr_str, data.maxlen, entry.mode, header_info, data_val, handler_info,
        ))
        return

    def append_legend(self):
        if self.args.quiet:
            return
        fmt = "{:<56s} {:<18s} {:<7s} {:<10s} {:<s}"
        legend = ["ParamName", "ParamAddress", "MaxLen", "Mode", "ParamValue"]
        if self.args.verbose:
            fmt = "{:<56s} {:<18s} {:<7s} {:<10s} {:<18s} {:<18s} {:<23s} {:<18s} {:<s}"
            legend = [
                "ParamName", "ParamAddress", "MaxLen", "Mode", "CtlTableHeader", "CtlTableSet",
                "Namespace", "ParamValue", "ProcHandler",
            ]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))
        return

    def dump_sysctls(self):
        if self.args.quiet:
            progress = None
        else:
            progress = ProgressBar(total=None)
        try:
            for entry in self.ksysctl.walk(skip_symlink=self.args.skip_symlink, progress=progress):
                self.dump_data(entry)
                if self.args.exact and self.exact_found:
                    break
        except gdb.MemoryError:
            self.err_add_out("Memory read error; sysctl scan incomplete")
            return None
        finally:
            if progress is not None:
                progress.close()
        return True

    def initialize(self, force=False):
        self.ksysctl = Kernel.sysctl()
        ret = self.ksysctl.initialize(force=force)
        self.meta = Kernel.export_meta(self, self.ksysctl.meta)
        return ret

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.exact_found = False
        if args.exact and not args.filter:
            self.quiet_err("Filter string is needed")
            return

        self.quiet_info("Wait for memory scan")
        ret = self.initialize(force=args.rescan)
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret or args.meta:
            return

        self.out = []
        self.append_legend()
        self.dump_sysctls()
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelFileSystemsCommand(GenericCommand, BufferingOutput):
    """Dump filesystems."""

    _cmdline_ = "kfilesystems"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-s", "--skip-mount-path", action="store_true", help="skip resolving path.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "",
        "Simplified file_systems structure:",
        "",
        "                  +-->+-file_system_type-+  +-->+-file_system_type-+  +-->...",
        "                  |   | name             |  |   | name             |  |",
        "+--------------+  |   | ...              |  |   | ...              |  |",
        "| file_systems |--+   | next             |--+   | next             |--+",
        "+--------------+      | fs_supers        |--+   | fs_supers        |",
        "                      | ...              |  |   | ...              |",
        "                      +------------------+  |   +------------------+",
        "                                            |",
        "   +----------------------------------------+",
        "   |",
        "   |   +-super_block-+   +-super_block-+             +-mount--------+",
        "   |   | s_list      |   | s_list      |             | ...          |",
        "   |   | ...         |   | ...         |             | mnt          |",
        "   |   | s_mounts    |   | s_mounts    |---------+   |   mnt_root   |",
        "   |   | ...         |   | ...         |         |   |   ...        |",
        "   +-->| s_instances |-->| s_instances |-->...   |   | ...          |",
        "       | ...         |   | ...         |         +-->| mnt_instance |",
        "       +-------------+   +-------------+             | ...          |",
        "                                                     +--------------+",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self):
        self.meta = []

        self.kfs = Kernel.file_system()
        ret = self.kfs.initialize()
        self.meta.extend(Kernel.export_meta(self, self.kfs.meta))
        if not ret:
            return None
        return True

    def get_dev_num(self, dev):
        major = dev >> 20
        minor = dev & ((1 << 20) - 1)
        name = KernelBlockDevicesCommand.get_bdev_name(major, minor)
        return major, minor, name

    def get_mount_point(self, mnt_instance):
        kfs = self.kfs
        if not kfs.kpath_ready or not is_valid_addr(mnt_instance):
            return None
        mount = kfs.get_mount(mnt_instance)
        # the s_mounts list head also looks like a mnt_instance, so reject what is not a mount
        if not kfs.kpath.is_mount(mount):
            return None
        vfsmnt = mount + kfs.offset_mount_mnt
        dentry = read_int_from_memory(vfsmnt + kfs.offset_vfsmount_mnt_root)

        path_info = kfs.kpath.prepend_path(dentry, vfsmnt, unknown="???")
        if path_info.status in ("cyclic", "unreadable"):
            return None
        filepath = path_info.path

        # The reason is unclear, but this works.
        if path_info.crossed is False and filepath == "/":
            next_mnt_instance = kfs.get_next_mnt_instance(mnt_instance)
            if next_mnt_instance:
                ret = self.get_mount_point(next_mnt_instance)
                if ret:
                    return ret
            return "-", "-"

        mount = kfs.get_mount(mnt_instance)
        return mount, filepath

    def parse_super_block(self, fst, super_block):
        kfs = self.kfs

        # name
        name = kfs.get_fst_name(fst)

        # dev
        dev = read_int32_from_memory(super_block + kfs.offset_s_dev)
        major, minor, devname = self.get_dev_num(dev)

        # mount
        s_mounts = read_int_from_memory(super_block + kfs.offset_s_mounts)
        mount = kfs.get_mount(s_mounts)

        # mount points
        if self.args.skip_mount_path:
            parsed_mount, mount_point = "-", "???"
        else:
            ret = self.get_mount_point(s_mounts)
            if ret is None:
                parsed_mount, mount_point = "-", "???"
            else:
                parsed_mount, mount_point = ret
                if isinstance(parsed_mount, int):
                    parsed_mount = "{:#018x}".format(parsed_mount)

        # devname
        if devname == "???":
            devname = kfs.get_dev_name(kfs.get_mount(s_mounts)) or "???"
        else:
            devname += " (guessed)"

        # dump
        self.out.append("{:#018x} {:12s} {:#018x} {:20s} {:<6d} {:<6d} {:#018x} {:18s} {:s}".format(
            fst, name, super_block, devname, major, minor, mount, parsed_mount, mount_point,
        ))
        return

    def parse_file_system_type(self, fst):
        # fs_supers
        fs_supers = read_int_from_memory(fst + self.kfs.offset_fs_supers)

        if fs_supers == 0:
            # fast return
            name = self.kfs.get_fst_name(fst)
            self.out.append("{:#018x} {:12s} {:18s} {:20s} {:6s} {:6s} {:18s} {:18s} {:s}".format(
                fst, name, "-", "-", "-", "-", "-", "-", "-",
            ))
            return

        s_instances = fs_supers
        seen = set()

        # parse more
        while s_instances:
            if s_instances in seen:
                self.quiet_warn("Stopped at cyclic s_instances: {:#x}".format(s_instances))
                break
            if len(seen) >= 0x10000:
                self.quiet_warn("Stopped at s_instances traversal limit: {:#x}".format(s_instances))
                break
            if not is_valid_addr(s_instances):
                self.quiet_warn("Stopped at unreadable s_instances: {:#x}".format(s_instances))
                break
            seen.add(s_instances)
            super_block = s_instances - self.kfs.offset_s_instances
            # parse super_block
            self.parse_super_block(fst, super_block)
            # go to next
            next_s_instances = read_int_from_memory(s_instances, safe=True)
            if next_s_instances is None:
                self.quiet_warn("Stopped at unreadable s_instances: {:#x}".format(s_instances))
                break
            s_instances = next_s_instances
        return

    def parse_file_systems(self):
        if not self.args.quiet:
            fmt = "{:18s} {:12s} {:18s} {:20s} {:6s} {:6s} {:18s} {:18s} {:s}"
            legend = [
                "file_system_type", "fsname", "super_block", "devname", "major", "minor",
                "s_mount", "(parsed) mount", "mount_point",
            ]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        fst = read_int_from_memory(self.kfs.file_systems)
        if fst:
            fst -= self.kfs.offset_hlist_node
        seen = set()
        while fst != 0:
            if fst in seen:
                self.quiet_warn("Stopped at cyclic file_system_type: {:#x}".format(fst))
                break
            if not is_valid_addr(fst):
                self.quiet_warn("Stopped at unreadable file_system_type: {:#x}".format(fst))
                break
            seen.add(fst)
            # parse file_system_type
            self.parse_file_system_type(fst)
            # go to next
            fst = read_int_from_memory(fst + self.kfs.offset_link)
            if fst:
                fst -= self.kfs.offset_hlist_node
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "3.3":
            err("Unsupported before v3.3")
            return

        ret = self.initialize()
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            return

        if args.meta:
            return

        self.out = []
        self.parse_file_systems()
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelClockSourceCommand(GenericCommand, BufferingOutput):
    """Dump the clocksource list."""

    _cmdline_ = "kclock-source"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified clocksource structure:",
        "",
        "                        +-clocksource-+",
        "                        | read        |",
        "+-clocksource_list-+    | ...         |",
        "| list_head        |--->| list        |--->...",
        "+------------------+    | ...         |",
        "                        +-------------+",
        "",
        "- The list is sorted by `rating` in descending order. `active` is the one `curr_clocksource` points to.",
        "- `frequency` is derived from `mult` and `shift` (ns = (cycles * mult) >> shift), and `bits` from `mask`.",
        "- `flags`: CONT (IS_CONTINUOUS), VERIFY (MUST_VERIFY), CALIB (CALIBRATED), WD (WATCHDOG),",
        "  HRES (VALID_FOR_HRES), UNSTABLE, NONSTOP (SUSPEND_NONSTOP), RESELECT,",
        "  VERIFY_PERCPU (~v7.0) or INLINE (CAN_INLINE_READ; v7.1~), COUPLED (HAS_COUPLED_CLOCK_EVENT), WDTEST, WDTEST_PERCPU.",
        "- The module is shown for a clocksource registered by a loadable module.",
        "- The member offsets come from the debug information (vmlinux or `ktypes-load`) when available.",
    ]
    _note_ = "\n".join(_note_)

    FLAGS = [
        (0x1, "CONT"),
        (0x2, "VERIFY"),
        (0x4, "CALIB"),
        (0x10, "WD"),
        (0x20, "HRES"),
        (0x40, "UNSTABLE"),
        (0x80, "NONSTOP"),
        (0x100, "RESELECT"),
        (0x200, "VERIFY_PERCPU"),
        (0x400, "COUPLED"),
        (0x800, "WDTEST"),
        (0x1000, "WDTEST_PERCPU"),
    ]

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def resolve_layout(self):
        """Return {member: offset} of `struct clocksource` from the debug information, or None."""
        layout = {}
        for name in ("list", "read", "mask", "mult", "shift", "name", "rating", "flags", "owner"):
            layout[name] = GefUtil.offsetof("clocksource", name)
        if None in [layout[name] for name in ("list", "read", "mask", "mult", "shift", "name")]:
            return None
        return layout

    def find_module(self, address=None, module=None):
        """Return the name of the loaded module whose text contains `address`, or which is `module`."""
        if self.module_text_ranges is None:
            self.module_text_ranges = Kernel.modules().get_text_ranges()
        for start, end, addr, name in self.module_text_ranges:
            if start <= (address or 0) < end or addr == module:
                return name
        return None

    def is_callback(self, address):
        """Return True if `address` is in the kernel text or the text of a loaded module."""
        if not address or not is_valid_addr(address):
            return False
        if self.klayout.text_base is not None and self.klayout.text_end is not None:
            if self.klayout.text_base <= address < self.klayout.text_end:
                return True
        return self.find_module(address) is not None

    def read_name(self, address):
        if is_valid_addr(address):
            name = read_cstring_from_memory(address, safe=True)
        else:
            name = None
        if not name or len(name) > 64 or not name.isprintable():
            return None
        return name

    def is_clocksource(self, cs, offsets, check_callback=True):
        """Check the members of the clocksource at `cs` that every registered one has."""
        try:
            read = read_int_from_memory(cs + offsets["read"])
            mask = read_int64_from_memory(cs + offsets["mask"])
            mult = read_int32_from_memory(cs + offsets["mult"])
            shift = read_int32_from_memory(cs + offsets["shift"])
            name = read_int_from_memory(cs + offsets["name"])
        except gdb.MemoryError:
            return False
        if not mask or mask & (mask + 1) or not mult or shift > 64:
            return False
        if not is_valid_addr(read) or self.read_name(name) is None:
            return False
        # a clocksource can be registered by a module (e.g., scx200_hrt), so its `read` is in the module
        return not check_callback or self.is_callback(read)

    def find_offsets(self):
        """Return {member: offset} found from the nodes of clocksource_list, or None.

        struct clocksource {
            u64 (*read)(struct clocksource *cs);
            u64 cycle_last; // ~v3.16
            u64 mask;
            u32 mult;
            u32 shift;
            u64 max_idle_ns;
            u32 maxadj;
            u32 uncertainty_margin; // v5.14~v7.0
        #ifdef CONFIG_ARCH_CLOCKSOURCE_DATA
            struct arch_clocksource_data archdata;
        #endif
            u64 max_cycles;
            u64 max_raw_delta; // v6.13~
            const char *name;
            struct list_head list;
            u32 freq_khz; // v6.11~
            int rating;
            enum clocksource_ids id; // v5.13~
            enum vdso_clock_mode vdso_clock_mode; // v5.7~
            unsigned long flags;
            ...
            struct module *owner; // v3.13~
        };

        `read` is the head and `name` is right before `list` in every version. A node that
        does not match is tolerated only when the others agree, since it is a corruption."""
        ptrsize = runtime.current_arch.ptrsize
        if is_x86_32():
            base_mask_offsets = (4, 8)
        elif is_arm32():
            # AAPCS aligns u64 to 8 bytes, while the legacy APCS ABI aligns it to 4.
            base_mask_offsets = (8, 4)
        elif is_riscv32():
            base_mask_offsets = (8,)
        else:
            base_mask_offsets = (ptrsize,)
        # Some old kernels have cycle_last between read and mask. Check both
        # layouts instead of applying the extra u64 to every v3.x kernel.
        mask_offsets = tuple(dict.fromkeys(
            offset for base in base_mask_offsets for offset in (base, base + 8)
        ))

        # A layout that every node matches is preferred, so a single healthy node of two can decide it
        # only when the other one is corrupted.
        for tolerance in range(min(len(self.nodes), 2)):
            for i in range(5, 64):
                offset_list = i * ptrsize
                for offset_mask in mask_offsets:
                    offsets = {
                        "list": offset_list,
                        "read": 0,
                        "mask": offset_mask,
                        "mult": offset_mask + 8,
                        "shift": offset_mask + 12,
                        "name": offset_list - ptrsize,
                    }
                    failed = 0
                    for node in self.nodes:
                        if not self.is_clocksource(node - offset_list, offsets):
                            failed += 1
                            if failed > tolerance:
                                break
                    else:
                        return offsets
        return None

    def find_offset_rating(self, clocksources):
        """`rating` follows `list` (and `freq_khz` at v6.11~). The list is sorted by it in descending order."""
        after = self.offsets["list"] + runtime.current_arch.ptrsize * 2
        if self.kversion >= "6.11":
            candidates = [after + 4, after]
        else:
            candidates = [after, after + 4]
        for offset in candidates:
            ratings = [read_int32_from_memory(cs + offset, signed=True, safe=True) for cs in clocksources]
            if None in ratings or not any(ratings) or any(not 0 <= r < 0x10000 for r in ratings):
                continue
            if ratings == sorted(ratings, reverse=True):
                return offset
        return None

    def find_offset_flags(self, clocksources):
        ptrsize = runtime.current_arch.ptrsize
        after = self.offsets["list"] + ptrsize * 2
        if self.kversion >= "6.11":
            offset = after + 16 # freq_khz, rating, id, vdso_clock_mode
        elif self.kversion >= "5.13":
            offset = align(after + 12, ptrsize) # rating, id, vdso_clock_mode
        elif self.kversion >= "5.7":
            offset = after + 8 # rating, vdso_clock_mode
        elif self.kversion >= "3.1":
            offset = align(after + 4, ptrsize) + ptrsize * 2 # rating, enable, disable
        else:
            offset = align(after + 4, ptrsize) + ptrsize * 3 # rating, vread, enable, disable
        values = [read_int_from_memory(cs + offset, safe=True) for cs in clocksources]
        if None in values or not any(values) or any(v >= 0x2000 for v in values):
            return None
        return offset

    def validate_type_info_offsets(self, clocksources, sources):
        rating_offset = self.offsets["rating"]
        if rating_offset is None:
            self.offsets["rating"] = self.find_offset_rating(clocksources)
            sources["rating"] = "heuristic"
        else:
            ratings = [read_int32_from_memory(cs + rating_offset, signed=True, safe=True) for cs in clocksources]
            if None not in ratings and (not any(ratings) or any(rating < 0 or rating >= 0x10000 for rating in ratings)
                                        or ratings != sorted(ratings, reverse=True)):
                self.meta.append((self.quiet_warn, "clocksource.rating has unusual values; keeping the debug information offset"))

        flags_offset = self.offsets["flags"]
        if flags_offset is None:
            self.offsets["flags"] = self.find_offset_flags(clocksources)
            sources["flags"] = "heuristic"
        else:
            flags = [read_int_from_memory(cs + flags_offset, safe=True) for cs in clocksources]
            if None not in flags and any(value >= 0x2000 for value in flags):
                self.meta.append((self.quiet_warn, "clocksource.flags has unknown high bits; keeping the debug information offset"))

        owner_offset = self.offsets["owner"]
        if owner_offset is None:
            sources["owner"] = "the module text of read"
            return
        for cs in clocksources:
            owner = read_int_from_memory(cs + owner_offset, safe=True)
            read = read_int_from_memory(cs + self.offsets["read"], safe=True)
            if owner is None or read is None:
                owner_offset = None
                break
            if owner:
                owner_module = self.find_module(module=owner)
            else:
                owner_module = None
            callback_module = self.find_module(address=read)
            if (owner and owner_module is None) or (callback_module and owner_module != callback_module):
                owner_offset = None
                break
        if owner_offset is None:
            self.offsets["owner"] = None
            sources["owner"] = "the module text of read"
            self.meta.append((self.quiet_warn, "The debug information offset of clocksource.owner does not match clocksource_list"))

    def initialize(self):
        self.meta = []
        self.incomplete = []
        self.kversion = Kernel.version()
        self.klayout = Kernel.layout()
        self.module_text_ranges = None
        self.use_type_info = False

        self.clocksource_list = KernelAddressHeuristicFinder.get_clocksource_list()
        if self.clocksource_list is None:
            self.meta.append((self.quiet_err, "Could not find clocksource_list"))
            return False
        self.meta.append((self.quiet_info, "clocksource_list: {:#x}".format(self.clocksource_list)))

        lh = KernelListHead(self.clocksource_list)
        self.nodes = [node for node in lh.iter_entries() if is_valid_addr(node)]
        if lh.broken:
            self.incomplete.append("clocksource_list is broken at {:#x}".format(lh.broken_at))
            backward = KernelListHead(self.clocksource_list)
            tail = [node for node in backward.iter_entries(backward=True) if is_valid_addr(node)]
            self.nodes = list(dict.fromkeys(self.nodes + tail[::-1]))
        if not self.nodes:
            self.meta.append((self.quiet_err, "clocksource_list is empty"))
            return False
        try:
            valid_list = is_double_link_list(self.clocksource_list)
        except gdb.MemoryError:
            valid_list = False
        if not valid_list:
            self.incomplete.append("clocksource_list has inconsistent links")

        layout = self.resolve_layout()
        if layout is not None:
            valid = sum(
                self.is_clocksource(node - layout["list"], layout, check_callback=False)
                for node in self.nodes
            )
            if valid >= max(1, len(self.nodes) - 1):
                self.offsets = dict(layout)
                self.use_type_info = True
                sources = dict.fromkeys(self.offsets, "debug info")
            else:
                self.meta.append((self.quiet_warn, "The debug information of struct clocksource does not match clocksource_list"))
                layout = None
        if layout is None:
            self.offsets = self.find_offsets()
            if self.offsets is None:
                self.meta.append((self.quiet_err, "Could not determine offsetof(clocksource, list) from clocksource_list"))
                return False
            clocksources = [node - self.offsets["list"] for node in self.nodes]
            clocksources = [cs for cs in clocksources if self.is_clocksource(cs, self.offsets)]
            self.offsets["rating"] = self.find_offset_rating(clocksources)
            self.offsets["flags"] = self.find_offset_flags(clocksources)
            self.offsets["owner"] = None
            sources = dict.fromkeys(self.offsets, "heuristic")
            sources["owner"] = "the module text of read"

        if self.use_type_info:
            clocksources = [
                node - self.offsets["list"]
                for node in self.nodes
                if self.is_clocksource(node - self.offsets["list"], self.offsets, check_callback=False)
            ]
            self.validate_type_info_offsets(clocksources, sources)

        for name, offset in self.offsets.items():
            label = "offsetof(clocksource, {:s})".format(name)
            if offset is None:
                self.meta.append((self.quiet_info, "{:s}: - ({:s})".format(label, sources[name])))
            else:
                self.meta.append((self.quiet_info, "{:s}: {:#x} ({:s})".format(label, offset, sources[name])))
        self.meta.append((self.quiet_info, "clocksource count: {:d}".format(len(self.nodes))))
        return True

    def format_frequency(self, mult, shift):
        if not mult or shift > 64:
            return "-"
        hz = (10 ** 9 << shift) / mult
        for unit, scale in (("GHz", 10 ** 9), ("MHz", 10 ** 6), ("kHz", 10 ** 3)):
            if hz >= scale:
                return "{:.3f} {:s}".format(hz / scale, unit)
        return "{:.0f} Hz".format(hz)

    def format_flags(self, flags):
        if flags is None:
            return "-"
        names, unknown = GefUtil.flags_to_names(flags, self.FLAGS)
        if "VERIFY_PERCPU" in names and self.kversion >= "7.1":
            names[names.index("VERIFY_PERCPU")] = "INLINE"
        if unknown:
            names.append("{:#x}".format(unknown))
        return "|".join(names) or "0"

    def read_clocksource(self, node):
        cs = node - self.offsets["list"]
        if not self.is_clocksource(cs, self.offsets, check_callback=not self.use_type_info):
            return None

        read = read_int_from_memory(cs + self.offsets["read"])
        mask = read_int64_from_memory(cs + self.offsets["mask"])
        mult = read_int32_from_memory(cs + self.offsets["mult"])
        shift = read_int32_from_memory(cs + self.offsets["shift"])
        rating = flags = None
        if self.offsets["rating"] is not None:
            rating = read_int32_from_memory(cs + self.offsets["rating"], signed=True, safe=True)
        if self.offsets["flags"] is not None:
            flags = read_int_from_memory(cs + self.offsets["flags"], safe=True)
        if self.offsets["owner"] is None:
            module = self.find_module(address=read)
        else:
            owner = read_int_from_memory(cs + self.offsets["owner"], safe=True)
            module = owner and (self.find_module(module=owner) or "{:#x}".format(owner))
        return {
            "address": cs,
            "name": self.read_name(read_int_from_memory(cs + self.offsets["name"])),
            "read": read,
            "bits": mask.bit_length(),
            "frequency": self.format_frequency(mult, shift),
            "rating": "-" if rating is None else str(rating),
            "flags": self.format_flags(flags),
            "module": module,
        }

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        ret = self.initialize()
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            return

        entries = []
        for node in self.nodes:
            entry = self.read_clocksource(node)
            if entry is None:
                self.incomplete.append("the clocksource of the node {:#x} is corrupted".format(node))
                continue
            entries.append(entry)

        if args.meta:
            for reason in self.incomplete:
                self.quiet_warn("Incomplete: {:s}".format(reason))
            return

        active = KernelAddressHeuristicFinder.get_current_clocksource(tuple(entry["address"] for entry in entries))

        self.out = []
        width = AddressUtil.get_format_address_width()
        flags_width = max([5] + [len(entry["flags"]) for entry in entries])
        fmt = "{:<{w}s} {:20s} {:8s} {:>6s} {:>13s} {:>4s} {:<{fw}s} "
        if not args.quiet:
            legend = ["address", "name", "status", "rating", "frequency", "bits", "flags"]
            legend = fmt.format(*legend, w=width, fw=flags_width) + "{:<{w}s} {:s}".format("read", "symbol", w=width)
            self.out.append(GefUtil.make_legend(legend))

        for entry in entries:
            if entry["address"] == active:
                status = "active"
            else:
                status = ""
            line = fmt.format(
                "{:#0{:d}x}".format(entry["address"], width), entry["name"], status, entry["rating"],
                entry["frequency"], str(entry["bits"]), entry["flags"], w=width, fw=flags_width,
            )
            line += Symbol.format(entry["read"], missing="NO_SYMBOL", show_address=True, nocolor=True)
            if entry["module"]:
                line += "  [module: {:s}]".format(entry["module"])
            self.out.append(line)
        for reason in self.incomplete:
            self.warn_add_out("Incomplete: {:s}".format(reason))

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelTimerCommand(GenericCommand, BufferingOutput):
    """Dump the timer."""

    _cmdline_ = "ktimer"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--classic-only", action="store_true", help="dump only classic timers.")
    group.add_argument("--hr-only", action="store_true", help="dump only high-resolution timers.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified timer structure (per-cpu):",
        "",
        "+-timer_bases[0]-----+    +-timer_list--+    +-timer_list--+",
        "| ...                |    | entry       |    | entry       |",
        "| vectors[0]         |--->|   next      |--->|   next      |--->...",
        "| ...                |    |   pprev     |    |   pprev     |",
        "| vectors[512or576]  |    | expires     |    | expires     |",
        "| ...                |    | function    |    | function    |",
        "+-timer_bases[1]-----+    | ...         |    | ...         |",
        "| ...                |    +-------------+    +-------------+",
        "| vectors[0]         |",
        "| ...                |",
        "| vectors[512or576]  |",
        "| ...                |",
        "+-timer_bases[2]-----+ <-- v6.10~",
        "| ...                |",
        "+--------------------+",
        "",
        "Before v4.8, each cpu has one `tvec_base` (pointed by `tvec_bases` before v4.2) with 512 buckets",
        "(tv1 to tv5). They are `struct list_head` before v4.2, and `struct hlist_head` after.",
        "",
        "Simplified hrtimer structure (per-cpu):",
        "",
        "+-hrtimer_cpu_bases--+",
        "| ...                |",
        "| clock_bases[0]     |   +--->+-hrtimer-------+",
        "|   ...              |   |    | node          |",
        "|   clockid          |   |    |   node        |",
        "|   ...              |   |    |     color     |",
        "|   active           |   |    |     right     |--->hrtimer",
        "|      rb_root       |   |    |     left      |--->hrtimer",
        "|        rb_root     |---+    |   prev(v7.1~) |--->hrtimer",
        "|        ...         |        |   next(v7.1~) |--->hrtimer",
        "|   get_time(~v6.17) |        |   expires     |",
        "|   ...              |        | ...           |",
        "| ...                |        | function      |",
        "| clock_bases[8]     |        | ...           |",
        "|   ...              |        +---------------+",
        "+--------------------+",
        "",
        "- Classic timers are sorted by `time_to_expired`, the signed difference from `jiffies` in unsigned long.",
        "- hrtimers are sorted by `expires`, since they are listed in the order of the rbtree.",
        "- The member offsets come from the debug information (vmlinux or `ktypes-load`) when available.",
        "  They are verified by `timer_base.cpu` and `hrtimer_clock_base.cpu_base` and `index`.",
    ]
    _note_ = "\n".join(_note_)

    clockid_dict = {
        0: "CLOCK_REALTIME",
        1: "CLOCK_MONOTONIC",
        2: "CLOCK_PROCESS_CPUTIME_ID",
        3: "CLOCK_THREAD_CPUTIME_ID",
        4: "CLOCK_MONOTONIC_RAW",
        5: "CLOCK_REALTIME_COARSE",
        6: "CLOCK_MONOTONIC_COARSE",
        7: "CLOCK_BOOTTIME",
        8: "CLOCK_REALTIME_ALARM",
        9: "CLOCK_BOOTTIME_ALARM",
        10: "CLOCK_SGI_CYCLE",
        11: "CLOCK_TAI",
    }

    def initialize(self, classic=True, high_resolution=True):
        self.meta = []
        self.incomplete = []
        self.klayout = Kernel.layout()
        self.module_text_ranges = None
        self.cpu_masks = None

        # resolve __per_cpu_offset
        self.percpu = Kernel.per_cpu()
        if self.percpu.per_cpu_offset is None:
            self.meta.append((self.quiet_info, "__per_cpu_offset: Not found"))
        else:
            self.meta.append((self.quiet_info, "__per_cpu_offset: {:#x}".format(self.percpu.per_cpu_offset)))
        self.classic = None
        self.hrtimer = None
        if classic:
            self.classic = self.get_classic_layout()
        if high_resolution:
            self.hrtimer = self.get_hrtimer_layout()
        self.classic_timer_initialized = self.classic is not None
        self.hrtimer_initialized = self.hrtimer is not None
        return self.classic_timer_initialized or self.hrtimer_initialized

    def get_classic_layout(self):
        layout = self.resolve_classic_layout()
        if layout is not None and not self.verify_classic_layout(layout):
            # the target has been replaced since the layout was cached
            Cache.clear_cache_for(self.resolve_classic_layout)
            layout = self.resolve_classic_layout()
        if layout is None:
            self.meta.extend(Kernel.export_meta(self, self.classic_meta))
            return None
        if not layout["verified"]:
            # resolve it again the next time
            Cache.clear_cache_for(self.resolve_classic_layout)
        self.meta.extend(Kernel.export_meta(self, layout["meta"]))
        return layout

    def get_hrtimer_layout(self):
        layout = self.resolve_hrtimer_bases()
        if layout is not None and not self.verify_hrtimer_bases(layout, self.percpu.addr_of(layout["hrtimer_bases"], 0)):
            Cache.clear_cache_for(self.resolve_hrtimer_bases)
            Cache.clear_cache_for(self.resolve_hrtimer_members)
            layout = self.resolve_hrtimer_bases()
        if layout is None:
            self.meta.extend(Kernel.export_meta(self, self.hrtimer_meta))
            return None
        self.meta.extend(Kernel.export_meta(self, layout["meta"]))

        members = self.resolve_hrtimer_members()
        if members is None:
            # every rbtree is empty now, so the offsets are not verified and must not be cached
            members = self.guess_hrtimer_members()
        self.meta.extend(Kernel.export_meta(self, members["meta"]))
        return {**layout, **members}

    def resolve_timer_list(self, meta, kind):
        """Return the offsets of `struct timer_list`.

        struct timer_list {
            struct hlist_node entry; // struct list_head (~v4.1)
            unsigned long expires;
            struct tvec_base *base; // ~v4.1
            void (*function)(struct timer_list *); // (unsigned long) ~v4.14
            unsigned long data; // ~v4.14
            u32 flags; // v4.2~
        #ifdef CONFIG_LOCKDEP
            struct lockdep_map lockdep_map;
        #endif
        };
        """
        ptrsize = runtime.current_arch.ptrsize
        offsets = {}
        fixed = {"expires": ptrsize * 2, "function": ptrsize * (4 if kind == "tvec_list" else 3)}
        for name, value in fixed.items():
            offset = GefUtil.offsetof("timer_list", name)
            source = "debug info"
            if offset is None:
                offset, source = value, "fixed"
            offsets["offset_" + name] = offset
            meta.append(("info", "offsetof(timer_list, {:s}): {:#x} ({:s})".format(name, offset, source)))
        return offsets

    def is_timer_base_header(self, timer_base, cpu, offset_clk):
        """Check the members of `struct timer_base` that never change after the initialization."""
        ptrsize = runtime.current_arch.ptrsize
        try:
            clk = read_int_from_memory(timer_base + offset_clk)
            next_expiry = read_int_from_memory(timer_base + offset_clk + ptrsize)
            data = read_memory(timer_base + offset_clk + ptrsize * 2, 7)
        except gdb.MemoryError:
            return False
        if clk == 0 or u32(data[:4]) != cpu or any(x > 1 for x in data[4:]):
            return False
        # see `find_timer_base_layout()`
        return not next_expiry or abs(self.time_to_expire(next_expiry, clk)) < 1 << 30

    def count_timer_bases(self, cpu_addrs, offset_clk, stride, limit):
        nr_bases = 1
        while nr_bases < limit:
            if not all(self.is_timer_base_header(addr + stride * nr_bases, cpu, offset_clk) for cpu, addr in cpu_addrs[:4]):
                break
            nr_bases += 1
        return nr_bases

    def resolve_timer_base(self, timer_bases, meta):
        """Return the layout of `timer_bases[NR_BASES]` (v4.8~), or None.

        struct timer_base {
            raw_spinlock_t lock;
            struct timer_list *running_timer;
        #ifdef CONFIG_PREEMPT_RT
            spinlock_t expiry_lock;
            atomic_t timer_waiters;
        #endif
            unsigned long clk;
            unsigned long next_expiry;
            unsigned int cpu;
            bool next_expiry_recalc;
            bool is_idle;
            bool timers_pending;
            DECLARE_BITMAP(pending_map, WHEEL_SIZE);
            struct hlist_head vectors[WHEEL_SIZE];
        } ____cacheline_aligned;
        """
        ptrsize = runtime.current_arch.ptrsize
        cpu_addrs = self.percpu.possible_addrs_of(timer_bases)
        if not cpu_addrs or cpu_addrs[0][0] != 0:
            meta.append(("err", "per-cpu timer_bases: Not found"))
            return None

        offset_vectors = GefUtil.offsetof("timer_base", "vectors")
        offset_cpu = GefUtil.offsetof("timer_base", "cpu")
        offset_clk = GefUtil.offsetof("timer_base", "clk")
        sizeof_timer_base = GefUtil.sizeof("timer_base")
        sizeof_vectors = GefUtil.sizeof("((struct timer_base *)0)->vectors")
        if None not in (offset_vectors, offset_cpu, offset_clk, sizeof_timer_base, sizeof_vectors):
            if all(self.is_timer_base_header(addr, cpu, offset_clk) for cpu, addr in cpu_addrs[:4]):
                try:
                    sizeof_timer_bases = GefUtil.type_size(gdb.parse_and_eval("timer_bases").type)
                except gdb.error:
                    sizeof_timer_bases = None
                if sizeof_timer_bases:
                    nr_bases = sizeof_timer_bases // sizeof_timer_base
                    source_nr_bases = "debug info"
                else:
                    nr_bases = self.count_timer_bases(cpu_addrs, offset_clk, sizeof_timer_base, 3)
                    source_nr_bases = "heuristic"
                return {
                    "nr_bases": (nr_bases, source_nr_bases),
                    "sizeof_timer_base": (sizeof_timer_base, "debug info"),
                    "offset_vectors": (offset_vectors, "debug info"),
                    "offset_cpu": (offset_cpu, "debug info"),
                    "nr_vectors": (sizeof_vectors // ptrsize, "debug info"),
                }
            meta.append(("warn", "The debug information of struct timer_base does not match the memory"))

        found = KernelAddressHeuristicFinder.find_timer_base_layout(cpu_addrs[0][1], 0)
        if found is None:
            meta.append(("err", "Could not determine the layout of struct timer_base"))
            return None
        offset_clk, wheels = found
        offset_cpu = offset_clk + ptrsize * 2

        # NR_BASES is 1 without CONFIG_NO_HZ_COMMON, 2 (BASE_STD, BASE_DEF) before v6.10,
        # and 3 (BASE_LOCAL, BASE_GLOBAL, BASE_DEF) after. Each of them is cacheline aligned.
        # `tick_nohz_idle_enter` is a global function that exists only with CONFIG_NO_HZ_COMMON=y.
        # (`sysctl_timer_migration` is a data symbol, so it is invisible with CONFIG_KALLSYMS_ALL=n)
        if not Ksym.get_addr("tick_nohz_idle_enter"):
            limit = 1
        elif Kernel.version() < "6.10":
            limit = 2
        else:
            limit = 3
        if len(cpu_addrs) > 1:
            # the cpu number of each base is a strong evidence, which a vendor backport cannot break
            limit = 3

        # An empty wheel matches both WHEEL_SIZEs, so every base of every cpu is checked.
        # The stride found from the next base also tells the right one.
        candidates = []
        for offset_vectors, wheel_size in wheels:
            end = offset_vectors + wheel_size * ptrsize
            stride, nr_bases = align(end, 64), 1
            for cacheline in (64, 128, 32, 256):
                size = align(end, cacheline)
                if all(self.is_timer_base_header(addr + size, cpu, offset_clk) for cpu, addr in cpu_addrs[:4]):
                    stride = size
                    nr_bases = self.count_timer_bases(cpu_addrs, offset_clk, stride, limit)
                    break
            nonempty = 0
            for _cpu, addr in cpu_addrs:
                for n in range(nr_bases):
                    result = KernelAddressHeuristicFinder.check_timer_wheel(addr + stride * n, offset_cpu + 8, offset_vectors, wheel_size)
                    if result is None or result[0] > 1:
                        break
                    nonempty += result[1]
                else:
                    continue
                break
            else:
                candidates.append((nr_bases, nonempty, stride, offset_vectors, wheel_size))
        if not candidates:
            meta.append(("err", "Could not determine the layout of struct timer_base"))
            return None

        candidates.sort(reverse=True)
        nr_bases, nonempty, stride, offset_vectors, wheel_size = candidates[0]
        verified = len(candidates) == 1 or candidates[1][:2] != (nr_bases, nonempty)
        if not verified:
            meta.append(("warn", "Every timer wheel is empty, so WHEEL_SIZE is not verified"))
        return {
            "verified": (verified, "heuristic"),
            "nr_bases": (nr_bases, "heuristic"),
            "sizeof_timer_base": (stride, "heuristic"),
            "offset_vectors": (offset_vectors, "heuristic"),
            "offset_cpu": (offset_cpu, "heuristic"),
            "nr_vectors": (wheel_size, "heuristic"),
        }

    def resolve_tvec_base(self, tvec_bases, meta):
        """Return the layout of `tvec_bases` (~v4.7), or None. See `find_tvec_base_layout()`."""
        ptrsize = runtime.current_arch.ptrsize
        slot = self.percpu.addr_of(tvec_bases, 0)
        if slot is None:
            meta.append(("err", "per-cpu tvec_bases: Not found"))
            return None

        # ~v4.1 holds a pointer to the struct, and v4.2~ holds the struct itself
        for pointer in (True, False):
            if pointer:
                base = read_int_from_memory(slot, safe=True)
            else:
                base = slot
            if not base or not is_valid_addr(base):
                continue
            offset_tv1 = GefUtil.offsetof("tvec_base", "tv1")
            offset_tv5 = GefUtil.offsetof("tvec_base", "tv5")
            sizeof_tv5 = GefUtil.sizeof("((struct tvec_base *)0)->tv5")
            sizeof_head = GefUtil.sizeof("((struct tvec_base *)0)->tv1.vec[0]")
            if None not in (offset_tv1, offset_tv5, sizeof_tv5, sizeof_head):
                nr_vectors = (offset_tv5 + sizeof_tv5 - offset_tv1) // sizeof_head
                found = (offset_tv1, nr_vectors, sizeof_head == ptrsize)
                source = "debug info"
            else:
                found = KernelAddressHeuristicFinder.find_tvec_base_layout(base, 0)
                source = "heuristic"
            if found is None:
                continue
            offset_vectors, nr_vectors, is_hlist = found
            return {
                "pointer": (pointer, source),
                "offset_vectors": (offset_vectors, source),
                "nr_vectors": (nr_vectors, source),
                "hlist": (is_hlist, source),
                # `int cpu` is followed by 2 bools with hlist_head (v4.2~)
                "offset_cpu": (offset_vectors - 8 if is_hlist else None, source),
            }
        meta.append(("err", "Could not determine the layout of struct tvec_base"))
        return None

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def resolve_classic_layout(self):
        """Return the layout of the timer wheel, verified by the memory, or None."""
        self.classic_meta = meta = []

        kind = None
        timer_bases = KernelAddressHeuristicFinder.get_timer_bases()
        if timer_bases:
            meta.append(("info", "timer_bases: {:#x}".format(timer_bases)))
            base_layout = self.resolve_timer_base(timer_bases, meta)
            kind = "wheel"
        else:
            tvec_bases = KernelAddressHeuristicFinder.get_tvec_bases()
            if not tvec_bases:
                meta.append(("err", "timer_bases: Not found"))
                return None
            meta.append(("info", "tvec_bases: {:#x}".format(tvec_bases)))
            base_layout = self.resolve_tvec_base(tvec_bases, meta)
            if base_layout:
                if base_layout["hlist"][0]:
                    kind = "tvec_hlist"
                else:
                    kind = "tvec_list"
        if base_layout is None:
            return None

        layout = {"kind": kind, "verified": True}
        if kind == "wheel":
            layout["timer_bases"] = timer_bases
        else:
            layout["tvec_bases"] = tvec_bases
        for name, (value, source) in base_layout.items():
            layout[name] = value
            if name in ("offset_cpu", "hlist", "verified"):
                continue
            label = {
                "nr_bases": "NR_BASES",
                "sizeof_timer_base": "sizeof(timer_base)",
                "offset_vectors": "offsetof({:s}, vectors)".format("timer_base" if kind == "wheel" else "tvec_base"),
                "nr_vectors": "the number of the buckets",
                "pointer": "tvec_bases is a pointer",
            }[name]
            if name == "pointer":
                fmt = "{:s}: {!s} ({:s})"
            elif name.startswith("nr_"):
                fmt = "{:s}: {:d} ({:s})"
            else:
                fmt = "{:s}: {:#x} ({:s})"
            meta.append(("info", fmt.format(label, value, source)))
        layout.update(self.resolve_timer_list(meta, kind))

        # jiffies
        jiffies = KernelAddressHeuristicFinder.get_jiffies()
        if not jiffies:
            meta.append(("err", "jiffies: Not found"))
            return None
        meta.append(("info", "jiffies: {:#x}".format(jiffies)))
        layout["jiffies"] = jiffies
        layout["meta"] = meta
        return layout

    def iter_classic_bases(self, layout):
        """Yield (cpu, the index of timer_base or None, the address of timer_base/tvec_base)."""
        if layout["kind"] == "wheel":
            for cpu, addr in self.percpu.possible_addrs_of(layout["timer_bases"]):
                for n in range(layout["nr_bases"]):
                    yield cpu, n, addr + layout["sizeof_timer_base"] * n
            return

        for cpu, slot in self.percpu.possible_addrs_of(layout["tvec_bases"]):
            base = slot
            if layout["pointer"]:
                base = read_int_from_memory(slot, safe=True)
                if not base or not is_valid_addr(base):
                    self.incomplete.append("tvec_bases of cpu{:d} is unreadable".format(cpu))
                    continue
            yield cpu, None, base
        return

    def verify_classic_base(self, layout, cpu, base):
        ptrsize = runtime.current_arch.ptrsize
        if layout["offset_cpu"] is not None:
            return read_int32_from_memory(base + layout["offset_cpu"], safe=True) == cpu
        # the empty list_head of tv1 links to itself
        head = base + layout["offset_vectors"]
        first = read_int_from_memory(head, safe=True)
        return bool(first) and read_int_from_memory(first + ptrsize, safe=True) == head

    def verify_classic_layout(self, layout):
        for cpu, _n, base in self.iter_classic_bases(layout):
            return self.verify_classic_base(layout, cpu, base)
        return False

    def walk_hlist(self, head):
        """Return the nodes of the hlist at `head` verified by `pprev`, and the reason if the walk stopped."""
        ptrsize = runtime.current_arch.ptrsize
        nodes = []
        link = head
        node = read_int_from_memory(head, safe=True)
        while node:
            # it also stops at a cycle, where `pprev` does not point to the current link
            if not is_valid_addr(node) or read_int_from_memory(node + ptrsize, safe=True) != link:
                return nodes, "broken at {:#x}".format(node)
            nodes.append(node)
            link = node
            node = read_int_from_memory(node, safe=True)
        if node is None:
            return nodes, "unreadable at {:#x}".format(link)
        return nodes, None

    def collect_classic_timers(self):
        """Return [{"cpu", "base", "timer", "expires", "function"}, ...] of every queued timer_list."""
        layout = self.classic
        ptrsize = runtime.current_arch.ptrsize
        is_hlist = layout["kind"] != "tvec_list"
        if is_hlist:
            sizeof_head = ptrsize
        else:
            sizeof_head = ptrsize * 2
        timers = []
        for cpu, n, base in self.iter_classic_bases(layout):
            name = "cpu{:d} {:s}".format(cpu, "timer_base[{:d}]".format(n) if n is not None else "tvec_base")
            if not self.verify_classic_base(layout, cpu, base):
                self.incomplete.append("{:s} ({:#x}) does not match the layout".format(name, base))
                continue
            vectors = base + layout["offset_vectors"]
            heads = read_memory(vectors, layout["nr_vectors"] * sizeof_head, safe=True)
            if heads is None:
                self.incomplete.append("{:s} ({:#x}) is unreadable".format(name, base))
                continue
            heads = slice_unpack(heads, ptrsize)
            for i in range(layout["nr_vectors"]):
                head = vectors + i * sizeof_head
                if is_hlist:
                    if heads[i] == 0:
                        continue
                    nodes, reason = self.walk_hlist(head)
                else:
                    if heads[i * 2] == head:
                        continue
                    lh = KernelListHead(head)
                    nodes = list(lh.iter_entries())
                    if lh.broken:
                        reason = "{:s} at {:#x}".format(lh.broken_reason, lh.broken_at)
                    else:
                        reason = None
                if reason:
                    self.incomplete.append("the bucket {:d} of {:s} is {:s}".format(i, name, reason))
                for timer in nodes:
                    expires = read_int_from_memory(timer + layout["offset_expires"], safe=True)
                    function = read_int_from_memory(timer + layout["offset_function"], safe=True)
                    if expires is None or function is None:
                        self.incomplete.append("timer_list {:#x} is unreadable".format(timer))
                        continue
                    timers.append({"cpu": cpu, "base": n, "timer": timer, "expires": expires, "function": function})
        return timers

    def get_classic_timers(self):
        """Return {"timers": [{"cpu", "base", "timer", "expires", "function"}, ...], "incomplete": [reason, ...]}
        of every queued timer_list without printing, or None if the timer wheel is not resolved."""
        if not self.initialize(classic=True, high_resolution=False):
            return None
        timers = self.collect_classic_timers()
        return {"timers": timers, "incomplete": self.incomplete}

    def time_to_expire(self, expires, now):
        """Return `expires - now` as the kernel does in `time_after()`, which wraps in unsigned long."""
        bits = runtime.current_arch.ptrsize * 8
        return u2i(expires - now, bits)

    def get_cpu_label(self, cpu):
        states = []
        if self.cpu_masks:
            possible = self.cpu_masks.get("possible")
            present = self.cpu_masks.get("present")
            online = self.cpu_masks.get("online")
            if possible is not None:
                states.append("possible" if cpu in possible else "impossible")
            if present is not None:
                states.append("present" if cpu in present else "not present")
            if online is not None:
                states.append("online" if cpu in online else "offline")
        label = "cpu{:d}".format(cpu)
        if states:
            label += " ({:s})".format(", ".join(states))
        return label

    def dump_timer(self):
        layout = self.classic
        jiffies = read_int_from_memory(layout["jiffies"], safe=True)
        if jiffies is None:
            self.err_add_out("jiffies is unreadable")
            return

        timers = {}
        for timer in self.collect_classic_timers():
            timers.setdefault((timer["cpu"], timer["base"]), []).append(timer)

        for cpu, n, base in self.iter_classic_bases(layout):
            if n is None:
                self.out.append(titlify("{:s} tvec_base: {:#x}".format(self.get_cpu_label(cpu), base)))
            else:
                self.out.append(titlify("{:s} timer_base[{:d}]: {:#x}".format(self.get_cpu_label(cpu), n, base)))

            # print legend
            if not self.args.quiet:
                fmt = "{:18s}  {:18s}  {:23s}  {:18s} {:s}"
                legend = ["timer_list", "expires", "time_to_expired", "function", "symbol"]
                self.out.append(GefUtil.make_legend(fmt.format(*legend)))

            entries = timers.get((cpu, n), [])
            for timer in sorted(entries, key=lambda x: self.time_to_expire(x["expires"], jiffies)):
                tte = self.time_to_expire(timer["expires"], jiffies)
                self.out.append("{:#018x}  {:#018x}  {:#018x} tick  {:s}".format(
                    timer["timer"], timer["expires"], tte,
                    Symbol.format(timer["function"], missing="NO_SYMBOL", show_address=True, nocolor=True),
                ).rstrip())
        return

    def verify_hrtimer_bases(self, layout, cpu_base):
        """Check `clock_base[i].cpu_base == cpu_base` and `clock_base[i].index == i`."""
        if cpu_base is None:
            return False
        for n in range(layout["nr_clock_bases"]):
            htb = cpu_base + layout["offset_clock_base"] + layout["sizeof_clock_base"] * n
            if read_int_from_memory(htb + layout["offset_cpu_base"], safe=True) != cpu_base:
                return False
            if read_int32_from_memory(htb + layout["offset_index"], safe=True) != n:
                return False
        return True

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def resolve_hrtimer_bases(self):
        """Return the layout of `hrtimer_cpu_base.clock_base[]`, verified by the memory, or None.

        struct hrtimer_cpu_base {
            raw_spinlock_t lock;
            unsigned int cpu;
            unsigned int active_bases;
            unsigned int clock_was_set_seq;
            unsigned int hres_active : 1, in_hrtirq : 1, hang_detected : 1,      // ~v7.0
                         softirq_activated : 1, online : 1;                      // ~v7.0
            bool hres_active, deferred_rearm, deferred_needs_update,             // v7.1~
                 hang_detected, softirq_activated, online;                       // v7.1~
        #ifdef CONFIG_HIGH_RES_TIMERS
            unsigned int nr_events;
            unsigned short nr_retries;
            unsigned short nr_hangs;
            unsigned int max_hang_time;
        #endif
        #ifdef CONFIG_PREEMPT_RT
            spinlock_t softirq_expiry_lock;
            atomic_t timer_waiters;
        #endif
            ktime_t expires_next;
            struct hrtimer *next_timer;
            ktime_t softirq_expires_next;
            struct hrtimer *softirq_next_timer;
            ktime_t deferred_expires_next; // v7.1~
            struct hrtimer_clock_base {
                struct hrtimer_cpu_base *cpu_base;
                unsigned int index;
                clockid_t clockid;
                seqcount_raw_spinlock_t seq; // v4.16~
                ktime_t expires_next; // v7.1~ (== the expires of active.rb_root.rb_leftmost)
                struct hrtimer *running; // v4.16~
                struct timerqueue_head { // struct timerqueue_linked_head at v7.1~
                    struct rb_root_cached {          // v5.4~ (struct rb_root_linked at v7.1~;
                        struct rb_root rb_root;      // v5.4~  the layout is the same, only
                        struct rb_node *rb_leftmost; // v5.4~  rb_leftmost gets the _linked type)
                    } rb_root;                       // v5.4~
                    struct rb_root head;             // ~v5.3
                    struct timerqueue_node *next;    // ~v5.3
                } active;
                ktime_t resolution; // ~v4.1
                ktime_t (*get_time)(void); // ~v6.17
                ktime_t softirq_time; // ~v4.1
                ktime_t offset;
            } __hrtimer_clock_base_align clock_base[HRTIMER_MAX_CLOCK_BASES];
            call_single_data_t csd;
        } ____cacheline_aligned;

        The members before `clock_base[]` differ a lot between the versions (e.g., `clock_base[]` is
        right after `lock` before v3.10), but `clock_base[]` is found by its `cpu_base` and `index`.

        DEFINE_PER_CPU(struct hrtimer_cpu_base, hrtimer_bases) =
        {
            .lock = __RAW_SPIN_LOCK_UNLOCKED(hrtimer_bases.lock),
            .clock_base =
            {
                {
                    .index = HRTIMER_BASE_MONOTONIC,
                    .clockid = CLOCK_MONOTONIC,
                    .get_time = &ktime_get,               -------
                },                                              ^
                {                                               | calc this
                    .index = HRTIMER_BASE_REALTIME,             |
                    .clockid = CLOCK_REALTIME,                  v
                    .get_time = &ktime_get_real,          -------
                },
                {
                    .index = HRTIMER_BASE_BOOTTIME,
                    .clockid = CLOCK_BOOTTIME,
                    .get_time = &ktime_get_boottime,
                },
                {                                         // v3.10~
                    .index = HRTIMER_BASE_TAI,
                    .clockid = CLOCK_TAI,
                    .get_time = &ktime_get_clocktai,
                },
                {                                         // v4.16~
                    .index = HRTIMER_BASE_MONOTONIC_SOFT,
                    .clockid = CLOCK_MONOTONIC,
                    .get_time = &ktime_get,
                },
                ...                                       // v4.16~ (REALTIME_SOFT, BOOTTIME_SOFT, TAI_SOFT)
            }
        };
        """
        self.hrtimer_meta = meta = []
        ptrsize = runtime.current_arch.ptrsize
        kversion = Kernel.version()

        hrtimer_bases = KernelAddressHeuristicFinder.get_hrtimer_bases()
        if not hrtimer_bases:
            meta.append(("err", "hrtimer_bases: Not found"))
            return None
        meta.append(("info", "hrtimer_bases: {:#x}".format(hrtimer_bases)))
        hrtimer_cpu_base = self.percpu.addr_of(hrtimer_bases, 0)
        if hrtimer_cpu_base is None:
            meta.append(("err", "per-cpu hrtimer_bases: Not found"))
            return None

        layout = {"hrtimer_bases": hrtimer_bases}
        offset_clock_base = GefUtil.offsetof("hrtimer_cpu_base", "clock_base")
        sizeof_clock_base = GefUtil.sizeof("hrtimer_clock_base")
        sizeof_clock_bases = GefUtil.sizeof("((struct hrtimer_cpu_base *)0)->clock_base")
        members = {name: GefUtil.offsetof("hrtimer_clock_base", name) for name in ("cpu_base", "index", "clockid", "get_time")}
        source = None
        if None not in (offset_clock_base, sizeof_clock_base, sizeof_clock_bases, members["cpu_base"], members["index"], members["clockid"]):
            layout.update({
                "offset_clock_base": offset_clock_base,
                "sizeof_clock_base": sizeof_clock_base,
                "nr_clock_bases": sizeof_clock_bases // sizeof_clock_base,
                "offset_cpu_base": members["cpu_base"],
                "offset_index": members["index"],
                "offset_clockid": members["clockid"],
                "offset_get_time": members["get_time"],
            })
            if self.verify_hrtimer_bases(layout, hrtimer_cpu_base):
                source = "debug info"
            else:
                meta.append(("warn", "The debug information of struct hrtimer_clock_base does not match the memory"))

        if source is None:
            source = "heuristic"
            layout.update({"offset_cpu_base": 0, "offset_index": ptrsize, "offset_clockid": ptrsize + 4})

            # `clock_base[i].cpu_base` points back to the `hrtimer_cpu_base` itself, so it gives the
            # head and the stride of `clock_base[]` directly. Unlike the calculation from `get_time`
            # below, it is exact even when the tail of `struct hrtimer_clock_base` is padded up to
            # the alignment (~v4.15), and it is the only way for v6.18 or later where `get_time`
            # has been removed.
            anchor = KernelAddressHeuristicFinder.find_clock_base_anchor(hrtimer_cpu_base)
            if anchor:
                layout["offset_clock_base"], layout["sizeof_clock_base"], _ = anchor

            # A merge-window build names the previous release (`6.17.0-11846-g...`) but already has
            # the next layout, so look for `get_time` instead of deciding by version alone.
            ktime_get = Ksym.get_addr("ktime_get")
            ktime_get_real = Ksym.get_addr("ktime_get_real")
            ktime_get_ofs = None
            ktime_get_real_ofs = None
            if kversion < "6.18" and ktime_get and ktime_get_real:
                if anchor:
                    limit = layout["offset_clock_base"] + layout["sizeof_clock_base"] * 2
                else:
                    limit = 0x400
                for ofs in range(0, limit, ptrsize):
                    v = read_int_from_memory(hrtimer_cpu_base + ofs, safe=True)
                    if v is None:
                        break
                    if v == ktime_get:
                        ktime_get_ofs = ofs
                    elif v == ktime_get_real:
                        ktime_get_real_ofs = ofs
                    if ktime_get_ofs and ktime_get_real_ofs:
                        break

            if ktime_get_ofs and ktime_get_real_ofs:
                if not anchor:
                    # fallback: `get_time` and `offset` are the last members of the structure
                    layout["sizeof_clock_base"] = ktime_get_real_ofs - ktime_get_ofs
                    clock_base_1 = ktime_get_ofs + ptrsize + 8 # get_time, offset
                    layout["offset_clock_base"] = clock_base_1 - layout["sizeof_clock_base"]
                layout["offset_get_time"] = ktime_get_ofs - layout["offset_clock_base"]
            elif anchor:
                layout["offset_get_time"] = None # removed at v6.18
            else:
                meta.append(("err", "clock_base: Not found"))
                return None

            # HRTIMER_MAX_CLOCK_BASES is 3 (~v3.9), 4 (v3.10~) or 8 (v4.16~)
            nr_clock_bases = 0
            while nr_clock_bases < 8:
                layout["nr_clock_bases"] = nr_clock_bases + 1
                if not self.verify_hrtimer_bases(layout, hrtimer_cpu_base):
                    break
                nr_clock_bases += 1
            layout["nr_clock_bases"] = nr_clock_bases
            if nr_clock_bases < 3:
                meta.append(("err", "clock_base: Not found"))
                return None

        layout["source"] = source
        meta.append(("info", "offsetof(hrtimer_cpu_base, clock_base): {:#x} ({:s})".format(layout["offset_clock_base"], source)))
        meta.append(("info", "sizeof(hrtimer_clock_base): {:#x} ({:s})".format(layout["sizeof_clock_base"], source)))
        meta.append(("info", "HRTIMER_MAX_CLOCK_BASES: {:d} ({:s})".format(layout["nr_clock_bases"], source)))
        meta.append(("info", "offsetof(hrtimer_clock_base, clockid): {:#x} ({:s})".format(layout["offset_clockid"], source)))
        if layout["offset_get_time"] is not None:
            meta.append(("info", "offsetof(hrtimer_clock_base, get_time): {:#x} ({:s})".format(layout["offset_get_time"], source)))
        layout["meta"] = meta
        return layout

    def iter_clock_bases(self):
        """Yield (cpu, hrtimer_cpu_base, index, hrtimer_clock_base)."""
        layout = self.resolve_hrtimer_bases()
        for cpu, cpu_base in self.percpu.possible_addrs_of(layout["hrtimer_bases"]):
            for n in range(layout["nr_clock_bases"]):
                yield cpu, cpu_base, n, cpu_base + layout["offset_clock_base"] + layout["sizeof_clock_base"] * n
        return

    def is_rb_root_cached(self, htbs, ofs):
        """Check whether `htb + ofs` looks like a `struct rb_root_cached` (or `timerqueue_head`) for all `htbs`."""
        found = False
        for htb in htbs:
            try:
                rb_root = read_int_from_memory(htb + ofs)
                rb_leftmost = read_int_from_memory(htb + ofs + runtime.current_arch.ptrsize)
                if rb_root == 0 and rb_leftmost == 0:
                    continue # empty rbtree, no information
                if not is_valid_addr(rb_root) or not is_valid_addr(rb_leftmost):
                    return False
                if read_int_from_memory(rb_root) & ~0b11: # the root node has no parent
                    return False
                if read_int_from_memory(rb_leftmost + runtime.current_arch.ptrsize * 2): # rb_left
                    return False
            except gdb.MemoryError:
                return False
            found = True
        return found

    def is_callback(self, address):
        """Return True if `address` is in the kernel text or the text of a loaded module."""
        if not address or not is_valid_addr(address):
            return False
        if self.klayout.text_base is not None and self.klayout.text_end is not None:
            if self.klayout.text_base <= address < self.klayout.text_end:
                return True
        if self.module_text_ranges is None:
            self.module_text_ranges = Kernel.modules().get_text_ranges()
        return any(start <= address < end for start, end, _module, _name in self.module_text_ranges)

    def guess_offset_active(self):
        """Return the offset of `active` in `struct hrtimer_clock_base` expected from the version."""
        ptrsize = runtime.current_arch.ptrsize
        kversion = Kernel.version()
        if is_x86_32():
            align_u64 = 4
        else:
            align_u64 = 8
        offset = align(ptrsize + 4 + 4, ptrsize) # cpu_base, index, clockid
        if kversion >= "4.16":
            offset += 4 # seq (without CONFIG_LOCKDEP)
            if kversion >= "7.1":
                offset = align(offset, align_u64) + 8 # expires_next
            offset = align(offset, ptrsize) + ptrsize # running
        return offset

    def find_hrtimer_members(self, samples):
        """Resolve the offsets of `expires`, `function` and `base` in `struct hrtimer` from the queued ones.
        `struct timerqueue_node` has gained a sorted list at v7.1, which shifts the members
        placed after it. `base`, which points back to the hrtimer_clock_base, is used as
        an anchor to absorb such a difference."""
        ptrsize = runtime.current_arch.ptrsize
        if not samples:
            return None
        for i in range(3, 0x80 // ptrsize):
            offset_base = ptrsize * i
            if not all(read_int_from_memory(hrtimer + offset_base, safe=True) == htb for hrtimer, htb in samples):
                continue
            if all(self.is_callback(read_int_from_memory(hrtimer + offset_base - ptrsize, safe=True)) for hrtimer, _ in samples):
                # `..., expires}, _softexpires, function, base` (~v7.0)
                # `function` is right before `base`
                return offset_base - ptrsize - 8 * 2, offset_base - ptrsize, offset_base
            # `..., prev, next, expires}, base, is_queued, ..., is_lazy,
            #  _softexpires, function` (v7.1~); `expires` is right before `base`
            for j in range(i + 1, 0x80 // ptrsize):
                if all(self.is_callback(read_int_from_memory(hrtimer + ptrsize * j, safe=True)) for hrtimer, _ in samples):
                    return offset_base - 8, ptrsize * j, offset_base
            return None
        return None

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def resolve_hrtimer_members(self):
        """Return the offsets of `hrtimer_clock_base.active` and `struct hrtimer`, verified by the queued
        hrtimers, or None if they are not verified (e.g., every rbtree is empty).

        struct hrtimer { // ~v7.0
            struct timerqueue_node {
                struct rb_node {
                    unsigned long __rb_parent_color;
                    struct rb_node *rb_right;
                    struct rb_node *rb_left;
                } node;
                ktime_t expires;
            } node;
            ktime_t _softexpires;
            enum hrtimer_restart (*function)(struct hrtimer *);
            struct hrtimer_clock_base *base;
            u8 state;
            u8 is_rel;
            u8 is_soft;
            u8 is_hard;
        };

        struct hrtimer { // v7.1~
            struct timerqueue_linked_node {
                struct rb_node_linked {
                    struct rb_node node;         // same as above, so the rbtree walk is common
                    struct rb_node_linked *prev; // sorted by expires, NULL terminated,
                    struct rb_node_linked *next; // so they are not list_head
                } node;
                ktime_t expires;
            } node;
            struct hrtimer_clock_base *base;
            bool is_queued; // was `u8 state`
            bool is_rel;
            bool is_soft;
            bool is_hard;
            bool is_lazy;
            ktime_t _softexpires;
            enum hrtimer_restart (*function)(struct hrtimer *);
        };

        `qemu-buildroot-x64-7.0-rc7` still uses the old layout, and
        `qemu-buildroot-x64-7.1.1` uses the new one.
        """
        layout = self.resolve_hrtimer_bases()
        if layout is None:
            return None
        meta = []

        offsets = self.get_hrtimer_member_type_info(layout)
        htbs = [htb for _cpu, _cpu_base, _n, htb in self.iter_clock_bases()]
        ptrsize = runtime.current_arch.ptrsize
        # `active` follows cpu_base, index, clockid (, seq, (expires_next,) running).
        # It is just a calculation, so verify it and scan if it is wrong (e.g., CONFIG_LOCKDEP=y).
        candidates = [self.guess_offset_active()] + list(range(ptrsize * 2, layout["sizeof_clock_base"] - 8, ptrsize))
        if offsets is not None:
            candidates.insert(0, offsets["offset_active"])
        for offset_active in candidates:
            if self.is_rb_root_cached(htbs, offset_active):
                break
        else:
            return None
        samples = self.collect_hrtimer_samples(htbs, offset_active)

        if offsets is not None:
            if offsets["offset_active"] == offset_active and all(
                read_int_from_memory(hrtimer + offsets["offset_base"], safe=True) == htb for hrtimer, htb in samples
            ):
                source = "debug info"
            else:
                meta.append(("warn", "The debug information of struct hrtimer does not match the memory"))
                offsets = None
        if offsets is None:
            source = "heuristic"
            members = self.find_hrtimer_members(samples)
            if members is None:
                return None
            offsets = {"offset_active": offset_active}
            offsets["offset_expires"], offsets["offset_function"], offsets["offset_base"] = members

        meta.append(("info", "offsetof(hrtimer_clock_base, active): {:#x} ({:s})".format(offsets["offset_active"], source)))
        meta.append(("info", "offsetof(hrtimer, node.expires): {:#x} ({:s})".format(offsets["offset_expires"], source)))
        meta.append(("info", "offsetof(hrtimer, function): {:#x} ({:s})".format(offsets["offset_function"], source)))
        meta.append(("info", "offsetof(hrtimer, base): {:#x} ({:s})".format(offsets["offset_base"], source)))
        offsets["meta"] = meta
        return offsets

    def get_hrtimer_member_type_info(self, layout):
        """Return the offsets of `hrtimer_clock_base.active` and `struct hrtimer` from the debug information,
        or None if they are unavailable or `clock_base[]` does not match it."""
        offsets = {
            "offset_active": GefUtil.offsetof("hrtimer_clock_base", "active"),
            "offset_expires": GefUtil.offsetof("hrtimer", "node.expires"),
            "offset_function": GefUtil.offsetof("hrtimer", "function"),
            "offset_base": GefUtil.offsetof("hrtimer", "base"),
        }
        if None in offsets.values() or layout["source"] != "debug info":
            return None
        return offsets

    def collect_hrtimer_samples(self, htbs, offset_active):
        """Return [(hrtimer, hrtimer_clock_base), ...] of some queued hrtimers."""
        samples = []
        for htb in htbs:
            nodes, _reason = self.walk_rbtree(htb + offset_active)
            samples += [(hrtimer, htb) for hrtimer in nodes[:4]]
            if len(samples) >= 16:
                break
        return samples

    def guess_hrtimer_members(self):
        """Return the offsets from the debug information or expected from the version, used only while
        they cannot be verified."""
        offsets = self.get_hrtimer_member_type_info(self.resolve_hrtimer_bases())
        if offsets is not None:
            offsets["meta"] = [
                ("warn", "Every hrtimer rbtree is empty, so the following offsets are not verified"),
                ("info", "offsetof(hrtimer_clock_base, active): {:#x} (debug info)".format(offsets["offset_active"])),
                ("info", "offsetof(hrtimer, node.expires): {:#x} (debug info)".format(offsets["offset_expires"])),
                ("info", "offsetof(hrtimer, function): {:#x} (debug info)".format(offsets["offset_function"])),
                ("info", "offsetof(hrtimer, base): {:#x} (debug info)".format(offsets["offset_base"])),
            ]
            return offsets

        ptrsize = runtime.current_arch.ptrsize
        if is_x86_32():
            align_u64 = 4
        else:
            align_u64 = 8
        offset_active = self.guess_offset_active()
        if Kernel.version() < "7.1":
            offset_expires = align(ptrsize * 3, align_u64) # rb_node
            offset_function = offset_expires + 8 * 2 # expires, _softexpires
            offset_base = offset_function + ptrsize
        else:
            offset_expires = align(ptrsize * 5, align_u64) # rb_node, prev, next
            offset_base = offset_expires + 8
            offset_function = align(offset_base + ptrsize + 5, align_u64) + 8 # base, 5 bools, _softexpires
        meta = [
            ("warn", "Every hrtimer rbtree is empty, so the following offsets are not verified"),
            ("info", "offsetof(hrtimer_clock_base, active): {:#x} (version)".format(offset_active)),
            ("info", "offsetof(hrtimer, node.expires): {:#x} (version)".format(offset_expires)),
            ("info", "offsetof(hrtimer, function): {:#x} (version)".format(offset_function)),
            ("info", "offsetof(hrtimer, base): {:#x} (version)".format(offset_base)),
        ]
        return {
            "offset_active": offset_active,
            "offset_expires": offset_expires,
            "offset_function": offset_function,
            "offset_base": offset_base,
            "meta": meta,
        }

    def walk_rbtree(self, root):
        """Return the nodes of the rbtree at `root` in order, verified by their parent, and the reason if the walk stopped."""
        ptrsize = runtime.current_arch.ptrsize
        nodes = []
        stack = []
        seen = set()
        parent = 0
        node = read_int_from_memory(root, safe=True)
        if node is None:
            return nodes, "unreadable at {:#x}".format(root)
        while stack or node:
            while node:
                if node in seen or not is_valid_addr(node):
                    return nodes, "broken at {:#x}".format(node)
                parent_color = read_int_from_memory(node, safe=True)
                if parent_color is None or parent_color & ~0b11 != parent:
                    return nodes, "broken at {:#x}".format(node)
                seen.add(node)
                stack.append(node)
                parent = node
                node = read_int_from_memory(node + ptrsize * 2, safe=True) # rb_left
                if node is None:
                    return nodes, "unreadable at {:#x}".format(parent)
            node = stack.pop()
            nodes.append(node)
            parent = node
            node = read_int_from_memory(node + ptrsize, safe=True) # rb_right
            if node is None:
                return nodes, "unreadable at {:#x}".format(parent)
        return nodes, None

    def dump_hrtimer(self):
        layout = self.hrtimer
        for cpu, cpu_base, n, htb in self.iter_clock_bases():
            name = "cpu{:d} hrtimer_clock_base[{:d}]".format(cpu, n)
            if (read_int_from_memory(htb + layout["offset_cpu_base"], safe=True) != cpu_base or
                    read_int32_from_memory(htb + layout["offset_index"], safe=True) != n):
                self.incomplete.append("{:s} ({:#x}) does not match the layout".format(name, htb))
                continue
            clockid = read_int32_from_memory(htb + layout["offset_clockid"], safe=True)
            if clockid is None:
                self.incomplete.append("{:s} clockid is unreadable".format(name))
                continue
            if layout["offset_get_time"] is None: # v6.18 or later
                self.out.append(titlify("{:s} hrtimer_clock_base[{:d}]: {:#x}  [{:s}]".format(
                    self.get_cpu_label(cpu), n, htb,
                    self.clockid_dict.get(clockid, "UNKNOWN"),
                )).rstrip())
            else:
                get_time = read_int_from_memory(htb + layout["offset_get_time"], safe=True)
                if get_time is None:
                    self.incomplete.append("{:s} get_time is unreadable".format(name))
                    continue
                self.out.append(titlify("{:s} hrtimer_clock_base[{:d}]: {:#x}  [{:s}; get_time: {:s}]".format(
                    self.get_cpu_label(cpu), n, htb, self.clockid_dict.get(clockid, "UNKNOWN"),
                    Symbol.format(get_time, missing="NO_SYMBOL", show_address=True, nocolor=True),
                )).rstrip())

            # print legend
            if not self.args.quiet:
                fmt = "{:18s}  {:18s}  {:23s}  {:18s} {:s}"
                legend = ["hrtimer", "expires", "time_to_expired", "function", "symbol"]
                self.out.append(GefUtil.make_legend(fmt.format(*legend)))

            nodes, reason = self.walk_rbtree(htb + layout["offset_active"])
            if reason:
                self.incomplete.append("the rbtree of {:s} is {:s}".format(name, reason))
            for hrtimer in nodes:
                expires = read_int64_from_memory(hrtimer + layout["offset_expires"], safe=True)
                function = read_int_from_memory(hrtimer + layout["offset_function"], safe=True)
                if expires is None or function is None:
                    self.incomplete.append("hrtimer {:#x} is unreadable".format(hrtimer))
                    continue
                timer_base = read_int_from_memory(hrtimer + layout["offset_base"], safe=True)
                if timer_base != htb:
                    self.incomplete.append("hrtimer {:#x} does not point back to {:s}".format(hrtimer, name))
                    continue
                if not self.is_callback(function):
                    self.incomplete.append("hrtimer {:#x} callback {:#x} is outside kernel/module text".format(hrtimer, function))
                self.out.append("{:#018x}  {:#018x}  {:23s}  {:s}".format(
                    hrtimer, expires, "? (too hard to calc)",
                    Symbol.format(function, missing="NO_SYMBOL", show_address=True, nocolor=True),
                ).rstrip())
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "3.0":
            err("Unsupported before v3.0")
            return

        self.quiet_info("Wait for memory scan")

        ret = self.initialize(classic=not args.hr_only, high_resolution=not args.classic_only)
        self.cpu_masks = self.percpu.get_cpu_masks()
        for name, cpus in self.cpu_masks.items():
            if cpus is None:
                value = "unknown"
            else:
                value = ", ".join(str(cpu) for cpu in sorted(cpus)) or "none"
            self.meta.append((self.quiet_info, "cpu {:s}: {:s}".format(name, value)))
        failed = ((not args.hr_only and not self.classic_timer_initialized)
                  or (not args.classic_only and not self.hrtimer_initialized))
        if args.meta or failed:
            for func, line in self.meta:
                func(line)
        if not ret:
            return

        if args.meta:
            return

        self.out = []
        if self.classic_timer_initialized:
            self.dump_timer()
        if self.hrtimer_initialized:
            self.dump_hrtimer()
        for reason in self.incomplete:
            self.warn_add_out("Incomplete: {:s}".format(reason))
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelPciDeviceCommand(GenericCommand, BufferingOutput):
    """Dump the PCI devices."""

    _cmdline_ = "kpcidev"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified pcidev structure:",
        "",
        "+----------------+   +-pci_bus--------+",
        "| pci_root_buses |-->| node.next      |-->...",
        "+----------------+   | node.prev      |",
        "                     | parent         |    +-pci_dev----------+",
        "                     | children.next  | +->| bus_list.next    |-->...",
        "                     | children.prev  | |  | bus_list.prev    |",
        "                     | devices.next   |-+  | ...              |",
        "                     | devices.prev   |    | vendor           |",
        "                     | ...            |    | device           |",
        "                     | dev            |    | subsystem_vendor |",
        "                     |   kobj         |    | subsystem_device |",
        "                     |     name       |    | class            |",
        "                     | ...            |    | revision         |",
        "                     +----------------+    | dev              |",
        "                                           |   kobj           |",
        "                                           |     name         |",
        "                                           | ...              |",
        "                                           | +-resource[0]-+  |",
        "                                           | | start       |  |",
        "                                           | | end         |  |",
        "                                           | | name        |  |",
        "                                           | | flags       |  |",
        "                                           | | ...         |  |",
        "                                           | +-resource[1]-+  |",
        "                                           | | ...         |  |",
        "                                           | +-------------+  |",
        "                                           | | ...         |  |",
        "                                           | +-------------+  |",
        "                                           | ...              |",
        "                                           +------------------+",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self):
        from gef.core.http import http_get
        if hasattr(self, "initialized") and self.initialized:
            return True

        # pci_root_buses
        self.pci_root_buses = KernelAddressHeuristicFinder.get_pci_root_buses()
        if not self.pci_root_buses:
            self.quiet_err("Could not find pci_root_buses (maybe, CONFIG_PCI is not set)")
            return False
        self.quiet_info("pci_root_buses: {:#x}".format(self.pci_root_buses))

        first_root_bus = read_int_from_memory(self.pci_root_buses)
        if self.pci_root_buses == first_root_bus:
            warn("No PCI devices found")
            return False

        # pci_bus->{node,children,devices}
        """
        struct pci_bus {
            struct list_head node;
            struct pci_bus *parent;
            struct list_head children;
            struct list_head devices;
            struct pci_dev *self;
            struct list_head slots;
            struct resource *resource[PCI_BRIDGE_RESOURCE_NUM];
            struct list_head resources;
            struct resource busn_res;
            struct pci_ops *ops;
            struct msi_controller *msi;
            void *sysdata;
            struct proc_dir_entry *procdir;
            unsigned char number;
            unsigned char primary;
            unsigned char max_bus_speed;
            unsigned char cur_bus_speed;
        #ifdef CONFIG_PCI_DOMAINS_GENERIC
            int domain_nr;
        #endif
            char name[48];
            unsigned short bridge_ctl;
            pci_bus_flags_t bus_flags;
            struct device *bridge;
            struct device {
                struct kobject {
                    const char *name; <-- search for this
                    ...
                } kobj;
                ...
            } dev;
            struct bin_attribute *legacy_io;
            struct bin_attribute *legacy_mem;
            unsigned int is_added:1;
        };
        """

        self.offset_pci_bus_node = 0
        self.offset_pci_bus_children = runtime.current_arch.ptrsize * 3
        self.offset_pci_bus_devices = runtime.current_arch.ptrsize * 5

        # pci_bus->dev
        for i in range(100):
            v = read_int_from_memory(first_root_bus + runtime.current_arch.ptrsize * i)
            if is_valid_addr(v):
                if read_cstring_from_memory(v) == "0000:00":
                    self.offset_pci_bus_dev = runtime.current_arch.ptrsize * i
                    self.quiet_info("offsetof(pci_bus, dev): {:#x}".format(self.offset_pci_bus_dev))
                    break
        else:
            self.quiet_err("Could not find pci_bus->dev")
            return False

        # pci_dev->{bus_list,vendor,device,subsystem_vendor,subsystem_device,class,revision}
        """
        struct pci_dev {
            struct list_head bus_list;
            struct pci_bus *bus;
            struct pci_bus *subordinate;
            void *sysdata;
            struct proc_dir_entry *procent;
            struct pci_slot *slot;
            unsigned int devfn;
            unsigned short vendor;
            unsigned short device;
            unsigned short subsystem_vendor;
            unsigned short subsystem_device;
            unsigned int class;
            u8 revision;
            u8 hdr_type;
            ...
            struct device {
                struct kobject {
                    const char *name; <-- search for this
                    ...
                } kobj;
                ...
            } dev;
            int cfg_size;
            unsigned int irq;
            struct resource resource[DEVICE_COUNT_RESOURCE];
            ...
        };
        """

        self.offset_pci_dev_bus_list = 0
        self.offset_pci_dev_vendor = runtime.current_arch.ptrsize * 7 + 4
        self.offset_pci_dev_device = self.offset_pci_dev_vendor + 2
        self.offset_pci_dev_subsystem_vendor = self.offset_pci_dev_device + 2
        self.offset_pci_dev_subsystem_device = self.offset_pci_dev_subsystem_vendor + 2
        self.offset_pci_dev_class = self.offset_pci_dev_subsystem_device + 2
        self.offset_pci_dev_revision = self.offset_pci_dev_class + 4

        # pci_dev->dev
        first_dev = read_int_from_memory(first_root_bus + self.offset_pci_bus_devices)
        for i in range(100):
            v = read_int_from_memory(first_dev + runtime.current_arch.ptrsize * i)
            if is_valid_addr(v):
                if read_cstring_from_memory(v) == "0000:00:00.0":
                    self.offset_pci_dev_dev = runtime.current_arch.ptrsize * i
                    self.quiet_info("offsetof(pci_dev, dev): {:#x}".format(self.offset_pci_dev_dev))
                    break
        else:
            self.quiet_err("Could not find pci_dev->dev")
            return False

        # pci_dev->resource
        """
        struct resource {
            resource_size_t start;
            resource_size_t end;
            const char *name;
            unsigned long flags;
            unsigned long desc;
            struct resource *parent, *sibling, *child;
        };
        """

        ofs_base = self.offset_pci_dev_dev + runtime.current_arch.ptrsize
        for i in range(200):
            v = read_int_from_memory(first_dev + ofs_base + runtime.current_arch.ptrsize * i)
            if is_valid_addr(v):
                if read_cstring_from_memory(v) == "0000:00:00.0":
                    self.offset_pci_dev_resource = ofs_base + runtime.current_arch.ptrsize * i - 0x10
                    self.sizeof_resource = 0x10 + runtime.current_arch.ptrsize * 6
                    self.quiet_info("offsetof(pci_dev, resource): {:#x}".format(self.offset_pci_dev_resource))
                    break
        else:
            self.quiet_err("Could not find pci_dev->resource")
            return False

        # pci.ids
        pci_ids_file_name = "/usr/share/misc/pci.ids"
        if os.path.exists(pci_ids_file_name):
            self.quiet_info("use {:s}".format(pci_ids_file_name))
            content = open(pci_ids_file_name).read()
        else:
            pci_ids_file_name = os.path.join(GEF_TEMP_DIR, "pci.ids")
            if os.path.exists(pci_ids_file_name):
                self.quiet_info("use {:s}".format(pci_ids_file_name))
                content = open(pci_ids_file_name).read()
            else:
                url = "https://raw.githubusercontent.com/pciutils/pciids/master/pci.ids"
                self.quiet_info("use {:s}".format(url))
                content = String.bytes2str(http_get(url) or "")
                if not content:
                    self.quiet_info("Connection timed out: {:s}".format(url))
                open(pci_ids_file_name, "w").write(content)
        self.pci_ids = self.parse_pci_ids(content)

        self.initialized = True
        return True

    def parse_pci_ids(self, content):
        dic = {}
        class_mode = False
        for line in content.splitlines():
            if not line or line.startswith("#"):
                continue

            if class_mode is False and line.startswith("C"):
                class_mode = True

            if class_mode is False:
                # device mode
                if not line.startswith("\t"):
                    vendor, *desc = line.split("  ")
                    vendor = int(vendor, 16)
                    dic[vendor] = " ".join(desc)
                    continue

                if line.startswith("\t") and not line.startswith("\t\t"):
                    device, *desc = line[1:].split("  ")
                    device = int(device, 16)
                    # Use the previous value for `vendor`.
                    dic[vendor, device] = " ".join(desc)
                    continue

                if line.startswith("\t\t"):
                    subsystem, *desc = line[2:].split("  ")
                    subv, subd = subsystem.split()
                    subv = int(subv, 16)
                    subd = int(subd, 16)
                    # Use the previous value for `vendor` and `device`.
                    dic[vendor, device, subv, subd] = " ".join(desc)
                    continue

            else:
                # class mode
                if not line.startswith("\t"):
                    base_class, *desc = line.split("  ")
                    base_class = int(base_class[2:], 16)
                    dic["C", base_class] = " ".join(desc)
                    continue

                if line.startswith("\t") and not line.startswith("\t\t"):
                    sub_class, *desc = line[1:].split("  ")
                    sub_class = int(sub_class, 16)
                    # Use the previous value for `base_class`.
                    dic["C", base_class, sub_class] = " ".join(desc)
                    continue

                if line.startswith("\t\t"):
                    prgif, *desc = line[2:].split("  ")
                    prgif = int(prgif, 16)
                    # Use the previous value for `base_class` and `sub_class`.
                    dic["C", base_class, sub_class, prgif] = " ".join(desc)
                    continue
        return dic

    def get_description(self, base_class, sub_class, prgif, vendor, device, subv, subd):
        # The information provided by the programming interface (prgif) is too detailed,
        # so it is not used.
        class_str = self.pci_ids.get(("C", base_class, sub_class), None)
        if class_str is None:
            class_str = self.pci_ids.get(("C", base_class), None)
        if class_str is None:
            class_str = "???"

        device_str = self.pci_ids.get((vendor, device, subv, subd), None)
        if device_str is None:
            device_str = self.pci_ids.get((vendor, device), None)
        if device_str is None:
            device_str = self.pci_ids.get(vendor, None)
        if device_str is None:
            device_str = "???"

        qemu_monitor_out = ""
        if is_qemu_system():
            dev = ""
            res = gdb.execute("monitor info qtree", to_string=True)
            target = "pci id {:04x}:{:04x} (sub {:04x}:{:04x})".format(vendor, device, subv, subd)
            for line in res.splitlines():
                m = re.search('dev: (.+), id ".*"', line)
                if m:
                    dev = m.group(1)
                    continue
                if target in line:
                    qemu_monitor_out = " ({:s})".format(Color.boldify(dev))
                    break

        return "{:s} / {:s}".format(class_str, device_str) + qemu_monitor_out

    @staticmethod
    def get_flags_str(flags_value):
        flags_dic = {
            0x8000_0000: "IORESOURCE_BUSY",
            0x4000_0000: "IORESOURCE_AUTO",
            0x2000_0000: "IORESOURCE_UNSET",
            0x1000_0000: "IORESOURCE_DISABLED",
            0x0800_0000: "IORESOURCE_EXCLUSIVE",
            0x0400_0000: "IORESOURCE_SYSRAM_MERGEABLE",
            0x0200_0000: "IORESOURCE_SYSRAM_DRIVER_MANAGED",
            0x0100_0000: "IORESOURCE_SYSRAM",
            0x0040_0000: "IORESOURCE_MUXED",
            0x0020_0000: "IORESOURCE_WINDOW",
            0x0010_0000: "IORESOURCE_MEM_64",
            0x0008_0000: "IORESOURCE_STARTALIGN",
            0x0004_0000: "IORESOURCE_SIZEALIGN",
            0x0002_0000: "IORESOURCE_SHADOWABLE",
            0x0001_0000: "IORESOURCE_RANGELENGTH",
            0x0000_8000: "IORESOURCE_CACHEABLE",
            0x0000_4000: "IORESOURCE_READONLY",
            0x0000_2000: "IORESOURCE_PREFETCH",
            0x0000_1000: "IORESOURCE_BUS",
            0x0000_0800: "IORESOURCE_DMA",
            0x0000_0400: "IORESOURCE_IRQ",
            0x0000_0200: "IORESOURCE_MEM",
            0x0000_0100: "IORESOURCE_IO",
        }
        flags = []
        for k, v in flags_dic.items():
            if flags_value & k:
                flags.append(v)

        if "IORESOURCE_IO" in flags and "IORESOURCE_MEM" in flags:
            flags.remove("IORESOURCE_IO")
            flags.remove("IORESOURCE_MEM")
            flags.append("IORESOURCE_REG")

        flags_str = " | ".join(flags)
        if flags_str == "":
            flags_str = "none"
        return flags_str.replace("IORESOURCE_", "")

    def search_label(self, start, end):
        if not is_qemu_system():
            return []

        label_list = []
        res = gdb.execute("monitor info mtree -f", to_string=True)
        for line in res.splitlines():
            if not line.startswith("  "):
                continue

            m = re.search(r"  ([0-9a-f]+)-([0-9a-f]+)", line)
            if not m:
                continue

            s = int(m.group(1), 16)
            e = int(m.group(2), 16)
            if not (start <= s and e <= end):
                continue

            line = "      -> " + line.lstrip()
            if line not in label_list:
                label_list.append(line)

        if label_list == []:
            label_list.append("      -> No results found from `monitor info mtree -f`")
        return label_list

    def walk_devices(self, dev):
        if not self.args.quiet:
            fmt = "{:18s} {:12s} {:7s} {:10s} {:10s} {:3s} {:s}"
            legend = ["pci_dev", "name", "class", "vendor:dev", "subsystem", "rev", "description"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        if not dev:
            return

        while dev not in self.seen_dev:
            self.seen_dev.append(dev)

            # parse device info
            dev_name = read_cstring_from_memory(read_int_from_memory(dev + self.offset_pci_dev_dev))
            vendor = read_int16_from_memory(dev + self.offset_pci_dev_vendor)
            device = read_int16_from_memory(dev + self.offset_pci_dev_device)
            sub_vendor = read_int16_from_memory(dev + self.offset_pci_dev_subsystem_vendor)
            sub_device = read_int16_from_memory(dev + self.offset_pci_dev_subsystem_device)
            revision = read_int8_from_memory(dev + self.offset_pci_dev_revision)

            # u32:class = u8:unused || u8:base_class || u8:sub_class || u8:programming-interface
            class_val = read_int32_from_memory(dev + self.offset_pci_dev_class)
            prgif = class_val & 0xff
            sub_class = (class_val >> 8) & 0xff
            base_class = (class_val >> 16) & 0xff

            desc = self.get_description(base_class, sub_class, prgif, vendor, device, sub_vendor, sub_device)
            self.out.append("{:#018x} {:s} {:02x}{:02x}:{:02x} {:04x}:{:04x}  {:04x}:{:04x}  {:02x}  {:s}".format(
                dev, dev_name, base_class, sub_class, prgif, vendor, device, sub_vendor, sub_device, revision, desc,
            ))

            if self.args.verbose:
                # parse resource
                i = 0
                while True:
                    resource_i = dev + self.offset_pci_dev_resource + self.sizeof_resource * i

                    # parse resource name
                    resource_i_name = read_int_from_memory(resource_i + 8 * 2)
                    if not is_valid_addr(resource_i_name):
                        break
                    if read_cstring_from_memory(resource_i_name) != dev_name:
                        break

                    # parse resource address
                    resource_i_start = read_int_from_memory(resource_i + 8 * 0)
                    resource_i_end = read_int_from_memory(resource_i + 8 * 1)
                    resource_i_size = resource_i_end - resource_i_start

                    if resource_i_start != 0 and resource_i_end != 0:
                        # parse resource flags
                        resource_i_flags = read_int_from_memory(resource_i + 8 * 2 + runtime.current_arch.ptrsize)
                        flag_str = KernelPciDeviceCommand.get_flags_str(resource_i_flags)
                        if (resource_i_flags & 0x300) == 0x300:
                            type_str = "RegOffs"
                        elif resource_i_flags & 0x100:
                            type_str = "I/O-Mem"
                        elif resource_i_flags & 0x200:
                            type_str = "PhysMem"
                        else:
                            type_str = "???"

                        self.out.append("  [{:d}] {:7s}: {:#010x}-{:#010x} ({:#010x}) flags:{:#x} ({:s})".format(
                            i, type_str, resource_i_start, resource_i_end, resource_i_size, resource_i_flags, flag_str,
                        ))

                        # add more details
                        ret = self.search_label(resource_i_start, resource_i_end)
                        self.out.extend(ret)
                    i += 1

            # goto next
            dev = read_int_from_memory(dev + self.offset_pci_dev_bus_list)
        return

    def walk_pci_bus(self, bus):
        if not bus:
            return

        while bus not in self.seen_bus:
            self.seen_bus.append(bus)
            bus_name = read_cstring_from_memory(read_int_from_memory(bus + self.offset_pci_bus_dev))
            self.out.append(titlify("Bus {:s}: {:#x}".format(bus_name, bus)))

            # parse device
            self.seen_dev.append(bus + self.offset_pci_bus_devices)
            dev = read_int_from_memory(bus + self.offset_pci_bus_devices)
            self.walk_devices(dev)

            # parse child
            self.seen_bus.append(bus + self.offset_pci_bus_children)
            first_child_bus = read_int_from_memory(bus + self.offset_pci_bus_children)
            self.walk_pci_bus(first_child_bus)

            # goto next
            bus = read_int_from_memory(bus + self.offset_pci_bus_node)
        return

    def dump_pci(self):
        first_root_bus = read_int_from_memory(self.pci_root_buses)
        self.seen_bus = [self.pci_root_buses]
        self.seen_dev = []
        self.walk_pci_bus(first_root_bus)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        if not self.initialize():
            return

        self.out = []
        self.dump_pci()
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelConfigCommand(GenericCommand, BufferingOutput):
    """Dump the kernel config if available."""

    _cmdline_ = "kconfig"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[],
                        help="REGEXP include filter.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    def get_config(self):
        kinfo = Kernel.get_kernel_layout()
        if kinfo.ro_base is None:
            err("Not recognized .rodata")
            return False

        if is_kgdb():
            info("The config is often near the top of .rodata; once found, the search stops early.")
            ro_data = b""
            tqdm = GefUtil.get_tqdm(not self.args.quiet)
            for pos in tqdm(range(0, kinfo.ro_size, 0x1000), leave=False):
                if not is_valid_addr(kinfo.ro_base + pos):
                    err("Memory read error")
                    return
                ro_data += read_memory(kinfo.ro_base + pos, 0x1000)
                if ro_data.find(b"IKCFG_ST") >= 0 and ro_data.find(b"IKCFG_ED") >= 0:
                    break
        else:
            if not is_valid_addr(kinfo.ro_base):
                err("Memory read error")
                return
            ro_data = read_memory(kinfo.ro_base, kinfo.ro_size)

        start_pos = ro_data.find(b"IKCFG_ST")
        if start_pos == -1:
            err("Could not find IKCFG_ST, this kernel may be built as CONFIG_IKCONFIG_PROC=n")
            return False
        end_pos = ro_data.find(b"IKCFG_ED")

        info("IKCFG_ST: {:#x}".format(kinfo.ro_base + start_pos))
        info("IKCFG_ED: {:#x}".format(kinfo.ro_base + end_pos))
        configz = ro_data[start_pos + len("IKCFG_ST"):end_pos]

        import gzip
        try:
            self.configs = String.bytes2str(gzip.decompress(configz))
        except gzip.BadGzipFile:
            err("Gzip decompress error")
            return False
        return True

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        if not hasattr(self, "configs"):
            self.configs = None

        if args.rescan:
            self.configs = None

        if self.configs is None:
            ret = self.get_config()
            if not ret:
                return

        self.out = self.configs.splitlines()

        if args.filter:
            out = []
            for line in self.out:
                for filt in args.filter:
                    if filt.search(line):
                        out.append(line)
                        break
            self.out = out

        self.print_output()
        return



@register_command
class KernelDmesgCommand(GenericCommand, BufferingOutput):
    """Dump the ring buffer of the dmesg area."""

    _cmdline_ = "kdmesg"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-c", "--use-cache", action="store_true", help="use previous result.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "The information such as [T1] or [C0] is the caller context ID.",
        "Originally, this information is displayed when CONFIG_PRINTK_CALLER=y.",
        "However it is always displayed because it is useful.",
        "",
        "prb points to the active ringbuffer; it may point to storage other than printk_rb_static.",
        "",
        "Simplified dmesg structure (5.10~):",
        "",
        "+-----+",
        "| prb |--+",
        "+-----+  |",
        "         |",
        "+--------+",
        "|",
        "+->+-printk_rb_static-+  +-------------------------->+-prb_desc[]----+",
        "   | desc_ring        |  |                       +---| state_var     |---+",
        "   |   count_bits     |  | +->+-printk_info[]-+  |   | ...           |   |",
        "   |   descs          |--+ |  | seq           |  |   +---------------+   |",
        "   |   infos          |----+  | ts_nsec       |  |   | state_var     |   |",
        "   |   head_id        |       | text_len      |  |   | ...           |   |",
        "   |   tail_id        |       | facility      |  |   +---------------+   |",
        "   |   ...            |       | flags, level  |  |   | ...           |   |",
        "   | text_data_ring   |       | caller_id     |  |   +---------------+<--+",
        "   |   size_bits      |       | dev_info      |  |   | state_var     |",
        "   |   data           |--+    +---------------+  |   | text_blk_lpos |",
        "   |   head_lpos      |  |    | seq           |  |   |   begin       |(=text block start offset)",
        "   |   tail_lpos      |  |    | ts_nsec       |  |   |   next        |(=text block end offset)",
        "   | fail             |  |    | text_len      |  |   +---------------+",
        "   +------------------+  |    | facility      |  |   | state_var     |",
        "                         |    | flags, level  |  |   | text_blk_lpos |",
        "+------------------------+    | caller_id     |  |   |   begin       |",
        "|                             | dev_info      |  |   |   next        |",
        "+->+-printk_record-+          +---------------+  |   +---------------+",
        "   | info          |          | ...           |  |",
        "   | text_buf      |-->text   +---------------+<-+",
        "   | text_buf_size |          | seq           |",
        "   +---------------+          | ...           |",
        "                              +---------------+",
        "* prb_desc and printk_info are accessed in two ways. One is seq number based access which is simply incremented",
        "  and the other is id number based access by lower bit of state_var.",
        "  1-A. (Seq-based prb_desc): Preserving entry state and entry index (=id).",
        "  1-B. (Id-based prb_desc): Preserving begin and next.",
        "  2-A. (Seq-based printk_info): Preserving text data length, time, thread ID, etc. for each entry.",
        "  2-B. (Id-based printk_info): Preserving seq for ring buffer reuse.",
        "",
        "Simplified dmesg structure (3.5~5.9):",
        "",
        "+-----------+",
        "| __log_buf |-------->+-log_buffer-----+   ^     ^",
        "+-----------+         | ts_nsec        |   |     |",
        "                      | len            |-->|     |",
        "                      | text_len       |   |     |",
        "                      | ...            |   |     |",
        "                      | text[text_len] |   |     |",
        "                      +----------------+   v     |",
        "+---------------+     | ...            |         |",
        "| log_first_idx |---->+----------------+         |",
        "+---------------+     | ts_nsec        |         |",
        " =start               | len            |         |    +-------------+",
        "                      | text_len       |         |<---| log_buf_len |",
        "                      | ...            |         |    +-------------+",
        "                      | text[text_len] |         |",
        "                      +----------------+         |",
        "+---------------+     | ...            |         |",
        "| log_next_idx  |---->+----------------+         |",
        "+---------------+     | ts_nsec        |         |",
        " =end                 | len            |         |",
        "                      | text_len       |         |",
        "                      | ...            |         |",
        "                      | text[text_len] |         |",
        "                      +----------------+         v",
        "",
        "Simplified dmesg structure (~3.4):",
        "",
        "+-----------+",
        "| log_buf   |-------->+-log_buffer-----+         ^",
        "+-----------+         | text bytes     |         |",
        "                      | ...            |         |",
        "                      | text bytes     |         |",
        "+-----------+         |                |         |    +-------------+",
        "| log_end   |-------->| next write     |         |<---| log_buf_len |",
        "+-----------+         | text bytes     |         |    +-------------+",
        " % log_buf_len        | ...            |         |",
        "                      | text bytes     |         |",
        "                      +----------------+         v",
        "The buffer is one circular byte array; there are no per-record headers.",
        "log_end is a byte counter; its position in the buffer is log_end % log_buf_len.",
        "log_buf points to active storage, which may differ from the initial __log_buf.",
    ]
    _note_ = "\n".join(_note_)

    def get_vmcoreinfo(self):
        """Read size and offset metadata from the running kernel."""
        values = {}
        size_addr = Ksym.get_addr("vmcoreinfo_size")
        data_addr = Ksym.get_addr("vmcoreinfo_data")
        if not size_addr or not data_addr:
            return values
        size = read_int_from_memory(size_addr, safe=True)
        if not size or size > 0x10000:
            return values
        try:
            prefix = b"OSRELEASE="[:runtime.current_arch.ptrsize]
            if read_memory(data_addr, len(prefix)) != prefix:
                data_addr = read_int_from_memory(data_addr, safe=True)
                if not data_addr:
                    return values
            text = read_memory(data_addr, size).decode("ascii", errors="ignore")
        except gdb.error:
            return values
        if not text.startswith("OSRELEASE="):
            return values
        for line in text.splitlines():
            match = re.match(r"(SIZE|OFFSET)\(([^)]+)\)=(\S+)", line)
            if not match:
                continue
            name = match.group(2)
            if name.startswith("struct "):
                name = name[7:]
            name = name.replace(",", ".").replace(" ", "")
            try:
                values[(match.group(1), name)] = int(match.group(3), 0)
            except ValueError:
                continue
        return values

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if args.use_cache and not args.meta:
            if hasattr(self, "cache") and self.cache:
                self.out = self.cache[::]
                self.print_output()
                return

        self.quiet_info("Wait for memory scan")

        self.out = []
        kversion = Kernel.version()
        vmcoreinfo = self.get_vmcoreinfo()
        has_ringbuffer_type = GefUtil.cached_lookup_type("struct printk_ringbuffer") is not None
        is_modern = (
            has_ringbuffer_type
            or ("SIZE", "printk_ringbuffer") in vmcoreinfo
            or (kversion is not None and kversion >= "5.10")
        )
        is_legacy_text = kversion is not None and kversion < "3.5"
        if kversion is None and not is_modern:
            log_end_addr = Ksym.get_addr("log_end")
            log_buf_len_addr = Ksym.get_addr("log_buf_len")
            is_legacy_text = bool((log_end_addr and log_buf_len_addr) or Ksym.get_addr("emit_log_char"))
            has_log_type = GefUtil.cached_lookup_type("struct printk_log") is not None
            if not has_log_type and ("SIZE", "printk_log") not in vmcoreinfo and not is_legacy_text:
                err("Could not determine the Linux printk layout")
                return

        if is_modern:
            ring = KernelDmesgModernRing(vmcoreinfo)
        elif is_legacy_text:
            ring = KernelDmesgOldestRing(vmcoreinfo)
        else:
            ring = KernelDmesgLegacyRing(vmcoreinfo)
        if not ring.resolve():
            return

        if args.meta:
            for message in ring.details:
                self.quiet_info(message)
            for message in ring.warnings:
                self.quiet_warn(message)
            return

        partial = ring.dump()
        self.out = ring.out
        if partial:
            self.warn_add_out(ring.partial_warning)

        if not self.out:
            self.out.append("No retained printk records")
        self.print_output()
        self.cache = self.out[::]
        return



@register_command
class KernelPipeCommand(GenericCommand, BufferingOutput):
    """Dump pipe information."""

    _cmdline_ = "kpipe"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-i", "--inode-filter", type=AddressUtil.parse_address, default=[], action="append",
                        help="filter by specific struct inode.")
    parser.add_argument("-f", "--file-filter", type=AddressUtil.parse_address, default=[], action="append",
                        help="filter by specific struct file.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n.",
        "",
        "Simplified pipe structure:",
        "",
        "+-task_struct-+  +->+-files_struct-+  +->+-fdtable---+  +->+-files*[]----+  +->+-file------+",
        "| ...         |  |  | ...          |  |  | max_fds   |  |  | [0]         |--+  | ...       |",
        "| files       |--+  | fdt          |--+  | fd        |--+  | ...         |     | f_path    |",
        "| ...         |     | ...          |     | ...       |     | [max_fds-1] |     |   dentry  |---+",
        "+-------------+     +--------------+     +-----------+     +-------------+     | ...       |   |",
        "                                                                               +-----------+   |",
        "                                                                                               |",
        "+----------------------------------------------------------------------------------------------+",
        "|",
        "|  +-dentry---+  +->+-inode-----+  +->+-pipe_inode_info--------+  +->+-pipe_buffer-+",
        "|  | ...      |  |  | ...       |  |  | ...                    |  |  | page        |--->page",
        "+->| d_inode  |--+  | i_pipe    |--+  | head, tail, (v5.5~)    |  |  | offset      |",
        "   | ...      |     | ...       |     | max_usage, (v5.5~)     |  |  | len         |",
        "   +----------+     +-----------+     | ring_size, (v5.5~)     |  |  | ...         |",
        "                                      | nrbuf, curbuf, (~v5.4) |  |  +-------------+",
        "                                      | buffers (~v5.4)        |  |  | page        |--->page",
        "                                      | ...                    |  |  | offset      |",
        "                                      | bufs                   |--+  | len         |",
        "                                      | ...                    |     | ...         |",
        "                                      +------------------------+     +-------------+",
        "                                                                     | ...         |",
        "                                                                     +-------------+",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self, pipe_files):
        if hasattr(self, "initialized") and self.initialized:
            return True

        # inode->i_pipe
        offset_i_pipe = self.get_offset_i_pipe(pipe_files)
        if not offset_i_pipe:
            self.quiet_err("Could not find inode->i_pipe")
            return False
        self.offset_i_pipe = offset_i_pipe
        self.quiet_info("offsetof(inode, i_pipe): {:#x}".format(self.offset_i_pipe))

        # pipe_inode_info->bufs
        offset_bufs = self.get_offset_bufs(pipe_files)
        if not offset_bufs:
            self.quiet_err("Could not find pipe_inode_info->bufs")
            return False
        self.offset_bufs = offset_bufs
        self.quiet_info("offsetof(pipe_inode_info, bufs): {:#x}".format(self.offset_bufs))

        kversion = Kernel.kernel_version()
        if "5.5" <= kversion:
            # pipe_inode_info->{head,tail,max_usage,ring_size}
            ret = self.get_offset_head_or_nrbuf(pipe_files)
            if ret is None:
                self.quiet_err("Could not find pipe_inode_info->head")
                return False
            self.offset_head = ret
            self.quiet_info("offsetof(pipe_inode_info, head): {:#x}".format(self.offset_head))
            self.offset_tail = self.offset_head + 4
            self.quiet_info("offsetof(pipe_inode_info, tail): {:#x}".format(self.offset_tail))
            self.offset_max_usage = self.offset_tail + 4
            self.quiet_info("offsetof(pipe_inode_info, max_usage): {:#x}".format(self.offset_max_usage))
            self.offset_ring_size = self.offset_max_usage + 4
            self.quiet_info("offsetof(pipe_inode_info, ring_size): {:#x}".format(self.offset_ring_size))
        else:
            # pipe_inode_info->{nrbuf,curbuf,buffers}
            ret = self.get_offset_head_or_nrbuf(pipe_files)
            if ret is None:
                self.quiet_err("Could not find pipe_inode_info->nrbuf")
                return False
            self.offset_nrbuf = ret
            self.quiet_info("offsetof(pipe_inode_info, nrbuf): {:#x}".format(self.offset_nrbuf))
            self.offset_curbuf = self.offset_nrbuf + 4
            self.quiet_info("offsetof(pipe_inode_info, curbuf): {:#x}".format(self.offset_curbuf))
            self.offset_buffers = self.offset_curbuf + 4
            self.quiet_info("offsetof(pipe_inode_info, buffers): {:#x}".format(self.offset_buffers))

        # pipe_buffer->{page, offset, len, flags}
        """
        struct pipe_buffer {
            struct page *page;
            unsigned int offset, len;
            const struct pipe_buf_operations *ops;
            unsigned int flags;
            unsigned long private;
        };
        """
        self.offset_page = 0
        self.quiet_info("offsetof(pipe_buffer, page): {:#x}".format(self.offset_page))
        self.offset_offset = runtime.current_arch.ptrsize
        self.quiet_info("offsetof(pipe_buffer, offset): {:#x}".format(self.offset_offset))
        self.offset_len = self.offset_offset + 4
        self.quiet_info("offsetof(pipe_buffer, len): {:#x}".format(self.offset_len))
        self.offset_flags = self.offset_len + 4 + runtime.current_arch.ptrsize
        self.quiet_info("offsetof(pipe_buffer, flags): {:#x}".format(self.offset_flags))
        self.sizeof_pipe_buffer = align_to_ptrsize(self.offset_flags + 4) + runtime.current_arch.ptrsize
        self.quiet_info("sizeof(pipe_buffer): {:#x}".format(self.sizeof_pipe_buffer))

        self.initialized = True
        return True

    def get_offset_i_pipe(self, pipe_files):
        """
        struct inode {
            ...
            struct list_head i_lru;
            struct list_head i_sb_list;
            struct list_head i_wb_list;
            ...
        #if defined(CONFIG_IMA) || defined(CONFIG_FILE_LOCKING)
            atomic_t i_readcount;
        #endif
            const struct file_operations *i_fop;     // ~v5.1
            union {                                  // v5.2~
                const struct file_operations *i_fop; // v5.2~
                void (*free_inode)(struct inode *);  // v5.2~
            };                                       // v5.2~
            struct file_lock_context *i_flctx;
            struct address_space i_data;
        #ifdef CONFIG_QUOTA                   // ~v3.18
            struct dquot *i_dquot[MAXQUOTAS]; // ~v3.18 // MAXQUOTAS=2
        #endif                                // ~v3.18
            struct list_head i_devices;       // ~v6.13
            union {                           // v6.14~
                struct list_head i_devices;   // v6.14~
                int i_linklen;                // v6.14~
            };                                // v6.14~
            union {
                struct pipe_inode_info *i_pipe;  <-- here
                struct block_device *i_bdev;
                struct cdev *i_cdev;
                char *i_link;
                unsigned i_dir_seq;
            };
            ...
        };
        """

        # plan 1
        inode = pipe_files[0][1]
        for i in range(0x100):
            # search three list_head
            if not is_double_link_list(inode + runtime.current_arch.ptrsize * (i + 0)):
                continue
            if not is_double_link_list(inode + runtime.current_arch.ptrsize * (i + 2)):
                continue
            if not is_double_link_list(inode + runtime.current_arch.ptrsize * (i + 4)):
                continue
            # search i_pipe
            for j in range(i + 6, 0x100):
                if not is_double_link_list(inode + runtime.current_arch.ptrsize * (j + 0)): # i_devices
                    continue
                if not is_valid_addr_addr(inode + runtime.current_arch.ptrsize * (j + 2)): # i_pipe
                    continue
                if is_double_link_list(inode + runtime.current_arch.ptrsize * (j + 2)): # i_pipe
                    continue
                i_pipe = read_int_from_memory(inode + runtime.current_arch.ptrsize * (j + 2))
                # count 0x10 and 0x01 value
                count_0x10 = 0
                count_0x01 = 0
                for k in range(0x20):
                    v = read_int32_from_memory(i_pipe + 4 * k)
                    if v == 0x01:
                        count_0x01 += 1
                    if v == 0x10:
                        count_0x10 += 1
                    if count_0x10 > 1 or count_0x01 > 3:
                        return runtime.current_arch.ptrsize * (j + 2)

        # plan 2
        for i in range(0x100):
            v = read_int_from_memory(inode + runtime.current_arch.ptrsize * i)
            # i_pipe is valid addr
            if v < 0x10000 or not is_valid_addr(v):
                continue
            # skip invalid chunk
            ret = Kernel.get_slab_contains(v)
            if ret is None:
                continue
            # pipe_inode_info is allocated from kmalloc-192 (x64) or kmalloc-256 (arm64).
            # sometimes it is allocated from kmalloc-512, kmalloc-128, kmalloc-96 and kmalloc-64.
            # Other candidates found are kmalloc-2k, kmalloc-1024 and inode_cache (these are false positives),
            # so these should be excluded.
            if re.search(r"kmalloc(-cg)?-(64|96|128|192|256|512)", ret):
                return runtime.current_arch.ptrsize * i

        return None

    def get_offset_bufs(self, pipe_files):
        """
        [v5.5~]
        struct pipe_inode_info {
            struct mutex mutex;
            wait_queue_head_t rd_wait, wr_wait; // v5.6~
            wait_queue_head_t wait; // ~v5.5
            unsigned int head;
            unsigned int tail;
            unsigned int max_usage;
            unsigned int ring_size;
        #ifdef CONFIG_WATCH_QUEUE // v5.8~
            bool note_loss;       // v5.8~
        #endif                    // v5.8~
            unsigned int nr_accounted; // v5.8~
            unsigned int readers;
            unsigned int writers;
            unsigned int files;
            unsigned int r_counter;
            unsigned int w_counter;
            bool poll_usage; // v5.10~
            struct page *tmp_page;
            struct fasync_struct *fasync_readers;
            struct fasync_struct *fasync_writers;
            struct pipe_buffer *bufs;  <-- here
            struct user_struct *user;
        #ifdef CONFIG_WATCH_QUEUE            // v5.8~
            struct watch_queue *watch_queue; // v5.8~
        #endif                               // v5.8~
        };

        [~v5.4]
        struct pipe_inode_info {
            struct mutex mutex; // v3.10~
            wait_queue_head_t wait;
            unsigned int nrbufs, curbuf, buffers;
            unsigned int readers;
            unsigned int writers;
            unsigned int files; // v3.10~
            unsigned int waiting_writers;
            unsigned int r_counter;
            unsigned int w_counter;
            struct page *tmp_page;
            struct fasync_struct *fasync_readers;
            struct fasync_struct *fasync_writers;
            struct inode *inode; // ~v3.9
            struct pipe_buffer *bufs; <-- here
            struct user_struct *user; // v3.10, v3.12, v3.14, v3.16, v3.18, v4.1, v4.4~
        };

        struct pipe_buffer {
            struct page *page;
            unsigned int offset, len;
            const struct pipe_buf_operations *ops; // allow NULL
            unsigned int flags;
            unsigned long private;
        };
        """

        # plan 1
        seen = []
        for _file, inode in pipe_files:
            if inode in seen:
                continue
            seen.append(inode)
            pipe_inode_info = read_int_from_memory(inode + self.offset_i_pipe)
            for i in range(0x40):
                offset_bufs = runtime.current_arch.ptrsize * i
                if not is_valid_addr_addr(pipe_inode_info + offset_bufs):
                    continue
                if is_double_link_list(pipe_inode_info + offset_bufs):
                    continue
                if is_double_link_list(pipe_inode_info + offset_bufs - runtime.current_arch.ptrsize):
                    continue
                # bufs
                bufs = read_int_from_memory(pipe_inode_info + offset_bufs)
                if is_64bit():
                    if not is_valid_addr_addr(bufs + runtime.current_arch.ptrsize * 0): # page
                        continue
                    len_ = read_int32_from_memory(bufs + runtime.current_arch.ptrsize * 1 + 4) # len
                    if len_ == 0 or is_valid_addr_addr(bufs + runtime.current_arch.ptrsize * 1): # offset||len
                        continue
                    ops = read_int_from_memory(bufs + runtime.current_arch.ptrsize * 2) # ops
                    if ops != 0 and not is_valid_addr(ops):
                        continue
                    if is_valid_addr_addr(bufs + runtime.current_arch.ptrsize * 3): # flags
                        continue
                    if is_valid_addr_addr(bufs + runtime.current_arch.ptrsize * 4): # private
                        continue
                else:
                    if not is_valid_addr_addr(bufs + runtime.current_arch.ptrsize * 0): # page
                        continue
                    if is_valid_addr_addr(bufs + runtime.current_arch.ptrsize * 1): # offset
                        continue
                    len_ = read_int_from_memory(bufs + runtime.current_arch.ptrsize * 2) # len
                    if len_ == 0 or is_valid_addr_addr(len_):
                        continue
                    ops = read_int_from_memory(bufs + runtime.current_arch.ptrsize * 3) # ops
                    if ops != 0 and not is_valid_addr(ops):
                        continue
                    if is_valid_addr_addr(bufs + runtime.current_arch.ptrsize * 4): # flags
                        continue
                    if is_valid_addr_addr(bufs + runtime.current_arch.ptrsize * 5): # private
                        continue
                # found
                self.quiet_info("offset of bufs is found by heuristic way1")
                return offset_bufs

        # plan 2
        kversion = Kernel.kernel_version()
        inode = pipe_files[0][1]
        pipe_inode_info = read_int_from_memory(inode + self.offset_i_pipe)
        for i in range(0x80):
            if not is_valid_addr(pipe_inode_info + runtime.current_arch.ptrsize * i):
                break
            v = read_int_from_memory(pipe_inode_info + runtime.current_arch.ptrsize * i)
            # bufs is valid addr
            if v < 0x10000 or not is_valid_addr(v):
                continue
            # bufs is not self
            if v == pipe_inode_info:
                continue
            # skip invalid chunk
            ret = Kernel.get_slab_contains(v)
            if ret is None:
                continue
            # pipe_inode_info is allocated from kmalloc-1k (x64) or kmalloc-512 (x86)
            if re.search(r"kmalloc(-cg)?-(1k|1024|512)", ret):
                self.quiet_info("offset of bufs is found by heuristic way2-1")
                return runtime.current_arch.ptrsize * i
            # before v5.5, pipe_buffer is allocated not from slub, but `user` is allocated from slub.
            if kversion < "5.5" and "uid_cache" in ret:
                self.quiet_info("offset of bufs is found by heuristic way2-2")
                return runtime.current_arch.ptrsize * (i - 1)
        return None

    def get_offset_head_or_nrbuf(self, pipe_files):
        inode = pipe_files[0][1]
        pipe_inode_info = read_int_from_memory(inode + self.offset_i_pipe)

        for i in range(3, 0x40):
            if is_64bit():
                # head||tail/nrbuf||curbuf is not address
                v1 = read_int_from_memory(pipe_inode_info + runtime.current_arch.ptrsize * i)
                if is_valid_addr(v1):
                    continue
                # head/nrbuf is too large
                v1_32 = read_int32_from_memory(pipe_inode_info + runtime.current_arch.ptrsize * i)
                if v1_32 > 0x100:
                    continue
                # max_usage||ring_size/buffers||readers is not address
                v2 = read_int_from_memory(pipe_inode_info + runtime.current_arch.ptrsize * (i + 1))
                if is_valid_addr(v2):
                    continue
                # max_usage/buffers is too large or zero
                v2_32 = read_int32_from_memory(pipe_inode_info + runtime.current_arch.ptrsize * (i + 1))
                if v2_32 > 0x100 or v2_32 == 0:
                    continue
                return runtime.current_arch.ptrsize * i
            else:
                # head/nrbuf is not address
                v1 = read_int_from_memory(pipe_inode_info + runtime.current_arch.ptrsize * i)
                if is_valid_addr(v1):
                    continue
                # head/nrbuf is too large
                v1_32 = read_int32_from_memory(pipe_inode_info + runtime.current_arch.ptrsize * i)
                if v1_32 > 0x100:
                    continue
                # max_usage/buffers is not address
                v2 = read_int_from_memory(pipe_inode_info + runtime.current_arch.ptrsize * (i + 2))
                if is_valid_addr(v2):
                    continue
                # max_usage/buffers is too large or zero
                v2_32 = read_int32_from_memory(pipe_inode_info + runtime.current_arch.ptrsize * (i + 2))
                if v2_32 > 0x100 or v2_32 == 0:
                    continue
                return runtime.current_arch.ptrsize * i
        return None

    def get_pipe_files(self):
        # struct file of pipe
        ret = gdb.execute("ktask --quiet --no-pager --user-process-only --print-fd", to_string=True)
        pipe_files = []
        for line in ret.splitlines():
            m = re.search(r"\d+\s+(0x\S+) 0x\S+ (0x\S+) pipe:\[\d+\]", line)
            if not m:
                continue
            file = int(m.group(1), 16)
            inode = int(m.group(2), 16)
            pipe_files.append((file, inode))
        if pipe_files:
            self.quiet_info("Num of pipe: {:d}".format(len({x[1] for x in pipe_files})))
        return pipe_files

    def get_flags_str(self, flags_value):
        flags_dic = {
            0x01: "PIPE_BUF_FLAG_LRU",
            0x02: "PIPE_BUF_FLAG_ATOMIC",
            0x04: "PIPE_BUF_FLAG_GIFT",
            0x08: "PIPE_BUF_FLAG_PACKET",
            0x10: "PIPE_BUF_FLAG_CAN_MERGE",
            0x20: "PIPE_BUF_FLAG_WHOLE",
            0x40: "PIPE_BUF_FLAG_LOSS",
        }
        flags = []
        for k, v in flags_dic.items():
            if flags_value & k:
                flags.append(v)

        flags_str = " | ".join(flags)
        if flags_str == "":
            flags_str = "none"
        return flags_str

    def dump_pipe(self, pipe_files):
        heap_page_color = Config.get_gef_setting("theme.heap_page_address")
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        used_address_color = Config.get_gef_setting("theme.heap_chunk_address_used")
        kversion = Kernel.kernel_version()

        inodes = {}
        for file, inode in pipe_files:
            inodes[inode] = inodes.get(inode, []) + [file]

        for inode, files in inodes.items():
            if self.args.inode_filter and inode not in self.args.inode_filter:
                continue

            if self.args.file_filter and not (set(self.args.file_filter) & set(files)):
                continue

            related_files = ", ".join(["{:#x}".format(x) for x in files])
            self.out.append("inode: {:#x} (related struct file: {:s})".format(inode, related_files))

            pipe_inode_info = read_int_from_memory(inode + self.offset_i_pipe)
            self.out.append("  pipe_inode_info: {:#x}".format(pipe_inode_info))

            pipe_buffer = read_int_from_memory(pipe_inode_info + self.offset_bufs)
            self.out.append("    pipe_buffer: {:#x}".format(pipe_buffer))

            if "5.5" <= kversion:
                head = read_int32_from_memory(pipe_inode_info + self.offset_head)
                tail = read_int32_from_memory(pipe_inode_info + self.offset_tail)
                max_usage = read_int32_from_memory(pipe_inode_info + self.offset_max_usage)
                ring_size = read_int32_from_memory(pipe_inode_info + self.offset_ring_size)
                self.out.append("    head: {:d}, tail: {:d}, max: {:d}, ring_size: {:d}".format(
                    head, tail, max_usage, ring_size,
                ))
            else:
                nrbuf = read_int32_from_memory(pipe_inode_info + self.offset_nrbuf)
                curbuf = read_int32_from_memory(pipe_inode_info + self.offset_curbuf)
                buffers = read_int32_from_memory(pipe_inode_info + self.offset_buffers)
                self.out.append("    nrbuf: {:d}, curbuf: {:d}, buffers: {:d}".format(
                    nrbuf, curbuf, buffers,
                ))
                head = curbuf + nrbuf
                tail = curbuf
                max_usage = buffers

            used_range = [x % max_usage for x in range(tail, head)]
            for idx in range(max_usage):
                base = pipe_buffer + self.sizeof_pipe_buffer * idx
                page = read_int_from_memory(base + self.offset_page)
                offset = read_int32_from_memory(base + self.offset_offset)
                len_ = read_int32_from_memory(base + self.offset_len)
                flags = read_int32_from_memory(base + self.offset_flags)
                virt = Kernel.page2virt(page)

                if idx in used_range:
                    status = Color.colorify("used", used_address_color)
                else:
                    status = Color.colorify("free", freed_address_color)

                if head % max_usage == idx:
                    head_marker = "head"
                else:
                    head_marker = "    "

                if tail % max_usage == idx:
                    tail_marker = "tail"
                else:
                    tail_marker = "    "

                out = "    {:s} {:s} {:s} [{:02d}] page: {:#x}, ".format(
                    head_marker, tail_marker, status, idx, page,
                )
                if virt:
                    colored_virt = Color.colorify_hex(virt, heap_page_color)
                    out += "(virt: {:s}), ".format(colored_virt)
                out += "offset: {:#x}, len: {:#x}, flags: {:#x} ({:s})".format(
                    offset, len_, flags, self.get_flags_str(flags),
                )
                self.out.append(out)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        allocator = Kernel.get_slab_type()
        if allocator not in ["SLUB", "SLUB_TINY", "SLAB"]:
            err("Unsupported: SLOB, Unknown allocator")
            return

        # init
        kinfo = Kernel.get_kernel_layout()
        if kinfo.has_none:
            self.quiet_err("The kernel .text area could not be determined correctly")
            return

        pipe_files = self.get_pipe_files()
        if not pipe_files:
            self.quiet_info("Nothing to dump")
            return

        ret = self.initialize(pipe_files)
        if ret is False:
            return

        # dump
        self.out = []
        self.dump_pipe(pipe_files)
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelBpfCommand(GenericCommand, BufferingOutput):
    """Dump the BPF information."""

    _cmdline_ = "kbpf"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-p", "--only-progs", action="store_true", help="print progs only.")
    parser.add_argument("-m", "--only-maps", action="store_true", help="print maps only.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n.",
        "",
        "Simplified bpf structure:",
        "",
        "+-prog_idr----+   +--->+-xa_node----------+   +--------->+-bpf_prog-------------+",
        "| idr_rt      |   |    | shift            |   |          | ...                  |",
        "|   xa_lock   |   |    | ...              |   |          | type                 |",
        "|   xa_flags  |   |    | count            |   |          | expected_attach_type |",
        "|   xa_head   |---+    | ...              |   |          | len                  |",
        "| idr_base    |        | slots[0]         |---+          | jited_len            |",
        "| idr_next    |        | slots[1]         |--->xa_node   | tag[8]               |",
        "+-------------+        | ...              |    or        | ...                  |",
        "                       | slots[15 or 63]  |    bpf_prog  | bpf_func             |---> BPF-code",
        "                       | ...              |              | ...                  |",
        "                       +------------------+              | aux                  |",
        "                                                         | ...                  |",
        "                                                         +----------------------+",
        "",
        "+-map_idr-----+   +--->+-xa_node----------+   +--------->+-bpf_array------------+",
        "| idr_rt      |   |    | shift            |   |          | map                  |",
        "|   xa_lock   |   |    | ...              |   |          |   ...                |",
        "|   xa_flags  |   |    | count            |   |          |   map_type           |",
        "|   xa_head   |---+    | ...              |   |          |   key_size           |",
        "| idr_base    |        | slots[0]         |---+          |   value_size         |",
        "| idr_next    |        | slots[1]         |--->xa_node   |   max_entries        |",
        "+-------------+        | ...              |    or        |   ...                |",
        "                       | slots[15 or 63]  |    bpf_array | elem_size            |",
        "                       | ...              |              | index_mask           |",
        "                       +------------------+              | ...                  |",
        "                                                         +----------------------+",
        "                                                         | value[0]             |",
        "                                                         | value[1]             |",
        "                                                         | ...                  |",
        "                                                         | value[max_entries-1] |",
        "                                                         +----------------------+",
    ]
    _note_ = "\n".join(_note_)

    def dump_bpf_progs_func(self, orig_prog, bpf_func, jited_len):
        lines = self.kbpf.disassemble_prog(orig_prog, bpf_func, jited_len, self.kbpf.seccomp_tools_command)
        if lines is None:
            self.err_add_out("Memory read error")
        else:
            self.out.extend(lines)
        return

    def dump_bpf_progs(self, progs):
        self.out.append(titlify("prog_idr"))
        fmt = "{:3s} {:6s} {:18s} {:16s} {:23s} {:30s} {:16s} {:18s} {:18s} {:9s} {:18s}"
        legend = ["#", "id", "bpf_prog", "name", "bpf_prog_type", "bpf_attach_type", "tag", "bpf_prog_aux", "bpf_func", "jited_len", "orig_prog"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        fmt = "{:<3d} {:<6d} {:#018x} {:16s} {:23s} {:30s} {:16s} {:#018x} {:#018x} {:<#9x} {:#018x}"
        for i, prog in enumerate(progs):
            bpf_type = prog["type"]
            bpf_attach_type = prog["expected_attach_type"]
            jited_len = prog["jited_len"]
            orig_prog = prog["orig_prog"]
            if bpf_type < len(self.kbpf.defined_prog_types):
                t1 = self.kbpf.defined_prog_types[bpf_type]
            else:
                t1 = "???"
            if bpf_attach_type is None:
                t2 = "-"
            elif bpf_attach_type < len(self.kbpf.defined_attach_types):
                t2 = self.kbpf.defined_attach_types[bpf_attach_type]
            else:
                t2 = "???"
            tag = prog["tag"]
            aux = prog["aux"]
            bpf_func = prog["bpf_func"]
            name = self.format_name(prog["name"])
            self.out.append(fmt.format(i, prog["id"], prog["address"], name, t1, t2, tag, aux, bpf_func, jited_len, orig_prog))

            if self.args.verbose:
                self.dump_bpf_progs_func(orig_prog, bpf_func, jited_len)
                self.out.append(titlify(""))
        return

    def dump_bpf_maps(self, maps):
        self.out.append(titlify("map_idr"))
        fmt = "{:3s} {:6s} {:18s} {:16s} {:21s} {:10s} {:10s} {:10s} {:18s}"
        legend = ["#", "id", "bpf_map", "name", "bpf_map_type", "key_size", "value_size", "max_ents", "array"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        fmt = "{:<3d} {:<6d} {:#018x} {:16s} {:21s} {:#010x} {:#010x} {:#010x} {:18s}"
        for i, m in enumerate(maps):
            map_type = m["type"]
            if map_type < len(self.kbpf.defined_map_types):
                t1 = self.kbpf.defined_map_types[map_type]
            else:
                t1 = "???"
            key_size = m["key_size"]
            val_size = m["value_size"]
            max_ents = m["max_entries"]
            union_array = m["union_array"]
            if map_type not in self.kbpf.array_map_types:
                array = "-"
            elif union_array is None:
                array = "???"
            else:
                array = "{:#018x}".format(union_array)
            name = self.format_name(m["name"])
            self.out.append(fmt.format(i, m["id"], m["address"], name, t1, key_size, val_size, max_ents, array).rstrip())

            if self.args.verbose:
                if union_array is not None and map_type == 2: # ARRAY
                    # each element occupies round_up(value_size, 8) bytes
                    count = (align(val_size, 8) * max_ents + runtime.current_arch.ptrsize - 1) // runtime.current_arch.ptrsize
                    res = gdb.execute("dereference -n {:#x} {:#x}".format(union_array, count), to_string=True)
                    self.out.append(res.rstrip())
        return

    @staticmethod
    def format_name(name):
        if name is not None:
            return name
        if "4.15" <= Kernel.version(): # BPF_OBJ_NAME_LEN is introduced from 4.15
            return "???"
        return "-"

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.kbpf = Kernel.bpf()
        self.quiet_info("Wait for memory scan")

        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "4.13":
            # prog_idr and map_idr are introduced from 4.13
            self.quiet_err("Unsupported before v4.13")
            return

        stv_bpf_ret = gdb.execute("ksyscalls -f bpf --quiet --no-pager", to_string=True)
        if "bpf" not in stv_bpf_ret:
            self.quiet_err("bpf syscall is unimplemented")
            return
        elif "invalid bpf" in stv_bpf_ret:
            self.quiet_err("bpf syscall is disabled")
            return

        # init
        ret = self.kbpf.initialize()
        progs = maps = None
        if ret:
            try:
                if args.meta or not args.only_maps:
                    progs = self.kbpf.get_progs()
                else:
                    progs = []
                if args.meta or not args.only_progs:
                    maps = self.kbpf.get_maps()
                else:
                    maps = []
            except gdb.MemoryError:
                pass
        if args.meta or not ret:
            meta = self.kbpf.meta[:]
            if maps is not None:
                meta.append(("info", "Num of progs: {:d}".format(len(progs))))
                meta.append(("info", "Num of maps: {:d}".format(len(maps))))
            for func, line in Kernel.export_meta(self, meta):
                func(line)
        if not ret:
            self.quiet_err("Failed to initialize")
            return
        if maps is None:
            self.quiet_err("Not found")
            return

        if args.meta:
            return

        # dump
        self.out = []
        if not args.only_maps:
            self.dump_bpf_progs(progs)
        if not args.only_progs:
            self.dump_bpf_maps(maps)

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelIpcsCommand(GenericCommand, BufferingOutput):
    """Dump IPCs information (System V semaphore, message queue and shared memory)."""

    _cmdline_ = "kipcs"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-v", "--verbose", action="store_true", help="dump the beginning of msg_msg.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n.",
        "",
        "Simplified ipc structure:",
        "",
        "+-task_struct-+  +-->+-nsproxy--+  +-->+-ipc_namespace-+",
        "| ...         |  |   | ...      |  |   | ...           |",
        "| nsproxy     |--+   | ipc_ns   |--+   | ids[0] (sem)  |",
        "| ...         |      | ...      |      |   ...         |",
        "+-------------+      +----------+      |   ipcs_idr    |",
        "                                       |     xa_head   |-->xarray-->+-sem_array-+",
        "                                       |     ...       |            | ...       |",
        "                                       | ids[1] (msg)  |            +-----------+",
        "                                       |   ...         |",
        "                                       |   ipcs_idr    |",
        "                                       |     xa_head   |-->xarray-->+-msg_queue-+",
        "                                       |     ...       |            | ...       |",
        "                                       | ids[2] (shm)  |            +-----------+",
        "                                       |   ...         |",
        "                                       |   ipcs_idr    |",
        "                                       |     xa_head   |-->xarray-->+-shmid_kernel-+",
        "                                       |     ...       |            | ...          |",
        "                                       | ...           |            +--------------+",
        "                                       +---------------+",
    ]
    _note_ = "\n".join(_note_)

    def get_all_ipc_ns(self):
        res = gdb.execute("ktask --print-namespace --user-process-only --no-pager --quiet", to_string=True)
        r = re.findall(r"nsproxy->ipc_ns\s+(0x\S+)", res)

        ipc_ns_list = []
        # do not use `set()` because the order is important.
        for x in r:
            x = int(x, 16)
            if x not in ipc_ns_list:
                ipc_ns_list.append(x)
        return ipc_ns_list

    def initialize(self, ipc_ns_list):
        if hasattr(self, "initialized") and self.initialized:
            return True

        if ipc_ns_list == []:
            return False

        if ipc_ns_list == [0]:
            err("Could not find valid ipc_ns (maybe CONFIG_SYSVIPC=n)")
            return False

        # ipc_namespace
        """
        struct ipc_namespace {
            refcount_t count; // ~5.10
            struct ipc_ids {
                int in_use;
                unsigned short seq;
                struct rw_semaphore {
                    atomic_long_t count;
                    atomic_long_t owner;
                #ifdef CONFIG_RWSEM_SPIN_ON_OWNER
                    struct optimistic_spin_queue osq;
                #endif
                    raw_spinlock_t wait_lock;
                    struct list_head wait_list;
                #ifdef CONFIG_DEBUG_RWSEMS
                    void *magic;
                #endif
                #ifdef CONFIG_DEBUG_LOCK_ALLOC
                    struct lockdep_map dep_map;
                #endif
                } rwsem;
                struct idr {
                    struct radix_tree_root { // =struct xarray
                        spinlock_t xa_lock;
                        gfp_t xa_flags;
                        void __rcu *xa_head;
                    } idr_rt;
                    unsigned int idr_base;
                    unsigned int idr_next;
                } ipcs_idr;
                int max_idx;
                int last_idx;
            #ifdef CONFIG_CHECKPOINT_RESTORE
                int next_id;
            #endif
                struct rhashtable key_ht;
            } ids[3];
            ...
        """
        kversion = Kernel.kernel_version()
        if "5.11" <= kversion:
            self.offset_ids = 0
        else:
            self.offset_ids = runtime.current_arch.ptrsize
        self.quiet_info("offsetof(ipc_namespace, ids): {:#x}".format(self.offset_ids))

        # offsetof(ipc_ids, ipcs_idr.idr_rt.xa_head): tagged valid pointer is `xa_head`.
        # sizeof(ids[0]): find two `xa_head` and calculate the distance.
        init_ipc_ns = ipc_ns_list[0]
        found = []
        first_xa_flags = None
        for i in range(6, 120):
            base = self.offset_ids + runtime.current_arch.ptrsize * i
            """
            [x64 before using IPC]
            0xffffffff8b1841f8|+0x0038|+007: 0x0080000400000000 <- xa_lock, xa_flags
            0xffffffff8b184200|+0x0040|+008: 0x0000000000000000 <- xa_head
            0xffffffff8b184208|+0x0048|+009: 0x0000000000000000 <- idr_base, idr_next
            [x64 after using IPC]
            0xffffffff8b1841f8|+0x0038|+007: 0x0080000400000000
            0xffffffff8b184200|+0x0040|+008: 0xffff9250c7dc2002 ->  0x0000000000000001
            0xffffffff8b184208|+0x0048|+009: 0x0000000100000000
            [x64 after deleting IPC]
            0xffffffff8b1841f8|+0x0038|+007: 0x0080000400000000
            0xffffffff8b184200|+0x0040|+008: 0x0000000000000000
            0xffffffff8b184208|+0x0048|+009: 0x0000000100000000

            [x86 before using IPC]
            0xc1b4e104|+0x0024|+009: 0x00000000 <- xa_lock
            0xc1b4e108|+0x0028|+010: 0x00800004 <- xa_flags
            0xc1b4e10c|+0x002c|+011: 0x00000000 <- xa_head
            0xc1b4e110|+0x0030|+012: 0x00000000 <- idr_base
            0xc1b4e114|+0x0034|+013: 0x00000000 <- idr_next
            [x86 after using IPC]
            0xc1b4e104|+0x0024|+009: 0x00000000
            0xc1b4e108|+0x0028|+010: 0x00800004
            0xc1b4e10c|+0x002c|+011: 0xc2c67392  ->  0x00000001
            0xc1b4e110|+0x0030|+012: 0x00000000
            0xc1b4e114|+0x0034|+013: 0x00000001
            [x86 after deleting IPC]
            0xc1b4e104|+0x0024|+009: 0x00000000
            0xc1b4e108|+0x0028|+010: 0x00800004
            0xc1b4e10c|+0x002c|+011: 0x00000000
            0xc1b4e110|+0x0030|+012: 0x00000000
            0xc1b4e114|+0x0034|+013: 0x00000001
            """

            # xa_flags
            x = read_int_from_memory(init_ipc_ns + base - runtime.current_arch.ptrsize)
            if x == 0 or is_valid_addr(x):
                continue
            if first_xa_flags is not None and first_xa_flags != x:
                continue

            # xa_head
            y = read_int_from_memory(init_ipc_ns + base)
            if y:
                if not is_valid_addr(y):
                    continue
                if y & 0x2 != 0x2: # xa_head is NULL or tagged address
                    continue

            # idr_base, idr_next
            if is_32bit():
                z1 = read_int_from_memory(init_ipc_ns + base + runtime.current_arch.ptrsize) # idr_base
                z2 = read_int_from_memory(init_ipc_ns + base + runtime.current_arch.ptrsize * 2) # idr_next
                if is_valid_addr(z1) or is_valid_addr(z2):
                    continue
                if y and z1 == 0 and z2 == 0:
                    continue
            else:
                z = read_int_from_memory(init_ipc_ns + base + runtime.current_arch.ptrsize) # idr_base, idr_next
                if is_valid_addr(z): # idr_base, idr_next
                    continue
                if y and z == 0:
                    continue

            # first found
            if not hasattr(self, "offset_xa_head"):
                self.offset_xa_head = base - self.offset_ids
                first_xa_flags = x

            # found
            found.append(base - self.offset_ids)

            # exit loop?
            if len(found) >= 2:
                self.sizeof_ipc_ids = found[1] - found[0]
                break
        else:
            self.quiet_err("Could not find ipc_namespace->ids[0].ipcs_idr.idr_rt.xa_head")
            self.quiet_err("Not recognized sizeof(struct ipc_ids)")
            self.quiet_err("Maybe CONFIG_SYSVIPC=n")
            return False
        self.quiet_info("offsetof(ipc_ids, ipcs_idr.idr_rt.xa_head): {:#x}".format(self.offset_xa_head))
        self.quiet_info("sizeof(struct ipc_ids): {:#x}".format(self.sizeof_ipc_ids))

        # xa_node
        """
        struct xa_node {
            unsigned char shift;
            unsigned char offset;
            unsigned char count;
            unsigned char nr_values;
            struct xa_node __rcu *parent;
            struct xarray *array;
            union {
                struct list_head private_list;
                struct rcu_head rcu_head;
            };
            void __rcu *slots[XA_CHUNK_SIZE];
            union {
                unsigned long tags[XA_MAX_MARKS][XA_MARK_LONGS];
                unsigned long marks[XA_MAX_MARKS][XA_MARK_LONGS];
            };
        };
        """
        # xa_node->{shift,count,slots}
        self.offset_shift = 0
        self.offset_count = 2
        self.offset_slots = runtime.current_arch.ptrsize * 5

        # kern_ipc_perm
        """
        struct kern_ipc_perm {
            spinlock_t lock;
            bool deleted;
            int id;
            key_t key;
            kuid_t uid;
            kgid_t gid;
            kuid_t cuid;
            kgid_t cgid;
            umode_t mode;
            unsigned long seq;
            void *security;
            struct rhash_head khtnode;
            struct rcu_head rcu;
            refcount_t refcount;
        } ____cacheline_aligned_in_smp __randomize_layout;
        """
        self.offset_id = 4 + 4
        self.offset_key = self.offset_id + 4
        self.offset_uid = self.offset_key + 4
        self.offset_gid = self.offset_uid + 4
        self.offset_mode = self.offset_gid + 4 + 4 + 4

        self.initialized = True
        return True

    def parse_xarray(self, ptr, root=False):
        if ptr == 0:
            return []

        ptr &= ~3 # untagged

        if root:
            # ptr is &ipc_ids[i]
            node = read_int_from_memory(ptr + self.offset_xa_head)
            return self.parse_xarray(node)

        shift = read_int8_from_memory(ptr + self.offset_shift)
        count = read_int8_from_memory(ptr + self.offset_count)
        slots = ptr + self.offset_slots
        elems = []
        for i in range(64): # 16 or 64
            x = read_int_from_memory(slots + runtime.current_arch.ptrsize * i)
            if x == 0:
                continue
            if shift:
                elems += self.parse_xarray(x)
            else:
                elems.append(x)
            count -= 1
            if count == 0:
                break
        return elems

    def dump_ipc_sem_ids(self, ipc_ids_ptr):
        """
        struct sem_array {
            struct kern_ipc_perm sem_perm;
            time64_t sem_ctime;
            struct list_head pending_alter;
            struct list_head pending_const;
            struct list_head list_id;
            int sem_nsems;
            ...
        } __randomize_layout;
        """
        self.out.append(titlify("Semaphore Arrays"))
        fmt = "{:18s} {:5s} {:10s} {:4s} {:4s} {:5s} {:s}"
        legend = ["sem_array", "semid", "key", "uid", "gid", "perms", "nsems"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        elems = self.parse_xarray(ipc_ids_ptr, root=True)
        for e in elems:
            semid = read_int32_from_memory(e + self.offset_id)
            key = read_int32_from_memory(e + self.offset_key)
            uid = read_int32_from_memory(e + self.offset_uid)
            gid = read_int32_from_memory(e + self.offset_gid)
            mode = read_int16_from_memory(e + self.offset_mode)

            if not hasattr(self, "offset_sem_nsems"):
                for i in range(1, 64):
                    # search pending_alter, pending_const, list_id
                    base = self.offset_mode + runtime.current_arch.ptrsize * i
                    addrs = [read_int_from_memory(e + base + runtime.current_arch.ptrsize * j) for j in range(6)]
                    if all(is_valid_addr(x) for x in addrs):
                        # found
                        self.offset_sem_nsems = base + runtime.current_arch.ptrsize * 6
                        break
            if hasattr(self, "offset_sem_nsems"):
                nsems = read_int_from_memory(e + self.offset_sem_nsems)
                self.out.append("{:#018x} {:<5d} {:#010x} {:<4d} {:<4d} {:#5o} {:d}".format(
                    e, semid, key, uid, gid, mode, nsems,
                ))
            else:
                self.out.append("{:#018x} {:<5d} {:#010x} {:<4d} {:<4d} {:#5o} {:s}".format(
                    e, semid, key, uid, gid, mode, "?",
                ))

        return

    def dump_ipc_msg_ids(self, ipc_ids_ptr):
        """
        struct msg_queue {
            struct kern_ipc_perm q_perm;
            time64_t q_stime;
            time64_t q_rtime;
            time64_t q_ctime;
            unsigned long q_cbytes;
            unsigned long q_qnum;
            unsigned long q_qbytes;
            struct pid *q_lspid;
            struct pid *q_lrpid;
            struct list_head q_messages; <--> msg_msg.m_list
            struct list_head q_receivers;
            struct list_head q_senders;
        } __randomize_layout;

        struct msg_msg {
            struct list_head m_list;
            long m_type;
            size_t m_ts; /* message text size */
            struct msg_msgseg *next;
            void *security;
        };
        """
        self.out.append(titlify("Message Queues"))
        fmt = "{:18s} {:5s} {:10s} {:4s} {:4s} {:5s} {:10s} {:s}"
        legend = ["msg_queue", "msqid", "key", "uid", "gid", "perms", "used-bytes", "messages"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        elems = self.parse_xarray(ipc_ids_ptr, root=True)
        for e in elems:
            msqid = read_int32_from_memory(e + self.offset_id)
            key = read_int32_from_memory(e + self.offset_key)
            uid = read_int32_from_memory(e + self.offset_uid)
            gid = read_int32_from_memory(e + self.offset_gid)
            mode = read_int16_from_memory(e + self.offset_mode)

            if not hasattr(self, "offset_q_cbytes"):
                for i in range(1, 64):
                    # search q_messages, q_receivers, q_senders
                    base = self.offset_mode + runtime.current_arch.ptrsize * i
                    addrs = [read_int_from_memory(e + base + runtime.current_arch.ptrsize * j) for j in range(6)]
                    if all(is_valid_addr(x) for x in addrs):
                        x = read_int_from_memory(e + base + runtime.current_arch.ptrsize * 6)
                        if not is_valid_addr(x):
                            # found
                            self.offset_q_cbytes = base - runtime.current_arch.ptrsize * 5
                            self.offset_q_qnum = base - runtime.current_arch.ptrsize * 4
                            self.offset_q_messages = base
                            break
            if hasattr(self, "offset_q_cbytes"):
                q_cbytes = read_int_from_memory(e + self.offset_q_cbytes)
                q_qnum = read_int_from_memory(e + self.offset_q_qnum)
                self.out.append("{:#018x} {:<5d} {:#010x} {:<4d} {:<4d} {:#5o} {:<#10x} {:<d}".format(
                    e, msqid, key, uid, gid, mode, q_cbytes, q_qnum,
                ))
            else:
                self.out.append("{:#018x} {:<5d} {:#010x} {:<4d} {:<4d} {:#5o} {:10s} {:s}".format(
                    e, msqid, key, uid, gid, mode, "?", "?",
                ))

            if self.args.verbose:
                if hasattr(self, "offset_q_messages"):
                    current = e + self.offset_q_messages
                    seen = [current]
                    while is_valid_addr(current):
                        current = read_int_from_memory(current)
                        if current in seen:
                            break
                        seen.append(current)
                        self.out.append("msg_msg: {:#x}".format(current))
                        res = gdb.execute("dereference -n {:#x} 8".format(current), to_string=True)
                        self.out.append(res.rstrip())
        return

    def dump_ipc_shm_ids(self, ipc_ids_ptr):
        """
        struct shmid_kernel {
            struct kern_ipc_perm shm_perm;
            struct file *shm_file;
            unsigned long shm_nattch;
            unsigned long shm_segsz;
            ...
        } __randomize_layout;
        """
        self.out.append(titlify("Shared Memory Segments"))
        fmt = "{:18s} {:5s} {:10s} {:4s} {:4s} {:5s} {:10s} {:s}"
        legend = ["shmid_kernel", "shmid", "key", "uid", "gid", "perms", "bytes", "nattch"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        elems = self.parse_xarray(ipc_ids_ptr, root=True)
        for e in elems:
            shmid = read_int32_from_memory(e + self.offset_id)
            key = read_int32_from_memory(e + self.offset_key)
            uid = read_int32_from_memory(e + self.offset_uid)
            gid = read_int32_from_memory(e + self.offset_gid)
            mode = read_int16_from_memory(e + self.offset_mode)

            if not hasattr(self, "offset_shm_nattch"):
                for i in range(1, 64):
                    # search shm_file and shm_segsz
                    base = self.offset_mode + runtime.current_arch.ptrsize * i
                    x = read_int_from_memory(e + base)
                    y = read_int_from_memory(e + base + runtime.current_arch.ptrsize * 2)
                    if is_valid_addr(x) and y != 0 and y % 0x1000 == 0:
                        # found
                        self.offset_shm_nattch = base + runtime.current_arch.ptrsize
                        self.offset_shm_segsz = base + runtime.current_arch.ptrsize * 2
                        break
            if hasattr(self, "offset_shm_nattch"):
                nattch = read_int_from_memory(e + self.offset_shm_nattch)
                segsz = read_int_from_memory(e + self.offset_shm_segsz)
                self.out.append("{:#018x} {:<5d} {:#010x} {:<4d} {:<4d} {:#5o} {:<#10x} {:<d}".format(
                    e, shmid, key, uid, gid, mode, segsz, nattch,
                ))
            else:
                self.out.append("{:#018x} {:<5d} {:#010x} {:<4d} {:<4d} {:#5o} {:10s} {:s}".format(
                    e, shmid, key, uid, gid, mode, "?", "?",
                ))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        kversion = Kernel.kernel_version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "4.20":
            # xarray is introduced from 4.20
            self.quiet_err("Unsupported before v4.20")
            return

        ipc_ns_list = self.get_all_ipc_ns()
        if not ipc_ns_list:
            self.quiet_info("Nothing to dump")
            return

        ret = self.initialize(ipc_ns_list)
        if not ret:
            self.quiet_err("Failed to initialize")
            return

        self.out = []
        for i, ipc_ns in enumerate(ipc_ns_list):
            if i == 0:
                self.out.append(titlify("init_ipc_ns: {:#x}".format(ipc_ns)))
            else:
                self.out.append(titlify("ipc_ns: {:#x}".format(ipc_ns)))
            self.dump_ipc_sem_ids(ipc_ns + self.offset_ids + self.sizeof_ipc_ids * 0)
            self.dump_ipc_msg_ids(ipc_ns + self.offset_ids + self.sizeof_ipc_ids * 1)
            self.dump_ipc_shm_ids(ipc_ns + self.offset_ids + self.sizeof_ipc_ids * 2)

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelDeviceIOCommand(GenericCommand, BufferingOutput):
    """Dump I/O-port and I/O-memory information."""

    _cmdline_ = "kdevio"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified ioport structure:",
        "",
        "+-ioport_resource-+       +-------->+-resource--------+",
        "| start           |       |         | start           |",
        "| end             |       |         | end             |",
        "| name            |       |         | name            |",
        "| flags           |       |         | flags           |",
        "| desc            |       |         | desc            |",
        "| parent          |-------+         | parent          |",
        "| sibling         |--> resource     | sibling         |",
        "| child           |--> resource     | child           |",
        "+-----------------+                 +-----------------+",
        "",
        "Simplified iomem structure:",
        "",
        "+-iomem_resource--+       +-------->+-resource--------+",
        "| start           |       |         | start           |",
        "| end             |       |         | end             |",
        "| name            |       |         | name            |",
        "| flags           |       |         | flags           |",
        "| desc            |       |         | desc            |",
        "| parent          |-------+         | parent          |",
        "| sibling         |--> resource     | sibling         |",
        "| child           |--> resource     | child           |",
        "+-----------------+                 +-----------------+",
    ]
    _note_ = "\n".join(_note_)

    def dump_resource(self, addr):
        if not is_valid_addr(addr):
            return []
        if addr in self.seen:
            return []
        self.seen.append(addr)

        if not hasattr(self, "sizeof_resource_size_t"):
            name_ptr = read_int_from_memory(addr + 0x8 * 2) # sizeof(resource_size_t) == 8
            if name_ptr and is_valid_addr(name_ptr):
                name = read_cstring_from_memory(name_ptr)
                if name in ["PCI IO", "PCI mem"]:
                    self.sizeof_resource_size_t = 0x8

        if not hasattr(self, "sizeof_resource_size_t"):
            name_ptr = read_int_from_memory(addr + 0x4 * 2) # sizeof(resource_size_t) == 4
            if name_ptr and is_valid_addr(name_ptr):
                name = read_cstring_from_memory(name_ptr)
                if name in ["PCI IO", "PCI mem"]:
                    self.sizeof_resource_size_t = 0x4

        if not hasattr(self, "sizeof_resource_size_t"):
            err("Not recognized sizeof(resource_size_t)")
            return []

        """
        struct resource {
            resource_size_t start; // 4 or 8
            resource_size_t end; // 4 or 8
            const char *name;
            unsigned long flags;
            unsigned long desc; // v4.5~
            struct resource *parent, *sibling, *child;
        };
        """
        if self.sizeof_resource_size_t == 8:
            start = read_int64_from_memory(addr)
            end = read_int64_from_memory(addr + 8)
        elif self.sizeof_resource_size_t == 4:
            start = read_int32_from_memory(addr)
            end = read_int32_from_memory(addr + 4)
        name = read_cstring_from_memory(read_int_from_memory(addr + self.sizeof_resource_size_t * 2))
        flags = read_int_from_memory(addr + self.sizeof_resource_size_t * 2 + runtime.current_arch.ptrsize)

        ret = [(addr, start, end, name, flags)]

        kversion = Kernel.kernel_version()
        if "4.5" <= kversion:
            parent = read_int_from_memory(addr + self.sizeof_resource_size_t * 2 + runtime.current_arch.ptrsize * 3)
            ret += self.dump_resource(parent)
            sibling = read_int_from_memory(addr + self.sizeof_resource_size_t * 2 + runtime.current_arch.ptrsize * 4)
            ret += self.dump_resource(sibling)
            child = read_int_from_memory(addr + self.sizeof_resource_size_t * 2 + runtime.current_arch.ptrsize * 5)
            ret += self.dump_resource(child)
        else:
            parent = read_int_from_memory(addr + self.sizeof_resource_size_t * 2 + runtime.current_arch.ptrsize * 2)
            ret += self.dump_resource(parent)
            sibling = read_int_from_memory(addr + self.sizeof_resource_size_t * 2 + runtime.current_arch.ptrsize * 3)
            ret += self.dump_resource(sibling)
            child = read_int_from_memory(addr + self.sizeof_resource_size_t * 2 + runtime.current_arch.ptrsize * 4)
            ret += self.dump_resource(child)
        return ret

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        self.out = []

        # ioport
        ioport_resource = KernelAddressHeuristicFinder.get_ioport_resource()
        if not ioport_resource:
            err("Could not find ioport_resource")
        else:
            info("ioport_resource: {:#x}".format(ioport_resource))

            self.seen = []
            resources = self.dump_resource(ioport_resource)
            if resources:
                name_width = max(len(res[3]) for res in resources)
            else:
                name_width = 4

            self.out.append(titlify("I/O-port"))
            fmt = "{:18s} {:17s} {:{:d}s} {:s}"
            legend = ["resource", "I/O address", "name", name_width, "flags"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

            for addr, start, end, name, flags in sorted(resources, key=lambda x: x[1]):
                self.out.append("{:#018x} {:#08x}-{:#08x} {:{:d}s} {:#010x} ({:s})".format(
                    addr, start, end, name, name_width, flags, KernelPciDeviceCommand.get_flags_str(flags),
                ))

        # iomem
        iomem_resource = KernelAddressHeuristicFinder.get_iomem_resource()
        if not iomem_resource:
            err("Could not find iomem_resource")
        else:
            info("iomem_resource: {:#x}".format(iomem_resource))

            self.seen = []
            resources = self.dump_resource(iomem_resource)
            if resources:
                name_width = max(len(res[3]) for res in resources)
            else:
                name_width = 4

            self.out.append(titlify("I/O-memory"))
            fmt = "{:18s} {:37s} {:{:d}s} {:s}"
            legend = ["resource", "Physical address", "name", name_width, "flags"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

            for addr, start, end, name, flags in sorted(resources, key=lambda x: x[1]):
                self.out.append("{:#018x} {:#018x}-{:#018x} {:{:d}s} {:#010x} ({:s})".format(
                    addr, start, end, name, name_width, flags, KernelPciDeviceCommand.get_flags_str(flags),
                ))

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelDmaBufCommand(GenericCommand, BufferingOutput):
    """Dump DMA-BUF information."""

    _cmdline_ = "kdmabuf"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified DMA-BUF structure:",
        "",
        "                     +-dma_buf-----+      +-dma_buf-----+",
        "                     | size        |      | size        |",
        "                     | file        |      | file        |",
        "                     | ...         |      | ...         |",
        "                     | exp_name    |      | exp_name    |",
        "                     | name        |      | name        |",
        "+---------+          | ...         |      | ...         |",
        "| db_list |--------->| list_node   |----->| list_node   |-->...",
        "+---------+          | priv        |--+   | priv        |",
        " v6.10+:debugfs_list | ...         |  |   | ...         |",
        " v6.16+:dmabuf_list  +-------------+  |   +-------------+",
        "                                      |",
        "     +--------------------------------+",
        "     |",
        "     +--->+-system_heap_buffer-+  +-->+-scatterlist--+",
        "          | ...                |  |   | page_link    |----->+------+",
        "          | len                |  |   | offset       |      | page |",
        "          | sg_table           |  |   | length       |      +------+",
        "          |   sgl              |--+   | ...          |",
        "          |   ...              |      +--------------+",
        "          | ...                |      | page_link    |-->page",
        "          +--------------------+      | offset       |   or",
        "                                      | length       |   scatterlist",
        "                                      | ...          |",
        "                                      +--------------+",
        "                                      | ...          |",
        "                                      +--------------+",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self):
        kversion = Kernel.kernel_version()
        if kversion is None:
            err("Could not find kernel version")
            return False
        if "5.10" <= kversion < "6.10":
            self.db_list = KernelAddressHeuristicFinder.get_db_list()
        elif "6.10" <= kversion < "6.16":
            self.db_list = KernelAddressHeuristicFinder.get_debugfs_list()
        else:
            self.db_list = KernelAddressHeuristicFinder.get_dmabuf_list()
        if self.db_list is None:
            err("Could not find db_list (maybe DMA_SHARED_BUFFER=n)")
            return False

        if "5.10" <= kversion < "6.10":
            self.quiet_info("db_list: {:#x}".format(self.db_list))
        elif "6.10" <= kversion < "6.16":
            self.quiet_info("debugfs_list: {:#x}".format(self.db_list))
        else:
            self.quiet_info("dmabuf_list: {:#x}".format(self.db_list))

        first_dma_buf = read_int_from_memory(self.db_list)
        if first_dma_buf == self.db_list:
            warn("Nothing to dump")
            return False

        """
        struct dma_buf {
            size_t size;
            struct file *file;
            struct list_head attachments;
            const struct dma_buf_ops *ops;
            struct mutex lock; // ~v6.2
            unsigned vmapping_counter;
            struct iosys_map {
                union {
                    void __iomem *vaddr_iomem;
                    void *vaddr;
                };
                bool is_iomem;
            } vmap_ptr;
            const char *exp_name;
            const char *name;
            spinlock_t name_lock;
            struct module *owner;
            struct list_head list_node;
            void *priv; <-- struct system_heap_buffer*
            struct dma_resv *resv;
            wait_queue_head_t poll;
            ...
        }

        [v6.4 x64 example]
        0xffff8880135f8a00|+0x0000|+000: 0x0000000000001000  // size
        0xffff8880135f8a08|+0x0008|+001: 0xffff888000f85800  ->  0x0000000000000000 // file
        0xffff8880135f8a10|+0x0010|+002: 0xffff8880135f8a10  ->  [loop detected] // attachments
        0xffff8880135f8a18|+0x0018|+003: 0xffff8880135f8a10  ->  [loop detected]
        0xffff8880135f8a20|+0x0020|+004: 0xffffffff83e79d00 <system_heap_buf_ops>  ->  0x0000000000000000 // ops
        0xffff8880135f8a28|+0x0028|+005: 0x0000000000000000  // vmapping_counter
        0xffff8880135f8a30|+0x0030|+006: 0x0000000000000000  // vmap_ptr.vaddr_iomem
        0xffff8880135f8a38|+0x0038|+007: 0x0000000000000000  // vmap_ptr.is_iomem
        0xffff8880135f8a40|+0x0040|+008: 0xffffffff8482754e <linux_banner+0x6d70ae>  ->  0x6e006d6574737973 ('system'?) // exp_name
        0xffff8880135f8a48|+0x0048|+009: 0x0000000000000000  // name
        0xffff8880135f8a50|+0x0050|+010: 0xdead4ead00000000  // name_lock
        0xffff8880135f8a58|+0x0058|+011: 0x00000000ffffffff
        0xffff8880135f8a60|+0x0060|+012: 0xffffffffffffffff
        0xffff8880135f8a68|+0x0068|+013: 0xffffffff883cc330 <__key.7>  ->  0x0000000000000000
        0xffff8880135f8a70|+0x0070|+014: 0x0000000000000000
        0xffff8880135f8a78|+0x0078|+015: 0x0000000000000000
        0xffff8880135f8a80|+0x0080|+016: 0xffffffff847790c3 <linux_banner+0x628c23>  ->  '&dmabuf->name_lock'
        0xffff8880135f8a88|+0x0088|+017: 0x0000000000000200
        0xffff8880135f8a90|+0x0090|+018: 0x0000000000000000  // owner
        0xffff8880135f8a98|+0x0098|+019: 0xffff8880135f8c98  ->  0xffffffff883cc360 <db_list>  ->  [loop detected] // list_node
        0xffff8880135f8aa0|+0x00a0|+020: 0xffffffff883cc360 <db_list>  ->  0xffff8880135f8a98  ->  0xffff8880135f8c98  ->  ...
        0xffff8880135f8aa8|+0x00a8|+021: 0xffff88800f978600  ->  ... // priv
        0xffff8880135f8ab0|+0x00b0|+022: 0xffff8880135f8b58  ->  0x0000000000000000
        0xffff8880135f8ab8|+0x00b8|+023: 0xdead4ead00000000
        0xffff8880135f8ac0|+0x00c0|+024: 0x00000000ffffffff
        0xffff8880135f8ac8|+0x00c8|+025: 0xffffffffffffffff
        """
        for i in range(1, 50):
            a = read_int_from_memory(first_dma_buf - runtime.current_arch.ptrsize * (i + 4)) # size
            b = read_int_from_memory(first_dma_buf - runtime.current_arch.ptrsize * (i + 3)) # file
            c = read_int_from_memory(first_dma_buf - runtime.current_arch.ptrsize * (i + 2)) # attachments
            e = read_int_from_memory(first_dma_buf - runtime.current_arch.ptrsize * (i + 0)) # ops

            # size check
            if a == 0 or (is_valid_addr(a) and AddressUtil.is_msb_on(a)):
                continue
            # file check
            if not is_valid_addr(b):
                continue
            # attachments check
            if not is_double_link_list(c):
                continue
            # ops check
            if not is_valid_addr(e):
                continue

            self.offset_list_node = runtime.current_arch.ptrsize * (i + 4)
            self.quiet_info("offsetof(dma_buf, list_node): {:#x}".format(self.offset_list_node))
            break
        else:
            err("Could not find dma_buf->list_node")
            return False

        # dma_buf->{size,file,priv}
        self.offset_size = 0
        self.offset_file = runtime.current_arch.ptrsize
        self.offset_priv = self.offset_list_node + runtime.current_arch.ptrsize * 2
        self.quiet_info("offsetof(dma_buf, size): {:#x}".format(self.offset_size))
        self.quiet_info("offsetof(dma_buf, file): {:#x}".format(self.offset_file))
        self.quiet_info("offsetof(dma_buf, priv): {:#x}".format(self.offset_priv))

        # dma_buf->{exp_name,name}
        for i in range(1, 50):
            top = first_dma_buf - self.offset_list_node
            x = read_int_from_memory(top + runtime.current_arch.ptrsize * i)
            s = read_cstring_from_memory(x)
            if s and len(s) >= 3:
                self.offset_exp_name = runtime.current_arch.ptrsize * i
                self.offset_name = runtime.current_arch.ptrsize * (i + 1)
                self.quiet_info("offsetof(dma_buf, exp_name): {:#x}".format(self.offset_exp_name))
                self.quiet_info("offsetof(dma_buf, name): {:#x}".format(self.offset_name))
                break
        else:
            err("Could not find dma_buf->{exp_name,name}")
            return False

        """
        struct system_heap_buffer {
            struct dma_heap *heap;
            struct list_head attachments;
            struct mutex lock;
            unsigned long len;
            struct sg_table {
                struct scatterlist *sgl;
                unsigned int nents;
                unsigned int orig_nents;
            } sg_table;
            int vmap_cnt;
            void *vaddr;
        };
        """
        # system_heap_buffer->sg_table
        size = read_int_from_memory(first_dma_buf - self.offset_list_node + self.offset_size)
        priv = read_int_from_memory(first_dma_buf - self.offset_list_node + self.offset_priv)
        for i in range(50):
            x = read_int_from_memory(priv + runtime.current_arch.ptrsize * i)
            if x == size:
                self.offset_sg_table = runtime.current_arch.ptrsize * (i + 1)
                break
        else:
            err("Could not find system_heap_buffer->sg_table")
            return False
        self.quiet_info("offsetof(system_heap_buffer, sg_table): {:#x}".format(self.offset_sg_table))
        return True

    def dump_sgl(self, sg):
        while True:
            page_link = read_int_from_memory(sg)

            # check if chain
            if page_link & 1: # SG_CHAIN
                sg = page_link & ~3
                continue

            # output page, phys, virt
            page = page_link & ~3

            phys = None
            phys_str = "???"
            ret = gdb.execute("page2phys {:#x}".format(page), to_string=True)
            r = re.search(r"Page: \S+ -> Phys: (\S+)", ret)
            if r:
                phys = int(r.group(1), 16)
                phys_str = "{:#018x}".format(phys)

            virt_str = "???"
            if phys:
                r = Kernel.p2v(phys)
                if r:
                    r = [hex(x) for x in r if AddressUtil.is_msb_on(x)]
                    virt_str = ",".join(r)

            offset = read_int32_from_memory(sg + runtime.current_arch.ptrsize)
            length = read_int32_from_memory(sg + runtime.current_arch.ptrsize + 4)

            self.out.append("  page: {:#018x}  offset: {:#010x}  length: {:#010x}  phys: {:18s}  virt: {:s}".format(
                page, offset, length, phys_str, virt_str,
            ))

            # check if end
            if page_link & 2: # SG_END:
                break

            # calc sizeof(scatterlist) then go to next
            """
            struct scatterlist {
                unsigned long page_link;
                unsigned int offset;
                unsigned int length;
                dma_addr_t dma_address;
            #ifdef CONFIG_NEED_SG_DMA_LENGTH
                unsigned int dma_length;
            #endif
            #ifdef CONFIG_PCI_P2PDMA
                unsigned int dma_flags;
            #endif
            };
            """
            sg += runtime.current_arch.ptrsize + 4 * 2 + runtime.current_arch.ptrsize
            if not is_valid_addr(read_int_from_memory(sg)):
                sg += runtime.current_arch.ptrsize
            if not is_valid_addr(read_int_from_memory(sg)):
                sg += runtime.current_arch.ptrsize
        return

    def dump_db_list(self):
        fmt = "{:18s} {:18s} {:16s} {:16s} {:18s} {:18s}"
        legend = ["dma_buf", "size", "exp_name", "name", "file", "priv"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        seen = [self.db_list]
        current = read_int_from_memory(self.db_list)
        while True:
            if not is_valid_addr(current):
                break
            if current in seen:
                break
            seen.append(current)

            # calc top
            dma_buf = current - self.offset_list_node

            # size, file, priv
            size = read_int_from_memory(dma_buf + self.offset_size)
            file = read_int_from_memory(dma_buf + self.offset_file)
            priv = read_int_from_memory(dma_buf + self.offset_priv)

            # exp_name
            exp_name_p = read_int_from_memory(dma_buf + self.offset_exp_name)
            exp_name = read_cstring_from_memory(exp_name_p)

            # name
            name_p = read_int_from_memory(dma_buf + self.offset_name)
            if is_valid_addr(name_p):
                name = read_cstring_from_memory(name_p)
            else:
                name = "<none>"

            # dump
            self.out.append("{:#018x} {:#018x} {:16s} {:16s} {:#018x} {:#018x}".format(
                dma_buf, size, exp_name, name, file, priv,
            ))

            # dump sgl
            sgl = read_int_from_memory(priv + self.offset_sg_table)
            self.dump_sgl(sgl)

            # go to next
            current = read_int_from_memory(current)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        kversion = Kernel.kernel_version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "5.11":
            err("Unsupported before v5.11")
            return

        ret = gdb.execute("ksymaddr-remote --quiet --no-pager dma_heap", to_string=True)
        if not ret:
            err("This kernel does not support DMA-BUF")
            return

        ret = self.initialize()
        if ret is False:
            return

        self.out = []
        self.dump_db_list()
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelIrqCommand(GenericCommand, BufferingOutput):
    """Dump IRQ (interrupt request) information."""

    _cmdline_ = "kirq"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also show unused IRQs, the count, the flow handler and the affinity.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Each action of a shared IRQ is shown on its own line. `count` is the sum of the per-cpu counts (-v).",
        "The affinity is shown only with the debug information (vmlinux or `ktypes-load`).",
        "",
        "Simplified irq structure:",
        "",
        "+-irq_desc_tree(~6.5)-+   +--->+-radix/xa node---+   +--->+-irq_desc------+",
        "| lock                |   |    | shift           |   |    | ...           |",
        "| flags               |   |    | ...             |   |    | irq_data      |",
        "| rnode/xa_head       |---+    | count           |   |    |   irq         |",
        "+---------------------+        | ...             |   |    |   hwirq       |",
        "                               | slots[0]        |---+    |   chip        |--->name",
        "                               | slots[1]        |   ^    |   ...         |",
        "                               | ...             |   |    | kstat_irqs    |--->per-cpu count",
        "                               | slots[15 or 63] |   |    | handle_irq    |",
        "                               | ...             |   |    | action        |---+",
        "                               +-----------------+   |    | ...           |   |",
        "                                                     |    +---------------+   |",
        "+-sparse_irqs(6.5~)-+   +-->+-maple_node------+      |                        |",
        "| ...               |   |   | ...             |      |    +-irqaction-+<------+",
        "| ma_root           |---+   | mr64|ma64|alloc |      |    | handler   |",
        "| ...               |       |   ...           |      |    | ...       |",
        "+-------------------+       |   slot[]        |------+    | next      |--->irqaction (shared IRQ)",
        "                            +-----------------+      |    | ...       |",
        "                                                     |    | name      |",
        "+-irq_desc[NR_IRQS] (CONFIG_SPARSE_IRQ=n)-+          |    +-----------+",
        "| irq_desc[0], irq_desc[1], ...           |----------+",
        "+-----------------------------------------+",
    ]
    _note_ = "\n".join(_note_)

    MAX_ACTIONS = 64
    MAX_NR_IRQS = 0x10000

    def add_offset_meta(self, name, offset, source):
        if offset is None:
            self.meta.append((self.quiet_warn, "{:s}: Not found".format(name)))
        else:
            self.meta.append((self.quiet_info, "{:s}: {:#x} ({:s})".format(name, offset, source)))
        return

    def find_desc_array_layout(self, base):
        """Return (offsetof(irq_desc, irq_data.irq), sizeof(irq_desc), NR_IRQS) of irq_desc[] at `base`, or None.
        early_irq_init() sets irq_desc[i].irq_data.irq = i for every descriptor, so the
        array ends where the sequence breaks."""
        offset_irq = GefUtil.offsetof("irq_desc", "irq_data.irq")
        stride = GefUtil.sizeof("irq_desc")
        if offset_irq is not None and stride:
            candidates = [(offset_irq, stride)]
        else:
            words = read_memory(base, 0x2000, safe=True)
            if words is None:
                return None
            words = slice_unpack(words, 4)
            candidates = []
            for offset in range(0, 0x100 // 4):
                if words[offset] != 0:
                    continue
                for step in range(0x20 // 4, 0x800 // 4):
                    if offset + step * 3 >= len(words):
                        break
                    if all(words[offset + step * i] == i for i in range(1, 4)):
                        candidates.append((offset * 4, step * 4))
                        break

        for offset_irq, stride in candidates:
            count = 0
            while count < self.MAX_NR_IRQS:
                irq = read_int32_from_memory(base + stride * count + offset_irq, safe=True)
                if irq != count:
                    break
                count += 1
            if count >= 4:
                return offset_irq, stride, count
        return None

    def resolve_array(self, base):
        """Return the layout of irq_desc[] at `base` (CONFIG_SPARSE_IRQ=n), or None."""
        if not base:
            return None
        array = self.find_desc_array_layout(base)
        if array is None:
            return None
        offset_irq, stride, count = array
        self.meta.append((self.quiet_info, "irq_desc[]: {:#x} (CONFIG_SPARSE_IRQ=n)".format(base)))
        self.meta.append((self.quiet_info, "sizeof(irq_desc): {:#x}".format(stride)))
        self.meta.append((self.quiet_info, "NR_IRQS: {:d}".format(count)))
        return {"kind": "array", "root": base, "stride": stride, "count": count, "offset_irq": offset_irq}

    def resolve_tree(self, root, root_name):
        """Return the layout of the tree at `root` (CONFIG_SPARSE_IRQ=y), or None."""
        kversion = Kernel.version()
        ptrsize = runtime.current_arch.ptrsize
        self.meta.append((self.quiet_info, "{:s}: {:#x}".format(root_name, root)))

        if kversion < "4.20":
            tree = KernelRadixTree(root, GefUtil.offsetof("radix_tree_root", "rnode"))
            if tree.find_rnode_offset(ptrsize * 0x20) is None:
                self.meta.append((self.quiet_err, "Could not find radix_tree_root->rnode. (maybe uninitialized?)"))
                return None
            self.meta.append((self.quiet_info, "offsetof(radix_tree_root, rnode): {:#x}".format(tree.rnode_offset)))
            return {"kind": "radix", "root": root, "head_offset": tree.rnode_offset}

        if kversion < "6.5":
            tree = KernelXArray(root, GefUtil.offsetof("xarray", "xa_head"))
            if tree.find_head_offset(ptrsize * 0x20) is None:
                self.meta.append((self.quiet_err, "Could not find xa_head. (maybe uninitialized?)"))
                return None
            self.meta.append((self.quiet_info, "offsetof(xarray, xa_head): {:#x}".format(tree.head_offset)))
            return {"kind": "xarray", "root": root, "head_offset": tree.head_offset}

        tree = KernelMapleTree(root, GefUtil.offsetof("maple_tree", "ma_root"))
        if tree.find_root_offset(ptrsize * 0x20) is None:
            self.meta.append((self.quiet_err, "Could not find offsetof(maple_tree, ma_root)"))
            return None
        self.meta.append((self.quiet_info, "offsetof(maple_tree, ma_root): {:#x}".format(tree.root_offset)))
        return {"kind": "maple", "root": root, "head_offset": tree.root_offset}

    def resolve_container(self):
        """Return the layout of the container that holds every irq_desc, or None."""
        if Kernel.version() < "6.5":
            root = KernelAddressHeuristicFinder.get_irq_desc_tree()
            root_name = "irq_desc_tree"
        else:
            root = KernelAddressHeuristicFinder.get_sparse_irqs()
            root_name = "sparse_irqs"

        # CONFIG_SPARSE_IRQ=n: irq_to_desc() refers to the static irq_desc[] instead of the tree
        if root:
            layout = self.resolve_array(root) or self.resolve_tree(root, root_name)
            if layout:
                return layout
        layout = self.resolve_array(KernelAddressHeuristicFinder.get_irq_desc())
        if layout:
            return layout
        if not root:
            self.meta.append((self.quiet_err, "Could not find {:s} or irq_desc[]".format(root_name)))
        return None

    def iter_descs(self, layout):
        """Return [(index or None, irq_desc), ...] and whether the walk was complete."""
        kind = layout["kind"]
        if kind == "array":
            return [(i, layout["root"] + layout["stride"] * i) for i in range(layout["count"])], True

        # a tree node may be unreadable (e.g., KGDB), so keep what has been collected
        descs = []
        try:
            if kind == "radix":
                tree = KernelRadixTree(layout["root"], layout["head_offset"])
                for index, desc in tree.iter_indexed_entries():
                    descs.append((index, desc))
            elif kind == "xarray":
                tree = KernelXArray(layout["root"], layout["head_offset"])
                descs = [(None, desc) for desc in tree.parse()]
            else:
                tree = KernelMapleTree(layout["root"], layout["head_offset"])
                for desc in tree.iter_entries():
                    descs.append((None, desc))
        except (gdb.MemoryError, OverflowError):
            return descs, False
        return descs, not tree.broken

    def resolve_offset_irq(self, layout, indexed_descs, descs):
        offset = GefUtil.offsetof("irq_desc", "irq_data.irq")
        if offset is not None:
            return offset, "debug info"
        if layout["kind"] == "array":
            return layout["offset_irq"], "irq_desc[] indices"

        ptrsize = runtime.current_arch.ptrsize
        if Kernel.version() < "4.3":
            # Before irq_data->common became a reliable back pointer, use the radix-tree index.
            indexed = [x for x in indexed_descs if x[0] is not None]
            if not indexed:
                return None, None
            samples = [indexed[i] for i in sorted({0, len(indexed) // 2, len(indexed) - 1})]
            candidates = set(range(0, ptrsize * 10, 4))
            for irq, irq_desc in samples:
                values = slice_unpack(read_memory(irq_desc, ptrsize * 10), 4)
                candidates &= {i * 4 for i, value in enumerate(values) if value == irq}
            if len(candidates) != 1:
                return None, None
            return candidates.pop(), "radix-tree indices"

        if is_x86():
            desc = descs[0]
        else:
            # ARM may have invalid descs[irq=0]
            desc = descs[-1]
        self.meta.append((self.quiet_info, "desc: {:#x}".format(desc)))
        for i in range(100):
            x = read_int_from_memory(desc + ptrsize * i)
            if x == desc:
                # irq_data.common points to irq_desc.irq_common_data, followed by u32 mask and irq
                if is_32bit():
                    return ptrsize * i - 8, "irq_data.common"
                return ptrsize * i - 12, "irq_data.common" # for padding
        return None, None

    def check_action(self, action, irq):
        """Return None if `action` is not a struct irqaction, else whether it holds `irq`."""
        if not is_valid_addr(action):
            return None
        data = read_memory(action, 0x48, safe=True)
        if data is None:
            return None
        handler = slice_unpack(data[:runtime.current_arch.ptrsize], runtime.current_arch.ptrsize)[0]
        if not KernelAddressHeuristicFinderUtil.is_kernel_space(handler) or not is_valid_addr(handler):
            return None
        # irqaction.irq follows handler and a few pointers in every version
        return irq in slice_unpack(data[runtime.current_arch.ptrsize:], 4)

    def resolve_offset_flow_action(self, offset_irq, descs):
        offset_flow = GefUtil.offsetof("irq_desc", "handle_irq")
        offset_action = GefUtil.offsetof("irq_desc", "action")
        if offset_flow is not None and offset_action is not None:
            return offset_flow, offset_action, "debug info"

        # Every descriptor has a flow handler (handle_bad_irq by default) in the kernel text.
        # It is followed by action, or by preflow_handler (CONFIG_IRQ_PREFLOW_FASTEOI, ~v5.4) and action.
        # Small flag values cannot be told from pointers by is_valid_addr() on 32-bit, so they are not used.
        ptrsize = runtime.current_arch.ptrsize
        klayout = Kernel.layout()
        irqs = [read_int32_from_memory(d + offset_irq, safe=True) for d in descs]
        for offset in range(align_to_ptrsize(offset_irq + 4), offset_irq + 0x200, ptrsize):
            values = [read_int_from_memory(d + offset, safe=True) for d in descs]
            values = [v for v in values if v is not None]
            if not values or not all(klayout.text_base <= v < klayout.text_end for v in values):
                continue
            for offset_action in [offset + ptrsize, offset + ptrsize * 2]:
                actions = [(read_int_from_memory(d + offset_action, safe=True), irq) for d, irq in zip(descs, irqs)]
                results = [self.check_action(a, irq) for a, irq in actions if a]
                # the chained IRQs share the static chained_action, whose irq is 0
                if results and None not in results and results.count(True) * 2 >= len(results):
                    return offset, offset_action, "heuristic"
            return offset, offset + ptrsize, "heuristic (no irqaction to verify)"
        return None, None, None

    def resolve_offset_name(self, actions):
        offset = GefUtil.offsetof("irqaction", "name")
        if offset is not None:
            return offset, "debug info"

        for i in range(100):
            names = [read_int_from_memory(a + runtime.current_arch.ptrsize * i) for a in actions]
            names = [x for x in names if is_valid_addr(x) and read_cstring_from_memory(x)]
            if len(names) * 2 > len(actions):
                return runtime.current_arch.ptrsize * i, "heuristic"
        return None, None

    def resolve_offset_next(self):
        offset = GefUtil.offsetof("irqaction", "next")
        if offset is not None:
            return offset, "debug info"

        # handler, [flags (~v3.4)], dev_id, [percpu_dev_id (v3.3~) or affinity (v7.0~)], next
        kversion = Kernel.version()
        if "3.3" <= kversion < "3.5":
            return runtime.current_arch.ptrsize * 4, "version"
        return runtime.current_arch.ptrsize * 3, "version"

    def resolve_offset_hwirq_chip(self, offset_irq):
        offset_hwirq = GefUtil.offsetof("irq_desc", "irq_data.hwirq")
        offset_chip = GefUtil.offsetof("irq_desc", "irq_data.chip")
        if offset_chip is not None:
            return offset_hwirq, offset_chip, "debug info"

        kversion = Kernel.version()
        ptrsize = runtime.current_arch.ptrsize
        if kversion < "3.1":
            # irq, node, state_use_accessors, chip
            return None, align_to_ptrsize(offset_irq + 4 * 3), "version"
        offset_hwirq = align_to_ptrsize(offset_irq + 4)
        if kversion < "4.3":
            # irq, hwirq, node, state_use_accessors, chip
            return offset_hwirq, align_to_ptrsize(offset_hwirq + ptrsize + 4 * 2), "version"
        # mask, irq, hwirq, common, chip
        return offset_hwirq, offset_hwirq + ptrsize * 2, "version"

    def resolve_offset_chip_name(self):
        offset = GefUtil.offsetof("irq_chip", "name")
        if offset is not None:
            return offset, "debug info"
        # parent_device is before name in v4.8 ~ v5.17
        if "4.8" <= Kernel.version() < "5.18":
            return runtime.current_arch.ptrsize, "version"
        return 0, "version"

    def resolve_affinity(self):
        """Return (offsetof(irq_desc, affinity cpumask), whether it is a pointer) from the debug information."""
        for member in ["irq_common_data.affinity", "irq_data.affinity"]:
            offset = GefUtil.offsetof("irq_desc", member)
            if offset is None:
                continue
            try:
                value_type = gdb.parse_and_eval("((struct irq_desc *)0)->{:s}".format(member)).type.strip_typedefs()
            except gdb.error:
                continue
            return offset, value_type.code == gdb.TYPE_CODE_PTR
        return None, None

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def initialize(self):
        self.meta = []

        layout = self.resolve_container()
        if layout is None:
            return None

        indexed_descs, _complete = self.iter_descs(layout)
        indexed_descs = [(i, d) for i, d in indexed_descs if is_valid_addr(d)]
        if not indexed_descs:
            self.meta.append((self.quiet_err, "Could not find any valid irq_desc"))
            return None
        descs = [d for _, d in indexed_descs]
        # a long static array is sampled to keep the scan short
        samples = descs[:0x100]

        # irq_desc->{irq,action}
        """
        struct irq_desc {
            struct irq_common_data {             // v4.3~
                unsigned int __private state_use_accessors;
            #ifdef CONFIG_NUMA
                unsigned int node;
            #endif
                void *handler_data;
                struct msi_desc *msi_desc;
            #ifdef CONFIG_SMP
                cpumask_var_t affinity;
            #endif
            #ifdef CONFIG_GENERIC_IRQ_EFFECTIVE_AFF_MASK
                cpumask_var_t effective_affinity;
            #endif
            #ifdef CONFIG_GENERIC_IRQ_IPI
                unsigned int ipi_offset;
            #endif
            } irq_common_data;
            struct irq_data {
                u32 mask;                        // v4.3~
                unsigned int irq;
                unsigned long hwirq;             // v3.1~
                struct irq_common_data *common;  // v4.3~
                struct irq_chip *chip;
                struct irq_domain *domain;
            #ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
                struct irq_data *parent_data;
            #endif
                void *chip_data;
            } irq_data;
            unsigned int __percpu *kstat_irqs;   // struct irqstat __percpu * (v6.10~)
            irq_flow_handler_t handle_irq;
        #ifdef CONFIG_IRQ_PREFLOW_FASTEOI        // ~v5.4
            irq_preflow_handler_t preflow_handler;
        #endif
            struct irqaction *action;
            unsigned int status_use_accessors;
            unsigned int core_internal_state__do_not_mess_with_it;
            ...
        };
        """
        layout["offset_irq"], source = self.resolve_offset_irq(layout, indexed_descs, samples)
        self.add_offset_meta("offsetof(irq_desc, irq_data.irq)", layout["offset_irq"], source)
        if layout["offset_irq"] is None:
            return None

        layout["offset_hwirq"], layout["offset_chip"], source = self.resolve_offset_hwirq_chip(layout["offset_irq"])
        chips = [read_int_from_memory(d + layout["offset_chip"], safe=True) for d in samples]
        if not any(x and is_valid_addr(x) for x in chips):
            layout["offset_chip"] = None
        if layout["offset_hwirq"] is not None:
            self.add_offset_meta("offsetof(irq_desc, irq_data.hwirq)", layout["offset_hwirq"], source)
        self.add_offset_meta("offsetof(irq_desc, irq_data.chip)", layout["offset_chip"], source)

        layout["offset_flow"], layout["offset_action"], source = self.resolve_offset_flow_action(layout["offset_irq"], samples)
        self.add_offset_meta("offsetof(irq_desc, handle_irq)", layout["offset_flow"], source)
        self.add_offset_meta("offsetof(irq_desc, action)", layout["offset_action"], source)
        if layout["offset_action"] is None:
            return None

        # kstat_irqs is right before handle_irq
        layout["offset_kstat"] = GefUtil.offsetof("irq_desc", "kstat_irqs")
        source = "debug info"
        if layout["offset_kstat"] is None:
            layout["offset_kstat"] = layout["offset_flow"] - runtime.current_arch.ptrsize
            source = "heuristic"
        self.add_offset_meta("offsetof(irq_desc, kstat_irqs)", layout["offset_kstat"], source)

        layout["offset_affinity"], layout["affinity_is_pointer"] = self.resolve_affinity()
        self.add_offset_meta("offsetof(irq_desc, affinity)", layout["offset_affinity"], "debug info")

        layout["offset_chip_name"], source = self.resolve_offset_chip_name()
        self.add_offset_meta("offsetof(irq_chip, name)", layout["offset_chip_name"], source)

        # irqaction->{handler,next,name}
        """
        struct irqaction {
            irq_handler_t handler;
            unsigned long flags;                 // ~v3.4
            void *dev_id;                        // in a union with percpu_dev_id (v7.0~)
            void __percpu *percpu_dev_id;        // v3.3~
            const struct cpumask *affinity;      // v7.0~
            struct irqaction *next;
            irq_handler_t thread_fn;
            struct task_struct *thread;
            struct irqaction *secondary;         // v4.5~
            unsigned int irq;
            unsigned int flags;                  // v3.5~
            unsigned long thread_flags;
            unsigned long thread_mask;
            const char *name;
            struct proc_dir_entry *dir;
        } ____cacheline_internodealigned_in_smp;
        """
        layout["offset_handler"] = GefUtil.offsetof("irqaction", "handler")
        source = "debug info"
        if layout["offset_handler"] is None:
            layout["offset_handler"] = 0
            source = "fixed"
        self.add_offset_meta("offsetof(irqaction, handler)", layout["offset_handler"], source)

        layout["offset_next"], source = self.resolve_offset_next()
        self.add_offset_meta("offsetof(irqaction, next)", layout["offset_next"], source)

        actions = [read_int_from_memory(d + layout["offset_action"], safe=True) for d in samples]
        actions = [x for x in actions if x and is_valid_addr(x)]
        if not actions:
            self.meta.append((self.quiet_err, "Could not find any irqaction"))
            return None
        layout["offset_name"], source = self.resolve_offset_name(actions)
        self.add_offset_meta("offsetof(irqaction, name)", layout["offset_name"], source)
        if layout["offset_name"] is None:
            return None

        layout["meta"] = self.meta
        return layout

    def read_actions(self, layout, action, irq):
        """Return [(irqaction, handler, name), ...] of the shared action chain."""
        actions = []
        seen = set()
        while action and action not in seen and len(actions) < self.MAX_ACTIONS:
            if not is_valid_addr(action):
                break
            seen.add(action)
            handler = read_int_from_memory(action + layout["offset_handler"], safe=True)
            name_ptr = read_int_from_memory(action + layout["offset_name"], safe=True)
            if handler is None or name_ptr is None:
                break
            # a chained action always has a primary handler (irq_default_primary_handler at least)
            if actions and not self.check_action(action, irq):
                break
            if is_valid_addr(name_ptr):
                name = read_cstring_from_memory(name_ptr, safe=True)
            else:
                name = None
            actions.append((action, handler, name or "???"))
            action = read_int_from_memory(action + layout["offset_next"], safe=True)
        return actions

    def read_chip_name(self, layout, desc):
        if layout["offset_chip"] is None:
            return "-"
        chip = read_int_from_memory(desc + layout["offset_chip"], safe=True)
        if not chip or not is_valid_addr(chip):
            return "-"
        name_ptr = read_int_from_memory(chip + layout["offset_chip_name"], safe=True)
        if not name_ptr or not is_valid_addr(name_ptr):
            return "-"
        name = read_cstring_from_memory(name_ptr, max_length=64, safe=True)
        if not name or not name.isprintable():
            return "-"
        return name

    def read_count(self, layout, desc):
        if layout["offset_kstat"] is None:
            return None
        kstat_irqs = read_int_from_memory(desc + layout["offset_kstat"], safe=True)
        percpu = Kernel.per_cpu()
        if not kstat_irqs or not percpu.nr_cpus:
            return None
        total = 0
        for address in percpu.addrs_of(kstat_irqs):
            count = read_int32_from_memory(address, safe=True)
            if count is None:
                return None
            total += count
        return total

    def read_affinity(self, layout, desc):
        from gef.commands.kernel.basic import KernelPerCpuCommand
        if layout["offset_affinity"] is None:
            return None
        address = desc + layout["offset_affinity"]
        if layout["affinity_is_pointer"]:
            address = read_int_from_memory(address, safe=True)
        cpus = Kernel.per_cpu().read_cpu_mask(address)
        if cpus is None:
            return None
        return KernelPerCpuCommand.format_cpus(cpus)

    def dump_irq(self, layout):
        indexed_descs, complete = self.iter_descs(layout)
        if not complete:
            self.warn_add_out("The walk of the irq_desc container stopped at an unreadable node")

        entries = {}
        for index, desc in indexed_descs:
            irq = read_int32_from_memory(desc + layout["offset_irq"], safe=True)
            action = read_int_from_memory(desc + layout["offset_action"], safe=True)
            if irq is None or action is None:
                continue # unreadable, e.g., KGDB
            if index is not None and irq != index:
                continue
            entries[irq] = {
                "desc": desc,
                "actions": self.read_actions(layout, action, irq),
                "hwirq": read_int_from_memory(desc + layout["offset_hwirq"], safe=True) if layout["offset_hwirq"] is not None else None,
                "chip": self.read_chip_name(layout, desc),
            }

        if not entries:
            self.err_add_out("Could not read any irq_desc")
            return

        width = AddressUtil.get_format_address_width()
        chip_width = max([8] + [len(e["chip"]) for e in entries.values()])
        name_width = max([16] + [len(a[2]) for e in entries.values() for a in e["actions"]])
        fmt = "{:>4s} {:{w}s} {:>8s} {:{cw}s} {:{w}s} {:{nw}s} {:s}"
        legend = ["irq", "irq_desc", "hwirq", "chip", "action", "name", "handler"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend, w=width, cw=chip_width, nw=name_width)))

        if self.args.verbose:
            irqs = range(max(entries) + 1)
        elif layout["kind"] == "array":
            # every descriptor of the static array exists, so list only the requested ones
            irqs = sorted(irq for irq, e in entries.items() if e["actions"])
        else:
            irqs = sorted(entries)

        for irq in irqs:
            entry = entries.get(irq)
            if entry is None:
                self.out.append(fmt.format(
                    str(irq), "unused", "-", "-", "unused", "-", "-", w=width, cw=chip_width, nw=name_width,
                ).rstrip())
                continue

            desc = entry["desc"]
            if entry["hwirq"] is None:
                hwirq = "-"
            else:
                hwirq = "{:#x}".format(entry["hwirq"])
            extras = []
            if self.args.verbose:
                count = self.read_count(layout, desc)
                if count is not None:
                    extras.append("count={:d}".format(count))
                if layout["offset_flow"] is not None:
                    flow = read_int_from_memory(desc + layout["offset_flow"], safe=True)
                    if flow is not None:
                        extras.append("flow=" + Symbol.format(flow, missing="NO_SYMBOL", show_address=True, nocolor=True))
                affinity = self.read_affinity(layout, desc)
                if affinity is not None:
                    extras.append("affinity={:s}".format(affinity))
            if extras:
                extras = "  [" + ", ".join(extras) + "]"
            else:
                extras = ""

            columns = [str(irq), "{:#0{:d}x}".format(desc, width), hwirq, entry["chip"]]
            if not entry["actions"]:
                line = fmt.format(*columns, "unused", "-", "-", w=width, cw=chip_width, nw=name_width).rstrip()
                self.out.append(line + extras)
                continue

            for i, (action, handler, name) in enumerate(entry["actions"]):
                if i > 0:
                    # the following actions of a shared IRQ
                    columns = ["", "", "", ""]
                line = fmt.format(
                    *columns, "{:#0{:d}x}".format(action, width), name,
                    Symbol.format(handler, missing="NO_SYMBOL", show_address=True, nocolor=True),
                    w=width, cw=chip_width, nw=name_width,
                ).rstrip()
                self.out.append(line + (extras if i == 0 else ""))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        layout = self.initialize()
        if layout:
            self.meta = layout["meta"]
        if args.meta or not layout:
            for func, line in self.meta:
                func(line)
        if not layout:
            return

        if args.meta:
            return

        self.out = []
        self.dump_irq(layout)
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelNetDeviceCommand(GenericCommand, BufferingOutput):
    """Dump net device information."""

    _cmdline_ = "knetdev"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified net_device structure:",
        "",
        "                     +-net_device--------+    +-net_device--------+",
        "                     | ... (v6.8~)       |    | ... (v6.8~)       |",
        "+-init_net------+    | name[]            |    | name[]            |",
        "| ...           |    | ...               |    | ...               |",
        "| dev_base_head |--->| dev_list          |--->| dev_list          |--->...",
        "| ...           |    | ...               |    | ...               |",
        "+---------------+    +-------------------+    +-------------------+",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            return True

        # init_net
        self.init_net = KernelAddressHeuristicFinder.get_init_net()
        if self.init_net is None:
            self.quiet_err("Could not find init_net")
            return False
        self.quiet_info("init_net: {:#x}".format(self.init_net))

        """
        struct net {
            ...
            struct list_head dev_base_head;
            ...
        };

        struct net_device {
            char name[IFNAMSIZ];
            ...
            struct list_head dev_list;  // dev_base_head points here
            struct list_head napi_list;
            struct list_head unreg_list;
            struct list_head close_list;
            struct list_head ptype_all;
            struct list_head ptype_specific; // ~v6.7
            ...
        };
        """
        # net->dev_base_head
        for i in range(0x100):
            candidate_offset = runtime.current_arch.ptrsize * i

            addr = self.init_net + candidate_offset
            if not is_double_link_list(addr):
                continue

            cand_netdev = read_int_from_memory(addr)
            if not is_double_link_list(cand_netdev + runtime.current_arch.ptrsize * 2): # napi_list
                continue
            if not is_double_link_list(cand_netdev + runtime.current_arch.ptrsize * 4): # unreg_list
                continue
            if not is_double_link_list(cand_netdev + runtime.current_arch.ptrsize * 6): # close_list
                continue
            if not is_double_link_list(cand_netdev + runtime.current_arch.ptrsize * 8): # ptype_all
                continue
            break # found
        else:
            self.quiet_err("Could not find net->dev_base_head")
            return False

        self.offset_dev_base_head = candidate_offset
        self.quiet_info("offsetof(net, dev_base_head): {:#x}".format(self.offset_dev_base_head))

        # net_device->dev_list
        netdev_dev_list = read_int_from_memory(self.init_net + self.offset_dev_base_head)
        for i in range(0x20):
            candidate_offset = runtime.current_arch.ptrsize * i
            if read_cstring_from_memory(netdev_dev_list - candidate_offset) == "lo":
                break
        else:
            self.quiet_err("Could not find net_device->dev_list")
            return False

        self.offset_dev_list = candidate_offset
        self.quiet_info("offsetof(net_device, dev_list): {:#x}".format(self.offset_dev_list))

        return True

    def dump_net(self):
        fmt = "{:18s} {:s}"
        legend = ["net_device", "name"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # `struct net_device` is a very complex struct, and detecting the offset of its members is very difficult.
        # My best effort is to detect only names and addresses.

        head = current = self.init_net + self.offset_dev_base_head
        while True:
            current = read_int_from_memory(current)
            if current == head:
                break

            netdev = current - self.offset_dev_list
            name = read_cstring_from_memory(netdev)
            self.out.append("{:#018x} {:s}".format(netdev, name))

        kversion = Kernel.kernel_version()
        if "6.8" <= kversion:
            info("In kernel 6.8 and later, the order of the members of `struct net_device` has changed significantly")
            info("Please note that the address detected as `net_device` is precisely the address of &net_device.name")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        ret = self.initialize()
        if ret is False:
            return

        self.out = []
        self.dump_net()
        self.print_output(check_terminal_size=True)
        return


class KernelDmesgRing:
    """Share layout lookup and resolved state across printk ring generations."""

    def __init__(self, vmcoreinfo):
        self.vmcoreinfo = vmcoreinfo
        self.address = None
        self.out = []
        self.details = []
        self.warnings = []

    def get_type_layout(self, type_name, members):
        """Get structure offsets and size from DWARF or live VMCOREINFO."""
        if type_name.startswith("struct "):
            name = type_name[7:]
        else:
            name = type_name
        offsets = {}
        sources = set()
        for member in members:
            offset = GefUtil.offsetof(type_name, member)
            if offset is not None:
                offsets[member] = offset
                sources.add("DWARF")
                continue
            offset = self.vmcoreinfo.get(("OFFSET", "{:s}.{:s}".format(name, member)))
            if offset is not None:
                offsets[member] = offset
                sources.add("VMCOREINFO")
        size = GefUtil.sizeof(type_name)
        if size:
            sources.add("DWARF")
        else:
            size = self.vmcoreinfo.get(("SIZE", name))
            if size:
                sources.add("VMCOREINFO")
        if sources:
            source = "/".join(sorted(sources))
        else:
            source = "fallback"
        return offsets, size, source



class KernelDmesgOldestRing(KernelDmesgRing):
    """Read the circular text printk ring used by Linux 3.0 through 3.4."""

    partial_warning = "Partial dump: the legacy printk ring contains unreadable memory"

    def resolve(self):
        """Find and validate the active text ring."""
        log_end_addr, log_buf_len_addr, buffer_pointer_addr, layout_source = (
            KernelAddressHeuristicFinder.get_printk_text_ring_symbols()
        )
        if not log_end_addr or not log_buf_len_addr:
            err("Could not resolve the pre-3.5 printk text ring metadata")
            return False
        log_buf_len = read_int32_from_memory(log_buf_len_addr, safe=True)
        log_end = read_int32_from_memory(log_end_addr, safe=True)
        if not log_buf_len or log_buf_len > 1 << 30 or log_end is None:
            err("Invalid legacy printk ring metadata")
            return False
        log_buf_start = KernelAddressHeuristicFinder.get_log_buffer(log_buf_len, buffer_pointer_addr)
        if not log_buf_start:
            err("Could not find the active log_buf")
            return False
        self.address = log_buf_start
        self.buf_len = log_buf_len
        self.log_end = log_end
        logged_chars_addr = Ksym.get_addr("logged_chars")
        if logged_chars_addr:
            logged_chars = read_int32_from_memory(logged_chars_addr, safe=True)
        else:
            logged_chars = None
        if logged_chars is not None and logged_chars <= log_buf_len:
            self.logged_chars = logged_chars
        else:
            self.logged_chars = None
        if self.logged_chars is None:
            log_start_addr = Ksym.get_addr("log_start")
        else:
            log_start_addr = None
        if not log_start_addr and self.logged_chars is None:
            if is_x86():
                log_start_addr = log_end_addr + 8
            elif is_arm32():
                log_start_addr = log_end_addr + 4
        if log_start_addr:
            log_start = read_int32_from_memory(log_start_addr, safe=True)
        else:
            log_start = None
        if log_start is not None and ((log_end - log_start) & 0xffff_ffff) <= log_buf_len:
            self.log_start = log_start
        else:
            self.log_start = None
        self.details = [
            "active log_buf: {:#x}, size: {:#x}".format(log_buf_start, log_buf_len),
            "legacy printk layout source: {:s}".format(layout_source),
        ]
        return True

    def dump(self):
        """Append retained text lines and report whether memory was unreadable."""
        size = min(self.log_end, self.buf_len)
        if self.log_start is not None:
            size = max(size, min((self.log_end - self.log_start) & 0xffff_ffff, self.buf_len))
        if self.logged_chars is not None:
            size = self.logged_chars
        start = self.log_end - size
        index = start % self.buf_len
        first_size = min(size, self.buf_len - index)
        segments = [(self.address + index, first_size)]
        if first_size < size:
            segments.append((self.address, size - first_size))
        text = b""
        partial = False
        for address, length in segments:
            try:
                text += read_memory(address, length)
            except gdb.error:
                partial = True
        self.out.extend(String.bytes2str(text).splitlines())
        return partial



class KernelDmesgLegacyRing(KernelDmesgRing):
    """Read the printk_log record ring used by Linux 3.5 through 5.9."""

    partial_warning = "Partial dump: the printk log ring contains unreadable or corrupt records"

    def get_legacy_layout(self, buf_start, buf_len, first_idx, next_idx):
        """Resolve and validate the printk_log record header layout."""
        offsets, size, source = self.get_type_layout(
            "struct printk_log", ("ts_nsec", "len", "text_len", "dict_len", "caller_id"),
        )
        offsets.setdefault("dict_len", 12)
        if all(name in offsets for name in ("ts_nsec", "len", "text_len")) and size:
            return {"offsets": offsets, "size": size, "source": source}
        offsets.setdefault("ts_nsec", 0)
        offsets.setdefault("len", 8)
        offsets.setdefault("text_len", 10)
        caller_hint = offsets.get("caller_id") is not None or Ksym.get_addr("print_caller") is not None
        if "caller_id" not in offsets:
            offsets["caller_id"] = 16
        candidates = ((16, 4), (16, 8), (20, 4), (24, 8))
        scored = []
        for header_size, alignment in candidates:
            score = self.validate_legacy_header(buf_start, buf_len, first_idx, next_idx, offsets, header_size, alignment)
            if score >= 0:
                if caller_hint:
                    preferred = header_size in (20, 24)
                else:
                    preferred = header_size == 16
                scored.append((score, preferred, header_size))
        if not scored:
            return None
        scored.sort(reverse=True)
        return {"offsets": offsets, "size": scored[0][2], "source": "validated fallback"}

    def validate_legacy_header(self, buf_start, buf_len, first_idx, next_idx, offsets, header_size, alignment):
        """Score a header layout against records in the active log buffer."""
        pos = first_idx
        visited = set()
        score = 0
        for _ in range(4):
            if pos == next_idx or pos in visited:
                break
            visited.add(pos)
            try:
                base = buf_start + pos
                rec_len = read_int16_from_memory(base + offsets["len"])
                if rec_len == 0:
                    pos = 0
                    continue
                text_len = read_int16_from_memory(base + offsets["text_len"])
                dict_len = read_int16_from_memory(base + offsets["dict_len"])
                expected_len = (header_size + text_len + dict_len + alignment - 1) & -alignment
                if rec_len != expected_len or rec_len > buf_len - pos:
                    return -1
                if text_len:
                    text = read_memory(base + header_size, min(text_len, 8))
                    if text[0] == 0 or any(byte not in (9, 10, 13) and not 0x20 <= byte <= 0x7e for byte in text[:1]):
                        return -1
                    score += 1
                pos += rec_len
                if pos >= buf_len:
                    pos = 0
            except gdb.error:
                return -1
        if score or first_idx == next_idx:
            return score
        return -1

    def resolve(self):
        """Find the active record ring and its header layout."""
        log_first_idx_ptr = Ksym.get_addr("log_first_idx") or KernelAddressHeuristicFinder.get_log_first_idx()
        log_next_idx_ptr = Ksym.get_addr("log_next_idx") or KernelAddressHeuristicFinder.get_log_next_idx()
        log_buf_len_ptr = Ksym.get_addr("log_buf_len") or KernelAddressHeuristicFinder.get_log_buf_len()
        if not log_first_idx_ptr or not log_next_idx_ptr or not log_buf_len_ptr:
            err("Could not resolve printk log indexes and size")
            return False
        log_first_idx = read_int32_from_memory(log_first_idx_ptr, safe=True)
        log_next_idx = read_int32_from_memory(log_next_idx_ptr, safe=True)
        log_buf_len = read_int32_from_memory(log_buf_len_ptr, safe=True)
        if log_first_idx is None or log_next_idx is None or not log_buf_len or log_buf_len > 1 << 30:
            err("Invalid legacy printk ring metadata")
            return False
        if log_first_idx >= log_buf_len or log_next_idx >= log_buf_len:
            err("Legacy printk ring indexes are outside log_buf_len")
            return False
        log_buf_start = KernelAddressHeuristicFinder.get_log_buffer(log_buf_len)
        if not log_buf_start:
            err("Could not find the active log_buf")
            return False
        layout = self.get_legacy_layout(log_buf_start, log_buf_len, log_first_idx, log_next_idx)
        if layout is None:
            err("Could not resolve a valid printk_log layout")
            return False
        self.address = log_buf_start
        self.buf_len = log_buf_len
        self.log_first_idx = log_first_idx
        self.log_next_idx = log_next_idx
        self.layout = layout
        self.details = [
            "active log_buf: {:#x}, size: {:#x}".format(log_buf_start, log_buf_len),
            "printk_log layout source: {:s}".format(layout["source"]),
        ]
        if layout["source"] == "validated fallback":
            self.warnings.append("Using validated printk_log header fallback ({:d} bytes)".format(layout["size"]))
        return True

    def dump(self):
        """Read records from the pre-5.10 printk_log ring.

        struct printk_log {
            u64 ts_nsec;  /* timestamp in nanoseconds */
            u16 len;      /* length of the entire record */
            u16 text_len; /* length of the text */
            u16 dict_len; /* length of the dictionary */
            u8 facility;  /* syslog facility */
            u8 flags:5;   /* internal record flags */
            u8 level:3;   /* syslog level */
        #ifdef CONFIG_PRINTK_CALLER
            u32 caller_id; /* thread ID or processor ID */
        #endif
        };
        """
        log_first_idx = self.log_first_idx
        log_end_idx = self.log_next_idx
        buf_start = self.address
        buf_end = self.address + self.buf_len
        layout = self.layout
        buf_len = buf_end - buf_start
        pos = log_first_idx
        visited = set()
        partial = False
        while pos != log_end_idx and pos not in visited and len(visited) <= buf_len // max(layout["size"], 1) + 1:
            visited.add(pos)
            try:
                base = buf_start + pos
                rec_len = read_int16_from_memory(base + layout["offsets"]["len"])
                if rec_len == 0:
                    pos = 0
                    continue
                text_len = read_int16_from_memory(base + layout["offsets"]["text_len"])
                dict_len = read_int16_from_memory(base + layout["offsets"]["dict_len"])
                if rec_len < layout["size"] or rec_len > buf_len - pos or text_len + dict_len > rec_len - layout["size"]:
                    partial = True
                    break
                ts_nsec = read_int64_from_memory(base + layout["offsets"]["ts_nsec"])
                if text_len:
                    text = read_memory(base + layout["size"], text_len)
                else:
                    text = b""
                sec = ts_nsec // 1_000_000_000
                nsec = "{:09d}".format(ts_nsec % 1_000_000_000)[:6]
                for line in String.bytes2str(text).splitlines():
                    self.out.append("[{:5d}.{:s}] {:s}".format(sec, nsec, line))
                pos += rec_len
                if pos >= buf_len:
                    pos = 0
            except gdb.error:
                partial = True
                break
        if pos != log_end_idx:
            partial = True
        return partial



class KernelDmesgModernRing(KernelDmesgRing):
    """Read the descriptor-based printk ring used by Linux 5.10 and later."""

    partial_warning = "Partial dump: some printk records were unreadable, changing, or corrupt"

    def get_atomic_long_offset(self):
        """Find the counter field within atomic_long_t."""
        offset = self.vmcoreinfo.get(("OFFSET", "atomic_long_t.counter"))
        if offset is not None:
            return offset, "VMCOREINFO"
        offset = GefUtil.member_offset("atomic_long_t", "counter")
        if offset is not None:
            return offset, "DWARF"
        return 0, "fallback"

    def resolve_printk_ring(self, ring_address, source):
        """Validate a ring candidate and return its resolved layout."""
        ptrsize = runtime.current_arch.ptrsize
        word_mask = (1 << (ptrsize * 8)) - 1
        id_mask = (1 << (ptrsize * 8 - 2)) - 1
        ring_offsets, _, ring_source = self.get_type_layout(
            "struct printk_ringbuffer", ("desc_ring", "text_data_ring"),
        )
        desc_offsets, desc_size, desc_source = self.get_type_layout(
            "struct prb_desc_ring",
            ("count_bits", "descs", "infos", "head_id", "tail_id"),
        )
        data_offsets, _, data_source = self.get_type_layout(
            "struct prb_data_ring", ("size_bits", "data"),
        )
        descriptor_offsets, descriptor_size, descriptor_source = self.get_type_layout(
            "struct prb_desc", ("state_var", "text_blk_lpos"),
        )
        lpos_offsets, _, lpos_source = self.get_type_layout(
            "struct prb_data_blk_lpos", ("begin", "next"),
        )
        info_offsets, info_size, info_source = self.get_type_layout(
            "struct printk_info", ("seq", "ts_nsec", "text_len", "caller_id", "caller_id2"),
        )
        atomic_offset, atomic_source = self.get_atomic_long_offset()

        defaults = {
            "count_bits": 0,
            "descs": ptrsize,
            "infos": ptrsize * 2,
            "head_id": ptrsize * 3,
            "tail_id": ptrsize * 4,
        }
        for name, offset in defaults.items():
            desc_offsets.setdefault(name, offset)
        data_defaults = {"size_bits": 0, "data": ptrsize}
        for name, offset in data_defaults.items():
            data_offsets.setdefault(name, offset)
        descriptor_offsets.setdefault("state_var", 0)
        descriptor_offsets.setdefault("text_blk_lpos", ptrsize)
        lpos_offsets.setdefault("begin", 0)
        lpos_offsets.setdefault("next", ptrsize)
        info_defaults = {"seq": 0, "ts_nsec": 8, "text_len": 16, "caller_id": 20}
        for name, offset in info_defaults.items():
            info_offsets.setdefault(name, offset)
        descriptor_size = descriptor_size or ptrsize * 3
        if not info_size:
            info_sizes = [88]
            if info_offsets.get("caller_id2") is not None or (Kernel.version() and Kernel.version() >= "7.0"):
                if is_x86_32():
                    info_sizes.insert(0, 108)
                else:
                    info_sizes.insert(0, 112)

        desc_base = ring_offsets.get("desc_ring", 0)
        text_base = ring_offsets.get("text_data_ring")
        if text_base is not None:
            text_bases = [text_base]
        elif desc_size:
            text_bases = [desc_base + desc_size]
        else:
            text_bases = [desc_base + ptrsize * count for count in (5, 6, 7)]

        for data_base in text_bases:
            try:
                count_bits = read_int32_from_memory(ring_address + desc_base + desc_offsets["count_bits"])
                descs = read_int_from_memory(ring_address + desc_base + desc_offsets["descs"])
                infos = read_int_from_memory(ring_address + desc_base + desc_offsets["infos"])
                head_id = read_int_from_memory(ring_address + desc_base + desc_offsets["head_id"] + atomic_offset) & id_mask
                tail_id = read_int_from_memory(ring_address + desc_base + desc_offsets["tail_id"] + atomic_offset) & id_mask
                size_bits = read_int32_from_memory(ring_address + data_base + data_offsets["size_bits"])
                data = read_int_from_memory(ring_address + data_base + data_offsets["data"])
                count = 0
                if 0 < count_bits <= 24:
                    count = 1 << count_bits
                capacity = 0
                if 1 <= size_bits <= 30:
                    capacity = 1 << size_bits
                distance = (head_id - tail_id) & id_mask
                if (
                    not count or not capacity or distance >= count or not descs or not infos or not data
                    or any(address % ptrsize for address in (descs, infos, data))
                    or not all(is_valid_addr(address) for address in (descs, infos, data))
                ):
                    continue
                desc_addr = descs + (tail_id & (count - 1)) * descriptor_size
                state = read_int_from_memory(desc_addr + descriptor_offsets["state_var"] + atomic_offset)
                if (state & id_mask) != tail_id:
                    continue
                resolved_info_size = info_size
                if not resolved_info_size:
                    for size in info_sizes:
                        valid = True
                        for offset in range(min(distance + 1, 4)):
                            identifier = (head_id - offset) & id_mask
                            index = identifier & (count - 1)
                            desc_addr = descs + index * descriptor_size
                            state = read_int_from_memory(desc_addr + descriptor_offsets["state_var"] + atomic_offset)
                            if (state & id_mask) != identifier or (state >> (ptrsize * 8 - 2)) not in (1, 2):
                                continue
                            seq = read_int64_from_memory(infos + index * size + info_offsets["seq"], safe=True)
                            if seq is None or (seq & (count - 1)) != index:
                                valid = False
                                break
                        if valid:
                            resolved_info_size = size
                            break
                    if not resolved_info_size:
                        continue
                read_int64_from_memory(infos + (tail_id & (count - 1)) * resolved_info_size + info_offsets["seq"])
            except gdb.error:
                continue
            return {
                "address": ring_address,
                "source": source,
                "desc_base": desc_base,
                "data_base": data_base,
                "desc_offsets": desc_offsets,
                "data_offsets": data_offsets,
                "descriptor_offsets": descriptor_offsets,
                "lpos_offsets": lpos_offsets,
                "info_offsets": info_offsets,
                "atomic_offset": atomic_offset,
                "descriptor_size": descriptor_size,
                "info_size": resolved_info_size,
                "count_bits": count_bits,
                "size_bits": size_bits,
                "descs": descs,
                "infos": infos,
                "data": data,
                "head_id": head_id,
                "tail_id": tail_id,
                "word_mask": word_mask,
                "id_mask": id_mask,
                "layout_source": "/".join(
                    sorted({ring_source, desc_source, data_source, descriptor_source, lpos_source, info_source, atomic_source})
                ),
            }
        return None

    def resolve(self):
        """Find and validate the active descriptor ring."""
        ring = None
        for address, source in KernelAddressHeuristicFinder.get_printk_ring_candidates():
            ring = self.resolve_printk_ring(address, source)
            if ring:
                break
        if ring is None:
            err("Could not resolve a valid active printk ringbuffer")
            return False
        self.ring = ring
        self.address = ring["address"]
        self.details = [
            "active printk ringbuffer: {:#x}".format(ring["address"]),
            "layout source: {:s}".format(ring["layout_source"]),
            "ring state: count={:d}, size={:#x}, tail_id={:#x}, head_id={:#x}".format(
                1 << ring["count_bits"], 1 << ring["size_bits"], ring["tail_id"], ring["head_id"],
            ),
            "layout offsets: desc_ring={:#x}, text_data_ring={:#x}, descriptor_size={}, info_size={}".format(
                ring["desc_base"], ring["data_base"], ring["descriptor_size"], ring["info_size"],
            ),
        ]
        if ring["layout_source"] == "fallback":
            self.warnings.append("Using validated printk ring layout fallback")
        return True

    def dump(self):
        """Read the active printk ringbuffer.

        struct printk_ringbuffer {
            struct prb_desc_ring {
                unsigned int count_bits;
                struct prb_desc *descs;
                struct printk_info *infos;
                atomic_long_t head_id;
                atomic_long_t tail_id;
                atomic_long_t last_finalized_id;  /* present in later kernels */
                atomic_long_t last_finalized_seq; /* present in later kernels */
            } desc_ring;
            struct prb_data_ring {
                unsigned int size_bits;
                char *data;
                atomic_long_t head_lpos;
                atomic_long_t tail_lpos;
            } text_data_ring;
            atomic_long_t fail;
        };

        struct prb_desc {
            atomic_long_t state_var;
            struct prb_data_blk_lpos {
                unsigned long begin;
                unsigned long next;
            } text_blk_lpos;
        };

        struct printk_info {
            u64 seq;
            u64 ts_nsec;
            u16 text_len;
            u8 facility;
            u8 flags:5;
            u8 level:3;
            u32 caller_id;
        #ifdef CONFIG_PRINTK_EXECUTION_CTX
            u32 caller_id2;
            char comm[TASK_COMM_LEN];
        #endif
            struct dev_printk_info {
                char subsystem[PRINTK_INFO_SUBSYSTEM_LEN];
                char device[PRINTK_INFO_DEVICE_LEN];
            } dev_info;
        };
        """
        ring = self.ring
        ptrsize = runtime.current_arch.ptrsize
        desc_count = 1 << ring["count_bits"]
        data_size = 1 << ring["size_bits"]
        data_mask = data_size - 1
        state_shift = ptrsize * 8 - 2
        identifier = ring["tail_id"]
        traversed = 0
        partial = False
        reached_head = False
        while traversed < desc_count:
            index = identifier & (desc_count - 1)
            desc_addr = ring["descs"] + index * ring["descriptor_size"]
            info_addr = ring["infos"] + index * ring["info_size"]
            try:
                state_var = read_int_from_memory(desc_addr + ring["descriptor_offsets"]["state_var"] + ring["atomic_offset"])
                is_head = identifier == ring["head_id"]
                if (state_var & ring["id_mask"]) != identifier:
                    if not is_head:
                        partial = True
                else:
                    state = (state_var >> state_shift) & 3
                    if state in (1, 2):
                        seq = read_int64_from_memory(info_addr + ring["info_offsets"]["seq"])
                        ts_nsec = read_int64_from_memory(info_addr + ring["info_offsets"]["ts_nsec"])
                        text_len = read_int16_from_memory(info_addr + ring["info_offsets"]["text_len"])
                        caller_id = read_int32_from_memory(info_addr + ring["info_offsets"]["caller_id"])
                        lpos = desc_addr + ring["descriptor_offsets"]["text_blk_lpos"]
                        begin = read_int_from_memory(lpos + ring["lpos_offsets"]["begin"])
                        next_pos = read_int_from_memory(lpos + ring["lpos_offsets"]["next"])
                        if begin & 1:
                            if begin == next_pos == 3 and text_len == 0:
                                entry = ""
                            else:
                                entry = "<lost>"
                                partial = True
                        else:
                            begin_index = begin & data_mask
                            next_index = next_pos & data_mask
                            if begin_index > next_index:
                                data_offset = 0
                            else:
                                data_offset = begin_index
                            text_offset = data_offset + ptrsize
                            available = max(next_index - text_offset, 0)
                            span = (next_pos - begin) & ring["word_mask"]
                            if span > data_size or span < ptrsize + text_len or available < text_len:
                                partial = True
                                text_len = min(text_len, available, max(data_size - text_offset, 0))
                            if text_len:
                                entry = String.bytes2str(read_memory(ring["data"] + text_offset, text_len))
                            else:
                                entry = ""
                        if caller_id & 0x80000000:
                            caller = "C{:d}".format(caller_id & 0x7fffffff)
                        else:
                            caller = "T{:d}".format(caller_id)
                        sec = ts_nsec // 1_000_000_000
                        nsec = "{:09d}".format(ts_nsec % 1_000_000_000)[:6]
                        output = "[{:5d}.{:s}] [{:>6s}] {:s}".format(sec, nsec, caller, entry)
                        state_address = desc_addr + ring["descriptor_offsets"]["state_var"] + ring["atomic_offset"]
                        state_after = read_int_from_memory(state_address)
                        seq_after = read_int64_from_memory(info_addr + ring["info_offsets"]["seq"])
                        if state_after != state_var or seq_after != seq:
                            partial = True
                        else:
                            self.out.append(output)
                    elif state == 0 and not is_head:
                        partial = True
            except gdb.error:
                partial = True
            traversed += 1
            if identifier == ring["head_id"]:
                reached_head = True
                break
            identifier = (identifier + 1) & ring["id_mask"]
        if not reached_head:
            partial = True
        return partial


@register_command
class KernelIoUringCommand(GenericCommand, BufferingOutput):
    """Display the kernel-side io_uring object graph."""

    _cmdline_ = "kio-uring"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", nargs="?", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the address of struct io_ring_ctx, io_kiocb or file.")
    parser.add_argument("-t", "--type", choices=["auto", "ctx", "request", "file"], default="auto",
                        help="the type of ADDRESS. (default: %(default)s)")
    parser.add_argument("-p", "--pid", type=int, help="select rings owned by this pid.")
    parser.add_argument("-f", "--fd", type=int, help="select this ring fd (requires --pid).")
    parser.add_argument("--no-requests", action="store_true", help="do not walk pending request lists.")
    parser.add_argument("--meta", action="store_true", help="display layout and discovery information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="show request flags and user_data.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} --pid 1337 --fd 4",
        "{0:s} --type ctx 0xffff888012340000",
        "{0:s} --type request 0xffff888056780000 -v",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "`iouring-dump` dumps userland io_uring mappings; this command follows kernel objects.",
        "io_uring first appeared in Linux v5.1. Older kernels are detected without scanning.",
        "DWARF is used when available. Without it, ring discovery uses open fd paths and validated ring metadata.",
        "ADDRESS with `--type ctx` or `--type request` needs neither the task list nor the VFS layout.",
        "Live request lists are transient and may be incomplete while another CPU is running.",
        "",
        "Kernel object graph:",
        "",
        "task_struct",
        "  +-- files -> fdtable[fd] -> file (anon_inode:[io_uring])",
        "  |                             +-- private_data -> io_ring_ctx",
        "  +-- io_uring -> io_uring_task",
        "                    +-- last ---------------------> io_ring_ctx",
        "                    +-- registered_rings[] -------> file",
        "                    +-- io_wq --------------------> io-wq workers",
        "",
        "io_ring_ctx",
        "  +-- rings ----------------------> io_rings (SQ / CQ)",
        "  +-- file table -----------------> file / io_rsrc_node",
        "  +-- buffer table ---------------> io_mapped_ubuf / io_rsrc_node",
        "  +-- iopoll/timeout/defer lists -> io_kiocb",
        "  |                                   +-- opcode / state / refs",
        "  |                                   +-- file / buffer node",
        "  |                                   +-- callback / linked request",
        "  +-- submitter / sq thread ------> task_struct",
    ]
    _note_ = "\n".join(_note_)

    MAX_FDS = 0x10000
    MAX_RESOURCES = 0x10000
    MAX_REQUESTS = 0x10000

    OPCODES = [
        "NOP", "READV", "WRITEV", "FSYNC", "READ_FIXED", "WRITE_FIXED", "POLL_ADD",
        "POLL_REMOVE", "SYNC_FILE_RANGE", "SENDMSG", "RECVMSG", "TIMEOUT", "TIMEOUT_REMOVE",
        "ACCEPT", "ASYNC_CANCEL", "LINK_TIMEOUT", "CONNECT", "FALLOCATE", "OPENAT", "CLOSE",
        "FILES_UPDATE", "STATX", "READ", "WRITE", "FADVISE", "MADVISE", "SEND", "RECV",
        "OPENAT2", "EPOLL_CTL", "SPLICE", "PROVIDE_BUFFERS", "REMOVE_BUFFERS", "TEE",
        "SHUTDOWN", "RENAMEAT", "UNLINKAT", "MKDIRAT", "SYMLINKAT", "LINKAT", "MSG_RING",
        "FSETXATTR", "SETXATTR", "FGETXATTR", "GETXATTR", "SOCKET", "URING_CMD", "SEND_ZC",
        "SENDMSG_ZC", "READ_MULTISHOT", "WAITID", "FUTEX_WAIT", "FUTEX_WAKE", "FUTEX_WAITV",
        "FIXED_FD_INSTALL", "FTRUNCATE", "BIND", "LISTEN", "RECV_ZC", "EPOLL_WAIT",
        "READV_FIXED", "WRITEV_FIXED", "PIPE", "NOP128", "URING_CMD128",
    ]

    def eval_value(self, type_name, address, member):
        try:
            return gdb.parse_and_eval("(({:s} *){:#x})->{:s}".format(type_name, address, member))
        except (gdb.error, RuntimeError):
            return None

    def eval_unsigned(self, type_name, address, member):
        value = self.eval_value(type_name, address, member)
        if value is None:
            return None
        try:
            value_type = value.type.strip_typedefs()
            if value_type.code in (gdb.TYPE_CODE_PTR, gdb.TYPE_CODE_ARRAY):
                return to_unsigned_long(value)
            return int(value) & ((1 << (value_type.sizeof * 8)) - 1)
        except (gdb.error, RuntimeError, TypeError):
            return None

    def eval_first(self, type_name, address, members):
        for member in members:
            value = self.eval_unsigned(type_name, address, member)
            if value is not None:
                return value, member
        return None, None

    @staticmethod
    def is_ring_path(path):
        return path == "anon_inode:[io_uring]" or path == "[io_uring]" or path.endswith(":[io_uring]")

    @staticmethod
    def is_power_of_two(value):
        return value != 0 and value & (value - 1) == 0

    # struct io_uring { u32 head ____cacheline_aligned_in_smp; u32 tail ____cacheline_aligned_in_smp; }
    # places head/tail at each cacheline (32/64/128 bytes, in u32 units here) on CONFIG_SMP=y,
    # or back to back on CONFIG_SMP=n and v7.0 or later.
    RING_STRIDES = (1, 8, 16, 32)

    def read_ring_words(self, ring):
        # the rings are mapped to the userland, so they start at a page boundary
        if not is_valid_addr(ring) or ring & 0xfff:
            return None
        data = read_memory(ring, 0x300, safe=True)
        if data is None:
            return None
        try:
            return slice_unpack(data, 4)
        except struct.error:
            return None

    @staticmethod
    def is_ring_padding(words, stride, count):
        """Return True if the padding between `count` cacheline aligned u32 fields is zero."""
        return all(words[i] == 0 for i in range(stride * count) if i % stride)

    def ring_memory_layout(self, rings):
        """Recognize and decode the combined io_rings (v5.4~) in memory."""
        words = self.read_ring_words(rings)
        if words is None:
            return None
        for stride in self.RING_STRIDES:
            # sq.head, sq.tail, cq.head and cq.tail are followed by the masks and the entries
            index = stride * 4
            sq_mask, cq_mask, sq_entries, cq_entries = words[index:index + 4]
            if not self.is_power_of_two(sq_entries) or not self.is_power_of_two(cq_entries):
                continue
            # the CQ is never smaller than the SQ (twice as large by default)
            if sq_entries > 0x100000 or cq_entries > 0x200000 or cq_entries < sq_entries:
                continue
            if sq_mask + 1 != sq_entries or cq_mask + 1 != cq_entries:
                continue
            if not self.is_ring_padding(words, stride, 4):
                continue
            sq_head, sq_tail, cq_head, cq_tail = (words[stride * i] for i in range(4))
            if (sq_tail - sq_head) & 0xffff_ffff > sq_entries or (cq_tail - cq_head) & 0xffff_ffff > cq_entries:
                continue
            result = {
                "address": rings, "heuristic": True,
                "sq_head": sq_head, "sq_tail": sq_tail, "cq_head": cq_head, "cq_tail": cq_tail,
                "sq_mask": sq_mask, "cq_mask": cq_mask,
                "sq_entries": sq_entries, "cq_entries": cq_entries,
                "dropped": words[index + 4], "sq_flags": words[index + 5],
                "cq_flags": None, "overflow": None,
            }
            if self.kversion >= "5.8":
                result["cq_flags"] = words[index + 6]
                result["overflow"] = words[index + 7]
            else:
                result["overflow"] = words[index + 6]
            return result
        return None

    def single_ring_layout(self, ring):
        """Recognize and decode io_sq_ring or io_cq_ring (v5.1~v5.3), each having its own head and tail."""
        words = self.read_ring_words(ring)
        if words is None:
            return None
        for stride in self.RING_STRIDES:
            index = stride * 2
            mask, entries = words[index:index + 2]
            if not self.is_power_of_two(entries) or entries > 0x200000 or mask + 1 != entries:
                continue
            if not self.is_ring_padding(words, stride, 2):
                continue
            head, tail = words[0], words[stride]
            if (tail - head) & 0xffff_ffff > entries:
                continue
            # io_sq_ring has dropped and flags, and io_cq_ring has overflow after them
            return {"address": ring, "head": head, "tail": tail, "mask": mask, "entries": entries,
                    "extra": words[index + 2:index + 4]}
        return None

    def find_rings_heuristic(self, ctx):
        """Return the ring metadata found from the pointers in io_ring_ctx, or None."""
        if not is_valid_addr(ctx) or ctx & (runtime.current_arch.ptrsize - 1):
            return None
        pointers = read_memory(ctx, 0x400, safe=True)
        if pointers is None:
            return None
        try:
            pointers = slice_unpack(pointers, runtime.current_arch.ptrsize)
        except struct.error:
            return None
        singles = []
        for pointer in pointers:
            layout = self.ring_memory_layout(pointer)
            if layout is not None:
                return layout
            if self.kversion < "5.4" and pointer not in [x["address"] for x in singles]:
                layout = self.single_ring_layout(pointer)
                if layout is not None:
                    singles.append(layout)
        # io_ring_ctx has sq_ring before cq_ring
        pairs = [(sq, cq) for i, sq in enumerate(singles) for cq in singles[i + 1:] if cq["entries"] >= sq["entries"]]
        if not pairs:
            return None
        sq, cq = pairs[0]
        return {
            "address": sq["address"], "cq_address": cq["address"], "heuristic": True,
            "sq_head": sq["head"], "sq_tail": sq["tail"], "cq_head": cq["head"], "cq_tail": cq["tail"],
            "sq_mask": sq["mask"], "cq_mask": cq["mask"], "sq_entries": sq["entries"], "cq_entries": cq["entries"],
            "dropped": sq["extra"][0], "sq_flags": sq["extra"][1], "cq_flags": None, "overflow": cq["extra"][0],
        }

    def context_score(self, ctx):
        if not is_valid_addr(ctx) or ctx & (runtime.current_arch.ptrsize - 1):
            return 0
        rings = self.eval_unsigned("struct io_ring_ctx", ctx, "rings")
        if rings is not None and is_valid_addr(rings):
            if self.ring_stats(ctx) is not None:
                return 10
            return 0
        sq_ring = self.eval_unsigned("struct io_ring_ctx", ctx, "sq_ring")
        cq_ring = self.eval_unsigned("struct io_ring_ctx", ctx, "cq_ring")
        if is_valid_addr(sq_ring) and is_valid_addr(cq_ring):
            if self.ring_stats(ctx) is not None:
                return 10
            return 0
        if self.find_rings_heuristic(ctx) is not None:
            return 3
        return 0

    def context_from_file(self, file):
        ctx = self.eval_unsigned("struct file", file, "private_data")
        if ctx is not None and self.context_score(ctx):
            return ctx, "debug information"

        # struct file is randomized in old kernels and was reordered in v6.5/v7.0.
        # Restrict the fallback to a known io_uring fd, then validate the target as a ring context.
        pointers = read_memory(file, 0x200, safe=True)
        if pointers is None:
            return None, None
        try:
            pointers = slice_unpack(pointers, runtime.current_arch.ptrsize)
        except struct.error:
            return None, None
        candidates = []
        for index, pointer in enumerate(pointers):
            score = self.context_score(pointer)
            if score:
                candidates.append((score, index, pointer))
        if not candidates:
            return None, None
        score, index, ctx = max(candidates)
        return ctx, "validated file member +{:#x}".format(index * runtime.current_arch.ptrsize)

    def get_task_command(self):
        """Return the task resolver initialized for the fd scan, or None. It is resolved on first use,
        so a ctx/request given by ADDRESS does not depend on the task layout."""
        if self.task_command is False:
            self.task_command = Kernel.task()
            task_ready = self.task_command.initialize(files=True)
            self.meta.extend(Kernel.export_meta(self, self.task_command.meta))
            if not task_ready:
                self.task_command = None
            if self.task_command is not None and (self.task_command.offset_files is None or self.task_command.offset_fdt is None):
                self.meta.append((self.quiet_err, "Could not find task_struct->files->fdt"))
                self.task_command = None
        return self.task_command

    def get_kpath(self):
        """Return the VFS resolver, or None. It is resolved on first use like get_task_command()."""
        if self.kpath is False:
            self.kpath = Kernel.path()
            if not self.kpath.initialized:
                self.meta.append((self.quiet_err, "Could not resolve the VFS object layout"))
                self.kpath = None
        return self.kpath

    def task_info(self, task):
        command = self.get_task_command()
        if command is None:
            return None, "???"
        try:
            pid = read_int32_from_memory(task + command.offset_pid)
            comm = read_cstring_from_memory(task + command.offset_comm) or "???"
        except (gdb.MemoryError, OverflowError):
            return None, "???"
        return pid, comm

    def task_label(self, task):
        if not is_valid_addr(task):
            return "{:#x}".format(task or 0)
        pid, comm = self.task_info(task)
        if pid is None:
            return "{:#x}".format(task)
        return "{:#x} {:s}[{:d}]".format(task, comm, pid)

    def iter_task_files(self, task):
        command = self.get_task_command()
        try:
            files = read_int_from_memory(task + command.offset_files)
            fdt = read_int_from_memory(files + command.offset_fdt)
            max_fds = read_int32_from_memory(fdt)
            array = read_int_from_memory(fdt + runtime.current_arch.ptrsize)
        except (gdb.MemoryError, OverflowError):
            return
        if not is_valid_addr(array) or max_fds <= 0:
            return
        for fd in range(min(max_fds, self.MAX_FDS)):
            file = read_int_from_memory(array + runtime.current_arch.ptrsize * fd, safe=True)
            if file:
                yield fd, file
        return

    def find_ring_files(self):
        command = self.get_task_command()
        kpath = self.get_kpath()
        if command is None or kpath is None:
            return None
        tasks = KernelTask.get_task_list(command.init_task, command.offset_tasks)
        rings = []
        for task in tasks:
            pid, comm = self.task_info(task)
            if pid is None or self.args.pid is not None and pid != self.args.pid:
                continue
            for fd, file in self.iter_task_files(task):
                if self.args.fd is not None and fd != self.args.fd:
                    continue
                try:
                    path = kpath.get_file_path(file)
                except (gdb.MemoryError, OverflowError, RuntimeError):
                    continue
                if not self.is_ring_path(path):
                    continue
                ctx, source = self.context_from_file(file)
                rings.append({
                    "task": task, "pid": pid, "comm": comm, "fd": fd, "file": file,
                    "path": path, "ctx": ctx, "ctx_source": source,
                })
        return rings

    def path_for_file(self, file):
        if not is_valid_addr(file) or self.get_kpath() is None:
            return ""
        try:
            return self.kpath.get_file_path(file)
        except (gdb.MemoryError, OverflowError, RuntimeError):
            return ""

    def ring_stats(self, ctx):
        rings = self.eval_unsigned("struct io_ring_ctx", ctx, "rings")
        if rings is not None and is_valid_addr(rings):
            names = ["sq.head", "sq.tail", "cq.head", "cq.tail", "sq_ring_mask", "cq_ring_mask",
                     "sq_ring_entries", "cq_ring_entries", "sq_dropped", "sq_flags.counter",
                     "sq_flags", "cq_flags", "cq_overflow"]
            values = {}
            for name in names:
                value = self.eval_unsigned("struct io_rings", rings, name)
                if value is not None:
                    values[name] = value
            sq_flags = values.get("sq_flags.counter", values.get("sq_flags"))
            return {
                "address": rings,
                "sq_head": values.get("sq.head"), "sq_tail": values.get("sq.tail"),
                "cq_head": values.get("cq.head"), "cq_tail": values.get("cq.tail"),
                "sq_mask": values.get("sq_ring_mask"), "cq_mask": values.get("cq_ring_mask"),
                "sq_entries": values.get("sq_ring_entries"), "cq_entries": values.get("cq_ring_entries"),
                "dropped": values.get("sq_dropped"), "sq_flags": sq_flags,
                "cq_flags": values.get("cq_flags"), "overflow": values.get("cq_overflow"),
            }

        sq = self.eval_unsigned("struct io_ring_ctx", ctx, "sq_ring")
        cq = self.eval_unsigned("struct io_ring_ctx", ctx, "cq_ring")
        if is_valid_addr(sq) and is_valid_addr(cq):
            return {
                "address": sq,
                "sq_head": self.eval_unsigned("struct io_sq_ring", sq, "r.head"),
                "sq_tail": self.eval_unsigned("struct io_sq_ring", sq, "r.tail"),
                "cq_head": self.eval_unsigned("struct io_cq_ring", cq, "r.head"),
                "cq_tail": self.eval_unsigned("struct io_cq_ring", cq, "r.tail"),
                "sq_mask": self.eval_unsigned("struct io_sq_ring", sq, "ring_mask"),
                "cq_mask": self.eval_unsigned("struct io_cq_ring", cq, "ring_mask"),
                "sq_entries": self.eval_unsigned("struct io_sq_ring", sq, "ring_entries"),
                "cq_entries": self.eval_unsigned("struct io_cq_ring", cq, "ring_entries"),
                "dropped": self.eval_unsigned("struct io_sq_ring", sq, "dropped"),
                "sq_flags": self.eval_unsigned("struct io_sq_ring", sq, "flags"),
                "cq_flags": None, "overflow": self.eval_unsigned("struct io_cq_ring", cq, "overflow"),
                "cq_address": cq,
            }

        return self.find_rings_heuristic(ctx)

    def format_optional(self, value):
        if value is None:
            return "?"
        return "{:#x}".format(value)

    def resource_nodes(self, ctx, table):
        nr = self.eval_unsigned("struct io_ring_ctx", ctx, table + ".nr")
        nodes = self.eval_unsigned("struct io_ring_ctx", ctx, table + ".nodes")
        if nr is None or nodes is None:
            return None
        result = []
        for index in range(min(nr, self.MAX_RESOURCES)):
            node = read_int_from_memory(nodes + index * runtime.current_arch.ptrsize, safe=True)
            result.append(node or 0)
        return nr, nodes, result

    def dump_registered_files(self, ctx):
        files = []
        total = None
        source = None

        resources = self.resource_nodes(ctx, "file_table.data")
        if resources is not None:
            total, root, nodes = resources
            source = "file_table.data.nodes={:#x}".format(root)
            for index, node in enumerate(nodes):
                if node:
                    file = self.eval_unsigned("struct io_rsrc_node", node, "file_ptr")
                else:
                    file = 0
                files.append((index, (file or 0) & ~3, node))
        else:
            total, _count_member = self.eval_first("struct io_ring_ctx", ctx, ["nr_user_files", "file_table.data.nr"])
            if total is not None:
                candidates = [
                    ("file_table.files", "struct io_fixed_file", "file_ptr"),
                    ("file_data->table", None, None),
                    ("user_files", None, None),
                ]
                for member, element_type, element_member in candidates:
                    base = self.eval_unsigned("struct io_ring_ctx", ctx, member)
                    if base is None:
                        continue
                    source = member + "={:#x}".format(base)
                    if not base:
                        break
                    two_level = False
                    if element_type:
                        table_type = self.eval_value("struct io_ring_ctx", ctx, member).type.strip_typedefs()
                        two_level = table_type.target().strip_typedefs().code == gdb.TYPE_CODE_PTR
                    for index in range(min(total, self.MAX_RESOURCES)):
                        if element_type:
                            if two_level:
                                block = read_int_from_memory(base + (index >> 9) * runtime.current_arch.ptrsize, safe=True)
                                if block:
                                    slot = block + (index & 511) * runtime.current_arch.ptrsize
                                else:
                                    slot = 0
                            else:
                                slot = base + index * runtime.current_arch.ptrsize
                            if slot:
                                file = self.eval_unsigned(element_type, slot, element_member)
                            else:
                                file = 0
                            mask = ~(runtime.current_arch.ptrsize - 1)
                        else:
                            if member != "user_files":
                                block_member = "file_data->table[{:d}].files".format(index >> 9)
                                block = self.eval_unsigned("struct io_ring_ctx", ctx, block_member)
                                if block:
                                    slot = block + (index & 511) * runtime.current_arch.ptrsize
                                else:
                                    slot = 0
                            else:
                                slot = base + index * runtime.current_arch.ptrsize
                            if slot:
                                file = read_int_from_memory(slot, safe=True)
                            else:
                                file = 0
                            mask = -1
                        files.append((index, (file or 0) & mask, None))
                    break

        if total is None:
            self.out.append("  registered files : unavailable (layout information is required)")
            return
        self.out.append("  registered files : {:d} ({:s})".format(total, source or "no table"))
        for index, file, node in files:
            if not file:
                continue
            if node:
                suffix = " node={:#x}".format(node)
            else:
                suffix = ""
            path = self.path_for_file(file)
            self.out.append("    [{:<4d}] file={:#x}{:s} {:s}".format(index, file, suffix, path).rstrip())
        if total > self.MAX_RESOURCES:
            self.warn_add_out("Registered file table truncated at {:d} entries".format(self.MAX_RESOURCES))
        return

    def buffer_description(self, buffer):
        if not is_valid_addr(buffer):
            return "buffer={:#x}".format(buffer or 0)
        ubuf = self.eval_unsigned("struct io_mapped_ubuf", buffer, "ubuf")
        length, member = self.eval_first("struct io_mapped_ubuf", buffer, ["len", "ubuf_end"])
        if member == "ubuf_end" and ubuf is not None and length is not None:
            length -= ubuf
        nr_bvecs = self.eval_unsigned("struct io_mapped_ubuf", buffer, "nr_bvecs")
        return "buffer={:#x} addr={:s} len={:s} nr_bvecs={:s}".format(
            buffer, self.format_optional(ubuf), self.format_optional(length), self.format_optional(nr_bvecs),
        )

    def dump_registered_buffers(self, ctx):
        buffers = []
        total = None
        source = None
        resources = self.resource_nodes(ctx, "buf_table")
        if resources is not None:
            total, root, nodes = resources
            source = "buf_table.nodes={:#x}".format(root)
            for index, node in enumerate(nodes):
                if node:
                    buffer = self.eval_unsigned("struct io_rsrc_node", node, "buf")
                else:
                    buffer = 0
                buffers.append((index, buffer or 0, node))
        else:
            total = self.eval_unsigned("struct io_ring_ctx", ctx, "nr_user_bufs")
            base = self.eval_unsigned("struct io_ring_ctx", ctx, "user_bufs")
            if total is not None and base is not None:
                source = "user_bufs={:#x}".format(base)
                pointer_array = self.kversion >= "5.13"
                element_size = GefUtil.type_size("struct io_mapped_ubuf")
                for index in range(min(total, self.MAX_RESOURCES)):
                    if pointer_array:
                        buffer = read_int_from_memory(base + index * runtime.current_arch.ptrsize, safe=True)
                    elif element_size is not None:
                        buffer = base + index * element_size
                    else:
                        buffer = 0
                    buffers.append((index, buffer or 0, None))

        if total is None:
            self.out.append("  registered bufs  : unavailable (layout information is required)")
            return
        self.out.append("  registered bufs  : {:d} ({:s})".format(total, source or "no table"))
        for index, buffer, node in buffers:
            if not buffer:
                continue
            if node:
                suffix = " node={:#x}".format(node)
            else:
                suffix = ""
            self.out.append("    [{:<4d}] {:s}{:s}".format(index, self.buffer_description(buffer), suffix))
        if total > self.MAX_RESOURCES:
            self.warn_add_out("Registered buffer table truncated at {:d} entries".format(self.MAX_RESOURCES))
        return

    def request_context(self, request):
        return self.eval_unsigned("struct io_kiocb", request, "ctx")

    def walk_request_list(self, ctx, ctx_member, req_member, state):
        head_offset = GefUtil.offsetof("struct io_ring_ctx", ctx_member)
        req_offset = GefUtil.offsetof("struct io_kiocb", req_member)
        if head_offset is None or req_offset is None:
            return []
        head = ctx + head_offset
        requests = []
        try:
            for request in KernelListHead(head, req_offset).iter_entries():
                if len(requests) >= self.MAX_REQUESTS:
                    break
                if self.request_context(request) != ctx:
                    break
                requests.append((request, state))
        except (gdb.MemoryError, OverflowError):
            pass
        return requests

    def walk_request_slist(self, ctx, ctx_member, req_member, state):
        first = self.eval_unsigned("struct io_ring_ctx", ctx, ctx_member + ".first")
        req_offset = GefUtil.offsetof("struct io_kiocb", req_member)
        if first is None or req_offset is None:
            return []
        requests = []
        seen = set()
        node = first
        while node and node not in seen and len(requests) < self.MAX_REQUESTS:
            seen.add(node)
            request = node - req_offset
            if self.request_context(request) != ctx:
                break
            requests.append((request, state))
            node = read_int_from_memory(node, safe=True)
        return requests

    def walk_request_container_list(self, ctx, ctx_member, container_type, list_member, request_member, state):
        head_offset = GefUtil.offsetof("struct io_ring_ctx", ctx_member)
        list_offset = GefUtil.offsetof(container_type, list_member)
        if head_offset is None or list_offset is None:
            return []
        requests = []
        try:
            for container in KernelListHead(ctx + head_offset, list_offset).iter_entries():
                if len(requests) >= self.MAX_REQUESTS:
                    break
                if request_member is None:
                    request = container
                else:
                    request = self.eval_unsigned(container_type, container, request_member)
                if not request or self.request_context(request) != ctx:
                    break
                requests.append((request, state))
        except (gdb.MemoryError, OverflowError):
            pass
        return requests

    def collect_requests(self, ctx):
        found = []
        if self.kversion < "5.5":
            for field, state in [("defer_list", "deferred"), ("timeout_list", "timeout"),
                                 ("poll_list", "poll"), ("cancel_list", "cancel")]:
                found += self.walk_request_list(ctx, field, "list", state)
        elif self.kversion < "5.16":
            found += self.walk_request_list(ctx, "iopoll_list", "inflight_entry", "iopoll")
            found += self.walk_request_list(ctx, "inflight_list", "inflight_entry", "inflight")
            if self.kversion < "5.9":
                found += self.walk_request_list(ctx, "defer_list", "list", "deferred")
                found += self.walk_request_list(ctx, "timeout_list", "list", "timeout")
        elif self.kversion < "7.0":
            found += self.walk_request_slist(ctx, "iopoll_list", "comp_list", "iopoll")
        else:
            found += self.walk_request_list(ctx, "iopoll_list", "iopoll_node", "iopoll")

        if self.kversion >= "5.9":
            found += self.walk_request_container_list(ctx, "defer_list", "struct io_defer_entry", "list", "req", "deferred")
            for field, state in [("timeout_list", "timeout"), ("ltimeout_list", "linked-timeout")]:
                found += self.walk_request_container_list(ctx, field, "struct io_timeout", "list", None, state)

        requests = []
        seen = set()
        for request, state in found:
            if request in seen:
                continue
            seen.add(request)
            requests.append((request, state))
            link = self.eval_unsigned("struct io_kiocb", request, "link")
            while link and link not in seen and len(requests) < self.MAX_REQUESTS:
                if self.request_context(link) != ctx:
                    break
                seen.add(link)
                requests.append((link, "linked"))
                link = self.eval_unsigned("struct io_kiocb", link, "link")
        return requests

    def opcode_name(self, opcode):
        if opcode is None:
            return "?"
        if opcode < len(self.OPCODES):
            return self.OPCODES[opcode]
        return "OP_{:d}".format(opcode)

    def request_info(self, request, state):
        opcode, opcode_member = self.eval_first("struct io_kiocb", request, ["opcode", "submit.sqe->opcode"])
        file = self.eval_unsigned("struct io_kiocb", request, "file")
        buffer, buffer_member = self.eval_first("struct io_kiocb", request, ["imu", "kbuf", "buf_node"])
        refs, refs_member = self.eval_first("struct io_kiocb", request, ["refs.counter", "refs.refs.counter", "refs"])
        flags = self.eval_unsigned("struct io_kiocb", request, "flags")
        user_data, user_member = self.eval_first("struct io_kiocb", request, ["cqe.user_data", "user_data", "submit.sqe.user_data"])
        callback, callback_member = self.eval_first(
            "struct io_kiocb", request, ["io_task_work.func", "task_work.func", "work.func"],
        )
        if callback is None:
            callback_text = "?"
        else:
            callback_text = Symbol.format(callback, show_address=True, nocolor=True)
        return {
            "address": request, "state": state, "opcode": opcode, "file": file,
            "buffer": buffer, "buffer_member": buffer_member, "refs": refs,
            "refs_member": refs_member, "flags": flags, "user_data": user_data,
            "user_member": user_member, "opcode_member": opcode_member,
            "callback": callback_text, "callback_member": callback_member,
        }

    def dump_requests(self, requests):
        self.out.append("  requests         : {:d}".format(len(requests)))
        if not requests:
            return
        fmt = "    {:18s} {:10s} {:20s} {:18s} {:18s} {:7s} {:s}"
        self.out.append(GefUtil.make_legend(fmt.format("io_kiocb", "state", "opcode", "file", "buffer", "refs", "callback")))
        for request, state in requests:
            info = self.request_info(request, state)
            if info["opcode"] is not None:
                opcode = "{:d}:{:s}".format(info["opcode"], self.opcode_name(info["opcode"]))
            else:
                opcode = "?"
            self.out.append(fmt.format(
                "{:#x}".format(request), state, opcode,
                self.format_optional(info["file"]), self.format_optional(info["buffer"]),
                "?" if info["refs"] is None else str(info["refs"]), info["callback"],
            ))
            if self.args.verbose:
                path = self.path_for_file(info["file"])
                self.out.append("      flags={:s} user_data={:s} file_path={:s}".format(
                    self.format_optional(info["flags"]), self.format_optional(info["user_data"]), path or "?",
                ))
        return

    def dump_workers(self, ctx, owners):
        workers = []
        for member in ["submitter_task", "sqo_task", "sqo_thread", "sq_data.thread"]:
            task = self.eval_unsigned("struct io_ring_ctx", ctx, member)
            if task:
                workers.append((member, task))
        io_wq = self.eval_unsigned("struct io_ring_ctx", ctx, "io_wq")
        if io_wq:
            self.out.append("  io_wq            : {:#x} (ctx)".format(io_wq))

        seen_tasks = set()
        for owner in owners:
            task = owner.get("task")
            if not task or task in seen_tasks:
                continue
            seen_tasks.add(task)
            tctx = self.eval_unsigned("struct task_struct", task, "io_uring")
            if not tctx:
                continue
            task_wq = self.eval_unsigned("struct io_uring_task", tctx, "io_wq")
            last = self.eval_unsigned("struct io_uring_task", tctx, "last")
            self.out.append("  task io_uring    : {:#x} owner={:s} last={:s} io_wq={:s}".format(
                tctx, self.task_label(task), self.format_optional(last), self.format_optional(task_wq),
            ))
            for index in range(16):
                ring_file = self.eval_unsigned("struct io_uring_task", tctx, "registered_rings[{:d}]".format(index))
                if ring_file:
                    self.out.append("    registered_rings[{:<2d}]={:#x}".format(index, ring_file))

        for member, task in workers:
            self.out.append("  {:16s}: {:s}".format(member, self.task_label(task)))
        return

    def dump_context(self, ctx, owners):
        self.out.append(titlify("struct io_ring_ctx {:#x}".format(ctx)))
        for owner in owners:
            if owner.get("file") and owner.get("task") is None:
                # the file given by ADDRESS; its owner task is not searched
                self.out.append("  file             : {:#x} {:s}".format(owner["file"], owner.get("path", "")).rstrip())
            elif owner.get("file"):
                self.out.append("  owner            : {:s}[{:d}] task={:#x} fd={:d} file={:#x} {:s}".format(
                    owner.get("comm", "???"), owner.get("pid", -1), owner.get("task", 0), owner.get("fd", -1),
                    owner["file"], owner.get("path", ""),
                ).rstrip())
            if owner.get("file") and owner.get("ctx_source"):
                self.out.append("  private_data     : {:s}".format(owner["ctx_source"]))

        flags = self.eval_unsigned("struct io_ring_ctx", ctx, "flags")
        int_flags = self.eval_unsigned("struct io_ring_ctx", ctx, "int_flags")
        self.out.append("  flags            : {:s}{:s}".format(
            self.format_optional(flags),
            " int_flags={:s}".format(self.format_optional(int_flags)) if int_flags is not None else "",
        ))

        stats = self.ring_stats(ctx)
        if stats is None:
            self.out.append("  rings            : unavailable")
        else:
            if stats.get("cq_address"):
                cq_address = " cq={:#x}".format(stats["cq_address"])
            else:
                cq_address = ""
            if stats.get("heuristic"):
                source = " (validated memory layout)"
            else:
                source = ""
            self.out.append("  rings            : {:#x}{:s}{:s}".format(stats["address"], cq_address, source))
            self.out.append("    SQ head={:s} tail={:s} mask={:s} entries={:s} dropped={:s} flags={:s}".format(
                self.format_optional(stats.get("sq_head")), self.format_optional(stats.get("sq_tail")),
                self.format_optional(stats.get("sq_mask")), self.format_optional(stats.get("sq_entries")),
                self.format_optional(stats.get("dropped")), self.format_optional(stats.get("sq_flags")),
            ))
            self.out.append("    CQ head={:s} tail={:s} mask={:s} entries={:s} overflow={:s} flags={:s}".format(
                self.format_optional(stats.get("cq_head")), self.format_optional(stats.get("cq_tail")),
                self.format_optional(stats.get("cq_mask")), self.format_optional(stats.get("cq_entries")),
                self.format_optional(stats.get("overflow")), self.format_optional(stats.get("cq_flags")),
            ))

        self.dump_workers(ctx, owners)
        self.dump_registered_files(ctx)
        self.dump_registered_buffers(ctx)
        if not self.args.no_requests:
            if GefUtil.type_size("struct io_ring_ctx") is None or GefUtil.type_size("struct io_kiocb") is None:
                self.out.append("  requests         : unavailable (layout information is required)")
            else:
                self.dump_requests(self.collect_requests(ctx))
        return

    def detect_address_type(self, address):
        if self.context_score(address):
            return "ctx"
        if self.request_context(address) and self.context_score(self.request_context(address)):
            return "request"
        if self.is_ring_path(self.path_for_file(address)):
            return "file"
        return None

    def print_meta(self):
        self.quiet_info("kernel version: {!s}".format(self.kversion))
        for type_name in ["struct file", "struct io_ring_ctx", "struct io_kiocb", "struct io_uring_task",
                          "struct io_mapped_ubuf", "struct io_rsrc_node"]:
            size = GefUtil.type_size(type_name)
            self.quiet_info("sizeof({:s}): {:s}".format(
                type_name.replace("struct ", ""),
                "unavailable" if size is None else "{:#x}".format(size),
            ))
        for type_name, member in [
            ("struct file", "private_data"), ("struct io_ring_ctx", "rings"),
            ("struct io_ring_ctx", "file_table"), ("struct io_ring_ctx", "buf_table"),
            ("struct io_ring_ctx", "nr_user_files"), ("struct io_ring_ctx", "nr_user_bufs"),
            ("struct io_kiocb", "opcode"), ("struct io_kiocb", "ctx"),
            ("struct task_struct", "io_uring"),
        ]:
            offset = GefUtil.offsetof(type_name, member)
            self.quiet_info("offsetof({:s}, {:s}): {:s}".format(
                type_name.replace("struct ", ""), member,
                "unavailable" if offset is None else "{:#x}".format(offset),
            ))
        return

    def initialize(self):
        self.meta = []
        self.kversion = Kernel.version()
        if self.kversion is None:
            self.meta.append((self.quiet_err, "Could not find Linux kernel"))
            return None
        # the task list and the VFS are needed only to find the rings from the fds
        self.task_command = False
        self.kpath = False
        return True

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.args = args
        if args.fd is not None and args.pid is None:
            err("--fd requires --pid")
            return
        if args.fd is not None and args.fd < 0:
            err("FD must not be negative")
            return
        self.quiet_info("Wait for memory scan")
        if not self.initialize():
            for func, line in self.meta:
                func(line)
            self.quiet_err("Failed to initialize")
            return
        if self.kversion < "5.1":
            self.quiet_warn("This kernel predates io_uring, which first appeared in mainline v5.1")
            return
        if args.meta:
            fd_scan = self.get_task_command() is not None and self.get_kpath() is not None
            for func, line in self.meta:
                func(line)
            self.print_meta()
            self.quiet_info("ring discovery from fds: {:s}".format("available" if fd_scan else "unavailable"))
            return

        self.out = []
        if args.address is not None:
            if args.type != "auto":
                address_type = args.type
            else:
                address_type = self.detect_address_type(args.address)
            if address_type == "request":
                ctx = self.request_context(args.address)
                if not self.context_score(ctx):
                    self.err_add_out("Could not validate request->ctx for {:#x}".format(args.address))
                else:
                    self.dump_context(ctx, [])
                    self.dump_requests([(args.address, "selected")])
            elif address_type == "file":
                path = self.path_for_file(args.address)
                ctx, source = self.context_from_file(args.address)
                if self.kpath is None:
                    for func, line in self.meta:
                        func(line)
                    self.err_add_out("An io_uring file cannot be verified without the VFS object layout")
                elif not self.is_ring_path(path) or ctx is None:
                    self.err_add_out("Could not interpret {:#x} as an io_uring file".format(args.address))
                else:
                    self.dump_context(ctx, [{"file": args.address, "path": path, "ctx_source": source}])
            elif address_type == "ctx":
                if not self.context_score(args.address):
                    self.err_add_out("Could not validate io_ring_ctx at {:#x}".format(args.address))
                else:
                    self.dump_context(args.address, [])
            else:
                self.err_add_out("Could not identify {:#x} as io_ring_ctx, io_kiocb or io_uring file".format(args.address))
            self.print_output(check_terminal_size=True)
            return

        ring_files = self.find_ring_files()
        if ring_files is None:
            for func, line in self.meta:
                func(line)
            self.quiet_err("Failed to initialize the fd scan (ADDRESS with --type ctx/request does not need it)")
            return
        contexts = collections.OrderedDict()
        unresolved = []
        for owner in ring_files:
            if owner["ctx"] is None:
                unresolved.append(owner)
            else:
                contexts.setdefault(owner["ctx"], []).append(owner)
        for ctx, owners in contexts.items():
            self.dump_context(ctx, owners)
        for owner in unresolved:
            self.warn_add_out("Found {:s}[{:d}] fd={:d} file={:#x}, but file->private_data could not be resolved".format(
                owner["comm"], owner["pid"], owner["fd"], owner["file"],
            ))
        if not ring_files:
            self.warn_add_out("No open io_uring file descriptors found")
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelLsmCommand(GenericCommand, BufferingOutput):
    """Dump the registered Linux Security Module hooks."""

    _cmdline_ = "klsm"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("hook", metavar="HOOK", nargs="*", help="the hook point name, or a part of it. (e.g., file_open)")
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-a", "--all", action="store_true", help="also show the hook points that have no callback.")
    parser.add_argument("--task", action="store_true", help="show the LSM security blobs of each task instead of the hooks.")
    parser.add_argument("-p", "--pid", type=lambda x: int(x, 0), help="with --task, filter by task pid.")
    parser.add_argument("-T", "--task-filter", action="append", type=AddressUtil.parse_address, default=[],
                        help="with --task, filter by specific task_struct address.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="with --task, comm string REGEXP filter.")
    parser.add_argument("-v", "--verbose", action="store_true", help="with --task, decode the blobs of the open files of each task too.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                   # list every hook point that has a callback",
        "{0:s} file_open         # list the callbacks of the hook points matching `file_open`",
        "{0:s} -a                # list every hook point including the empty ones",
        "{0:s} --task            # list the security blob and the LSM labels of each task",
        "{0:s} --task -p 1337    # decode the blobs of the task, its cred and its open files and inodes",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "The layout of the LSM framework changed twice, and all three are supported:",
        "",
        "  ~v4.1  : a single `struct security_operations` pointed to by `security_ops`",
        "  v4.2~  : `security_hook_heads`, an array of the lists of `struct security_hook_list`",
        "  v6.12~ : one static call slot per (hook point, LSM), `__SCK__lsm_static_call_*`",
        "",
        "+-security_ops(~v4.1)-+",
        "| name[]              |",
        "| ptrace_access_check |--> callback",
        "| ptrace_traceme      |--> callback",
        "| ...                 |",
        "+---------------------+",
        "",
        "+-security_hook_heads(v4.2~)-+     +-security_hook_list--+",
        "| ptrace_access_check        |---->| list                |--> next hook_list",
        "| ptrace_traceme             |     | head                |--> the head at the left",
        "| ...                        |     | hook                |--> callback",
        '+----------------------------+     | lsm (v4.12~)        |--> "selinux"',
        "                                   +---------------------+",
        "",
        "+-__SCK__lsm_static_call_<hook>_<N>(v6.12~)-+",
        "| func                                      |--> callback",
        "+-------------------------------------------+",
        "",
        "Before v6.12, hook point names are recovered from each `security_*` dispatcher and",
        "the head or member offset it references. A head that no dispatcher pointed at is",
        "shown as `hook[NN]`. On v6.12 and later, names are read from generated static-call",
        "symbols such as `__SCK__lsm_static_call_<hook>_<N>`.",
        "",
        "When CONFIG_KALLSYMS_ALL=n removes these data symbols, x86 decodes the trampolines",
        "`__SCT__lsm_static_call_<hook>_<N>` (text symbols), and the other architectures take",
        "the keys each `security_*` dispatcher loads. The latter names a hook point after its",
        "dispatcher and misses the ones no dispatcher calls (e.g., inode_free_security_rcu).",
        "",
        "`--task` follows the security blobs instead. Until v5.0 the active major LSM owns each",
        "blob as a whole. From v5.1 the LSMs share one blob per object, and the offset of each",
        "part is read from `<lsm>_blob_sizes`; without the symbol it is guessed from the samples.",
        "",
        "+-task_struct-+                    +-cred-----+     +-file-------+    +-inode------+",
        "| security    |--> blob (v5.1~)    | ...      |     | ...        |    | i_sb       |",
        "| cred        |------------------->| security |-+   | f_security |-+  | i_mapping  |",
        "+-------------+                    +----------+ |   +------------+ |  | i_security |-+",
        "                                                |                  |  +------------+ |",
        "   +-blob--------------+ <----------------------+------------------+-----------------+",
        "   | part of LSM A     | <-- offset from <lsmA>_blob_sizes.lbs_*",
        "   | part of LSM B     | <-- offset from <lsmB>_blob_sizes.lbs_*",
        "   +-------------------+",
        "",
        "SELinux, Smack, AppArmor, TOMOYO and Landlock parts are decoded. This mode requires",
        "CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
    ]
    _note_ = "\n".join(_note_)

    SCK_PREFIX = "__SCK__lsm_static_call_"
    SCT_PREFIX = "__SCT__lsm_static_call_"

    # the prefixes the hook callbacks of each LSM use, tried from the longest one
    LSM_PREFIXES = (
        ("apparmor", "apparmor_"), ("apparmor", "aa_"),
        ("bpf", "bpf_lsm_"),
        ("capability", "cap_"),
        ("evm", "evm_"),
        ("ima", "ima_"),
        ("integrity", "integrity_"),
        ("ipe", "ipe_"),
        ("landlock", "landlock_"), ("landlock", "hook_"),
        ("loadpin", "loadpin_"),
        ("lockdown", "lockdown_"),
        ("safesetid", "safesetid_"),
        ("selinux", "selinux_"),
        ("smack", "smack_"), ("smack", "smk_"),
        ("tomoyo", "tomoyo_"),
        ("yama", "yama_"),
    )

    @staticmethod
    def format_addr(value):
        return Color.colorify(AddressUtil.format_address(value), "bold blue")

    def read_cstring(self, addr, size=32):
        """Read a NUL-terminated ASCII string, or return '' if it is not one."""
        if not addr or not is_valid_addr(addr):
            return ""
        data = read_memory(addr, size, safe=True)
        if data is None:
            return ""
        data = data.split(b"\0")[0]
        if not data or not all(0x20 <= c < 0x7f for c in bytearray(data)):
            return ""
        return String.bytes2str(data)

    def read_lsm_name(self, addr):
        """Decode either an old `char *lsm` or a new `struct lsm_id *lsmid`."""
        if not addr or not is_valid_addr(addr):
            return ""

        # struct lsm_id { const char *name; u64 id; }.  Resolve `name` from
        # DWARF when present, while retaining offset zero as the ABI fallback.
        offsets = [0]
        dwarf_offset = GefUtil.offsetof("lsm_id", "name")
        if dwarf_offset is not None and dwarf_offset not in offsets:
            offsets.insert(0, dwarf_offset)
        for offset in offsets:
            name_ptr = read_int_from_memory(addr + offset, safe=True)
            if name_ptr is None:
                continue
            name = self.read_cstring(name_ptr, 32)
            if re.fullmatch(r"[a-z][a-z0-9_]{1,31}", name):
                return name

        # v4.12-era security_hook_list stored the string pointer directly.
        name = self.read_cstring(addr, 32)
        if re.fullmatch(r"[a-z][a-z0-9_]{1,31}", name):
            return name
        return ""

    def is_kernel_text(self, addr):
        if not addr:
            return False
        layout = self.klayout
        if layout is None or not layout.text_base or not layout.text_end:
            return False
        if layout.text_base <= addr < layout.text_end:
            return True
        # a module may register hooks too
        consts = KernelAddressHeuristicFinder.consts()
        if consts is None or not consts.MODULES_VADDR:
            return False
        return consts.MODULES_VADDR <= addr < consts.MODULES_END

    def extract_data_refs(self, res):
        """Return the addresses of the globals the disassembled code refers to."""
        lea_rip = r"lea\s+\w+,\s*\[rip[+-]0x\w+\].*#\s*(0x\w+)"
        if is_x86_64():
            g = itertools.chain(
                KernelAddressHeuristicFinderUtil.x64_qword_ptr_rip_base(res),
                KernelAddressHeuristicFinderUtil.common_addr_gen(res, lea_rip, 0, False, False),
                # a kCFI build materializes the head with `mov reg, imm64` instead
                KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res),
            )
        elif is_x86_32():
            g = itertools.chain(
                KernelAddressHeuristicFinderUtil.x86_ds_absolute(res),
                KernelAddressHeuristicFinderUtil.x64_x86_mov_reg_const(res),
            )
        elif is_arm64():
            g = itertools.chain(
                KernelAddressHeuristicFinderUtil.aarch64_adrp_ldr(res, allow_add=True),
                KernelAddressHeuristicFinderUtil.aarch64_adrp_add(res),
            )
        elif is_arm32():
            g = itertools.chain(
                KernelAddressHeuristicFinderUtil.arm32_movw_movt_ldr(res),
                KernelAddressHeuristicFinderUtil.arm32_movw_movt(res),
                KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative_ldr(res),
                KernelAddressHeuristicFinderUtil.arm32_ldr_pc_relative(res),
            )
        elif is_riscv32() or is_riscv64():
            # gcc may materialize the address of the whole array and load a head at an offset from it,
            # so take the loaded heads before the addresses themselves
            g = itertools.chain(
                KernelAddressHeuristicFinderUtil.riscv_auipc_gen(res, False, True, 0, False, False, word_only=True, follow_addi=True),
                KernelAddressHeuristicFinderUtil.riscv_auipc_addi(res),
            )
        else:
            return []
        # `get_kernel_image_range()` stops at the RW range gef could detect, and the array
        # sits past it on many builds, so only reject what cannot be a head at all.
        refs = []
        for x in g:
            if x is None or x % runtime.current_arch.ptrsize:
                continue
            if not KernelAddressHeuristicFinderUtil.is_kernel_space(x) or self.is_kernel_text(x):
                continue
            if x not in refs:
                refs.append(x)
        return refs

    def extract_call_displacement(self, res):
        """Return the member offset of the indirect call the dispatcher makes, or None."""
        if is_x86():
            m = re.search(r"call\s+(?:[QD]WORD PTR\s+)?\[\w+(?:\+(0x\w+))?\]", res)
            if m:
                if m.group(1):
                    return int(m.group(1), 16)
                return 0
            return None
        if is_arm64() or is_arm32():
            loaded = {}
            for line in res.splitlines():
                m = re.search(r"ldr\s+(\w+),\s*\[\w+(?:,\s*#(\d+))?\]", line)
                if m:
                    if m.group(2):
                        loaded[m.group(1)] = int(m.group(2), 0)
                    else:
                        loaded[m.group(1)] = 0
                    continue
                m = re.search(r"bl[rx]\s+(\w+)", line)
                if m and m.group(1) in loaded:
                    return loaded[m.group(1)]
            return None
        return None

    def iter_dispatchers(self, count=None):
        """Yield (hook name, disassembly) of each `security_*` function."""
        ret = Ksym.get_kallsyms()
        if ret is None:
            return
        kallsyms, _kallsyms_map = ret
        if count is None:
            # RVC halves most instructions, and the head is often loaded after a call that allocates something
            if is_riscv32() or is_riscv64():
                count = 64
            else:
                count = 40
        seen = set()
        for addr, name, typ in sorted(kallsyms):
            if typ.lower() not in ("t", "w"):
                continue
            if not name.startswith("security_") or "." in name:
                continue
            hook = name[len("security_"):]
            if not hook or hook in seen:
                continue
            seen.add(hook)
            try:
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, count)
            except gdb.error:
                continue
            yield hook, res
        return

    @staticmethod
    def hook_name_from_callback(func_name, lsm):
        """Guess the hook point name from the name of one of its callbacks."""
        if not func_name:
            return None
        prefixes = []
        if lsm:
            prefixes.append("{:s}_".format(lsm))
            prefixes += [p for name, p in KernelLsmCommand.LSM_PREFIXES if name == lsm]
        prefixes += [p for _name, p in KernelLsmCommand.LSM_PREFIXES]
        for prefix in sorted(set(prefixes), key=len, reverse=True):
            if func_name.startswith(prefix) and len(func_name) > len(prefix):
                return func_name[len(prefix):]
        return None

    #
    # v6.12 or later: one static call slot per (hook point, LSM)
    #

    def collect_static_calls(self):
        """Return {hook name: [(slot, key address, callback), ...]} built from the static call keys."""
        ret = Ksym.get_kallsyms()
        if ret is None:
            return {}
        kallsyms, _kallsyms_map = ret
        hooks = {}
        for addr, name, _typ in kallsyms:
            if not name.startswith(self.SCK_PREFIX):
                continue
            hook, _sep, slot = name[len(self.SCK_PREFIX):].rpartition("_")
            if not hook or not slot.isdigit():
                continue
            func = read_int_from_memory(addr, safe=True)
            if func is None:
                continue
            hooks.setdefault(hook, []).append((int(slot), addr, func))
        for entries in hooks.values():
            entries.sort()
        return hooks

    def collect_static_call_trampolines(self):
        """Return {hook name: [(slot, trampoline address, callback), ...]} decoded from the trampolines.
        CONFIG_HAVE_STATIC_CALL (x86) generates a text symbol `__SCT__lsm_static_call_<hook>_<N>` for each slot,
        which remains even if CONFIG_KALLSYMS_ALL=n. static_call_update() rewrites it into `jmp callback`,
        or `ret` (or a jump to the return thunk) for an empty slot."""
        if not is_x86():
            return {}
        ret = Ksym.get_kallsyms()
        if ret is None:
            return {}
        kallsyms, _kallsyms_map = ret
        hooks = {}
        for addr, name, _typ in kallsyms:
            if not name.startswith(self.SCT_PREFIX):
                continue
            hook, _sep, slot = name[len(self.SCT_PREFIX):].rpartition("_")
            if not hook or not slot.isdigit():
                continue
            code = read_memory(addr, 5, safe=True)
            if code is None:
                continue
            func = 0
            if code[0] == 0xe9: # jmp rel32
                target = AddressUtil.normalize_address(addr + 5 + struct.unpack("<i", code[1:5])[0])
                if (self.is_kernel_text(target)
                        and "return_thunk" not in Symbol.format(target, ksym="prefer", bracket="")):
                    func = target
            hooks.setdefault(hook, []).append((int(slot), addr, func))
        for entries in hooks.values():
            entries.sort()
        return hooks

    def trace_dispatcher_refs(self, res):
        """Return (the addresses of the globals whose value is called in the slot order, every global address
        materialized) in the disassembled dispatcher of ARM32, ARM64 or RISC-V, e.g. `adrp x21;
        add x21, x21, #lo; ldr x1, [x21, #off]; blr x1`. The base registers are tracked through the listing
        in address order.
        The call of each slot sits in an out-of-line block, and neither the block order nor the key address
        order is the slot order. The main flow checks the slots in order and branches to the blocks
        (a patched jump label, or `ldr; cmp; bgt` without CONFIG_JUMP_LABEL), so the calls are sorted by
        the first branch into their block. The calls that no branch reaches follow in the code order."""
        if is_arm64():
            patterns = {
                "base": r"adrp\s+(x\d+),\s*(0x[0-9a-f]+)",
                "add": r"add\s+(x\d+),\s*(x\d+),\s*#(0x[0-9a-f]+|\d+)$",
                "load": r"ldr\s+(x\d+),\s*\[(x\d+)(?:,\s*#(-?(?:0x[0-9a-f]+|\d+)))?\](?:\s*//.*)?$",
                "icall": r"blr\s+(x\d+)",
                "call": r"bl\s",
                "branch": r"(?:b|b\.\w+|cbn?z\s+\w+,|tbn?z\s+\w+,\s*#\d+,)\s*(0x[0-9a-f]+)",
                "jump": r"b\s",
                "return": r"ret\b|br\s",
            }
            no_write = r"st\w*|cmp|cmn|tst|cbn?z|tbn?z|b|b\.\w+|br|blr|bl|ret|nop|ccmp|prfm|hint|bti|pac\w*|aut\w*"
        elif is_arm32():
            patterns = {
                "movw": r"movw\s+(\w+),.*@\s*(0x[0-9a-f]+)",
                "movt": r"movt\s+(\w+),.*@\s*(0x[0-9a-f]+)",
                "literal": r"ldr\s+(\w+),\s*\[pc,\s*#-?\d+\]\s*@\s*(0x[0-9a-f]+)",
                "add": r"add\s+(\w+),\s*(\w+),\s*#(\d+)",
                "load": r"ldr\s+(\w+),\s*\[(\w+)(?:,\s*#(-?\d+))?\](?:\s*@.*)?$",
                "icall": r"blx\s+(\w+)",
                "call": r"bl\s",
                "branch": r"b(?:[a-z]{2})?\s+(0x[0-9a-f]+)",
                "jump": r"b\s",
                "return": r"bx\s+lr|(?:ldm\w*|pop)\s+.*\bpc\}",
            }
            no_write = r"str\w*|stm\w*|push|cmp|cmn|tst|teq|b|b[a-z]{2}|bx|blx|bl|nop"
        elif is_riscv32() or is_riscv64():
            patterns = {
                "auipc": r"auipc\s+(\w+),\s*(0x[0-9a-f]+|\d+)",
                "add": r"addi\s+(\w+),\s*(\w+),\s*(-?\d+)",
                "load": r"(?:ld|lw)\s+(\w+),\s*(-?\d+)\((\w+)\)",
                "icall": r"jalr\s+(?:\w+,\s*(?:0)?\()?(\w+)\)?$",
                "call": r"(?:jal|call|tail)\s|jalr\s+-?\d+\(",
                "branch": r"(?:j|b\w+\s+\w+,(?:\s*\w+,)?)\s*(0x[0-9a-f]+)",
                "jump": r"j\s",
                "return": r"ret\b|jr\s",
            }
            no_write = r"s[bhwd]|b\w*|j|jr|jalr|ret|fence\S*|nop|wfi"
        else:
            return [], []

        bases = {}
        loaded = {}
        called = []
        branches = []
        materialized = []
        # the registers at each branch are taken to its target, which is reached after an epilogue in the listing
        pending = {}
        dead = False
        for line in res.splitlines():
            m = re.match(r"\s*(?:=>\s*)?(0x[0-9a-f]+)(?:\s+<[^>]*>)?:\s*(\S+)\s*(.*)", line)
            if not m:
                continue
            pc, mnemonic = int(m.group(1), 16), m.group(2)
            insn = "{:s} {:s}".format(mnemonic, m.group(3).strip())
            if pc in pending:
                if dead:
                    bases, loaded = dict(pending[pc][0]), dict(pending[pc][1])
                else:
                    bases, loaded = dict(pending[pc][0], **bases), dict(pending[pc][1], **loaded)
            dead = False
            written = None
            m = re.match(patterns["branch"], insn)
            if m:
                target = int(m.group(1), 16)
                branches.append((pc, target))
                pending.setdefault(target, (dict(bases), dict(loaded)))
                dead = bool(re.match(patterns["jump"], insn))
                continue
            if re.match(patterns["return"], insn):
                dead = True
                continue
            # A call does not forget the caller-saved registers, since the blocks after it are often
            # reached by branches with those registers restored (e.g. `ldrd r2, [r11, #-28]` on ARM32).
            m = re.match(patterns["icall"], insn)
            if m:
                if m.group(1) in loaded:
                    called.append((pc, loaded[m.group(1)]))
                continue
            if re.match(patterns["call"], insn):
                continue
            if "base" in patterns and re.match(patterns["base"], insn):
                m = re.match(patterns["base"], insn)
                bases[m.group(1)] = int(m.group(2), 16)
                loaded.pop(m.group(1), None)
                materialized.append(bases[m.group(1)])
                continue
            if "auipc" in patterns and re.match(patterns["auipc"], insn):
                m = re.match(patterns["auipc"], insn)
                hi20 = int(m.group(2), 0) & 0xfffff
                if hi20 & 0x80000:
                    hi20 -= 0x100000
                bases[m.group(1)] = AddressUtil.normalize_address(pc + (hi20 << 12))
                loaded.pop(m.group(1), None)
                continue
            if "movw" in patterns:
                m = re.match(patterns["movw"], insn)
                if m:
                    bases[m.group(1)] = int(m.group(2), 16)
                    loaded.pop(m.group(1), None)
                    continue
                m = re.match(patterns["movt"], insn)
                if m and m.group(1) in bases:
                    bases[m.group(1)] = (bases[m.group(1)] & 0xffff) | (int(m.group(2), 16) << 16)
                    materialized.append(bases[m.group(1)])
                    continue
                m = re.match(patterns["literal"], insn)
                if m:
                    value = read_int_from_memory(int(m.group(2), 16), safe=True)
                    if value is not None:
                        bases[m.group(1)] = value
                        loaded.pop(m.group(1), None)
                        materialized.append(value)
                        continue
            m = re.match(patterns["add"], insn)
            if m and m.group(2) in bases:
                bases[m.group(1)] = AddressUtil.normalize_address(bases[m.group(2)] + int(m.group(3), 0))
                loaded.pop(m.group(1), None)
                materialized.append(bases[m.group(1)])
                continue
            m = re.match(patterns["load"], insn)
            if m:
                if is_riscv32() or is_riscv64():
                    dst, offset, base = m.group(1), m.group(2), m.group(3)
                else:
                    dst, base, offset = m.group(1), m.group(2), m.group(3)
                if base in bases:
                    addr = AddressUtil.normalize_address(bases[base] + int(offset or "0", 0))
                    materialized.append(addr)
                    bases.pop(dst, None)
                    loaded[dst] = addr
                    continue
            # any other instruction overwrites its first operand
            if not re.fullmatch(no_write, mnemonic):
                m = re.match(r"\S+\s+(\w+)", insn)
                if m:
                    written = re.sub(r"^w(\d+)$", r"x\1", m.group(1))
                    bases.pop(written, None)
                    loaded.pop(written, None)

        # the block of a call is the few instructions before it
        first_branch = {}
        for pc, target in sorted(branches):
            for call_pc, key in called:
                if 0 <= call_pc - target <= 0x40:
                    first_branch.setdefault(key, pc)
                    break
        keys = list(dict.fromkeys(key for _pc, key in called))
        keys.sort(key=lambda x: (x not in first_branch, first_branch.get(x, 0)))
        return keys, list(dict.fromkeys(materialized))

    # the hook points whose dispatcher has another name, which the static call keys are named after
    DISPATCHER_HOOK_NAMES = {
        "bprm_check": "bprm_check_security",
        "file_alloc": "file_alloc_security", "file_free": "file_free_security",
        "inode_alloc": "inode_alloc_security", "inode_free": "inode_free_security",
        "sb_alloc": "sb_alloc_security", "sb_free": "sb_free_security",
        "msg_msg_alloc": "msg_msg_alloc_security", "msg_msg_free": "msg_msg_free_security",
        "msg_queue_alloc": "msg_queue_alloc_security", "msg_queue_free": "msg_queue_free_security",
        "shm_alloc": "shm_alloc_security", "shm_free": "shm_free_security",
        "sem_alloc": "sem_alloc_security", "sem_free": "sem_free_security",
        "sk_alloc": "sk_alloc_security", "sk_free": "sk_free_security", "sk_clone": "sk_clone_security",
        "sock_rcv_skb": "socket_sock_rcv_skb",
        "prepare_creds": "cred_prepare", "transfer_creds": "cred_transfer",
        "settime64": "settime", "free_mnt_opts": "sb_free_mnt_opts", "create_user_ns": "userns_create",
        "vm_enough_memory_mm": "vm_enough_memory",
        "xfrm_policy_alloc": "xfrm_policy_alloc_security", "xfrm_policy_free": "xfrm_policy_free_security",
        "xfrm_policy_delete": "xfrm_policy_delete_security", "xfrm_state_free": "xfrm_state_free_security",
        "xfrm_state_delete": "xfrm_state_delete_security",
    }

    def collect_static_call_dispatchers(self):
        """Return {hook name: [(slot, key address, callback), ...]} built from the keys the dispatchers load.
        Without CONFIG_HAVE_STATIC_CALL, a static call loads `key.func` and calls it, so a dispatcher calls
        through every key of its hook point, and the keys of a hook point are adjacent. A few dispatchers iterate
        `static_calls_table.<hook>[]` (struct lsm_static_call {key, trampoline, hl, active}) instead, which
        holds the keys in the slot order.
        Some dispatchers call another hook point too (e.g. inode_xattr_skipcap from security_inode_setxattr()),
        so a key belongs to the dispatcher that refers to the fewest keys, and a dispatcher that owns several
        hook points is split by the number of slots."""
        ptrsize = runtime.current_arch.ptrsize
        refs = {}
        table_refs = {}
        for hook, res in self.iter_dispatchers(count=400):
            hook = self.DISPATCHER_HOOK_NAMES.get(hook, hook)
            called, materialized = self.trace_dispatcher_refs(res)
            keys = []
            for addr in called:
                value = read_int_from_memory(addr, safe=True)
                if value is not None and (value == 0 or self.is_kernel_text(value)):
                    keys.append(addr)
            for addr in materialized:
                value = read_int_from_memory(addr, safe=True)
                if value and not self.is_kernel_text(value) and is_valid_addr(value):
                    table_refs.setdefault(hook, []).append(addr)
            refs[hook] = keys

        counts = collections.Counter(len(keys) for keys in refs.values() if keys)
        if not counts:
            return {}
        nr_slots = counts.most_common(1)[0][0]

        stride = ptrsize * 4
        for hook, candidates in table_refs.items():
            for addr in candidates:
                try:
                    entries = [slice_unpack(read_memory(addr + stride * i, stride), ptrsize) for i in range(nr_slots)]
                    keys = [key for key, _trampoline, _hl, _active in entries]
                    funcs = [read_int_from_memory(key) for key in keys]
                except (gdb.MemoryError, OverflowError):
                    continue
                # the trampoline is NULL without CONFIG_HAVE_STATIC_CALL, and every slot has its static key
                if any(trampoline or not is_valid_addr(active) for _key, trampoline, _hl, active in entries):
                    continue
                # the keys of a hook point are adjacent, while other variables may be between them
                if len(set(keys)) != nr_slots or max(keys) - min(keys) >= stride * nr_slots:
                    continue
                if any(func and not self.is_kernel_text(func) for func in funcs):
                    continue
                refs[hook] = list(dict.fromkeys(refs[hook] + keys))

        owners = {}
        for hook, keys in sorted(refs.items(), key=lambda x: (len(x[1]), len(x[0]), x[0])):
            for key in keys:
                owners.setdefault(key, hook)

        hooks = {}
        for hook, keys in sorted(refs.items()):
            keys = [key for key in keys if owners[key] == hook]
            if not keys:
                continue
            # the keys of each hook point are adjacent, while the slot order is the order in `refs`
            groups = [keys]
            if len(keys) > nr_slots and len(keys) % nr_slots == 0:
                by_address = sorted(keys)
                groups = [sorted(by_address[i:i + nr_slots], key=keys.index) for i in range(0, len(keys), nr_slots)]
            unnamed = []
            for group in groups:
                # the slots are filled from the first one, so the empty keys follow
                funcs = {key: read_int_from_memory(key) for key in group}
                group = sorted(group, key=lambda x: not funcs[x])
                entries = [(slot, key, funcs[key]) for slot, key in enumerate(group)]
                guessed = None
                if len(groups) > 1 and funcs[group[0]]:
                    name = Symbol.format(funcs[group[0]], ksym="prefer", bracket="")
                    guessed = self.hook_name_from_callback(name, None)
                if guessed and guessed != hook:
                    hooks.setdefault(guessed + " (guessed)", entries)
                else:
                    unnamed.append(entries)
            # the one that has callbacks is its own hook point among the ones that cannot be named
            unnamed.sort(key=lambda x: -sum(1 for _slot, _key, func in x if func))
            for i, entries in enumerate(unnamed):
                hooks.setdefault(hook if i == 0 else "{:s} (another hook point {:d})".format(hook, i), entries)
        return hooks

    def dump_static_calls(self):
        sources = [
            ("the static call keys", self.collect_static_calls),
            ("the static call trampolines", self.collect_static_call_trampolines),
            ("the keys the dispatchers load", self.collect_static_call_dispatchers),
        ]
        hooks = source = None
        for name, collect in sources:
            hooks = collect()
            if hooks:
                source = name
                break
        if not hooks:
            self.err_add_out("Could not find the static calls of the hook points")
            return
        self.quiet_info_add_out("LSM framework: static calls (v6.12 or later)")
        self.quiet_info_add_out("Static calls resolved from: {:s}".format(source))
        self.quiet_info_add_out("Number of the hook points: {:d}".format(len(hooks)))
        if source == "the static call trampolines":
            where = "trampoline"
        else:
            where = "key"

        resolved = {}
        lsms = set()
        for hook, entries in hooks.items():
            callbacks = []
            for slot, addr, func in entries:
                if not func:
                    continue
                name = Symbol.format(func, ksym="prefer", bracket="")
                callbacks.append((slot, addr, func, name))
                lsm = self.lsm_of_callback(name)
                if lsm:
                    lsms.add(lsm)
            resolved[hook] = callbacks
        self.dump_lsm_list(lsms)

        for hook in sorted(resolved):
            callbacks = resolved[hook]
            if not callbacks and not self.args.all:
                continue
            if not self.match_filter(hook):
                continue
            self.out.append("{:s} ({:d} callback{:s})".format(hook, len(callbacks), "" if len(callbacks) == 1 else "s"))
            for slot, addr, func, name in callbacks:
                line = "    {:s} <{:s}>".format(self.format_addr(func), name or "NO_SYMBOL")
                lsm = self.lsm_of_callback(name)
                if lsm:
                    line += " [{:s}]".format(lsm)
                if self.args.meta:
                    line += "  (slot {:d}, {:s} {:s})".format(slot, where, self.format_addr(addr))
                self.out.append(line)
        return

    def lsm_of_callback(self, name):
        """Guess which LSM a callback belongs to from its name, or None if it is unknown."""
        if not name:
            return None
        for lsm, prefix in sorted(self.LSM_PREFIXES, key=lambda x: len(x[1]), reverse=True):
            if name.startswith(prefix):
                return lsm
        return None

    #
    # v4.2 - v6.11: security_hook_heads, an array of the lists of struct security_hook_list
    #

    def walk_head(self, head, is_list_head, off_head):
        """Return the `struct security_hook_list`s linked from the head, or None if it is not a valid list.
        Every node must link back to the previous link and to the head, and hold a kernel text callback,
        so that a neighboring variable or a kmem_cache is never taken as a hook list."""
        ptrsize = runtime.current_arch.ptrsize
        first = read_int_from_memory(head, safe=True)
        if first is None:
            return None
        if is_list_head:
            last = read_int_from_memory(head + ptrsize, safe=True)
        if is_list_head:
            end = head
        else:
            end = 0
        nodes = []
        prev = head
        current = first
        while current != end:
            if current in nodes or len(nodes) >= 64 or not is_valid_addr(current):
                return None
            # `list.prev` of list_head, or `list.pprev` of hlist_node that is the address of the previous `next`
            back = read_int_from_memory(current + ptrsize, safe=True)
            owner = read_int_from_memory(current + off_head * ptrsize, safe=True)
            func = read_int_from_memory(current + (off_head + 1) * ptrsize, safe=True)
            if back != prev or owner != head or not self.is_kernel_text(func):
                return None
            nodes.append(current)
            prev = current
            current = read_int_from_memory(current, safe=True)
            if current is None:
                return None
        if is_list_head and last != prev:
            return None
        return nodes

    def find_node_offsets(self, anchors):
        """Return offsetof(security_hook_list, head) in pointers, or None."""
        for off in range(1, 7):
            ok = 0
            for head, node in anchors:
                try:
                    if read_int_from_memory(node + off * runtime.current_arch.ptrsize) != head:
                        break
                    if not self.is_kernel_text(read_int_from_memory(node + (off + 1) * runtime.current_arch.ptrsize)):
                        break
                except gdb.MemoryError:
                    break
                ok += 1
            if ok and ok == len(anchors):
                return off
        return None

    def collect_hook_head_refs(self):
        """Return {hook name: [candidate address, ...]} from the dispatchers' disassembly."""
        refs = {}
        for hook, res in self.iter_dispatchers():
            candidates = self.extract_data_refs(res)
            if candidates:
                refs[hook] = candidates
        return refs

    def find_head_anchors(self, refs):
        """Return [(head, node), ...] of the candidates that really hold a security_hook_list."""
        ptrsize = runtime.current_arch.ptrsize
        anchors = []
        for candidates in refs.values():
            for head in candidates:
                if head % ptrsize:
                    continue
                node = read_int_from_memory(head, safe=True)
                if node is None:
                    continue
                if not node or node == head or not is_valid_addr(node):
                    continue
                for off in range(1, 7):
                    try:
                        if read_int_from_memory(node + off * ptrsize) != head:
                            continue
                        if not self.is_kernel_text(read_int_from_memory(node + (off + 1) * ptrsize)):
                            continue
                    except gdb.MemoryError:
                        break
                    anchors.append((head, node))
                    break
        return anchors

    def get_hook_heads_type(self):
        """Return (sizeof(struct security_hook_heads), {member offset: name}) from the debug type, or (None, {})."""
        struct_type = GefUtil.cached_lookup_type("struct security_hook_heads")
        if struct_type is None or not struct_type.sizeof:
            return None, {}
        return struct_type.sizeof, {f.bitpos // 8: f.name for f in struct_type.fields()}

    def get_head_array_base(self, refs, anchors, member_names):
        """Return the address of the security_hook_heads array, or None if it is unknown."""
        base = Ksym.get_addr("security_hook_heads")
        if base is not None or not member_names:
            return base
        # The debug type tells the offset of each member, so the confirmed heads referred to by the dispatcher
        # of the same name locate the array.
        offset_by_name = {name: offset for offset, name in member_names.items()}
        heads = {h for h, _n in anchors}
        votes = {}
        for hook, candidates in refs.items():
            offset = offset_by_name.get(hook)
            if offset is None:
                continue
            for head in candidates:
                if head in heads:
                    votes[head - offset] = votes.get(head - offset, 0) + 1
        if not votes:
            return None
        return max(votes.items(), key=lambda kv: kv[1])[0]

    def get_head_array_range(self, refs, anchors, stride, is_valid_head, is_empty_head, base, sizeof):
        """Return [start, end) of the security_hook_heads array."""
        if base is not None and sizeof:
            return base, base + sizeof
        heads = sorted({h for h, _n in anchors})
        if not heads:
            return None, None
        lo, hi = heads[0], heads[-1] + stride
        if base is not None and base <= lo:
            # The next symbol bounds the array, but a variable that follows it can lack a symbol.
            ret = Ksym.get_kallsyms()
            if ret:
                kallsyms, _kallsyms_map = ret
            else:
                kallsyms, _kallsyms_map = ([], {})
            end = min([a for a, _n, _t in kallsyms if a > base], default=None)
            if end is not None and hi <= end:
                lo = base
                while hi < end and is_valid_head(hi):
                    hi += stride
                # the alignment padding before the next variable looks like empty heads
                referred = {x for candidates in refs.values() for x in candidates}
                while hi - stride > heads[-1] and hi - stride not in referred and is_empty_head(hi - stride):
                    hi -= stride
                return lo, hi

        # Without the symbol the range comes from the heads that were confirmed to hold a hook list, which misses the empty ones
        # at both ends. Widen it to the heads the dispatchers referred to, as long as every head up to there is a valid list.
        # A dispatcher that already refers to a head in the range may also refer to a neighbor of the array (e.g. `lsm_inode_cache`
        # of security_inode_alloc()), so only the dispatchers that have none are used.
        margin = stride * 0x80
        changed = True
        while changed:
            changed = False
            for candidates in refs.values():
                if any(lo <= x < hi for x in candidates):
                    continue
                for x in sorted(candidates, key=lambda x: min(abs(x - lo), abs(x - hi))):
                    if (x - lo) % stride:
                        continue
                    if lo - margin <= x < lo:
                        slots = range(x, lo, stride)
                    elif hi <= x < hi + margin:
                        slots = range(hi, x + stride, stride)
                    else:
                        continue
                    if all(is_valid_head(s) for s in slots):
                        lo, hi = min(lo, x), max(hi, x + stride)
                        changed = True
                        break
        return lo, hi

    def dump_hook_heads(self):
        ptrsize = runtime.current_arch.ptrsize
        refs = self.collect_hook_head_refs()
        anchors = self.find_head_anchors(refs)
        # both `struct list_head list` and `struct hlist_node list` take two pointers
        off_head = self.find_node_offsets(anchors) or 2

        # v4.11 turned each head from a `struct list_head` into a `struct hlist_head`, which halves the stride.
        # The distance between the confirmed heads shows it directly, so trust that when there are enough of them.
        kversion = Kernel.version()
        if kversion and kversion < "4.11":
            stride = ptrsize * 2
        else:
            stride = ptrsize
        heads = sorted({h for h, _n in anchors})
        gaps = [b - a for a, b in zip(heads, heads[1:]) if b > a]
        if len(gaps) >= 8:
            if min(gaps) >= ptrsize * 2:
                stride = ptrsize * 2
            else:
                stride = ptrsize
        is_list_head = stride == ptrsize * 2

        walked = {}

        def walk(head):
            if head not in walked:
                walked[head] = self.walk_head(head, is_list_head, off_head)
            return walked[head]

        sizeof, member_names = self.get_hook_heads_type()
        base = self.get_head_array_base(refs, anchors, member_names)
        start, end = self.get_head_array_range(refs, anchors, stride, lambda x: walk(x) is not None, lambda x: walk(x) == [], base, sizeof)
        if start is None:
            self.err_add_out("Could not find `security_hook_heads`")
            return

        # A dispatcher may call another hook point first (e.g. inode_xattr_skipcap from security_inode_setxattr() and
        # security_inode_removexattr() on v6.10~), so a head that only one dispatcher refers to is taken first.
        # A wrapper such as security_capable_noaudit() refers to the head of another hook point, and the shortest name
        # is the canonical one among the dispatchers that refer to the head first.
        heads_by_hook = {}
        for hook, candidates in refs.items():
            heads_by_hook[hook] = [x for x in candidates if start <= x < end and (x - start) % stride == 0 and walk(x) is not None]
        users = collections.Counter(x for heads in heads_by_hook.values() for x in set(heads))
        name_by_head = {}
        hooks = sorted(heads_by_hook, key=lambda x: (len(x), x))
        for hook in hooks:
            head = next((x for x in heads_by_hook[hook] if users[x] == 1), None)
            if head is not None:
                name_by_head[head] = hook
        # the head a dispatcher refers to first is its own one rather than the ones it refers to later
        named = set(name_by_head.values())
        for rank in range(max((len(x) for x in heads_by_hook.values()), default=0)):
            for hook in hooks:
                if hook in named or rank >= len(heads_by_hook[hook]):
                    continue
                head = heads_by_hook[hook][rank]
                if head not in name_by_head:
                    name_by_head[head] = hook
                    named.add(hook)
        if base == start and sizeof:
            for offset, name in member_names.items():
                name_by_head[start + offset] = name

        self.quiet_info_add_out("LSM framework: security_hook_heads (v4.2 - v6.11)")
        self.quiet_info_add_out("security_hook_heads: {:s}-{:s}".format(self.format_addr(start), self.format_addr(end)))
        self.quiet_info_add_out("Number of the recovered hook point names: {:d}".format(len(name_by_head)))
        if self.args.meta:
            self.quiet_info_add_out("offsetof(security_hook_list, head): {:#x}".format(off_head * ptrsize))

        if self.args.meta:
            self.quiet_info_add_out("sizeof(each head): {:#x} ({:s})".format(stride, "list_head" if is_list_head else "hlist_head"))

        chains = []
        nodes_seen = set()
        for i in range((end - start) // stride):
            head = start + i * stride
            nodes = walk(head)
            nodes_seen.update(nodes or [])
            chains.append((i, head, nodes))

        # the `lsm` member was added at v4.12, which widens `struct security_hook_list`.
        # Each LSM registers its hooks from one static array, so the distance between the neighboring nodes is the size of the struct.
        sorted_nodes = sorted(nodes_seen)
        gaps = [b - a for a, b in zip(sorted_nodes, sorted_nodes[1:]) if b > a]
        if gaps:
            node_size = min(gaps)
        else:
            node_size = None
        has_lsm = node_size is not None and node_size >= (off_head + 3) * ptrsize
        if self.args.meta and node_size is not None:
            self.quiet_info_add_out("sizeof(security_hook_list): {:#x}{:s}".format(node_size, "" if has_lsm else " (no `lsm` member)"))

        rows = []
        lsms = set()
        for i, head, nodes in chains:
            callbacks = []
            for node in nodes or []:
                try:
                    func = read_int_from_memory(node + (off_head + 1) * ptrsize)
                    # Probe the owner slot even when neighboring-node distances could not prove that the member exists
                    # (for example, a list with only one callback).
                    # Old layouts simply fail the strict string/lsm_id validation in read_lsm_name().
                    lsm = self.read_lsm_name(read_int_from_memory(node + (off_head + 2) * ptrsize))
                except gdb.MemoryError:
                    continue
                if not re.fullmatch(r"[a-z][a-z0-9_]{1,15}", lsm):
                    lsm = ""
                name = Symbol.format(func, ksym="prefer", bracket="")
                if not lsm:
                    lsm = self.lsm_of_callback(name) or ""
                if lsm:
                    lsms.add(lsm)
                callbacks.append((node, func, name, lsm))
            name = name_by_head.get(head)
            if name is None and callbacks:
                name = self.hook_name_from_callback(callbacks[0][2], callbacks[0][3])
                if name:
                    name += " (guessed)"
            rows.append((i, head, name, nodes is None, callbacks))
        self.dump_lsm_list(lsms)

        for i, head, name, broken, callbacks in rows:
            if not callbacks and not broken and not self.args.all:
                continue
            label = name or "hook[{:d}]".format(i)
            if not self.match_filter(label):
                continue
            if broken:
                line = "{:s} (broken list)".format(label)
            else:
                line = "{:s} ({:d} callback{:s})".format(label, len(callbacks), "" if len(callbacks) == 1 else "s")
            if self.args.meta:
                line += "  (head {:s})".format(self.format_addr(head))
            self.out.append(line)
            for node, func, func_name, lsm in callbacks:
                line = "    {:s} <{:s}>".format(self.format_addr(func), func_name or "NO_SYMBOL")
                if lsm:
                    line += " [{:s}]".format(lsm)
                if self.args.meta:
                    line += "  (hook_list {:s})".format(self.format_addr(node))
                self.out.append(line)
        return

    #
    # v4.1 or earlier: a single struct security_operations
    #

    def find_security_ops(self):
        """Return (the address of `security_ops`, its value, {hook name: member offset})."""
        members = {}
        candidates = []
        for hook, res in self.iter_dispatchers():
            disp = self.extract_call_displacement(res)
            for addr in self.extract_data_refs(res):
                candidates.append(addr)
                if disp is not None:
                    members.setdefault(hook, (addr, disp))
                break

        addr = Ksym.get_addr("security_ops")
        if addr is None:
            counter = {}
            for x in candidates:
                counter[x] = counter.get(x, 0) + 1
            for x, _count in sorted(counter.items(), key=lambda kv: -kv[1]):
                if self.validate_security_ops(x):
                    addr = x
                    break
        if addr is None:
            return None, None, {}
        ops = read_int_from_memory(addr, safe=True)
        if ops is None:
            return addr, None, {}
        offsets = {hook: disp for hook, (base, disp) in members.items() if base == addr}
        return addr, ops, offsets

    def validate_security_ops(self, addr):
        """Return True if `addr` holds a pointer to a plausible `struct security_operations`."""
        ptrsize = runtime.current_arch.ptrsize
        ops = read_int_from_memory(addr, safe=True)
        if ops is None:
            return False
        if not ops or not is_valid_addr(ops):
            return False
        if not self.read_cstring(ops, 16):
            return False
        text = 0
        for i in range(2, 16):
            func = read_int_from_memory(ops + i * ptrsize, safe=True)
            if func is None:
                return False
            if self.is_kernel_text(func):
                text += 1
        return text >= 4

    def dump_security_ops(self):
        ptrsize = runtime.current_arch.ptrsize
        addr, ops, offsets = self.find_security_ops()
        if addr is None or not ops:
            self.err_add_out("Could not find `security_ops`; this kernel may be CONFIG_SECURITY=n")
            return

        lsm = self.read_cstring(ops, 16)
        self.quiet_info_add_out("LSM framework: security_ops (v4.1 or earlier)")
        self.quiet_info_add_out("security_ops: {:s} -> {:s}{:s}".format(
            self.format_addr(addr), self.format_addr(ops),
            " " + Symbol.format(ops, ksym="prefer", missing="NO_SYMBOL"),
        ))
        self.dump_lsm_list({lsm} if lsm else set())

        # the largest member the dispatchers touch is the tightest bound on the struct;
        # the next symbol only bounds it when the struct itself has a symbol
        limit = None
        if offsets:
            limit = max(offsets.values()) // ptrsize + 1
        elif Ksym.get_name(ops) is not None:
            ret = Ksym.get_kallsyms()
            if ret is not None:
                kallsyms, _kallsyms_map = ret
                end = min([a for a, _n, _t in kallsyms if a > ops], default=None)
                if end is not None and ops < end:
                    limit = (end - ops) // ptrsize

        # several dispatchers can share one member (security_capable / _capable_noaudit),
        # and the shorter name is the canonical one
        name_by_offset = {}
        for hook, disp in sorted(offsets.items(), key=lambda kv: (len(kv[0]), kv[0]), reverse=True):
            name_by_offset[disp] = hook
        rows = []
        miss = 0
        i = 0
        while limit is None or i < limit:
            if limit is None and ((rows and miss >= 16) or i >= 0x200):
                break
            func = read_int_from_memory(ops + i * ptrsize, safe=True)
            if func is None:
                break
            if self.is_kernel_text(func):
                miss = 0
                func_name = Symbol.format(func, ksym="prefer", bracket="")
                name = name_by_offset.get(i * ptrsize)
                if name is None:
                    name = self.hook_name_from_callback(func_name, lsm)
                    if name:
                        name += " (guessed)"
                # the capability hooks are chained into the struct of the active LSM
                rows.append((i * ptrsize, func, func_name, name, self.lsm_of_callback(func_name) or lsm))
            else:
                miss += 1
            i += 1

        self.quiet_info_add_out("Number of the registered hooks: {:d}".format(len(rows)))
        for disp, func, func_name, name, hook_lsm in rows:
            label = name or "hook[{:#x}]".format(disp)
            if not self.match_filter(label):
                continue
            line = "{:s}".format(label)
            if self.args.meta:
                line += " (+{:#x})".format(disp)
            self.out.append(line)
            self.out.append("    {:s} <{:s}>{:s}".format(
                self.format_addr(func), func_name or "NO_SYMBOL", " [{:s}]".format(hook_lsm) if hook_lsm else "",
            ))
        return

    #
    # --task: the security blobs of task_struct, cred, file and inode
    #

    # the index of each member of `struct lsm_blob_sizes` (v5.1 or later), which holds ints
    BLOB_SIZES_INDEX = (
        ("7.1", {"cred": 0, "file": 1, "inode": 4, "task": 11}),
        ("6.12", {"cred": 0, "file": 1, "inode": 3, "task": 10}),
        ("5.13", {"cred": 0, "file": 1, "inode": 2, "task": 6}),
        ("5.1", {"cred": 0, "file": 1, "inode": 2, "task": 5}),
    )

    # the kinds of blobs each LSM keeps, as [since, until) of the kernel version
    BLOB_USERS = {
        "selinux": {"cred": (None, None), "file": (None, None), "inode": (None, None), "task": ("6.18", None)},
        "smack": {"cred": (None, None), "file": (None, None), "inode": (None, None)},
        "apparmor": {"cred": (None, None), "file": (None, None), "task": ("5.1", None)},
        "tomoyo": {"cred": (None, "5.1"), "task": ("5.1", None)},
        "landlock": {"cred": ("5.13", None), "file": ("6.2", None), "inode": ("5.13", None)},
        "bpf": {"inode": ("5.10", None), "task": ("5.11", None)},
        "integrity": {"inode": ("6.9", None)},
        "ima": {"inode": ("6.9", None)},
        "evm": {"inode": ("6.9", None)},
        "ipe": {"inode": ("6.12", None)},
    }

    # the parts of the blobs that decode_blob() understands
    DECODABLE_BLOBS = {
        "selinux": ("cred", "task", "file", "inode"),
        "smack": ("cred", "file", "inode"),
        "apparmor": ("cred", "task", "file"),
        "tomoyo": ("cred", "task"),
        "landlock": ("cred",),
    }
    # the parts that are valid with NULL pointers, which cannot be located by decoding
    WEAK_BLOBS = (("landlock", "cred"), ("apparmor", "task"))

    def is_blob_user(self, lsm, kind):
        version_range = self.BLOB_USERS.get(lsm, {}).get(kind)
        if version_range is None:
            return False
        since, until = version_range
        kversion = Kernel.version()
        if since is not None and kversion < since:
            return False
        if until is not None and kversion >= until:
            return False
        return True

    def trace_arg_accesses(self, res):
        """Return ([offsets stored zero], [offsets loaded]) of the pointer-sized members accessed through the first argument.
        A register that holds the argument plus a constant is followed too, because a member far from the head is
        reached by adding the upper part of the offset first (e.g. `lui a0, 0x1; add s1, s1, a0; sd zero, -1384(s1)`)."""
        branch = r"b(?:\.\w+|eq|ne|cs|cc|hs|lo|mi|pl|vs|vc|hi|ls|ge|lt|gt|le|al)?"
        if is_x86():
            if is_x86_64():
                width = "QWORD"
            else:
                width = "DWORD"
            mem = width + r" PTR \[(?P<base>\w+)(?P<disp>[+-]0x\w+)?\]"
            # -mregparm=3 on x86_32
            if is_x86_64():
                arg, clobbered = ("rdi", "rax rcx rdx rsi rdi r8 r9 r10 r11")
            else:
                arg, clobbered = ("eax", "eax ecx edx")
            rules = [
                ("store", r"(?:mov|and)\s+" + mem + r",(?P<src>\w+)"),
                ("call", r"call.*"),
                ("probe", r"(?:cmp|test)\s+\w+," + mem),
                ("skip", r"(?:j\w+|cmp|test|push|nop\w*|ret\w*|bt)(?:\s.*)?|\S+\s+\w+ PTR .*"),
                ("load", r"(?:mov|add)\s+(?P<dst>\w+)," + mem),
                ("move", r"mov\s+(?P<dst>\w+),(?P<src>\w+)"),
                # `lea esi,[esi+eiz*1+0x0]` is a multi-byte nop
                ("add", r"lea\s+(?P<dst>\w+),(?:ds:)?\[(?P<src>\w+)(?:\+eiz\*1)?(?P<imm>[+-]0x\w+)?\]"),
                ("add", r"add\s+(?P<dst>(?P<src>\w+)),(?P<imm>0x\w+)"),
                ("zero", r"xor\s+(?P<dst>\w+),(?P=dst)"),
            ]
        elif is_arm64() or is_arm32():
            mem = r"\s+(?P<{:s}>\w+),\s*\[(?P<base>\w+)(?:,\s*#(?P<disp>-?\w+))?\]"
            if is_arm64():
                arg, clobbered = ("x0", " ".join("x{:d}".format(i) for i in range(19)) + " x30")
            else:
                arg, clobbered = ("r0", "r0 r1 r2 r3 ip lr")
            rules = [
                ("store", r"(?:str|stur)(?:\.w)?" + mem.format("src")),
                ("call", r"(?:bl|blx|blr)\s.*"),
                ("skip", r"(?:st\w*|push|cmp|cmn|tst|teq|" + branch + r"|cbn?z|tbn?z|ret|nop|bx\w*|dmb|dsb|isb|pld\w*)(?:\.[wn])?(?:\s.*)?"),
                ("load", r"(?:ldr|ldur)(?:\.w)?" + mem.format("dst")),
                ("move", r"movs?(?:\.w)?\s+(?P<dst>\w+),\s*(?P<src>[a-z]\w*)"),
                ("const", r"movs?(?:\.w)?\s+(?P<dst>\w+),\s*#(?P<imm>\w+)"),
                ("add", r"adds?(?:\.w)?\s+(?P<dst>\w+),\s*(?P<src>\w+),\s*#(?P<imm>\w+)(?:,\s*lsl\s*#(?P<shift>\d+))?"),
            ]
        elif is_riscv32() or is_riscv64():
            if is_64bit():
                size = "d"
            else:
                size = "w"
            mem = r",(?P<disp>-?\d+)\((?P<base>\w+)\)"
            arg = "a0"
            clobbered = "ra " + " ".join("a{:d}".format(i) for i in range(8)) + " " + " ".join("t{:d}".format(i) for i in range(7))
            rules = [
                ("store", r"s" + size + r"\s+(?P<src>\w+)" + mem),
                ("call", r"(?:jal|jalr|call|tail)(?:\s.*)?"),
                ("skip", r"(?:c\.)?(?:f?s[bhwdq]|b\w+|j|jr|ret|fence\S*|nop|wfi)(?:\s.*)?"),
                ("load", r"l" + size + r"\s+(?P<dst>\w+)" + mem),
                ("move", r"mv\s+(?P<dst>\w+),(?P<src>\w+)"),
                ("const", r"li\s+(?P<dst>\w+),(?P<imm>-?\w+)"),
                ("const", r"lui\s+(?P<dst>\w+),(?P<imm>\w+)(?P<shift>)"),
                ("add", r"addi\s+(?P<dst>\w+),(?P<src>\w+),(?P<imm>-?\w+)"),
                ("add", r"add\s+(?P<dst>\w+),(?P<src>\w+),(?P<reg>\w+)"),
            ]
        else:
            return [], []

        def norm(reg):
            # x86_64: the 32-bit name of a register refers to the same one
            if reg and is_x86_64():
                reg = re.sub(r"^e([abcd]x|[sd]i|[sb]p)$", r"r\1", reg)
                reg = re.sub(r"^(r\d+)d$", r"\1", reg)
            return reg

        def imm(x):
            try:
                return int(x, 0)
            except (TypeError, ValueError):
                return None

        clobbered = clobbered.split()
        aliases = {arg: 0} # register -> the argument plus this delta
        consts = {} # register -> value (zero, or the upper part of an offset)
        stores, loads = [], []
        for line in res.splitlines():
            m = re.match(r"\s*(?:=>\s*)?0x[0-9a-f]+(?:\s+<[^>]*>)?:\s*(.*)", line)
            if not m:
                continue
            insn = re.split(r"\s+(?:#|;|//|@)\s", m.group(1))[0].strip()
            kind, g = None, {}
            for _kind, regex in rules:
                m = re.fullmatch(regex, insn)
                if m:
                    kind = _kind
                    g = {k: norm(v) for k, v in m.groupdict().items()}
                    break
            else:
                kind = None
            if kind == "store":
                src = g["src"]
                # a pointer-sized store only; ARM64 has `w` registers for 32-bit
                if g["base"] in aliases and not src.startswith("w") and (src in ("xzr", "zero") or imm(src) == 0 or consts.get(src) == 0):
                    stores.append(aliases[g["base"]] + (imm(g["disp"]) or 0))
                continue
            if kind == "call":
                for reg in clobbered:
                    aliases.pop(reg, None)
                    consts.pop(reg, None)
                continue
            if kind in ("load", "probe") and g["base"] in aliases and not g.get("dst", "").startswith("w"):
                loads.append(aliases[g["base"]] + (imm(g["disp"]) or 0))
            if kind in ("skip", "probe"):
                continue
            if kind is None:
                m = re.match(r"\S+\s+(\w+)", insn)
                g = {"dst": norm(m.group(1)) if m else None}
            dst = g["dst"]
            alias = aliases.get(g.get("src"))
            if kind == "add" and alias is None and g.get("reg") in aliases:
                # `add rd, rs1, rs2` is commutative
                g["src"], g["reg"] = g["reg"], g["src"]
                alias = aliases[g["src"]]
            aliases.pop(dst, None)
            consts.pop(dst, None)
            if kind == "move" and alias is not None:
                aliases[dst] = alias
            elif kind == "add" and alias is not None and imm(g.get("imm")) is not None:
                aliases[dst] = alias + (imm(g["imm"]) << int(g.get("shift") or 0))
            elif kind == "add" and alias is not None and g.get("reg") in consts:
                aliases[dst] = alias + consts[g["reg"]]
            elif kind == "zero":
                consts[dst] = 0
            elif kind == "const" and imm(g["imm"]) is not None:
                consts[dst] = imm(g["imm"]) << (12 if g.get("shift") == "" else 0)
        return stores, loads

    def find_arg_member_offset(self, func_names):
        """Return the offset of the member a function clears through its first argument (e.g. `task->security = NULL`
        in security_task_free()), or the one it reads if it clears nothing."""
        for name in func_names:
            addr = Ksym.get_addr(name)
            if addr is None:
                continue
            try:
                res = KernelAddressHeuristicFinderUtil.disassemble_until_next_symbol(addr, 80)
            except gdb.error:
                continue
            stores, loads = self.trace_arg_accesses(res)
            for offset in stores + loads:
                if 0 < offset < 0x4000 and offset % runtime.current_arch.ptrsize == 0:
                    return offset
        return None

    def is_blob_value(self, value):
        return value == 0 or (value % runtime.current_arch.ptrsize == 0 and is_valid_addr(value))

    def resolve_member_offset(self, type_name, member, objects, funcs=(), fallback=None):
        """Return offsetof(type, member) from the debug type, from what `funcs` access through the first argument, or
        `fallback`, if the member of every object is NULL or a valid address."""
        offset = GefUtil.offsetof(type_name, member)
        if offset is None:
            offset = self.find_arg_member_offset(funcs)
        if offset is None:
            offset = fallback
        if offset is None or not objects:
            return None
        # an object freed while listing is unreadable, so it is not an evidence either way
        values = [read_int_from_memory(x + offset, safe=True) for x in objects]
        values = [x for x in values if x is not None]
        if not values or not all(self.is_blob_value(x) for x in values):
            return None
        return offset

    def resolve_security_offsets(self, lsms, creds, files):
        """Return {kind: offsetof(object, security)}; a kind that could not be found is omitted."""
        kversion = Kernel.version()
        offsets = {}
        # KernelCred finds it from `user_ns`, which cred has had since v3.5
        offsets["cred"] = self.task_command.kcred.offset_security
        if offsets["cred"] is None:
            funcs = ["{:s}_cred_free".format(lsm) for lsm in sorted(lsms)] + ["security_cred_free"]
            offsets["cred"] = self.resolve_member_offset("struct cred", "security", creds, funcs)
        # it has existed since v4.12, but nothing used it before v5.1
        if kversion >= "5.1":
            funcs = ["security_task_free"]
        else:
            funcs = []
        offsets["task"] = self.resolve_member_offset("struct task_struct", "security", self.task_addrs, funcs)
        if files:
            # the LSM freed its own blob until v5.0, while some distro kernels backported the v5.1 way
            if kversion < "5.1":
                funcs = ["{:s}_file_free_security".format(lsm) for lsm in sorted(lsms)]
            else:
                funcs = []
            offsets["file"] = self.resolve_member_offset("struct file", "f_security", files, funcs + ["security_file_free"])
            # `i_security` follows `i_sb` and `i_mapping`
            offset_i_sb = getattr(self.task_command.kpath, "offset_i_sb", None)
            if offset_i_sb is None:
                fallback = None
            else:
                fallback = offset_i_sb + runtime.current_arch.ptrsize * 2
            inodes = [x for x in (self.get_file_inode(file) for file in files) if x]
            offsets["inode"] = self.resolve_member_offset("struct inode", "i_security", inodes, fallback=fallback)
        return {kind: offset for kind, offset in offsets.items() if offset is not None}

    def get_blob_sizes_offset(self, lsm, kind):
        """Return the offset of the part `lsm` owns in the blob of `kind`, read from `<lsm>_blob_sizes`, or None."""
        sym = {"bpf": "bpf_lsm_blob_sizes", "ipe": "ipe_blobs"}.get(lsm, "{:s}_blob_sizes".format(lsm))
        addr = Ksym.get_addr(sym)
        if addr is None:
            return None
        offset = GefUtil.offsetof("struct lsm_blob_sizes", "lbs_{:s}".format(kind))
        if offset is None:
            kversion = Kernel.version()
            for version, index in self.BLOB_SIZES_INDEX:
                if kversion >= version:
                    offset = index[kind] * 4
                    break
        if offset is None:
            return None
        value = read_int32_from_memory(addr + offset, safe=True)
        # lsm_set_blob_size() aligns each part to a pointer
        if value is None or value >= 0x1000 or value % runtime.current_arch.ptrsize:
            return None
        return value

    def resolve_blob_layout(self, lsms, samples):
        """Return {kind: [(lsm, offset, how), ...]}, the part each active LSM owns in the blob of each kind.
        Until v5.0 the major LSM owns the whole blob (offset 0). From v5.1 one blob is shared by the LSMs, and
        the offset of each part is read from `<lsm>_blob_sizes`. Without the symbol, the only user owns the head
        of the blob, and otherwise the offset where the part decodes on most samples is taken (guessed)."""
        kversion = Kernel.version()
        layout = {}
        for kind, values in samples.items():
            users = [lsm for lsm in sorted(lsms) if self.is_blob_user(lsm, kind)]
            entries = []
            for lsm in users:
                if lsm not in self.DECODABLE_BLOBS:
                    continue
                if kversion < "5.1":
                    entries.append((lsm, 0, "whole"))
                    continue
                # a new member of `struct lsm_blob_sizes` shifts the index, so check the offset with the samples
                decodable = kind in self.DECODABLE_BLOBS[lsm]
                offset = self.get_blob_sizes_offset(lsm, kind)
                if offset is not None:
                    if not decodable or self.count_decodable(lsm, kind, offset, values) * 2 >= len([x for x in values if x[0]]):
                        entries.append((lsm, offset, "{:s}_blob_sizes".format(lsm)))
                        continue
                if len(users) == 1:
                    # the inode blob starts with a `struct rcu_head` to free it
                    if kind == "inode":
                        offset = runtime.current_arch.ptrsize * 2
                    else:
                        offset = 0
                    if not decodable or self.count_decodable(lsm, kind, offset, values) * 2 >= len([x for x in values if x[0]]):
                        entries.append((lsm, offset, "only user"))
                        continue
                    # a distro kernel may put its own data at the head (e.g. the display LSM slot of Ubuntu)
                    offset = self.guess_blob_offset(lsm, kind, values, allow_weak=True)
                else:
                    if decodable:
                        offset = self.guess_blob_offset(lsm, kind, values)
                    else:
                        offset = None
                entries.append((lsm, offset, "guessed"))
            # the part of the LSM initialized first starts at the head of the blob
            if kind == "inode" and kversion >= "5.1":
                base = runtime.current_arch.ptrsize * 2
            else:
                base = 0
            unknown = [i for i, (_lsm, offset, _how) in enumerate(entries) if offset is None]
            if len(unknown) == 1 and len(entries) == len(users) and all(offset != base for _lsm, offset, _how in entries):
                entries[unknown[0]] = (entries[unknown[0]][0], base, "guessed")
            layout[kind] = entries
        return layout

    def count_decodable(self, lsm, kind, offset, samples):
        return sum(1 for blob, obj in samples if blob and self.decode_blob(lsm, kind, blob + offset, obj) is not None)

    def guess_blob_offset(self, lsm, kind, samples, allow_weak=False):
        """Return the lowest offset where the part decodes on the majority of the samples. The same part of the next object
        in the slab also decodes beyond the end of the blob, and so does a later member that looks like the first one."""
        if (lsm, kind) in self.WEAK_BLOBS and not allow_weak:
            return None
        blobs = [(blob, obj) for blob, obj in samples if blob]
        if not blobs:
            return None
        for offset in range(0, 0x80, runtime.current_arch.ptrsize):
            if self.count_decodable(lsm, kind, offset, blobs) * 2 > len(blobs):
                return offset
        return None

    def read_label(self, addr, pattern=r"[\x21-\x7e][\x20-\x7e]*"):
        """Read the string at `addr` if it looks like a label."""
        # do not cross the page, which may be unmapped
        name = self.read_cstring(addr, min(0x100, get_pagesize() - addr % get_pagesize()))
        if name and re.fullmatch(pattern, name):
            return name
        return ""

    def apparmor_label_name(self, label):
        """Return the name of an `aa_label` (v4.13~) or an `aa_profile` (~v4.12)."""
        if not label or not is_valid_addr(label):
            return ""
        # the refcount, rb_node, rcu_head and proxy come before `hname` of aa_label, and `name` is the first member of aa_profile
        for i in range(12):
            ptr = read_int_from_memory(label + i * runtime.current_arch.ptrsize, safe=True)
            if ptr is None:
                break
            if ptr and is_valid_addr(ptr):
                name = self.read_label(ptr)
                if len(name) >= 2:
                    return name
        return ""

    def smack_label_name(self, skp):
        """Return the label of a `struct smack_known`, or of a label string of old kernels."""
        if not skp or not is_valid_addr(skp):
            return ""
        # smk_known follows `struct list_head list` and `struct hlist_node smk_hashed`
        ptr = read_int_from_memory(skp + runtime.current_arch.ptrsize * 4, safe=True)
        if ptr and is_valid_addr(ptr):
            name = self.read_label(ptr, r"[\x21-\x7e]{1,255}")
            if name:
                return name
        return self.read_label(skp, r"[\x21-\x7e]{1,255}")

    def tomoyo_domain_name(self, domain):
        """Return the name of a `struct tomoyo_domain_info`, found through `domainname`."""
        if not domain or not is_valid_addr(domain):
            return ""
        # domainname follows `list` and `acl_info_list[]`
        for i in range(2, 10):
            path_info = read_int_from_memory(domain + i * runtime.current_arch.ptrsize, safe=True)
            if not path_info or not is_valid_addr(path_info):
                continue
            ptr = read_int_from_memory(path_info, safe=True)
            if ptr and is_valid_addr(ptr):
                name = self.read_label(ptr, r"<[\x20-\x7e]+")
                if name:
                    return name
        return ""

    def format_label_ptr(self, ptr, name):
        if not ptr:
            return "0x0"
        return "{:s}{:s}".format(AddressUtil.format_address(ptr), " ({:s})".format(name) if name else "")

    def decode_blob(self, lsm, kind, part, obj):
        """Return (summary, detail) of the part of the blob `lsm` owns, or None if it does not look like one.
        `part` is the address of the part, and `obj` is the object that owns the blob."""
        kversion = Kernel.version()
        ptrsize = runtime.current_arch.ptrsize
        stacked = kversion >= "5.1"
        if not part or not is_valid_addr(part):
            return None

        def sids(names, offset=0):
            """Return the u32 SIDs at `part + offset` and their detail, or (None, "") if one is not a SID."""
            type_name = "struct {:s}_security_struct".format(kind)
            offsets = [GefUtil.offsetof(type_name, name) for name in names]
            if None in offsets:
                if GefUtil.type_size(type_name):
                    return None, ""
                configs = runtime.CommandRegistry.instances["kconfig"].get_configs()
                if not configs or any(configs.get(key) == "y" for key in ("CONFIG_RANDSTRUCT", "CONFIG_GCC_PLUGIN_RANDSTRUCT")):
                    return None, ""
                offsets = [offset + i * 4 for i in range(len(names))]
            values = [read_int32_from_memory(part + offset, safe=True) for offset in offsets]
            if not all(x is not None and x < 0x100000 for x in values):
                return None, ""
            return values, " ".join("{:s}={:d}".format(n, x) for n, x in zip(names, values))

        def labels(names, resolve, ptrs=None, optional=False):
            """Return the label of the first pointer and the detail of all, or None if the first is not labeled
            (if `optional`, if a non-NULL one is not labeled). `ptrs` defaults to the pointers at `part`."""
            if ptrs is None:
                ptrs = [read_int_from_memory(part + i * ptrsize, safe=True) for i in range(len(names))]
            if not all(x is not None and self.is_blob_value(x) for x in ptrs):
                return None
            resolved = [resolve(x) if x else "" for x in ptrs]
            if optional:
                unlabeled = any(x and not y for x, y in zip(ptrs, resolved))
            else:
                unlabeled = not resolved[0]
            if unlabeled:
                return None
            return resolved[0], " ".join("{:s}={:s}".format(n, self.format_label_ptr(x, y)) for n, x, y in zip(names, ptrs, resolved))

        if lsm == "selinux":
            if kind == "cred":
                values, detail = sids(["osid", "sid", "exec_sid", "create_sid", "keycreate_sid", "sockcreate_sid"])
                if values and values[0] and values[1]:
                    return "sid={:d}".format(values[1]), detail
            elif kind == "task":
                values, detail = sids(["avdcache.sid", "avdcache.seqno"])
                if values:
                    return "", detail
            elif kind == "file":
                # isid is 0 for a file that was not opened through a path (e.g. a pipe)
                values, detail = sids(["sid", "fown_sid", "isid", "pseqno"])
                if values and values[0] and values[1]:
                    return "sid={:d}".format(values[0]), detail
            elif kind == "inode" and read_int_from_memory(part, safe=True) == obj:
                # inode, list, task_sid, sid, sclass, initialized
                values, detail = sids(["task_sid", "sid"], ptrsize * 3)
                sclass = read_int16_from_memory(part + ptrsize * 3 + 8, safe=True)
                initialized = read_int8_from_memory(part + ptrsize * 3 + 10, safe=True)
                if values and sclass is not None and initialized is not None:
                    detail = "inode={:s} {:s} sclass={:d} initialized={:d}".format(AddressUtil.format_address(obj), detail, sclass, initialized)
                    return "sid={:d}".format(values[1]), detail

        elif lsm == "apparmor":
            if kind == "cred":
                # a pointer to the label (v5.1~), the label itself (v4.17~), or the first member of struct aa_task_ctx (~v4.16)
                if not stacked and kversion >= "4.17":
                    ptrs = [part]
                else:
                    ptrs = None
                return labels(["label"], self.apparmor_label_name, ptrs)
            if kind == "task":
                ret = labels(["nnp", "onexec", "previous"], self.apparmor_label_name, optional=True)
                return ret and ("", ret[1])
            if kind == "file" and kversion < "4.13":
                allow = read_int16_from_memory(part, safe=True)
                if allow is not None:
                    return "", "allow={:#x}".format(allow)
            elif kind == "file":
                # the label follows a spinlock, which grows after SPINLOCK_MAGIC with CONFIG_DEBUG_SPINLOCK
                for i in (range(2, 12) if read_int32_from_memory(part + 4, safe=True) == 0xdead4ead else [1]):
                    ret = labels(["label"], self.apparmor_label_name, [read_int_from_memory(part + i * ptrsize, safe=True)])
                    if ret is not None:
                        return ret

        elif lsm == "smack":
            if kind == "cred":
                return labels(["smk_task", "smk_forked"], self.smack_label_name)
            if kind == "inode":
                return labels(["smk_inode", "smk_task", "smk_mmap"], self.smack_label_name)
            if kind == "file":
                return labels(["smk_file"], self.smack_label_name, None if stacked else [part])

        elif lsm == "tomoyo":
            if kind == "cred" and not stacked:
                return labels(["domain"], self.tomoyo_domain_name, [part])
            if kind == "task" and stacked:
                return labels(["domain_info", "old_domain_info"], self.tomoyo_domain_name)

        elif lsm == "landlock" and kind == "cred":
            domain = read_int_from_memory(part, safe=True)
            if domain is not None and self.is_blob_value(domain):
                return "domain={:#x}".format(domain) if domain else "", "domain={:s}".format(self.format_label_ptr(domain, ""))
        return None

    def get_task_files(self, task, limit=0x400):
        """Return [(fd, file), ...] of the task."""
        task_command = self.task_command
        ptrsize = runtime.current_arch.ptrsize
        files = read_int_from_memory(task + task_command.offset_files, safe=True)
        if not files or not is_valid_addr(files):
            return []
        fdt = read_int_from_memory(files + task_command.offset_fdt, safe=True)
        if not fdt or not is_valid_addr(fdt):
            return []
        max_fds = read_int32_from_memory(fdt, safe=True)
        array = read_int_from_memory(fdt + ptrsize, safe=True)
        if not max_fds or not array or not is_valid_addr(array):
            return []
        ret = []
        for fd in range(min(max_fds, 0x10000)):
            file = read_int_from_memory(array + fd * ptrsize, safe=True)
            if file is None:
                break
            if file and is_valid_addr(file):
                ret.append((fd, file))
                if len(ret) >= limit:
                    break
        return ret

    def get_file_inode(self, file):
        task_command = self.task_command
        dentry = read_int_from_memory(file + task_command.offset_dentry, safe=True)
        if not dentry or not is_valid_addr(dentry):
            return None
        inode = read_int_from_memory(dentry + task_command.offset_d_inode, safe=True)
        if not inode or not is_valid_addr(inode):
            return None
        return inode

    def detect_lsms(self, kversion):
        """Return the set of the active LSMs, recovered from the registered hooks."""
        saved_out = self.out
        self.out = []
        self.detected_lsms = set()
        try:
            self.dump_hooks(kversion)
        finally:
            self.out = saved_out
        return self.detected_lsms

    def format_parts(self, kind, obj, blob, indent):
        lines = []
        for lsm, offset, _how in self.blob_layout.get(kind, []) if blob else []:
            decodable = kind in self.DECODABLE_BLOBS.get(lsm, ())
            if offset is None:
                if decodable:
                    lines.append("{:s}[{:s} +?] (unknown offset)".format(indent, lsm))
                continue
            label = "{:s}[{:s} +{:#x}]".format(indent, lsm, offset)
            decoded = self.decode_blob(lsm, kind, blob + offset, obj)
            if decoded is not None:
                lines.append("{:s} {:s}".format(label, decoded[1]))
                continue
            words = [read_int_from_memory(blob + offset + i * runtime.current_arch.ptrsize, safe=True) for i in range(2)]
            raw = " ".join("?" if x is None else AddressUtil.format_address(x) for x in words)
            lines.append("{:s} {:s} {:s}".format(label, "(could not decode)" if decodable else "raw:", raw))
        return lines

    def get_labels(self, task, cred, cred_blob, task_blob):
        """Return the short labels of a task, decoded from the blobs of its cred and task_struct."""
        labels = []
        for kind, obj, blob in [("cred", cred, cred_blob), ("task", task, task_blob)]:
            for lsm, offset, _how in self.blob_layout.get(kind, []) if blob else []:
                if offset is None:
                    decoded = None
                else:
                    decoded = self.decode_blob(lsm, kind, blob + offset, obj)
                if decoded and decoded[0]:
                    labels.append("{:s}:{:s}".format(lsm, decoded[0]))
        return labels

    def dump_task_detail(self, entry):
        task, pid, comm, cred, cred_blob, task_blob = entry
        offsets = self.security_offsets
        self.out.append('task: {:s} (pid: {:d}, comm: "{:s}")'.format(AddressUtil.format_address(task), pid, comm))
        self.out.append("    cred->security  {:s} (cred: {:s})".format(AddressUtil.format_address(cred_blob or 0), AddressUtil.format_address(cred)))
        self.out.extend(self.format_parts("cred", cred, cred_blob, " " * 8))
        if "task" in offsets:
            self.out.append("    task->security  {:s}".format(AddressUtil.format_address(task_blob or 0)))
            self.out.extend(self.format_parts("task", task, task_blob, " " * 8))
        if "file" in offsets or "inode" in offsets:
            for fd, file in self.get_task_files(task):
                inode = self.get_file_inode(file)
                self.out.append("    fd {:<3d} {:s} (file: {:s}, inode: {:s})".format(
                    fd, self.task_command.kpath.get_file_path(file), AddressUtil.format_address(file), AddressUtil.format_address(inode or 0),
                ))
                for kind, member, obj in [("file", "f_security", file), ("inode", "i_security", inode)]:
                    if kind in offsets and obj:
                        blob = read_int_from_memory(obj + offsets[kind], safe=True)
                        self.out.append("        {:s}  {:s}".format(member, AddressUtil.format_address(blob or 0)))
                        self.out.extend(self.format_parts(kind, obj, blob, " " * 12))
        self.out.append("")
        return

    def dump_task_table(self, entries):
        width = 2 + runtime.current_arch.ptrsize * 2
        fmt = "{:%ds} {:>7s} {:16s} {:%ds} {:%ds} {:s}" % (width, width, width)
        if not self.args.quiet:
            legend = ["task", "pid", "comm", "cred->security", "task->security", "labels"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))
        for task, pid, comm, cred, cred_blob, task_blob in entries:
            if "task" not in self.security_offsets:
                task_blob_str = "-"
            else:
                task_blob_str = AddressUtil.format_address(task_blob or 0)
            self.out.append(fmt.format(
                AddressUtil.format_address(task), str(pid), comm, AddressUtil.format_address(cred_blob or 0), task_blob_str,
                " ".join(self.get_labels(task, cred, cred_blob, task_blob)),
            ))
        return

    def dump_task_blobs(self, kversion):
        args = self.args
        detail = bool(args.verbose or args.pid is not None or args.task_filter or args.filter)
        self.meta = []
        task_command = Kernel.task()
        task_ready = task_command.initialize(files=detail)
        self.meta.extend(Kernel.export_meta(self, task_command.meta))
        if not task_ready:
            task_command = None
        if args.meta or task_command is None:
            for func, line in self.meta:
                func(line)
        if task_command is None:
            return
        self.task_command = task_command
        self.task_addrs = KernelTask.get_task_list(task_command.init_task, task_command.offset_tasks)
        lsms = self.detect_lsms(kversion)

        tasks = []
        for task in self.task_addrs:
            pid = read_int32_from_memory(task + task_command.offset_pid, safe=True)
            comm = read_cstring_from_memory(task + task_command.offset_comm, safe=True)
            cred = read_int_from_memory(task + task_command.offset_cred, safe=True)
            if pid is not None and comm is not None and cred and is_valid_addr(cred):
                tasks.append((task, pid, comm, cred))
        files = []
        if detail and getattr(task_command, "kpath", None) is not None:
            files = [file for task in tasks for _fd, file in self.get_task_files(task[0])][:0x400]
        self.security_offsets = offsets = self.resolve_security_offsets(lsms, [x[3] for x in tasks], files)
        if "cred" not in offsets:
            self.err_add_out("Could not find cred->security; this kernel may be CONFIG_SECURITY=n")
            return

        def read_blob(kind, obj):
            if kind in offsets:
                return read_int_from_memory(obj + offsets[kind], safe=True)
            return None

        entries = [(task, pid, comm, cred, read_blob("cred", cred), read_blob("task", task)) for task, pid, comm, cred in tasks]
        inodes = [x for x in dict.fromkeys(self.get_file_inode(file) for file in files) if x]
        samples = {"cred": [(e[4], e[3]) for e in entries], "task": [(e[5], e[0]) for e in entries]}
        samples.update({"file": [(read_blob("file", x), x) for x in files], "inode": [(read_blob("inode", x), x) for x in inodes]})
        self.blob_layout = self.resolve_blob_layout(lsms, {kind: v for kind, v in samples.items() if kind in offsets})

        self.dump_lsm_list(lsms)
        members = {"task": "task_struct, security", "cred": "cred, security", "file": "file, f_security", "inode": "inode, i_security"}
        for kind in ("task", "cred", "file", "inode"):
            if args.meta and kind in offsets:
                self.quiet_info_add_out("offsetof({:s}): {:#x}".format(members[kind], offsets[kind]))
        for kind in ("task", "cred", "file", "inode"):
            parts = self.blob_layout.get(kind)
            if parts:
                layout = ", ".join("{:s} {:s} ({:s})".format(
                    lsm, "+?" if offset is None else "+{:#x}".format(offset), how) for lsm, offset, how in parts)
                self.quiet_info_add_out("The {:s} blob: {:s}".format(kind, layout))

        selected = [e for e in entries if (args.pid is None or e[1] == args.pid) and (not args.task_filter or e[0] in args.task_filter)
                    and GefUtil.matches_regex(e[2], args.filter)]
        if not selected:
            self.err_add_out("No task matched")
            return
        if detail:
            for entry in selected:
                self.dump_task_detail(entry)
        else:
            self.dump_task_table(selected)
        return

    def dump_lsm_list(self, lsms):
        self.detected_lsms = set(lsms)
        if lsms:
            self.quiet_info_add_out("LSMs detected or inferred from hooks: {:s}".format(", ".join(sorted(lsms))))
        return

    def match_filter(self, name):
        if not self.args.hook:
            return True
        return any(h in name for h in self.args.hook)

    def dump_hooks(self, kversion):
        if Ksym.get_addrs(self.SCK_PREFIX, match="prefix"):
            self.dump_static_calls()
        elif not self.has_lsm_framework():
            self.err_add_out("No LSM dispatcher was found; this kernel may be CONFIG_SECURITY=n")
        elif kversion >= "6.12":
            self.dump_static_calls()
        elif kversion >= "4.2":
            self.dump_hook_heads()
        else:
            self.dump_security_ops()
        return

    def has_lsm_framework(self):
        """Return True if this kernel looks like CONFIG_SECURITY=y.
        A kernel built without it keeps only a handful of `security_*` stubs, while the
        framework brings one dispatcher per hook point."""
        ret = Ksym.get_kallsyms()
        if ret is None:
            return True
        kallsyms, _kallsyms_map = ret
        count = sum(1 for _a, name, typ in kallsyms
                    if name.startswith("security_") and typ.lower() in ("t", "w"))
        return count >= 16

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    @switch_to_intel_syntax
    def do_invoke(self, args):
        # the kernel version and the memory layout are resolved below and both are slow,
        # so tell the user before anything starts
        self.out = []
        self.quiet_info("Wait for memory scan")

        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return

        self.klayout = Kernel.layout()

        if args.task:
            self.dump_task_blobs(kversion)
        else:
            self.dump_hooks(kversion)

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelMountCommand(GenericCommand, BufferingOutput):
    """Dump the mount tree of each mount namespace."""

    _cmdline_ = "kmount"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-p", "--pid", type=int, help="dump the mount namespace of this pid.")
    parser.add_argument("-T", "--task", type=AddressUtil.parse_address, help="dump the mount namespace of this task_struct.")
    parser.add_argument("-a", "--all", action="store_true", help="dump every mount namespace.")
    parser.add_argument("-t", "--tasks", action="store_true", help="list the tasks of each mount namespace.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="also show mnt_id, peer_group, mnt_master and propagation.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} --pid 1337",
        "{0:s} --all --tasks",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "",
        "- Walks `mnt_mounts/mnt_child`, so all mounts in the namespace are shown, including bind mounts sharing a `super_block`.",
        "  `kfilesystems` instead shows filesystem types and all their `super_block`s, mounted or not.",
        "- Mount namespaces are inferred from mounts reachable through tasks, so namespaces with no task are invisible.",
        "- Without `--pid/--task`, the whole namespace is shown with absolute paths.",
        "  With either option, output is rooted at `task->fs->root`; unreachable mounts are marked `outside-root`.",
        "",
        "Simplified mount tree structure:",
        "",
        "+-task_struct--+     +-fs_struct-+     +-path----+",
        "| ...          |     | ...       |     | mnt     |--+",
        "| fs           |---->| root      |---->| dentry  |  |",
        "| ...          |     | pwd       |     +---------+  |",
        "+--------------+     +-----------+                  |",
        "                                                    |",
        "    +-----------------------------------------------+",
        "    |",
        "    v",
        "+-mount----------+<-+     +-mount----------+<-+     +-mount----------+",
        "| mnt_parent     |--+<----| mnt_parent     |  +<----| mnt_parent     |",
        "| mnt_mountpoint |     +--| mnt_mountpoint |     +--| mnt_mountpoint |",
        "| mnt (vfsmount) |     |  | mnt (vfsmount) |     |  | mnt (vfsmount) |",
        "|   mnt_root     |     |  |   mnt_root     |     |  |   mnt_root     |",
        "|   mnt_sb       |-+   |  |   mnt_sb       |     |  |   mnt_sb       |",
        "|   mnt_flags    | |   |  |   mnt_flags    |     |  |   mnt_flags    |",
        "| mnt_mounts     |-|-+ |  | mnt_mounts     |--+  |  | mnt_mounts     |",
        "| mnt_child      | | +-|->| mnt_child      |  +--|->| mnt_child      |",
        "| mnt_devname    | |   |  | mnt_devname    |     |  | mnt_devname    |",
        "+----------------+ |   |  +----------------+     |  +----------------+",
        "                   |   +-->dentry                +-->dentry",
        "                   v",
        "            +-super_block-+     +-file_system_type-+",
        '            | ...         |     | name             |-->"ext4"',
        "            | s_type      |---->| ...              |",
        "            | ...         |     +------------------+",
        "            +-------------+",
    ]
    _note_ = "\n".join(_note_)

    # include/linux/mount.h
    MNT_FLAGS = [
        (0x00_0001, "nosuid"),
        (0x00_0002, "nodev"),
        (0x00_0004, "noexec"),
        (0x00_0008, "noatime"),
        (0x00_0010, "nodiratime"),
        (0x00_0020, "relatime"),
        (0x00_0080, "nosymfollow", "5.10"),
        (0x00_0100, "shrinkable"),
        (0x00_0200, "write_hold"),
        (0x00_4000, "internal"),
        (0x04_0000, "lock_atime", "3.17"),
        (0x08_0000, "lock_noexec", "3.17"),
        (0x10_0000, "lock_nosuid", "3.17"),
        (0x20_0000, "lock_nodev", "3.17"),
        (0x40_0000, "lock_readonly", "3.17"),
        (0x80_0000, "locked", "3.17"),
        (0x100_0000, "doomed"),
        (0x200_0000, "sync_umount"),
        (0x800_0000, "umount", "3.18"),
        (0x1000_0000, "onrb"),
    ]
    MNT_READONLY = 0x40

    def initialize(self):
        self.meta = []

        kversion = Kernel.version()
        if kversion is None:
            self.meta.append((self.quiet_err, "Could not find Linux kernel"))
            return None
        self.kversion = kversion

        task_command = Kernel.task()
        task_ready = task_command.initialize(files=kversion < "3.3", namespaces=True,
                                             threads=self.args.pid is not None)
        self.meta.extend(Kernel.export_meta(self, task_command.meta))
        if not task_ready:
            task_command = None
        if task_command is None:
            return None
        self.task_command = task_command
        self.offset_nsproxy = getattr(task_command, "offset_nsproxy", None)

        self.kfs = None
        if "3.3" <= kversion:
            self.kfs = Kernel.file_system()
            kfs_ret = self.kfs.initialize()
            self.meta.extend(Kernel.export_meta(self, self.kfs.meta, demote_err=True))
            if not kfs_ret:
                self.meta.append((
                    self.quiet_warn, "Could not resolve the super_block layout; fstype and devname are not shown",
                ))
                self.kfs = None

        self.kpath = Kernel.path()
        if not self.kpath.initialized:
            self.meta.append((self.quiet_err, "Could not resolve the struct dentry layout"))
            return None

        if task_command.offset_files is None:
            self.meta.append((self.quiet_err, "Could not find task_struct->files"))
            return None
        self.offset_fs = self.kpath.get_offset_task_fs(task_command.offset_files)
        if self.offset_fs is None:
            self.meta.append((self.quiet_err, "Could not find task_struct->fs"))
            return None
        self.meta.append((self.quiet_info, "offsetof(task_struct, fs): {:#x}".format(self.offset_fs)))

        self.namespaces = self.collect_namespaces()
        if not self.namespaces:
            self.meta.append((self.quiet_err, "Could not find any mount namespace"))
            return None
        self.meta.append((self.quiet_info, "Number of mount namespaces: {:d}".format(len(self.namespaces))))

        root_mount = list(self.namespaces.keys())[0]
        self.offset_mnt_flags = self.kpath.get_offset_mnt_flags(root_mount)
        if self.offset_mnt_flags is None:
            self.meta.append((self.quiet_warn, "Could not find mount->mnt.mnt_flags"))
            self.mnt_onrb_present = False
        else:
            self.meta.append((self.quiet_info, "offsetof(mount, mnt.mnt_flags): {:#x}".format(self.offset_mnt_flags)))
            # MNT_ONRB accompanied the namespace rbtree from v6.8, but it was
            # later removed and that removal was backported to stable trees.
            # Every namespace root collected above is attached, so its live bit
            # is a better discriminator than the release string.
            self.mnt_onrb_present = False
            for mount in self.namespaces:
                flags = read_int32_from_memory(mount + self.offset_mnt_flags, safe=True)
                if flags is None:
                    continue
                if flags & 0x1000_0000:
                    self.mnt_onrb_present = True
                    break
            self.meta.append((self.quiet_info, "MNT_ONRB: {:s} (live mount flags)".format(
                "present" if self.mnt_onrb_present else "absent",
            )))

        if kversion < "3.3":
            self.offset_s_type = GefUtil.offsetof("super_block", "s_type")
            if self.offset_s_type is None:
                loff_t_align = 8 if is_64bit() or is_arm32() else 4
                self.offset_s_type = align(runtime.current_arch.ptrsize * 3 + 8, loff_t_align) + 8
            self.meta.append((self.quiet_info, "offsetof(super_block, s_type): {:#x}".format(self.offset_s_type)))

            self.offset_mnt_devname = GefUtil.offsetof("vfsmount", "mnt_devname")
            if self.offset_mnt_devname is None and self.offset_mnt_flags is not None:
                base = align(self.offset_mnt_flags + 4, runtime.current_arch.ptrsize)
                candidates = (base, align(self.offset_mnt_flags + 8, runtime.current_arch.ptrsize) + runtime.current_arch.ptrsize)
                mounts = [mount for mount, _ in self.walk_tree(root_mount)][:16]
                scores = []
                for offset in candidates:
                    score = 0
                    for mount in mounts:
                        name_ptr = read_int_from_memory(mount + offset, safe=True)
                        if not is_valid_addr(name_ptr):
                            continue
                        name = read_cstring_from_memory(name_ptr, max_length=64, safe=True)
                        if name and all(0x20 <= ord(char) < 0x7f for char in name):
                            score += 1
                    scores.append(score)
                if max(scores) > 0 and scores.count(max(scores)) == 1:
                    self.offset_mnt_devname = candidates[scores.index(max(scores))]
            if self.offset_mnt_devname is not None:
                self.meta.append((self.quiet_info, "offsetof(vfsmount, mnt_devname): {:#x}".format(self.offset_mnt_devname)))
            else:
                self.meta.append((self.quiet_warn, "Could not find vfsmount->mnt_devname"))

        self.offset_mnt_t_flags = GefUtil.offsetof("mount", "mnt_t_flags")
        self.offset_mnt_master = GefUtil.offsetof("mount", "mnt_master")
        self.offset_mnt_group_id = GefUtil.offsetof("mount", "mnt_group_id")
        self.offset_mnt_id = GefUtil.offsetof("mount", "mnt_id")
        self.offset_mnt_share = GefUtil.offsetof("mount", "mnt_share")
        self.offset_mnt_slave = GefUtil.offsetof("mount", "mnt_slave")
        for member, offset in (
            ("mnt_t_flags", self.offset_mnt_t_flags),
            ("mnt_master", self.offset_mnt_master),
            ("mnt_group_id", self.offset_mnt_group_id),
            ("mnt_id", self.offset_mnt_id),
            ("mnt_share", self.offset_mnt_share),
            ("mnt_slave", self.offset_mnt_slave),
        ):
            if offset is not None:
                self.meta.append((self.quiet_info, "offsetof(mount, {:s}): {:#x}".format(member, offset)))

        if self.offset_mnt_t_flags is not None:
            self.propagation_flag_source = "mnt_t_flags (debug information)"
            self.mnt_slave_is_hlist = True
        elif kversion < "6.17":
            self.propagation_flag_source = "mnt_flags (version fallback)"
            self.mnt_slave_is_hlist = False
        else:
            self.propagation_flag_source = "mnt_group_id/mnt_share/mnt_slave (version fallback)"
            self.mnt_slave_is_hlist = True
        self.meta.append((self.quiet_info, "Mount propagation source: {:s}".format(self.propagation_flag_source)))
        return True

    def get_mnt_ns(self, task):
        """Return task->nsproxy->mnt_ns using the current base + 3 * ptrsize layout assumption."""
        if self.offset_nsproxy is None:
            return None
        try:
            nsproxy = read_int_from_memory(task + self.offset_nsproxy)
            if not is_valid_addr(nsproxy):
                return None
            mnt_ns = read_int_from_memory(nsproxy + runtime.current_arch.ptrsize * 3)
        except (gdb.MemoryError, OverflowError):
            return None
        if not is_valid_addr(mnt_ns):
            return None
        return mnt_ns

    def collect_namespaces(self):
        """Group every task by the root mount of the mount namespace it belongs to."""
        kpath = self.kpath
        task_command = self.task_command
        namespaces = collections.OrderedDict()
        for task in KernelTask.get_task_list(task_command.init_task, task_command.offset_tasks):
            root = kpath.get_task_root(task, self.offset_fs)
            if root is None:
                continue
            root_mount = kpath.get_root_mount(root[0] - kpath.offset_mount_mnt)
            if root_mount not in namespaces:
                namespaces[root_mount] = {"mnt_ns": self.get_mnt_ns(task), "tasks": []}
            namespaces[root_mount]["tasks"].append(task)

        if not namespaces and self.kfs is not None and self.kfs.sample_mount is not None:
            # no task->fs->root was readable, but a mount found via super_block still gives the tree
            root_mount = kpath.get_root_mount(self.kfs.sample_mount)
            namespaces[root_mount] = {"mnt_ns": None, "tasks": []}
        return namespaces

    def get_task_by_pid(self, pid):
        task_command = self.task_command
        task_addrs = KernelTask.get_task_list(task_command.init_task, task_command.offset_tasks)
        if task_command.enabled.get("threads"):
            task_addrs = task_command.add_lwp_task(task_addrs)
        for task in task_addrs:
            if read_int32_from_memory(task + task_command.offset_pid) == pid:
                return task
        return None

    def resolve_target(self):
        """Return (ok, [(namespace root mount, tree root mount), ...], root).
        `root` is the (vfsmount, dentry) pair the pathnames stop at, or None when they are absolute.
        With --pid/--task the tree starts at the mount of task->fs->root instead of the namespace
        root. Mounts outside that root may also be returned and are marked `outside-root`."""
        args = self.args
        kpath = self.kpath

        if args.pid is None and args.task is None:
            root_mounts = list(self.namespaces.keys())
            if not args.all:
                root_mounts = root_mounts[:1]
            return True, [(root_mount, root_mount) for root_mount in root_mounts], None

        task = args.task
        if task is None:
            task = self.get_task_by_pid(args.pid)
            if task is None:
                err("Could not find the task of pid {:d}".format(args.pid))
                return False, [], None

        root = kpath.get_task_root(task, self.offset_fs)
        if root is None:
            err("Could not find task->fs->root of {:#x}".format(task))
            return False, [], None
        tree_root = root[0] - kpath.offset_mount_mnt
        return True, [(kpath.get_root_mount(tree_root), tree_root)], root

    def get_children(self, mount):
        kpath = self.kpath
        head = mount + kpath.offset_mount_mnt_mounts
        if not is_double_link_list(head):
            return []
        children = []
        for child in KernelListHead(head, kpath.offset_mount_mnt_child).iter_entries():
            if is_valid_addr(child):
                children.append(child)
        return children

    def walk_tree(self, root_mount, max_mounts=0x20000):
        """Yield (mount, tree prefix) over the whole tree under `root_mount`, depth first."""
        kpath = self.kpath
        if kpath.get_offset_mnt_mounts(root_mount) is None:
            yield root_mount, ""
            return

        seen = set()
        stack = [(root_mount, "", True, True)]
        while stack:
            mount, prefix, is_last, is_root = stack.pop()
            if mount in seen:
                continue
            if len(seen) >= max_mounts:
                self.err_add_out("Mount tree truncated after {:d} mounts".format(max_mounts))
                break
            seen.add(mount)
            if is_root:
                mark, child_prefix = "", ""
            else:
                mark = prefix + ("`- " if is_last else "|- ")
                child_prefix = prefix + ("   " if is_last else "|  ")
            yield mount, mark
            children = self.get_children(mount)
            for i, child in enumerate(reversed(children)):
                stack.append((child, child_prefix, i == 0, False))
        return

    def get_mnt_flags(self, mount):
        if self.offset_mnt_flags is None:
            return None
        return read_int32_from_memory(mount + self.offset_mnt_flags, safe=True)

    def get_mount_list_node_status(self, mount, offset, hlist=False):
        if offset is None:
            return None
        node = mount + offset
        next_entry = read_int_from_memory(node, safe=True)
        prev_entry = read_int_from_memory(node + runtime.current_arch.ptrsize, safe=True)
        if next_entry is None or prev_entry is None:
            return None
        if hlist:
            if prev_entry == 0:
                return False
            if not is_valid_addr(prev_entry):
                return None
            first = read_int_from_memory(prev_entry, safe=True)
            if first is None:
                return None
            return first == node
        if not is_valid_addr(next_entry) or not is_valid_addr(prev_entry):
            return None
        if read_int_from_memory(next_entry + runtime.current_arch.ptrsize, safe=True) != node:
            return None
        if read_int_from_memory(prev_entry, safe=True) != node:
            return None
        return next_entry != node

    def get_mnt_propagation_str(self, mount):
        flags = self.get_mnt_flags(mount)
        t_flags = None
        if self.offset_mnt_t_flags is not None:
            t_flags = read_int32_from_memory(mount + self.offset_mnt_t_flags, safe=True)

        shared_flag = None
        unbindable = None
        if t_flags is not None:
            shared_flag = bool(t_flags & 1)
            unbindable = bool(t_flags & 2)
        elif self.kversion < "6.17" and flags is not None:
            shared_flag = bool(flags & 0x1000)
            unbindable = bool(flags & 0x2000)

        shared_list = self.get_mount_list_node_status(mount, self.offset_mnt_share)
        shared = shared_flag
        if shared is None and self.offset_mnt_group_id is not None:
            group_id = read_int32_from_memory(mount + self.offset_mnt_group_id, safe=True)
            if group_id is not None:
                shared = bool(group_id)
        if shared is None and shared_list is True:
            shared = True
        mismatch = shared is False and shared_list is True

        master = None
        if self.offset_mnt_master is not None:
            master = read_int_from_memory(mount + self.offset_mnt_master, safe=True)
            if master == 0:
                master = False
            elif master is not None:
                if is_valid_addr(master):
                    master = True
                else:
                    master = None
        slave_list = self.get_mount_list_node_status(mount, self.offset_mnt_slave, self.mnt_slave_is_hlist)
        slave = master
        if slave is None:
            slave = slave_list
        if master is not None and slave_list is not None and master != slave_list:
            mismatch = True

        if shared is False and slave is False and unbindable is None:
            state = "private,?unbindable"
        else:
            states = []
            for value, name in ((shared, "shared"), (slave, "slave"), (unbindable, "unbindable")):
                if value is True:
                    states.append(name)
                elif value is None:
                    states.append("?" + name)
            if not states:
                state = "private"
            else:
                state = ",".join(states)
        if mismatch:
            state += " (list mismatch)"
        return state

    def get_mnt_flags_str(self, mount):
        flags = self.get_mnt_flags(mount)
        if flags is None:
            return "???"
        names = ["ro" if flags & self.MNT_READONLY else "rw"]
        for entry in self.MNT_FLAGS:
            bit, name = entry[0], entry[1]
            if len(entry) > 2 and self.kversion < entry[2]:
                continue
            if name == "onrb" and not self.mnt_onrb_present:
                continue
            if flags & bit:
                names.append(name)
        if self.offset_mnt_t_flags is not None:
            t_flags = read_int32_from_memory(mount + self.offset_mnt_t_flags, safe=True)
            if t_flags is not None:
                if t_flags & 4:
                    names.append("marked")
                if t_flags & 8:
                    names.append("umount_candidate")
        elif self.kversion < "6.17" and flags & 0x0400_0000:
            names.append("marked")
        return ",".join(names)

    def get_mount_row(self, mount, mark, root):
        kpath = self.kpath
        vfsmnt = mount + kpath.offset_mount_mnt
        try:
            mnt_root = read_int_from_memory(vfsmnt + kpath.offset_vfsmount_mnt_root)
            super_block = read_int_from_memory(vfsmnt + kpath.offset_vfsmount_mnt_sb)
        except (gdb.MemoryError, OverflowError):
            self.warn_add_out("Unreadable mount: {:#x}".format(mount))
            return None

        fstype = None
        devname = None
        if self.kfs is not None:
            fstype = self.kfs.get_fstype_name(super_block)
            devname = self.kfs.get_dev_name(mount)
        elif self.kversion < "3.3":
            fst = read_int_from_memory(super_block + self.offset_s_type, safe=True)
            if is_valid_addr(fst):
                name_ptr = read_int_from_memory(fst, safe=True)
                if is_valid_addr(name_ptr):
                    fstype = read_cstring_from_memory(name_ptr, max_length=64, safe=True)
            if self.offset_mnt_devname is not None:
                name_ptr = read_int_from_memory(vfsmnt + self.offset_mnt_devname, safe=True)
                if is_valid_addr(name_ptr):
                    devname = read_cstring_from_memory(name_ptr, max_length=64, safe=True)

        path_info = kpath.get_mount_path(mount, root)
        path = path_info.path or "???"
        if path_info.status != "normal":
            path += " ({:s})".format(path_info.status)

        row = [
            "{:#018x}".format(mount), "{:#018x}".format(vfsmnt), "{:#018x}".format(mnt_root), "{:#018x}".format(super_block),
            fstype or "???", devname or "???", mark + path, self.get_mnt_flags_str(mount),
        ]
        if not self.args.verbose:
            return row

        mount_id = None
        if self.offset_mnt_id is not None:
            mount_id = read_int32_from_memory(
                mount + self.offset_mnt_id, safe=True, signed=True,
            )
        group_id = None
        if self.offset_mnt_group_id is not None:
            group_id = read_int32_from_memory(
                mount + self.offset_mnt_group_id, safe=True, signed=True,
            )
        master = None
        if self.offset_mnt_master is not None:
            master = read_int_from_memory(mount + self.offset_mnt_master, safe=True)
        if mount_id is None:
            mount_id = "?"
        else:
            mount_id = str(mount_id)
        if group_id is None:
            group_id = "?"
        else:
            group_id = str(group_id)
        if master is None:
            master = "?"
        elif master == 0:
            master = "none"
        elif is_valid_addr(master):
            master = "{:#x}".format(master)
        else:
            master = "?"
        row += [mount_id, group_id, master, self.get_mnt_propagation_str(mount)]
        return row

    def dump_namespace(self, root_mount, tree_root, root):
        info = self.namespaces.get(root_mount, {"mnt_ns": None, "tasks": []})
        if info["mnt_ns"] is not None:
            title = "mount namespace {:#x}".format(info["mnt_ns"])
        else:
            title = "mount namespace of root mount {:#x}".format(root_mount)
        self.out.append(titlify(title))

        task_command = self.task_command
        tasks = info["tasks"]
        if tasks:
            # the idle task heads the list, but it says nothing about who owns the namespace
            sample = tasks[0]
            for task in tasks:
                if read_int32_from_memory(task + task_command.offset_pid) != 0:
                    sample = task
                    break
            comm = read_cstring_from_memory(sample + task_command.offset_comm)
            self.quiet_info_add_out('root mount: {:#018x}, tasks: {:d} (e.g. "{:s}")'.format(root_mount, len(tasks), comm))
            if self.args.tasks:
                for task in tasks:
                    pid = read_int32_from_memory(task + task_command.offset_pid)
                    comm = read_cstring_from_memory(task + task_command.offset_comm)
                    self.out.append('  task: {:#018x} (pid: {:d}, comm: "{:s}")'.format(task, pid, comm))
        else:
            self.quiet_info_add_out("root mount: {:#018x}, tasks: 0".format(root_mount))

        if tree_root != root_mount:
            self.quiet_info_add_out("the tree starts at the mount of task->fs->root: {:#018x}".format(tree_root))

        legend = ["mount", "vfsmount", "mnt_root", "super_block", "fstype", "devname", "mount_point", "mnt_flags"]
        if self.args.verbose:
            legend += ["mnt_id", "peer_group", "mnt_master", "propagation"]
        rows = []
        for mount, mark in self.walk_tree(tree_root):
            row = self.get_mount_row(mount, mark, root)
            if row is not None:
                rows.append(row)
        widths = [max(len(row[i]) for row in [legend] + rows) for i in range(len(legend))]
        fmt = " ".join("{{:{:d}s}}".format(width) for width in widths)
        if not self.args.quiet:
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))
        for row in rows:
            self.out.append(fmt.format(*row).rstrip())
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        ret = self.initialize()
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            return

        if args.meta:
            return

        ok, targets, root = self.resolve_target()
        if not ok:
            return

        if args.pid is None and args.task is None and len(self.namespaces) > len(targets):
            self.quiet_info("{:d} more mount namespaces exist; use --all".format(len(self.namespaces) - len(targets)))

        self.out = []
        for i, (root_mount, tree_root) in enumerate(targets):
            if i > 0:
                self.out.append("")
            self.dump_namespace(root_mount, tree_root, root)
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelNftablesCommand(GenericCommand, BufferingOutput):
    """Dump the nftables (netfilter) object graph."""

    _cmdline_ = "knft"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", nargs="?", type=AddressUtil.parse_address,
                        help="reverse-lookup: report an exact/containing known nftables object, or the nearest known object.")
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-R", "--no-rules", action="store_true", help="do not decode or render rules and expressions.")
    parser.add_argument("-E", "--no-elements", action="store_true", help="do not decode or render set elements.")
    parser.add_argument("-F", "--family", help="only show tables of this family (inet, ip, ip6, arp, bridge, netdev).")
    parser.add_argument("-T", "--table", metavar="NAME", help="only show tables with this name.")
    parser.add_argument("-k", "--kind", action="append", choices=["chain", "set", "object", "flowtable"],
                        help="only show this kind of table child. It can be specified multiple times.")
    parser.add_argument("-N", "--name", help="only show chains, sets, objects and flowtables with this name.")
    parser.add_argument("-H", "--handle", type=AddressUtil.parse_address,
                        help="only show the rule with this handle (implies `-k chain`).")
    parser.add_argument("--net", type=AddressUtil.parse_address,
                        help="only show the network namespace with this struct net address or ns inode number.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show object attributes, hooks and expression contents (mostly needs type information).")
    parser.add_argument("--meta", action="store_true", help="display discovery information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                          # dump the whole nftables object graph",
        "{0:s} -R                       # dump the graph without rules and expressions",
        "{0:s} -E                       # dump the graph without set elements",
        "{0:s} -F inet -T filter -k set # show only the sets of the inet table `filter`",
        "{0:s} -T filter -N input -v    # show chain `input` with attributes, hook and expressions",
        "{0:s} -T filter -H 12 -v       # show rule handle 12 and its decoded expressions",
        "{0:s} --net 4026531840         # show only the network namespace net:[4026531840]",
        "{0:s} 0xffff888012345600       # find which nftables object owns this address",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Walks table -> chain -> rule -> expr and table -> set -> element / object / flowtable.",
        "The mainline location of the table list changed over time:",
        "",
        "  v3.13~v4.15 : net.nft.af_info -> nft_af_info.tables (one list per family)",
        "  v4.16~v5.12 : net.nft.tables (one list for every family)",
        "  v5.13~      : net_generic(net, nf_tables_net_id) -> nftables_pernet.tables",
        "",
        "nftables first appeared in mainline v3.13. Older kernels have no nftables object graph.",
        "",
        "+-nftables_pernet-+   +-nft_table---+   +-nft_chain--+   +-nft_rule_blob-+",
        "| tables          |-->| list        |   | blob_gen_0 |-->| size          |",
        "| ...             |   | chains      |-->| list       |   | data[]        |",
        "+-----------------+   | sets        |   | name       |   +-------+-------+",
        "                      | objects     |   +------------+           |  (one nft_rule_dp per rule)",
        "                      | flowtables  |                            v",
        "                      | name        |                     +-nft_rule_dp-+",
        "                      +-------------+                     | is_last     |",
        "                                                          | dlen,handle |",
        "                                                          | data[]      |--> +-nft_expr-+",
        "                                                          +-------------+    | ops      |--> type->name",
        "                                                                             +----------+",
        "",
        "On v4.16 and later, chains / sets / objects / flowtables hang off nft_table as four",
        "consecutive list_head fields; legacy tables have the lists available in that kernel release.",
        "Table discovery first validates this list topology and child->table back-references, then",
        "uses rule/expression decoding only for the actual chains instead of for every table candidate.",
        "",
        "Rule headers, blob fields, set extensions and backend layouts prefer kernel type information.",
        "Stripped targets use versioned layout fallbacks; --meta reports the selected source and offsets.",
        "Broken walks keep validated entries where possible and mark the output as partial.",
        "nftables names may be up to 255 bytes; identifier-like names are preferred only as a heuristic",
        "and are not a kernel validity rule. The datapath representation changed from linked nft_rule objects before",
        "v5.17 to a contiguous nft_rule_blob in mainline v5.17 and later; the control-plane rule list",
        "still exists on newer kernels, and both representations are understood where applicable.",
        "",
        "Filters are applied after the table list is discovered; only the selected chains and sets are",
        "decoded. With -v, the table handle/flags/genmask/owner come from the validated nft_table layout",
        "and the rule genmask/userdata from the rule header even on stripped kernels. The chain, base",
        "chain hook, set, object and flowtable attributes and the expression private data are printed",
        "only when type information (e.g., vmlinux and nf_tables.ko debug info) is loaded.",
    ]
    _note_ = "\n".join(_note_)

    FAMILY_NAMES = {"inet": 1, "ip": 2, "ipv4": 2, "arp": 3, "netdev": 5, "bridge": 7, "ip6": 10, "ipv6": 10}

    TABLE_FLAGS = {0x1: "dormant", 0x2: "owner", 0x4: "persist"}
    CHAIN_FLAGS = {0x1: "base", 0x2: "hw-offload", 0x4: "binding"}
    SET_FLAGS = {
        0x1: "anonymous", 0x2: "constant", 0x4: "interval", 0x8: "map", 0x10: "timeout",
        0x20: "eval", 0x40: "object", 0x80: "concat", 0x100: "expr",
    }
    FLOWTABLE_FLAGS = {0x1: "hw-offload", 0x2: "counter"}
    SET_POLICIES = {0: "performance", 1: "memory"}
    CHAIN_POLICIES = {0: "drop", 1: "accept"}
    OBJECT_TYPES = {
        1: "counter", 2: "quota", 3: "ct helper", 4: "limit", 5: "connlimit", 6: "tunnel",
        7: "ct timeout", 8: "secmark", 9: "ct expectation", 10: "synproxy",
    }
    HOOK_NAMES = {
        None: ("prerouting", "input", "forward", "output", "postrouting", "ingress"),
        3: ("input", "output", "forward"),
        5: ("ingress", "egress"),
    }
    SET_UDATA = {
        0: "keybyteorder", 1: "databyteorder", 2: "merge_elements", 3: "key_typeof", 4: "data_typeof",
        5: "expr", 6: "data_interval", 7: "comment",
    }

    def table_selected(self, table):
        if self.family_filter is not None and table["family"] != self.family_filter:
            return False
        return self.args.table is None or table["name"] == self.args.table

    def kind_selected(self, kind):
        if self.args.handle is not None:
            return kind == "chains"
        if not self.args.kind:
            return True
        return kind[:-1] in self.args.kind

    def get_table_children(self, table, net):
        # Apply the child filters before any set element is decoded; rules are decoded only for
        # chains whose name matched.
        children = []
        for kind in ("chains", "sets", "objects", "flowtables"):
            if kind not in table["kinds"] or not self.kind_selected(kind):
                continue
            for entry in table["kinds"][kind]["entries"]:
                name = self.knft.entry_name(entry, kind, table=table["address"])
                if self.args.name is not None and name != self.args.name:
                    continue
                rules, status = None, None
                if kind == "chains" and not self.args.no_rules:
                    rules, status = self.knft.rules.chain_rules(entry, net)
                    if self.args.handle is not None and not any(rule["handle"] == self.args.handle for rule in rules or []):
                        continue
                children.append({
                    "kind": kind,
                    "address": entry,
                    "name": name,
                    "rules": rules,
                    "status": status,
                })
        return children

    def get_object_ranges(self, net, label, nftables):
        # Type information provides exact object ranges; stripped targets retain exact/nearest semantics.
        nodes = []
        for table in nftables["tables"]:
            if not self.table_selected(table):
                continue
            table_start, table_end = self.knft.table_range(table)
            nodes.append({
                "address": table_start, "end": table_end,
                "description": 'table "{:s}" ({:s})'.format(table["name"], label or "net {:#x}".format(net)),
            })
            for kind, child_list in table["kinds"].items():
                if not self.kind_selected(kind):
                    continue
                for entry in child_list["entries"]:
                    name = self.knft.entry_name(entry, kind, table=table["address"])
                    if self.args.name is not None and name != self.args.name:
                        continue
                    object_start, object_end = self.knft.entry_object_range(entry, kind)
                    nodes.append({
                        "address": object_start, "end": object_end,
                        "description": '{:s} "{:s}" in table "{:s}"'.format(kind[:-1], name, table["name"]),
                    })
                    if kind == "chains":
                        base_range = self.knft.rules.base_chain_range(entry)
                        if base_range is not None:
                            nodes.append({
                                "address": base_range[0], "end": base_range[1],
                                "description": 'base chain "{:s}" in table "{:s}"'.format(name, table["name"]),
                            })
                    if kind == "sets" and not self.args.no_elements:
                        info = self.knft.sets.parse_set(entry)
                        for element in info["elements"]:
                            key = "0x" + element["key"].hex()
                            nodes.append({
                                "address": element["address"], "end": element["end"],
                                "description": 'set element key={:s} in set "{:s}"'.format(key, name),
                            })
                    if kind != "chains" or self.args.no_rules:
                        continue

                    blob_range = self.knft.rules.chain_blob_range(entry, net)
                    if blob_range is not None:
                        nodes.append({"address": blob_range[0], "end": blob_range[1],
                                      "description": 'rule blob of chain "{:s}"'.format(name)})
                    rules, status = self.knft.rules.chain_rules(entry, net)
                    if status and "control-plane" in status:
                        source = "control-plane "
                    else:
                        source = ""
                    for rule in rules or []:
                        if self.args.handle is not None and rule["handle"] != self.args.handle:
                            continue
                        nodes.append({"address": rule["address"], "end": rule["end"],
                                      "description": '{:s}rule handle={:d} in chain "{:s}"'.format(
                                          source, rule["handle"], name)})
                        for expr in rule["exprs"]:
                            nodes.append({"address": expr["address"], "end": expr["end"],
                                          "description": '{:s}expression "{:s}" in rule handle={:d} of chain "{:s}"'.format(
                                              source, expr["name"], rule["handle"], name)})
        return nodes

    @staticmethod
    def flags_str(value, names):
        if value is None:
            return None
        parts, rest = GefUtil.flags_to_names(value, sorted(names.items()))
        if rest:
            parts.append("{:#x}".format(rest))
        return "{:#x}".format(value) + ("({:s})".format(",".join(parts)) if parts else "")

    @staticmethod
    def attrs_str(attrs):
        return " ".join("{:s}={}".format(key, value) for key, value in attrs if value is not None)

    def hook_name(self, family, hooknum):
        if hooknum is None:
            return None
        names = self.HOOK_NAMES.get(family, self.HOOK_NAMES[None])
        if 0 <= hooknum < len(names):
            return "{:s}({:d})".format(names[hooknum], hooknum)
        return str(hooknum)

    @staticmethod
    def udata_string(data, names=None):
        # libnftnl stores userdata as {u8 type, u8 len, value[len]} records; type 0 is a comment
        # except for sets.
        if names is None:
            names = {0: "comment"}
        items = []
        pos = 0
        while pos + 2 <= len(data):
            kind, length = data[pos], data[pos + 1]
            value = data[pos + 2:pos + 2 + length]
            if len(value) != length:
                break
            name = names.get(kind)
            if value.endswith(b"\0"):
                text = value[:-1]
            else:
                text = value
            if name == "comment" and text and all(0x20 <= char < 0x7f for char in text):
                items.append('comment="{:s}"'.format(text.decode()))
            elif name is not None and length == 4:
                items.append("{:s}={:d}".format(name, u32(value)))
            else:
                items.append("{:s}=0x{:s}".format(name or "udata[{:d}]".format(kind), value.hex()))
            pos += 2 + length
        if pos != len(data) or not items:
            return "udata=0x" + data.hex()
        return " ".join(items)

    def table_detail(self, table, nftables):
        attrs = self.knft.get_table_attrs(table, nftables)
        if attrs is None:
            return None
        text = self.attrs_str([
            ("handle", attrs["handle"]),
            ("flags", self.flags_str(attrs["flags"], self.TABLE_FLAGS)),
            ("genmask", attrs["genmask"]),
            ("nlpid", attrs["nlpid"]),
        ])
        if attrs["udata"]:
            text += " " + self.udata_string(attrs["udata"])
        return text

    def chain_detail(self, entry, family):
        attrs = self.knft.rules.get_chain_attrs(entry)
        if attrs is None:
            return []
        text = self.attrs_str([
            ("handle", attrs["handle"]),
            ("use", attrs["use"]),
            ("level", attrs["level"]),
            ("flags", self.flags_str(attrs["flags"], self.CHAIN_FLAGS)),
            ("bound", attrs["bound"]),
            ("genmask", attrs["genmask"]),
        ])
        if attrs["udata"]:
            text += " " + self.udata_string(attrs["udata"])
        lines = [text]

        hook = attrs["hook"]
        if hook is None:
            return lines
        text = self.attrs_str([
            ("type", hook["type"]),
            ("hook", self.hook_name(family, hook["hooknum"])),
            ("priority", hook["priority"]),
            ("policy", self.CHAIN_POLICIES.get(hook["policy"], hook["policy"])),
            ("base-chain", Color.colorify_hex(hook["base_chain"], "blue")),
        ])
        if hook["devices"]:
            text += " devices={:s}".format(",".join(hook["devices"]))
        lines.append("hook: " + text)
        return lines

    def set_detail(self, entry):
        attrs = self.knft.sets.get_set_attrs(entry)
        if attrs is None:
            return []
        concat = None
        if attrs["concat"] is not None:
            concat = ",".join(str(length) for length in attrs["concat"]) or None
        text = self.attrs_str([
            ("handle", attrs["handle"]),
            ("flags", self.flags_str(attrs["flags"], self.SET_FLAGS)),
            ("ktype", attrs["ktype"]),
            ("klen", attrs["klen"]),
            ("dtype", None if attrs["dtype"] is None else "{:#x}".format(attrs["dtype"])),
            ("dlen", attrs["dlen"]),
            ("objtype", attrs["objtype"]),
            ("policy", self.SET_POLICIES.get(attrs["policy"], attrs["policy"])),
            ("size", attrs["size"]),
            ("timeout", attrs["timeout"]),
            ("gc_int", attrs["gc_int"]),
            ("use", attrs["use"]),
            ("nelems", attrs["nelems"]),
            ("genmask", attrs["genmask"]),
            ("concat", concat),
        ])
        if attrs["udata"]:
            text += " " + self.udata_string(attrs["udata"], self.SET_UDATA)
        lines = [text]
        for expr in attrs["exprs"]:
            lines += self.expr_detail(expr)
        return lines

    def object_detail(self, entry):
        attrs = self.knft.get_object_attrs(entry)
        if attrs is None:
            return []
        text = self.attrs_str([
            ("handle", attrs["handle"]),
            ("type", self.OBJECT_TYPES.get(attrs["type"], attrs["type"])),
            ("use", attrs["use"]),
            ("genmask", attrs["genmask"]),
        ])
        if attrs["udata"]:
            text += " " + self.udata_string(attrs["udata"])
        return [text]

    def flowtable_detail(self, entry):
        attrs = self.knft.get_flowtable_attrs(entry)
        if attrs is None:
            return []
        text = self.attrs_str([
            ("handle", attrs["handle"]),
            ("use", attrs["use"]),
            ("flags", self.flags_str(attrs["flags"], self.FLOWTABLE_FLAGS)),
            ("genmask", attrs["genmask"]),
            ("hook", self.hook_name(5, attrs["hooknum"])),
            ("priority", attrs["priority"]),
        ])
        if attrs["devices"]:
            text += " devices={:s}".format(",".join(attrs["devices"]))
        return [text]

    def rule_detail(self, rule):
        attrs = self.knft.rules.get_rule_attrs(rule)
        if attrs is None:
            return None
        text = self.attrs_str([("genmask", attrs["genmask"])])
        if attrs["udata"]:
            text += " " + self.udata_string(attrs["udata"])
        return text

    def expr_detail(self, expr):
        if expr["end"] is None:
            return ["expr ? {:s}".format(Color.colorify_hex(expr["address"], "blue"))]
        size = expr["end"] - expr["address"]
        lines = ["expr {:s} {:s} size={:#x}".format(expr["name"], Color.colorify_hex(expr["address"], "blue"), size)]
        xt = expr["xt"]
        if xt is not None:
            info_text = "?"
            if xt["info"] is not None:
                info_text = "0x" + xt["info"].hex() + ("..." if xt["size"] > len(xt["info"]) else "")
            lines[0] += " {:s} {:s} rev={} size={:#x} info={:s}".format(
                xt["type"], xt["name"], xt["revision"], xt["size"], info_text)
            return lines
        if expr["value"] is None:
            return lines
        try:
            lines[0] += " {:s} {:s}".format(expr["type_name"].split()[1], expr["value"].format_string(
                pretty_structs=False, pretty_arrays=False, array_indexes=False))
        except gdb.error:
            return lines
        for nested in expr["nested"]:
            lines += ["  " + line for line in self.expr_detail(nested)]
        return lines

    def dump_meta(self, nets):
        for func, line in self.meta:
            func(line)
        for net, label in nets:
            nftables = self.knft.parse_tables(net)
            meta = self.knft.get_net_meta(net, label, nftables, elements=not self.args.no_elements)
            for func, line in Kernel.export_meta(self, meta):
                func(line)
        return

    def dump_table(self, table, prefix, children):
        for index, child in enumerate(children):
            kind = child["kind"]
            entry = child["address"]
            name = child["name"]
            rules = child["rules"]
            status = child["status"]
            entry_last = index == len(children) - 1
            if entry_last:
                connector = "`- "
            else:
                connector = "|- "
            if entry_last:
                extension = "   "
            else:
                extension = "|  "
            if kind == "chains":
                if rules is None:
                    rules_text = ""
                elif status and "limit" in status:
                    rules_text = " rules>={:d} [scan limit]".format(len(rules))
                else:
                    rules_text = " rules={:d}".format(len(rules))
                    if status and "broken" in status:
                        rules_text += " [corrupt]"
                if status and "control-plane" in status:
                    rules_text += " [control-plane; active datapath unavailable]"
                self.out.append(prefix + connector + "chain {:s} {:s}{:s}".format(
                    Color.colorify(name, "bold green"), Color.colorify_hex(entry, "blue"), rules_text))
                if self.args.handle is not None:
                    rules = [rule for rule in rules if rule["handle"] == self.args.handle]
                control = None
                if self.args.verbose:
                    for line in self.chain_detail(entry, table["family"]):
                        self.out.append(prefix + extension + ("|  " if rules else "   ") + line)
                    if rules:
                        control = self.knft.rules.control_rules(entry) or {}
                for rule_index, rule in enumerate(rules or []):
                    names = [expr["name"] for expr in rule["exprs"]]
                    rule_last = rule_index == len(rules) - 1
                    if rule_last:
                        rule_connector = "`- "
                    else:
                        rule_connector = "|- "
                    if names:
                        suffix = " [{:s}]".format(", ".join(names))
                    else:
                        suffix = ""
                    self.out.append(prefix + extension + rule_connector + "rule handle={:d}".format(rule["handle"]) + suffix)
                    if control is None:
                        continue
                    detail_lines = []
                    if rule["handle"] in control:
                        text = self.rule_detail(control[rule["handle"]])
                        if text:
                            detail_lines.append(text)
                    for expr in rule["exprs"]:
                        expr_info = self.knft.rules.get_expr_info(expr["address"], expr["end"], expr["name"])
                        detail_lines += self.expr_detail(expr_info)
                    for line in detail_lines:
                        self.out.append(prefix + extension + ("   " if rule_last else "|  ") + "   " + line)
            elif kind == "sets":
                info = self.knft.sets.parse_set(entry, elements=not self.args.no_elements)
                expected = info["nelems"]
                count = len(info["elements"])
                if info["status"] == "disabled":
                    element_text = ""
                elif expected is not None and expected != count:
                    element_text = " elements={:d}/{:d}".format(count, expected)
                else:
                    element_text = " elements={:d}".format(count)
                if info["status"] not in ("ok", "empty", "disabled"):
                    element_text += " [{:s}]".format(info["status"])
                if info["backend"]:
                    backend_text = " type={:s}".format(info["backend"])
                else:
                    backend_text = ""
                self.out.append(prefix + connector + "set {:s} {:s}{:s}{:s}".format(
                    Color.colorify(name, "bold green"), Color.colorify_hex(entry, "blue"), backend_text, element_text))
                if self.args.verbose:
                    for line in self.set_detail(entry):
                        self.out.append(prefix + extension + ("|  " if info["elements"] else "   ") + line)
                for element_index, element in enumerate(info["elements"]):
                    element_last = element_index == len(info["elements"]) - 1
                    if element_last:
                        element_conn = "`- "
                    else:
                        element_conn = "|- "
                    key = "0x" + element["key"].hex()
                    if element["key_end"] is not None:
                        key += "-0x" + element["key_end"].hex()
                    suffix = ""
                    if element["data"] is not None:
                        suffix += " data=0x" + element["data"].hex()
                    if element["flags"] is not None and element["flags"] & 1:
                        suffix += " [interval-end]"
                    self.out.append(prefix + extension + element_conn + "element {:s} key={:s}{:s}".format(
                        Color.colorify_hex(element["address"], "blue"), key, suffix))
            else:
                self.out.append(prefix + connector + "{:s} {:s} {:s}".format(
                    kind[:-1], Color.colorify(name, "bold green"), Color.colorify_hex(entry, "blue")))
                if self.args.verbose:
                    if kind == "objects":
                        detail_lines = self.object_detail(entry)
                    elif kind == "flowtables":
                        detail_lines = self.flowtable_detail(entry)
                    else:
                        detail_lines = []
                    for line in detail_lines:
                        self.out.append(prefix + extension + "   " + line)
        return

    def dump_net(self, net, label, nftables):
        header = "net {:s}".format(Color.colorify_hex(net, "blue"))
        if label:
            header += " ({:s})".format(label)
        if self.args.verbose:
            inum = self.knft.net_inum(net)
            if inum is not None:
                header += " inum={:d}".format(inum)

        selected = []
        for table in nftables["tables"]:
            if not self.table_selected(table):
                continue
            children = self.get_table_children(table, net)
            if self.child_filter and not children:
                continue
            selected.append((table, children))
        if not selected:
            return

        self.out.append(header)
        for table_index, (table, children) in enumerate(selected):
            table_last = table_index == len(selected) - 1
            if table_last:
                table_connector = "`- "
            else:
                table_connector = "|- "
            if table_last:
                text = "  "
            else:
                text = "| "
            meta = []
            if table["family"] is not None:
                meta.append(KernelNftables.FAMILIES.get(table["family"], "family{:d}".format(table["family"])))
            if table["use"] is not None:
                meta.append("use={:d}".format(table["use"]))
            if meta:
                suffix = " [{:s}]".format(" ".join(meta))
            else:
                suffix = ""
            self.out.append("{:s}table {:s} {:s}".format(
                table_connector, Color.colorify(table["name"], "bold"), Color.colorify_hex(table["address"], "blue")) + suffix)
            if self.args.verbose:
                detail = self.table_detail(table, nftables)
                if detail:
                    self.out.append(text + ("|  " if children else "   ") + detail)
            self.dump_table(table, text, children)
        return

    def dump_reverse_lookup(self, addr, all_nodes):
        exact = [node for node in all_nodes if node["address"] == addr]
        if exact:
            for node in exact:
                self.out.append("{:s} is {:s}".format(Color.colorify_hex(addr, "blue"), node["description"]))
            return

        containing = [node for node in all_nodes if node["end"] is not None and node["address"] <= addr < node["end"]]
        if containing:
            node = max(containing, key=lambda node: node["address"])
            start, desc = node["address"], node["description"]
            self.out.append("{:s} is +{:#x} into {:s} ({:s})".format(
                Color.colorify_hex(addr, "blue"), addr - start, desc, Color.colorify_hex(start, "blue")))
            return

        below = [node for node in all_nodes if node["address"] <= addr]
        if not below:
            self.err_add_out("{:#x} does not match any known nftables object".format(addr))
            return
        node = max(below, key=lambda node: node["address"])
        start, desc = node["address"], node["description"]
        self.out.append("{:s}: nearest known nftables object below is {:s} at {:s} (+{:#x})".format(
            Color.colorify_hex(addr, "blue"), desc, Color.colorify_hex(start, "blue"), addr - start,
        ))
        return

    def dump(self, nets):
        all_nodes = []
        for net, label in nets:
            nftables = self.knft.parse_tables(net)
            if nftables is None or not nftables["tables"]:
                continue
            if self.args.address is None:
                self.dump_net(net, label, nftables)
            else:
                all_nodes += self.get_object_ranges(net, label, nftables)

        if self.args.address is not None:
            self.dump_reverse_lookup(self.args.address, all_nodes)
        elif self.out:
            return
        elif self.family_filter is not None or self.args.table is not None or self.child_filter:
            self.warn_add_out("No nftables object matched the filter")
        else:
            self.warn_add_out("No nftables tables found (is CONFIG_NF_TABLES enabled and any table created?)")
            if self.knft.kversion < "3.13":
                self.warn_add_out("This kernel predates nftables, which first appeared in mainline v3.13")
        return

    def setup(self, args):
        self.args = args
        self.family_filter = None
        if args.family is not None:
            self.family_filter = self.FAMILY_NAMES.get(args.family.lower())
            if self.family_filter is None:
                err("Unknown family: {:s} (choose from {:s})".format(args.family, ", ".join(self.FAMILY_NAMES)))
                return
        if args.handle is not None:
            args.no_rules = False
        self.child_filter = bool(args.kind) or args.name is not None or args.handle is not None
        return True

    def initialize(self):
        self.knft = Kernel.nftables()
        ret = self.knft.initialize()
        self.meta = Kernel.export_meta(self, self.knft.meta)
        return ret

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if not self.setup(args):
            return
        self.quiet_info("Wait for memory scan")

        ret = self.initialize()
        if not ret:
            for func, line in self.meta:
                func(line)
            return

        nets = self.knft.nets
        if args.net is not None:
            nets = [(net, label) for net, label in nets if net == args.net or self.knft.net_inum(net) == args.net]
            if not nets:
                err("Could not find the network namespace {:#x} ({:d})".format(args.net, args.net))
                return
        if args.verbose and GefUtil.cached_lookup_type("struct nft_chain") is None:
            self.quiet_info("No nftables type information; "
                            "chain/set/object/flowtable attributes and expression contents are omitted")

        self.out = []
        if args.meta:
            self.dump_meta(nets)
        else:
            self.dump(nets)
        if self.knft.partial_reasons:
            self.warn_add_out("Partial result: {:s}".format(", ".join(sorted(self.knft.partial_reasons))))
        self.print_output(check_terminal_size=not args.meta)
        return



@register_command
class KernelPathCommand(GenericCommand, BufferingOutput):
    """Reconstruct the pathname of a dentry, path, file or mount."""

    _cmdline_ = "kpath"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the address of struct dentry, path, file, mount or vfsmount.")
    parser.add_argument("-t", "--type", choices=["auto", "dentry", "path", "file", "mount", "vfsmount"],
                        default="auto", help="the type of ADDRESS. (default: %(default)s)")
    parser.add_argument("-p", "--pid", type=int, help="resolve the path as the task of this pid sees it.")
    parser.add_argument("-T", "--task", type=AddressUtil.parse_address, help="resolve the path as this task_struct sees it.")
    parser.add_argument("-a", "--all", action="store_true", help="print every mount the dentry is reachable through.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffff888003b0a000",
        "{0:s} --pid 1 0xffff888003b0a000",
        "{0:s} --all 0xffff888003b0a000",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "",
        "- Without `--pid/--task`, paths are resolved to the mount-namespace root.",
        "  With either option, resolution stops at `task->fs->root`; `outside-root` means the target lies outside it.",
        "- A bare dentry has no mount information. If multiple mounts match, `ambiguous` is shown; use `--all` to list them.",
        "- The target mount namespace is searched first, then other namespaces reachable through scanned tasks.",
        "  `no-mount` means no matching reachable mount was found, which is normal for pseudo-filesystems or unmounted mounts.",
        "- Only a bare dentry and `--pid/--task` need the task list. The other types are resolved from the object alone.",
        "",
        "Simplified path structure:",
        "",
        "+-file-----------+     +-path----+",
        "| ...            |     | mnt     |--+",
        "| f_path         |---->| dentry  |--|--+",
        "| ...            |     +---------+  |  |",
        "+----------------+                  |  |",
        "                                    |  |",
        "    +-------------------------------+  |",
        "    |                                  |",
        "    v                                  v",
        "+-mount----------+<-+     +----------->+-dentry-----+",
        "| mnt_hash       |  |     |            | ...        |",
        "| mnt_parent     |--+     |            | d_parent   |-->dentry",
        "| mnt_mountpoint |--------+            | ...        |",
        "| mnt (vfsmount) |                     | d_name     |",
        '|   mnt_root     |-------------------->|   name     |-->"foo"',
        "|   mnt_sb       |-->super_block       | d_inode    |-->inode",
        "| ...            |                     | d_iname    |",
        "| mnt_mounts     |--+                  +------------+",
        "| mnt_child      |  |",
        "+----------------+  +-->child mounts",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self):
        self.meta = []
        self.task_command = None
        self.task_tried = False
        self.offset_fs = None
        self.root_mount = None

        kversion = Kernel.version()
        if kversion is None:
            self.meta.append((self.quiet_err, "Could not find Linux kernel"))
            return None

        self.kpath = Kernel.path()
        if not self.initialize_layout(kversion):
            return None

        if self.args.meta:
            self.initialize_tasks()
        return True

    def get_seed_dentry(self, address, kind):
        """Return the dentry the object of `kind` refers to, used to resolve the dentry layout."""
        kpath = self.kpath
        if kind == "dentry":
            return address
        if kind == "path":
            return read_int_from_memory(address + runtime.current_arch.ptrsize)
        if kind == "mount":
            address += kpath.offset_mount_mnt
        return read_int_from_memory(address + kpath.offset_vfsmount_mnt_root)

    def initialize_layout(self, kversion):
        kpath = self.kpath
        if kpath.initialized:
            self.meta.extend(Kernel.export_meta(self, kpath.meta))
            return True

        # plan 1: the root dentry of a registered filesystem, which needs no task
        if "3.3" <= kversion:
            kfs = Kernel.file_system()
            if kfs.initialize() and kpath.initialized:
                self.meta.extend(Kernel.export_meta(self, kpath.meta))
                self.meta.append((self.quiet_info, "dentry (sample): the root of a mount in file_systems"))
                return True

        # plan 2: the object given with --type
        kind = self.args.type
        if kind != "auto" and kpath.ensure_mount_offsets():
            try:
                if kind == "file":
                    ret = kpath.initialize(file=self.args.address)
                else:
                    ret = kpath.initialize(dentry=self.get_seed_dentry(self.args.address, kind))
            except (gdb.MemoryError, OverflowError, RuntimeError):
                ret = None
            if ret:
                self.meta.extend(Kernel.export_meta(self, kpath.meta))
                self.meta.append((self.quiet_info, "{:s} (sample): {:#x}".format(kind, self.args.address)))
                return True

        # plan 3: the open files of the tasks
        task_command = Kernel.task()
        task_ready = task_command.initialize(files=True, threads=self.args.pid is not None)
        self.meta.extend(Kernel.export_meta(self, task_command.meta))
        if not task_ready:
            task_command = None
        if task_command is not None and kpath.initialized:
            self.task_command = task_command
            return True

        self.meta.append((self.quiet_err, "Could not resolve the struct dentry layout"))
        if kind == "auto":
            self.meta.append((self.quiet_err, "Specifying the type with --type may help"))
        return None

    def initialize_tasks(self):
        """Resolve what walking the tasks needs. Only a bare dentry and --pid/--task need it."""
        if self.task_tried:
            return self.offset_fs is not None
        self.task_tried = True

        task_command = self.task_command
        if task_command is None:
            task_command = Kernel.task()
            task_ready = task_command.initialize(threads=self.args.pid is not None)
            self.meta.extend(Kernel.export_meta(self, task_command.meta))
            if not task_ready:
                task_command = None
            if task_command is None:
                return None

        # task_struct->fs sits just before task_struct->files, which init_task is enough to find
        try:
            offset_files = task_command.get_offset_files(task_command.offset_comm)
        except (gdb.MemoryError, OverflowError):
            offset_files = None
        if offset_files is None:
            self.meta.append((self.quiet_err, "Could not find task_struct->files"))
            return None
        offset_fs = self.kpath.get_offset_task_fs(offset_files)
        if offset_fs is None:
            self.meta.append((self.quiet_err, "Could not find task_struct->fs"))
            return None
        self.meta.append((self.quiet_info, "offsetof(task_struct, fs): {:#x}".format(offset_fs)))

        init_root = self.kpath.get_task_root(task_command.init_task, offset_fs)
        if init_root is None:
            self.meta.append((self.quiet_warn, "Could not find init_task->fs->root"))
        else:
            self.root_mount = self.kpath.get_root_mount(init_root[0] - self.kpath.offset_mount_mnt)
            self.meta.append((self.quiet_info, "root mount: {:#x}".format(self.root_mount)))
        self.task_command = task_command
        self.offset_fs = offset_fs
        return True

    def get_task_by_pid(self, pid):
        task_command = self.task_command
        task_addrs = KernelTask.get_task_list(task_command.init_task, task_command.offset_tasks)
        if task_command.enabled.get("threads"):
            task_addrs = task_command.add_lwp_task(task_addrs)
        for task in task_addrs:
            if read_int32_from_memory(task + task_command.offset_pid, safe=True) == pid:
                return task
        return None

    def resolve_root(self):
        """Return (ok, root, task). `root` is None when the path must be resolved absolutely."""
        args = self.args
        if args.pid is None and args.task is None:
            return True, None, None

        n = len(self.meta)
        if not self.initialize_tasks():
            for func, line in self.meta[n:]:
                func(line)
            err("Could not resolve task_struct->fs->root, which --pid/--task needs")
            return False, None, None

        task = args.task
        if task is None:
            task = self.get_task_by_pid(args.pid)
            if task is None:
                err("Could not find the task of pid {:d}".format(args.pid))
                return False, None, None

        root = self.kpath.get_task_root(task, self.offset_fs)
        if root is None:
            err("Could not find task->fs->root of {:#x}".format(task))
            return False, None, None
        return True, root, task

    def detect_type(self, address):
        kpath = self.kpath
        if kpath.is_mount(address):
            return "mount"
        if kpath.is_vfsmount(address):
            return "vfsmount"
        if kpath.is_path(address):
            return "path"
        # f_path.dentry and f_op of a file can pass as d_parent and d_name.name of a dentry,
        # so the stricter check of a file, whose f_path must hold both objects, goes first
        if self.resolve_targets(address, "file"):
            return "file"
        if kpath.is_dentry(address):
            return "dentry"
        return None

    def get_primary_root(self, task_root):
        """Return the root mount of the mount namespace the answer is asked about."""
        kpath = self.kpath
        if task_root is not None:
            return [kpath.get_root_mount(task_root[0] - kpath.offset_mount_mnt)]
        if self.root_mount is not None:
            return [self.root_mount]
        return []

    def get_other_roots(self, primary):
        """Return the root mount of every other mount namespace that has a task."""
        kpath = self.kpath
        others = []
        task_command = self.task_command
        for task in KernelTask.get_task_list(task_command.init_task, task_command.offset_tasks):
            root = kpath.get_task_root(task, self.offset_fs)
            if root is None:
                continue
            mount = kpath.get_root_mount(root[0] - kpath.offset_mount_mnt)
            if mount not in primary and mount not in others:
                others.append(mount)
        return others

    def search_mounts_for_dentry(self, index, root_mounts, visited):
        kpath = self.kpath
        candidates = []
        for root_mount in root_mounts:
            for mount in kpath.iter_mounts(root_mount):
                if mount in visited:
                    continue
                visited.add(mount)
                vfsmnt = mount + kpath.offset_mount_mnt
                mnt_root = read_int_from_memory(vfsmnt + kpath.offset_vfsmount_mnt_root, safe=True)
                if mnt_root is None:
                    continue
                if mnt_root in index:
                    # the discovery order breaks ties, so the nearest mount of the nearest namespace wins
                    candidates.append((index[mnt_root], len(candidates), vfsmnt))
        candidates.sort()
        return [vfsmnt for _, _, vfsmnt in candidates]

    def find_mounts_for_dentry(self, dentry, task_root):
        """Return every (vfsmount, dentry) the dentry can be reached through, the nearest mount first.
        Only the target mount namespace is searched first. The other namespaces are searched
        just when that finds nothing, so that a container private mount does not shadow the
        answer the user is asking about."""
        kpath = self.kpath

        if not self.initialize_tasks():
            return []

        chain = []
        seen = set()
        current = dentry
        while is_valid_addr(current) and current not in seen:
            seen.add(current)
            chain.append(current)
            parent = read_int_from_memory(current + kpath.offset_d_parent, safe=True)
            if parent is None:
                break
            if parent == current:
                break
            current = parent
        index = {d: i for i, d in enumerate(chain)}

        primary = self.get_primary_root(task_root)
        visited = set()
        found = self.search_mounts_for_dentry(index, primary, visited)
        if not found:
            found = self.search_mounts_for_dentry(index, self.get_other_roots(primary), visited)
        return [(vfsmnt, dentry) for vfsmnt in found]

    def resolve_targets(self, address, kind, task_root=None):
        kpath = self.kpath
        ptrsize = runtime.current_arch.ptrsize

        try:
            if kind == "path":
                vfsmnt = read_int_from_memory(address)
                dentry = read_int_from_memory(address + ptrsize)
            elif kind == "file":
                return self.resolve_file(address)
            elif kind in ("mount", "vfsmount"):
                if kind == "mount":
                    vfsmnt = address + kpath.offset_mount_mnt
                else:
                    vfsmnt = address
                dentry = read_int_from_memory(vfsmnt + kpath.offset_vfsmount_mnt_root)
            else:
                return self.find_mounts_for_dentry(address, task_root)
        except (gdb.MemoryError, OverflowError, RuntimeError):
            return []

        # an explicit type is trusted even if the parent of the dentry is unreadable, which the walk reports
        if not kpath.is_vfsmount(vfsmnt) or not kpath.is_dentry(dentry, strict=self.args.type == "auto"):
            return []
        return [(vfsmnt, dentry)]

    def resolve_file(self, file):
        kpath = self.kpath
        probing = kpath.offset_file_mnt is None
        n = len(kpath.meta)
        try:
            if not probing or kpath.initialize_file_offsets(file):
                vfsmnt = read_int_from_memory(file + kpath.offset_file_mnt)
                dentry = read_int_from_memory(file + kpath.offset_file_dentry)
                strict = probing or self.args.type == "auto"
                if kpath.is_vfsmount(vfsmnt) and kpath.is_dentry(dentry, strict=strict):
                    return [(vfsmnt, dentry)]
        except (gdb.MemoryError, OverflowError, RuntimeError):
            pass
        if probing:
            # the offsets were guessed from this object, which turned out not to be a file
            kpath.offset_file_mnt = None
            kpath.offset_file_dentry = None
            del kpath.meta[n:]
        return []

    def dump(self, targets, root):
        kpath = self.kpath

        if not self.args.quiet:
            fmt = "{:18s} {:18s} {:18s} {:12s} {:s}"
            legend = ["dentry", "mount", "vfsmount", "status", "path"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for vfsmnt, dentry in targets:
            path_info = kpath.prepend_path(dentry, vfsmnt, root)
            status = path_info.status
            if len(targets) > 1 and status == "normal":
                status = "ambiguous"
            path = kpath.decorate_path(path_info, dentry) or "???"
            if kpath.is_unlinked(dentry):
                path += " (deleted)"
            self.out.append("{:#018x} {:#018x} {:#018x} {:12s} {:s}".format(dentry, vfsmnt - kpath.offset_mount_mnt, vfsmnt, status, path))
            if not self.args.all and len(targets) > 1:
                self.quiet_info_add_out("{:d} more mounts can reach this dentry; use --all".format(len(targets) - 1))
                break
        return

    def dump_without_mount(self, dentry):
        if not self.args.quiet:
            fmt = "{:18s} {:18s} {:18s} {:12s} {:s}"
            legend = ["dentry", "mount", "vfsmount", "status", "path"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))
        path_info = self.kpath.get_dentry_path_info(dentry)
        path = self.kpath.decorate_path(path_info, dentry) or "???"
        if self.kpath.is_unlinked(dentry):
            path += " (deleted)"
        self.out.append("{:#018x} {:18s} {:18s} {:12s} {:s}".format(dentry, "-", "-", path_info.status, path))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        ret = self.initialize()
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            return

        if args.meta:
            return

        if not is_valid_addr(args.address):
            err("Unreadable address: {:#x}".format(args.address))
            return

        ok, root, _task = self.resolve_root()
        if not ok:
            return

        kind = args.type
        if kind == "auto":
            kind = self.detect_type(args.address)
            if kind is None:
                err("Could not tell what {:#x} points to; specify it with --type".format(args.address))
                return
        self.quiet_info("Interpreted ADDRESS as struct {:s}".format(kind))

        targets = self.resolve_targets(args.address, kind, root)

        self.out = []
        if not targets:
            if kind == "dentry":
                if self.offset_fs is None:
                    self.quiet_warn("Could not walk the tasks, so no mount was searched (see --meta)")
                else:
                    self.quiet_warn("Could not find a mount holding this dentry")
                self.dump_without_mount(args.address)
            else:
                err("Could not interpret {:#x} as struct {:s}".format(args.address, kind))
                return
        else:
            self.dump(targets, root)
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelRefsCommand(GenericCommand, BufferingOutput):
    """Search the kernel pointers that reference the specified address."""

    _cmdline_ = "krefs"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    @staticmethod
    def parse_range(text):
        """Parse `START-END` or `START+SIZE` into (start, size)."""
        for sep in ("-", "+"):
            lhs, found, rhs = text.partition(sep)
            if not found:
                continue
            start = AddressUtil.parse_address(lhs)
            value = AddressUtil.parse_address(rhs)
            if sep == "-":
                size = value - start
            else:
                size = value
            if size <= 0:
                raise ValueError("empty range: {:s}".format(text))
            return start, size
        raise ValueError("invalid range: {:s}".format(text))

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address, help="the address which the found pointers refer to.")
    parser.add_argument("-d", "--data", action="store_true", help="scan the static data of the kernel image. (default if no area is given)")
    parser.add_argument("-p", "--percpu", action="store_true", help="scan the per-cpu areas.")
    parser.add_argument("-c", "--cache", action="append", default=[], help="scan the slab pages of this kmem_cache.")
    parser.add_argument("-o", "--object", action="append", type=AddressUtil.parse_address, default=[],
                        help="scan the slab object that contains this address. (e.g., a task_struct)")
    parser.add_argument("-r", "--range", action="append", type=parse_range.__func__, default=[],
                        help="scan this address range. (START-END or START+SIZE)")
    parser.add_argument("-M", "--kernel-writable", "--physmap", dest="physmap", action="store_true",
                        help="scan every writable kernel mapping. (--physmap is a legacy alias; very slow)")
    parser.add_argument("-t", "--tolerance", type=AddressUtil.parse_address, default=0,
                        help="also report the pointers into [ADDRESS, ADDRESS+TOLERANCE].")
    parser.add_argument("-l", "--limit", type=lambda x: int(x, 0), default=0x100,
                        help="stop after this many hits. 0 means unlimited. (default: %(default)s)")
    parser.add_argument("--no-owner", action="store_true", help="do not resolve the owner of each hit.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffff888012345600                        # scan the static data of the kernel image",
        "{0:s} -p 0xffff888012345600                     # scan the per-cpu areas too",
        "{0:s} -c filp 0xffff888012345600                # scan the slab pages of the filp cache",
        "{0:s} -o 0xffff888045670000 0xffff888012345600  # scan one slab object (e.g. a task_struct)",
        "{0:s} -r 0xffff888012340000+0x1000 0xffff888012345600",
        "{0:s} -t 0x100 0xffff888012345600               # also catch the interior pointers",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "- Full-memory scans are too slow over a gdb stub, so the default search is limited to kernel static data,",
        "  where global object references commonly live.",
        "- Hits are annotated with their likely context: the preceding kallsyms symbol, per-cpu variable and CPU,",
        "  or slab cache and object boundary. Kallsyms ownership is only a heuristic.",
        "- Only pointer-size-aligned raw pointers are found; encoded, tagged, XORed, mangled, or unaligned pointers are missed.",
        "- `-c` scans the slab pages reachable from the per-cpu and per-node lists and the sheaves.",
        "  SLUB links no full slab without CONFIG_SLUB_DEBUG, and SLOB has no slab page owned by a cache.",
        "- Overlapping virtual ranges are scanned once. Physical aliases are reported at each virtual address.",
        "- The slab cache of a hit is resolved on x86 and ARM only.",
        "- Use `kobj ADDRESS` to identify the referenced object.",
    ]
    _note_ = "\n".join(_note_)

    def get_image_symbols(self):
        """Return the kallsyms entries as a sorted ([addr, ...], [name, ...])."""
        if self.image_symbols is not None:
            return self.image_symbols
        ret = Ksym.get_kallsyms()
        if ret is None:
            self.image_symbols = [], []
            return self.image_symbols
        kallsyms, _kallsyms_map = ret
        entries = sorted({(a, n) for a, n, _typ in kallsyms})
        self.image_symbols = [a for a, _n in entries], [n for _a, n in entries]
        return self.image_symbols

    def lookup_image_symbol(self, addr):
        """Return the nearest preceding kallsyms symbol as `name+0x..`, or ''."""
        addrs, names = self.get_image_symbols()
        if not addrs:
            return ""
        i = bisect.bisect_right(addrs, addr) - 1
        if i < 0:
            return ""
        sym_addr, name = addrs[i], names[i]
        if addr == sym_addr:
            return name
        # a kernel without CONFIG_KALLSYMS_ALL has no data symbol at all, so the nearest
        # preceding one can be megabytes away and means nothing
        if addr - sym_addr > 0x20000:
            return ""
        return "{:s}+{:#x}".format(name, addr - sym_addr)

    def collect_cache_ranges(self, name):
        """Return the slab page ranges of the kmem_cache `name`."""
        pagesize = KernelAddressHeuristicFinder.consts().PAGE_SIZE
        allocator, kmem_caches = Kernel.get_slab_caches([name])
        if kmem_caches is None:
            self.err_add_out("Could not parse the kmem_caches (allocator: {!s})".format(allocator))
            return []
        if not kmem_caches:
            self.err_add_out("The cache `{:s}` was not found".format(name))
            return []
        if allocator == "SLOB":
            self.err_add_out("SLOB has no slab page owned by a kmem_cache")
            return []

        kmem_cache = kmem_caches[0]
        pages = []
        if allocator == "SLUB":
            for kmem_cache_cpu in kmem_cache.get("kmem_cache_cpu", {}).values():
                pages += [kmem_cache_cpu["active_page"]] + kmem_cache_cpu["partial_pages"]
            for page_list in kmem_cache.get("nodes_partial", []) + kmem_cache.get("nodes_full", []):
                pages += page_list
            pages = [(p.get("virt_addr"), p.get("num_pages")) for p in pages]
            # v6.18~: a sheaf holds freed objects whose slab no list may reach
            for chunk in KernelSlub.get_sheaf_objects(kmem_cache):
                if not isinstance(chunk, int) or not chunk:
                    continue
                if any(vaddr and num_pages and vaddr <= chunk < vaddr + num_pages * pagesize for vaddr, num_pages in pages):
                    continue
                obj = Kernel.get_slab_object(chunk)
                if obj and obj["name"] == name:
                    pages.append((obj["base"], obj["num_pages"]))
                else:
                    pages.append((chunk & -pagesize, 1))
        elif allocator == "SLUB_TINY":
            for page_list in kmem_cache["nodes"]:
                pages += [(p.get("virt_addr"), p.get("num_pages")) for p in page_list]
        elif allocator == "SLAB":
            for slabs_list in kmem_cache["nodes"]:
                for page_list in slabs_list.values():
                    pages += [(p.get("s_mem_base"), kmem_cache["pagesperslab"]) for p in page_list]

        seen = set()
        for vaddr, num_pages in pages:
            if vaddr and num_pages and 0 < num_pages <= 0x1000:
                seen.update(range(vaddr, vaddr + num_pages * pagesize, pagesize))
        ranges = []
        for vaddr in sorted(seen):
            if ranges and ranges[-1][0] + ranges[-1][1] == vaddr:
                ranges[-1] = (ranges[-1][0], ranges[-1][1] + pagesize, ranges[-1][2])
            else:
                ranges.append((vaddr, pagesize, "slab:{:s}".format(name)))
        if not ranges:
            self.err_add_out("No slab page was found for the cache `{:s}`".format(name))
        return ranges

    def collect_object_range(self, addr):
        """Return the range of the slab object that contains `addr`."""
        obj = Kernel.get_slab_object(addr)
        if obj is None or obj["object_base"] is None:
            self.err_add_out("{:#x} is not in a slab object".format(addr))
            return []
        return [(obj["object_base"], obj["chunk_size"], "object:{:s}".format(obj["name"]))]

    def collect_physmap_ranges(self):
        """Return every writable kernel mapping."""
        klayout = Kernel.layout()
        if not klayout.maps:
            self.err_add_out("Could not resolve the kernel memory map")
            return []
        ranges = []
        for entry in klayout.maps:
            if not entry.is_writable():
                continue
            ranges.append((entry.vstart, entry.vsize, "mapped"))
        return ranges

    def collect_ranges(self):
        """Return the [(start, size, label), ...] to scan."""
        args = self.args
        ranges = []

        if args.data or not (args.percpu or args.cache or args.object or args.range or args.physmap):
            klayout = Kernel.layout()
            found = False
            if klayout.ro_base and klayout.ro_size:
                ranges.append((klayout.ro_base, klayout.ro_size, "kernel .rodata"))
                found = True
            if klayout.rw_base and klayout.rw_size:
                ranges.append((klayout.rw_base, klayout.rw_size, "kernel .data/.bss"))
                found = True
            if not found:
                self.err_add_out("Could not resolve the kernel memory map")

        if args.percpu:
            units = Kernel.per_cpu().unit_ranges()
            for cpu, (start, end) in enumerate(units):
                ranges.append((start, end - start, "per-cpu cpu{:d}".format(cpu)))
            if not units:
                self.err_add_out("Could not resolve the per-cpu areas")

        for name in args.cache:
            ranges += self.collect_cache_ranges(name)

        for addr in args.object:
            ranges += self.collect_object_range(addr)

        for start, size in args.range:
            ranges.append((start, size, "user range"))

        if args.physmap:
            ranges += self.collect_physmap_ranges()

        unique_ranges = []
        for start, size, label in ranges:
            fragments = [(start, start + size)]
            for previous_range in unique_ranges:
                previous = previous_range[0]
                previous_end = previous + previous_range[1]
                remaining = []
                for first, last in fragments:
                    if last <= previous or previous_end <= first:
                        remaining.append((first, last))
                    else:
                        if first < previous:
                            remaining.append((first, previous))
                        if previous_end < last:
                            remaining.append((previous_end, last))
                fragments = remaining
                if not fragments:
                    break
            unique_ranges.extend((first, last - first, label) for first, last in fragments)
        return unique_ranges

    def scan_block(self, addr, data, label):
        """Yield the pointers inside `data` that hit the target."""
        ptrsize = runtime.current_arch.ptrsize
        for i, value in enumerate(slice_unpack(data, ptrsize)):
            if self.lo <= value <= self.hi:
                yield addr + i * ptrsize, value, label
        return

    def scan_range(self, start, size, label, bar):
        """Yield (location, value, label) of the pointers inside [start, start+size)."""
        ptrsize = runtime.current_arch.ptrsize
        page = get_pagesize()
        if start % ptrsize:
            pos = align(start, ptrsize)
        else:
            pos = start
        end = start + size
        while pos < end:
            n = min(0x10000, end - pos)
            n -= n % ptrsize
            if n <= 0:
                break
            data = read_memory(pos, n, safe=True)
            if data is None:
                # A range may begin in the middle of a page.  Bound each retry at
                # the next page boundary; otherwise an unreadable following page
                # makes us discard the readable tail of the current one as well.
                sub = pos
                block_end = pos + n
                while sub < block_end:
                    next_page = (sub & ~(page - 1)) + page
                    m = min(next_page - sub, block_end - sub)
                    m -= m % ptrsize
                    if m > 0:
                        data = read_memory(sub, m, safe=True)
                        if data is not None:
                            for hit in self.scan_block(sub, data, label):
                                yield hit
                    sub = next_page
                bar.update(n)
                pos += n
                continue
            for hit in self.scan_block(pos, data, label):
                yield hit
            bar.update(n)
            pos += n
        return

    def resolve_owner(self, addr):
        """Return a short description of what holds the pointer at `addr`."""
        if self.args.no_owner:
            return ""

        image = KernelAddressHeuristicFinderUtil.get_kernel_image_range()
        if image and image[0] <= addr < image[1]:
            name = self.lookup_image_symbol(addr)
            if name:
                return "<{:s}>".format(name)
            return ""

        pc = Kernel.per_cpu()
        ret = pc.resolve(addr)
        if ret is not None:
            cpu, _static_addr, sym = ret
            if sym is None:
                return "cpu{:d} (dynamic per-cpu)".format(cpu)
            return "cpu{:d} <{:s}+{:#x}>".format(cpu, sym[0], sym[1])

        obj = Kernel.get_slab_object(addr)
        if obj is not None:
            if obj["object_base"] is None:
                return "cache: {:s}".format(obj["name"])
            return "cache: {:s}  object: {:#x}+{:#x}".format(obj["name"], obj["object_base"], obj["offset"])
        return ""

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if args.tolerance < 0:
            err("The tolerance must not be negative")
            return

        self.image_symbols = None
        self.lo = args.address
        self.hi = args.address + args.tolerance
        self.out = []
        # resolving the kernel version and the scan areas already takes a while
        self.quiet_info("Wait for memory scan")

        if Kernel.version() is None:
            err("Could not find Linux kernel")
            return

        ranges = self.collect_ranges()
        if not ranges:
            self.print_output()
            return

        total = sum(size for _start, size, _label in ranges)
        self.quiet_info_add_out("Target: {:#x}{:s}".format(args.address, "-{:#x}".format(self.hi) if args.tolerance else ""))
        for start, size, label in ranges:
            self.quiet_info_add_out("Scan area: {:<18s} {:#x}-{:#x}".format(label, start, start + size))

        hits = []
        truncated = False
        bar = ProgressBar(total=total, disable=args.quiet)
        try:
            for start, size, label in ranges:
                for hit in self.scan_range(start, size, label, bar):
                    if args.limit and len(hits) >= args.limit:
                        truncated = True
                        break
                    hits.append(hit)
                if truncated:
                    break
        finally:
            bar.close()

        if not hits:
            self.info_add_out("No reference was found")
            self.print_output(check_terminal_size=True)
            return

        self.quiet_info_add_out("Number of references: {:d}{:s}".format(len(hits), " (truncated by --limit)" if truncated else ""))
        for addr, value, label in hits:
            owner = self.resolve_owner(addr)
            line = "{:s} -> {:s}  [{:s}]".format(AddressUtil.format_address(addr), AddressUtil.format_address(value), label)
            if owner:
                line += "  " + owner
            self.out.append(line)

        self.print_output(check_terminal_size=True)
        return


@register_command
class KernelSkbCommand(GenericCommand, BufferingOutput):
    """Parse a single sk_buff and show its buffer layout, refcount and fragment information."""

    _cmdline_ = "kskb"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("skb", metavar="SKB_ADDR", nargs="?", type=AddressUtil.parse_address,
                        help="a `struct sk_buff` address.")
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-d", "--dump", action="store_true",
                        help="hexdump the first 64 bytes of the linear packet data.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffff888012345000",
        "{0:s} -d 0xffff888012345000",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified sk_buff structure:",
        "",
        "+-sk_buff----+",
        "| next, prev |  list linkage (rbnode/list in a union)",
        "| ...        |",
        "| len        |  total length (headlen + data_len)",
        "| data_len   |  bytes held in fragments (nonlinear)",
        "| ...        |",
        "| tail       |  offset of the end of packet data",
        "| end        |  offset of skb_shared_info",
        "| head       |  start of the allocated buffer",
        "| data       |  start of packet data",
        "| truesize   |",
        "| users      |  refcount",
        "| ...        |",
        "+------------+",
        "",
        "head        data          tail          head+end",
        "|           |             |             |",
        "v           v             v             v",
        "+-----------+-------------+-------------+------------------+",
        "|  headroom | packet data |  tailroom   | skb_shared_info  |",
        "+-----------+-------------+-------------+------------------+",
        "|<-- data ->|             |             |",
        "|<-------- tail --------->|             |",
        "|<---------------- end ---------------->|",
        "",
        "skb_shared_info (at head + end) holds nr_frags, frag_list, frags[] ...",
        "On 64-bit, tail/end are u32 offsets from head; on 32-bit they are absolute pointers.",
        "The offsets are taken from the debug information if available, otherwise probed from the memory.",
        "frags[] is decoded only with the debug information.",
        "truesize is an accounting value (e.g., 2 for a local TCP pure ACK), not the buffer size.",
    ]
    _note_ = "\n".join(_note_)

    def dump_frags(self, shinfo, nr_frags):
        for item in self.kskb.get_frags(shinfo, nr_frags):
            i = item["index"]
            if "error" in item:
                self.out.append("    frags[{:d}]: ??? (unreadable)".format(i))
                continue
            page, offset, size, virt = item["page"], item["offset"], item["size"], item["virt"]
            out = "    frags[{:d}]: page: {:#x}, ".format(i, page)
            if virt:
                out += "(virt: {:#x}), ".format(virt)
            out += "offset: {:#x}, size: {:#x}".format(offset, size)
            self.out.append(out)
        return

    def dump_shared_info(self, head, end):
        shinfo = head + end
        self.out.append("  skb_shared_info: {:#018x}".format(shinfo))
        layout = self.kskb.resolve_shared_info_layout(shinfo)
        if layout is None:
            self.out.append("    nr_frags: ??? (layout could not be resolved)")
            return
        nr_frags, frag_list, nr_offset, max_frags, source = layout
        if max_frags is None:
            limit = ""
        else:
            limit = ", CONFIG_MAX_SKB_FRAGS={:d}".format(max_frags)
        self.out.append("    nr_frags: {:d}  (offset +{:#x}, {:s}{:s})".format(
            nr_frags, nr_offset, source, limit,
        ))
        if source == "DWARF":
            self.dump_frags(shinfo, nr_frags)
        if frag_list == 0:
            self.out.append("    frag_list: (none)")
        elif is_valid_addr(frag_list):
            self.out.append("    frag_list: {:#018x}".format(frag_list))
        return

    @staticmethod
    def get_data_dump(info):
        """Return the hexdump lines of the first 64 bytes of the linear packet data (from data to head + tail)."""
        data, headlen, size, raw = info["address"], info["headlen"], info["size"], info["data"]
        if headlen == 0:
            return ["data: (no linear data)"]
        if raw is None:
            return ["data: ??? (unreadable @ {:#018x})".format(data)]
        lines = ["data (first {:#x} of {:#x} linear bytes @ {:#018x}):".format(size, headlen, data)]
        lines += hexdump(raw, 0x10, show_symbol=False, base=data, unit=1).splitlines()
        return lines

    def dump_skb(self, skb, layout):
        info = self.kskb.get_skb(skb, layout)
        head = layout["head_value"]
        data = layout["data_value"]
        tail = layout["tail_value"]
        end = layout["end_value"]

        self.out.append("sk_buff: {:#018x}".format(skb))
        # next / prev (list linkage at offset 0)
        nxt, prv = info["next"], info["prev"]
        self.out.append("  next: {:#018x}  prev: {:#018x}".format(nxt, prv))
        self.out.append("  head: {:#018x}".format(head))
        self.out.append("  data: {:#018x}  (headroom: {:#x})".format(data, data - head))
        self.out.append("  tail: {:#x}  (-> {:#018x})".format(tail, head + tail))
        self.out.append("  end:  {:#x}  (-> {:#018x})".format(end, head + end))

        # headlen from the buffer geometry (skb->len - skb->data_len)
        headlen = tail - (data - head)
        len_v, data_len = info["len"], info["data_len"]
        if len_v is not None:
            self.out.append("  len: {:#x} ({:d})  data_len: {:#x}  (headlen: {:#x})".format(
                len_v, len_v, data_len, headlen))
            if len_v - data_len != headlen:
                self.out.append("  [!] len - data_len does not match tail - (data - head)")
        else:
            self.out.append("  headlen (tail - data): {:#x} ({:d})".format(headlen, headlen))

        if info["truesize"] is not None:
            truesize = info["truesize"]
            if truesize == 2:
                note = " (local TCP pure ACK)"
            else:
                note = ""
            self.out.append("  truesize: {:#x} ({:d}){:s}".format(truesize, truesize, note))
        if info["users"] is not None:
            users = info["users"]
            self.out.append("  users: {:d}".format(users))

        dtor = info["destructor"]
        if dtor:
            p, nm, off = dtor
            if nm:
                self.out.append("  destructor: {:#018x} <{:s}> (at +{:#x})".format(p, nm, off))
            else:
                self.out.append("  destructor: {:#018x} (at +{:#x})".format(p, off))

        self.dump_shared_info(head, end)

        if self.args.dump:
            for line in self.get_data_dump(self.kskb.get_data(layout)):
                self.out.append("  " + line)
        return

    def dump_meta(self, layout):
        source = layout["source"]
        for member in ["len", "data_len", "tail", "end", "head", "data", "truesize", "users", "destructor"]:
            if layout[member] is not None:
                self.quiet_info("offsetof(sk_buff, {:s}): {:#x} ({:s})".format(member, layout[member], source))
        self.quiet_info("sk_buff_data_t: {:s} ({:s})".format("offset" if layout["tail_is_offset"] else "pointer", source))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        skb = args.skb
        self.out = []
        if skb is None:
            self.usage()
            return
        if not is_valid_addr(skb):
            err("Invalid address: {:#x}".format(skb))
            return

        self.kskb = Kernel.skb()
        layout = self.kskb.resolve_layout(skb)
        if layout is None:
            err("Could not resolve the sk_buff layout at {:#x}".format(skb))
            return
        if layout["dwarf_mismatch"]:
            self.quiet_warn("The debug info of struct sk_buff does not match the memory; fall back to heuristic")
        if layout["candidates"] > 1:
            self.quiet_warn("{:d} candidates of the sk_buff layout are found; the first one is used".format(layout["candidates"]))
        if args.meta:
            self.dump_meta(layout)

        self.dump_skb(skb, layout)
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelSocketCommand(GenericCommand, BufferingOutput):
    """Walk from a file descriptor (or a raw struct sock) through socket, sock and its skb queues."""

    _cmdline_ = "ksock"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("sock", metavar="SOCK_ADDR", nargs="?", type=AddressUtil.parse_address,
                        help="a raw `struct sock` address to inspect directly.")
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-F", "--fd", type=lambda x: int(x, 0), default=None,
                        help="filter by this file descriptor number.")
    parser.add_argument("-T", "--task-filter", action="append", type=AddressUtil.parse_address, default=[],
                        help="filter by specific task_struct address.")
    parser.add_argument("-f", "--comm-filter", action="append", type=re.compile, default=[],
                        help="comm string REGEXP filter.")
    parser.add_argument("-l", "--list-skb", action="store_true", help="list each skb address in the queues.")
    parser.add_argument("-d", "--dump", action="store_true",
                        help="hexdump the first 64 bytes of each listed skb's linear packet data (implies --list-skb).")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
        "{0:s} --fd 5",
        "{0:s} -d --fd 5",
        "{0:s} 0xffff888012345000",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "",
        "Simplified socket structure:",
        "",
        "+-file------+  +->+-socket----+  +->+-sock--------------------+",
        "| ...       |  |  | state     |  |  | (sock_common)           |",
        "| private   |--+  | type      |  |  |   skc_family            |",
        "| ...       |     | flags     |  |  |   skc_state             |",
        "+-----------+     | file      |  |  |   skc_prot              |--->struct proto (name)",
        "                  | sk        |--+  | ...                     |",
        "                  | ops       |     | sk_receive_queue        |--->skb->skb->...",
        "                  | ...       |     | sk_write_queue          |--->skb->skb->...",
        "                  +-----------+     | sk_error_queue          |--->skb->skb->...",
        "                                    | sk_state_change         |",
        "                                    | sk_data_ready           |",
        "                                    | sk_write_space          |",
        "                                    | sk_error_report         |",
        "                                    | ...                     |",
        "                                    | sk_destruct             |",
        "                                    +-------------------------+",
        "",
        "The skc_state value is protocol-dependent; TCP_* names are shown only when the",
        "resolved protocol is TCP-like. The offsets are taken from the debug information if available,",
        "otherwise recovered heuristically because struct sock varies with the kernel version and configuration.",
        "The protocol is shown only when its `struct proto` is verified.",
        "",
        "Use `kskb ADDR` to inspect a single sk_buff in detail.",
    ]
    _note_ = "\n".join(_note_)

    def add_meta(self, name, value, source):
        if not self.args.meta:
            return
        values = self.meta.setdefault(name, set())
        item = (value, source)
        if item in values:
            return
        line = "{:s}: {:#x} ({:s})".format(name, value, source)
        if values:
            line += " [{:s}]".format(self.meta_context)
        values.add(item)
        self.out.append(line)
        return

    def dump_queue(self, sk, name, off):
        queue = self.ksocket.get_queue(sk, off)
        head, qlen, skbs = queue["address"], queue["qlen"], queue["skbs"]
        self.out.append("     |- {:<14s} {:#018x} ({:d} skb)".format(name, head, qlen if qlen else 0))
        if self.args.list_skb and skbs:
            for idx, skb in enumerate(skbs):
                self.out.append("     |    [{:d}] {:#018x}".format(idx, skb))
                if self.args.dump:
                    self.dump_skb_data(skb, "     |        ")
            if queue["truncated"]:
                self.out.append("     |    ... (truncated by 4096-skb limit; qlen={:d})".format(qlen))
        return

    def dump_skb_data(self, skb, prefix):
        """Hexdump the first 64 bytes of the linear packet data of an skb (shares kskb's layout resolver)."""
        kskb = Kernel.skb()
        layout = kskb.resolve_layout(skb)
        if layout is None:
            self.out.append("{:s}data: ??? (the sk_buff layout could not be resolved)".format(prefix))
            return
        for line in KernelSkbCommand.get_data_dump(kskb.get_data(layout)):
            self.out.append(prefix + line)
        return

    def dump_sock(self, info, header):
        for name, value, source in info["meta"]:
            self.add_meta(name, value, source)
        if self.args.meta:
            return
        sk, socket, file = info["sock"], info["socket"], info["file"]
        if header:
            self.out.append(header)
        parts = ["sock: {:#018x}".format(sk)]
        if socket:
            parts.insert(0, "socket: {:#018x}".format(socket))
        if file:
            parts.insert(0, "file: {:#018x}".format(file))
        self.out.append("  " + "  ".join(parts))
        self.out.append("  `- sock {:#018x}".format(sk))

        # family / state
        fam = info["family"]
        if fam is not None:
            self.out.append("     |- {:<14s} {:s}".format("family", self.ksocket.AF_FAMILY.get(fam, str(fam))))
            st = info["state"]
            proto_name = (info["protocol_name"] or info["protocol_symbol"] or "").lower()
            if proto_name.startswith(("tcp", "mptcp")):
                state = self.ksocket.SK_STATE.get(st)
            else:
                state = None
            self.out.append("     |- {:<14s} {:s}".format("state", state or "{:#x}".format(st)))

        # socket->{type,state}
        if socket:
            stype, sstate = info["type"], info["socket_state"]
            self.out.append("     |- {:<14s} {:s}".format("type", self.ksocket.SOCK_TYPE.get(stype, str(stype))))
            self.out.append("     |- {:<14s} {:s}".format("socket_state", self.ksocket.SS_STATE.get(sstate, str(sstate))))

        # protocol
        prot, prot_sym, prot_iname = info["protocol"], info["protocol_symbol"], info["protocol_name"]
        if prot is not None:
            if prot_iname:
                proto_disp = prot_iname
            else:
                proto_disp = self.ksocket.PROTO_SYMBOL_RE.sub("", prot_sym).upper() or prot_sym
            if prot_sym:
                annot = " <{:s}>".format(prot_sym)
            else:
                annot = ""
            self.out.append("     |- {:<14s} {:s} ({:#x}{:s})".format("protocol", proto_disp, prot, annot))

        # queues
        queues = info["queues"]
        if not queues:
            self.out.append("     |- {:<14s} ??? (layout could not be resolved)".format("queues"))
        for name in ("receive_queue", "write_queue", "error_queue"):
            if name in queues:
                self.dump_queue(sk, name, queues[name])

        # callbacks
        if info["callbacks"]:
            self.out.append("     `- callbacks")
            for label, p, nm, _, _ in info["callbacks"]:
                if nm:
                    self.out.append("        {:<16s} {:#018x} <{:s}>".format(label, p, nm))
                else:
                    self.out.append("        {:<16s} {:#018x}".format(label, p))
        self.out.append("")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.out = []
        if args.dump:
            args.list_skb = True  # dumping data only makes sense together with the skb listing

        self.ksocket = Kernel.socket()
        self.ksocket.initialize()
        self.meta = {}

        # direct mode: a raw struct sock address was given.
        if args.sock is not None:
            sk = args.sock
            if not is_valid_addr(sk):
                err("Invalid address: {:#x}".format(sk))
                return
            self.meta_context = "sock {:#x}".format(sk)
            info = self.ksocket.get_socket(sk=sk, details=not args.meta)
            self.dump_sock(info, "[direct] struct sock {:#018x}".format(sk))
            for func, line in Kernel.export_meta(self, self.ksocket.meta):
                func(line)
            self.print_output(check_terminal_size=True)
            return

        self.quiet_info("Wait for memory scan")
        socks = self.ksocket.collect_socket_files()
        if socks is None:
            for func, line in Kernel.export_meta(self, self.ksocket.meta):
                func(line)
            return
        if not socks:
            self.quiet_info("Nothing to dump")
            return

        # apply filters
        matched = []
        for s in socks:
            if args.fd is not None and s["fd"] != args.fd:
                continue
            if args.task_filter and s["task"] not in args.task_filter:
                continue
            if args.comm_filter and not any(r.search(s["comm"] or "") for r in args.comm_filter):
                continue
            matched.append(s)
        if not matched:
            self.quiet_info("Nothing to dump")
            return

        for s in matched:
            self.meta_context = "pid {:d}, fd {:d}, file {:#x}".format(s["pid"] or 0, s["fd"], s["file"])
            info = self.ksocket.get_socket(file=s["file"], details=not args.meta)
            if info["socket"] is None:
                self.out.append("[pid {:d}] {:s}  fd {:d}  file {:#018x}  socket: <not found>".format(
                    s["pid"] or 0, s["comm"] or "?", s["fd"], s["file"]))
                self.out.append("")
                continue
            header = "[pid {:d}] {:s}  fd {:d}".format(s["pid"] or 0, s["comm"] or "?", s["fd"])
            self.dump_sock(info, header)

        for func, line in Kernel.export_meta(self, self.ksocket.meta):
            func(line)
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelSyscallsCommand(GenericCommand, BufferingOutput):
    """Display syscall_table entries."""

    _cmdline_ = "ksyscalls"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"
    _aliases_ = ["kst", "syscall-table-view"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="REGEXP syscall name filter.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} --filter write",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "On x86, Linux v6.9 and later dispatch syscalls via switch statements.",
        "This command shows a table for readability; remaining syscall tables are used for tracing, not dispatch.",
    ]
    _note_ = "\n".join(_note_)

    @staticmethod
    def is_plausible_address(addr):
        """Check an address without issuing a remote memory read."""
        if not isinstance(addr, int) or not 0 <= addr < AddressUtil.get_vmem_end():
            return False
        if is_arm32():
            return bool(addr & 1) or addr % 4 == 0
        if is_arm64():
            return addr % 4 == 0
        return True

    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def get_ni_syscalls(self, abi):
        ni_syscall_names = {
            "x86": ["__ia32_sys_ni_syscall", "sys_ni_syscall"],
            "x86_64": ["__x64_sys_ni_syscall", "sys_ni_syscall"],
            "x86_32": ["__ia32_sys_ni_syscall", "sys_ni_syscall"],
            "x86_x32": ["__x64_sys_ni_syscall", "sys_ni_syscall"],
            "arm64": ["__arm64_sys_ni_syscall", "sys_ni_syscall"],
            "arm64_32": ["__arm64_sys_ni_syscall", "sys_ni_syscall"],
        }.get(abi, ["sys_ni_syscall"])
        ni_syscalls = {}
        for name in ni_syscall_names:
            address = Ksym.get_addr(name)
            if address is not None:
                ni_syscalls[address] = name
        return ni_syscalls

    @staticmethod
    def get_insn_pair(addr):
        try:
            if is_arm32() and Config.get("context_code.use_capstone"):
                read_memory(addr & ~1, 1)
                if addr & 1:
                    mode = "THUMB"
                else:
                    mode = "ARM"
                insns = list(Disasm.capstone_disassemble(addr, 2, mode=mode))
            else:
                insns = list(Disasm.gef_disassemble(addr, 2))
        except (gdb.error, gdb.MemoryError):
            return None, None
        if len(insns) < 2:
            return None, None
        return insns[0], insns[1]

    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def analyze_syscall_function(self, syscall_function_addr):
        try:
            if is_arm32():
                symbol_addr = syscall_function_addr & ~1
            else:
                symbol_addr = syscall_function_addr
            symbol = Symbol.format(symbol_addr, missing="NO_SYMBOL")
        except (gdb.error, gdb.MemoryError):
            return None
        if "+" in symbol:
            return None

        insn, insn2 = self.get_insn_pair(syscall_function_addr)
        if insn is None or insn2 is None:
            return None

        if is_x86():
            prefix_mnemonics = ["endbr64", "endbr32"]
            call_mnemonics = ["call"]
        elif is_arm64():
            prefix_mnemonics = ["bti"]
            call_mnemonics = ["bl"]
        elif is_arm32():
            prefix_mnemonics = []
            call_mnemonics = ["bl", "blx"]
        else:
            prefix_mnemonics = []
            call_mnemonics = []

        # Skip control-flow instrumentation before the actual syscall body.
        if insn.mnemonic in prefix_mnemonics:
            insn, insn2 = self.get_insn_pair(insn.address + len(insn.opcodes))
        while insn and insn2 and insn.mnemonic in call_mnemonics:
            insn, insn2 = self.get_insn_pair(insn.address + len(insn.opcodes))
        # CONFIG_FRAME_POINTER saves the frame pointer first (push rbp; mov rax, -ENOSYS; mov rbp, rsp; pop rbp; ret)
        if insn and is_x86() and insn.mnemonic == "push" and insn.operands[-1] in ("rbp", "ebp"):
            insn, insn2 = self.get_insn_pair(insn.address + len(insn.opcodes))

        if insn is None or insn2 is None:
            return None

        # check if the target system call is disabled
        is_valid = True
        if is_x86():
            if is_x86_64():
                err = "0xffffffffffffffda"
            else:
                err = "0xffffffda"
            if len(insn.operands) == 2 and insn.operands[-1] == err:
                while insn2 and (insn2.mnemonic in ("pop", "leave") or insn2.mnemonic == "mov" and insn2.operands[-1] in ("rsp", "esp")):
                    insn2 = self.get_insn_pair(insn2.address + len(insn2.opcodes))[0]
                if insn2 is None:
                    pass
                elif insn2.mnemonic == "ret":
                    is_valid = False
                elif insn2.mnemonic == "jmp":
                    try:
                        insn3 = get_insn(AddressUtil.parse_address(insn2.operands[-1]))
                        if insn3 and insn3.mnemonic == "ret":
                            is_valid = False
                    except (gdb.error, gdb.MemoryError, ValueError):
                        pass
        elif is_arm64():
            if len(insn.operands) == 2 and insn.operands[-1].split()[0] == "#0xffffffffffffffda":
                is_valid = False
            elif len(insn.operands) == 3 and insn.operands[-1] == "// #-38":
                is_valid = False
        return symbol, is_valid

    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    def scan_syscall_function_addrs(self, sys_call_table_addr, count):
        try:
            data = read_memory(sys_call_table_addr, count * runtime.current_arch.ptrsize)
            candidates = slice_unpack(data, runtime.current_arch.ptrsize)
        except gdb.MemoryError:
            candidates = []
            for i in range(count):
                try:
                    addr = sys_call_table_addr + i * runtime.current_arch.ptrsize
                    candidates.append(read_int_from_memory(addr))
                except gdb.MemoryError:
                    break

        function_addrs = []
        for syscall_function_addr in candidates:
            if not self.is_plausible_address(syscall_function_addr):
                break
            try:
                if is_arm32():
                    symbol_addr = syscall_function_addr & ~1
                else:
                    symbol_addr = syscall_function_addr
                symbol = Symbol.format(symbol_addr, missing="NO_SYMBOL")
            except (gdb.error, gdb.MemoryError):
                break
            if "+" in symbol:
                break
            if symbol == "<NO_SYMBOL>":
                insn, insn2 = self.get_insn_pair(syscall_function_addr)
                if insn is None or insn2 is None:
                    break
            function_addrs.append(syscall_function_addr)
        return tuple(function_addrs)

    @Cache.cache_this_session(per_inferior=True, until_new_objfile=True)
    @switch_to_intel_syntax
    def parse_syscall_table(self, sys_call_table_addr, indices=None):
        table = []
        if indices is None:
            index_iter = itertools.count()
        else:
            index_iter = indices
        for i in index_iter:
            addr = sys_call_table_addr + i * runtime.current_arch.ptrsize
            syscall_function_addr = read_int_from_memory(addr, safe=True)
            if syscall_function_addr is None:
                if indices is None:
                    break
                continue
            if not self.is_plausible_address(syscall_function_addr):
                if indices is None:
                    break
                continue

            parsed = self.analyze_syscall_function(syscall_function_addr)
            if parsed is None:
                if indices is None:
                    break
                continue
            symbol, is_valid = parsed
            table.append([i, addr, syscall_function_addr, symbol, is_valid])
        return table

    def get_filtered_indices(self, syscall_list, nr_base):
        all_indices = []
        filtered_indices = []
        for nr, entry in syscall_list.nr_table.items():
            i = nr - nr_base
            # x86-64 definitions contain both native and x32 numbers.
            if not 0 <= i < 0x10000:
                continue
            all_indices.append(i)
            if self.args.filter and GefUtil.matches_regex(entry.name, self.args.filter):
                filtered_indices.append(i)
        return tuple(sorted(all_indices)), tuple(sorted(filtered_indices))

    def dump_one_syscall_table(self, title, abi, address_getter, syscall_list, nr_base=0):
        # check syscall_list
        if syscall_list is None:
            self.quiet_add_out(titlify(title))
            self.quiet_add_out("{} {}".format(Color.colorify("[!]", "bold red"), "Could not find the syscall table"))
            return

        # filter exists check
        selection = None
        if self.args.filter:
            selection = self.get_filtered_indices(syscall_list, nr_base)
            _, filtered_indices = selection
            if not filtered_indices:
                return

        # check sys_call_table_addr
        sys_call_table_addr = address_getter()
        if sys_call_table_addr is None:
            self.quiet_add_out(titlify(title))
            removed_table = {
                "x86_32": ("ia32_sys_call_table", "ia32_sys_call"),
                "x86_x32": ("x32_sys_call_table", "x32_sys_call"),
            }.get(abi)
            kversion = Kernel.version()
            if removed_table and kversion and "6.6.26" <= kversion:
                self.quiet_add_out("{:s} is removed from 6.6.26.".format(removed_table[0]))
                if Ksym.get_addr(removed_table[1]):
                    self.quiet_add_out("each entry is embedded in `{:s}()` as call instruction.".format(removed_table[1]))
                else:
                    self.quiet_add_out("`{:s}()` is unavailable; the corresponding ABI may be disabled.".format(removed_table[1]))
            else:
                self.quiet_add_out("{} {}".format(Color.colorify("[!]", "bold red"), "Could not find the symbol"))
            return

        # parse with filtering
        if selection is not None:
            all_indices, filtered_indices = selection
            function_addrs = self.scan_syscall_function_addrs(sys_call_table_addr, max(all_indices) + 1)
            filtered_indices = tuple(i for i in filtered_indices if i < len(function_addrs))
            table = self.parse_syscall_table(sys_call_table_addr, filtered_indices)
        else:
            table = self.parse_syscall_table(sys_call_table_addr)
            function_addrs = tuple(row[2] for row in table)
        if selection is not None and not table:
            return

        self.quiet_add_out(titlify(title))
        ni_syscalls = self.get_ni_syscalls(abi)

        # print legend
        if not self.args.quiet:
            fmt = "{:8s} {:5s} {:7s} {:30s} {:18s} {:18s} {:s}"
            legend = ["ABI", "Index", "IsValid", "Syscall Name", "Table Address", "Function Address", "Symbol"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # for duplication check
        seen_count = {}
        for syscall_function_addr in function_addrs:
            seen_count[syscall_function_addr] = seen_count.get(syscall_function_addr, 0) + 1

        # print
        for i, addr, syscall_function_addr, symbol, is_valid in table:
            if is_arm32():
                symbol_addr = syscall_function_addr & ~1
            else:
                symbol_addr = syscall_function_addr
            if symbol_addr in ni_syscalls:
                symbol = "<{:s}>".format(ni_syscalls[symbol_addr])
            nr = nr_base + i
            if nr in syscall_list.nr_table:
                expected_name = syscall_list.nr_table[nr].name
            else:
                expected_name = "<UNDEFINED_IN_THIS_ARCH>"

            fmt = "{:8s} [{:03d}] {:7s} {:30s} {:#018x} {:#018x} {:s}"
            if seen_count[syscall_function_addr] == 1 and is_valid: # valid entry
                msg = fmt.format(abi, i, "valid", expected_name, addr, syscall_function_addr, symbol)
            if seen_count[syscall_function_addr] > 1 or not is_valid: # invalid entry
                msg = fmt.format(abi, i, "invalid", expected_name, addr, syscall_function_addr, symbol)
                msg = Color.grayify(msg)
            self.out.append(msg)
        return

    def dump_syscall_tables(self):
        if is_x86_32():
            self.dump_one_syscall_table(
                "sys_call_table (x86)", "x86", KernelAddressHeuristicFinder.get_sys_call_table_x86,
                Syscall.get_syscall_table("X86", "N32"),
            )

        elif is_x86_64():
            self.dump_one_syscall_table(
                "sys_call_table (x64)", "x86_64", KernelAddressHeuristicFinder.get_sys_call_table_x64,
                Syscall.get_syscall_table("X86", "64"),
            )
            self.dump_one_syscall_table(
                "ia32_sys_call_table", "x86_32", KernelAddressHeuristicFinder.get_sys_call_table_x86,
                Syscall.get_syscall_table("X86", "32"),
            )
            self.dump_one_syscall_table(
                "x32_sys_call_table", "x86_x32", KernelAddressHeuristicFinder.get_sys_call_table_x32,
                Syscall.get_syscall_table("X86", "64"), nr_base=0x4000_0000,
            )

        elif is_arm32():
            self.dump_one_syscall_table(
                "sys_call_table (arm32)", "arm32", KernelAddressHeuristicFinder.get_sys_call_table_arm32,
                Syscall.get_syscall_table("ARM", "N32"),
            )

        elif is_arm64():
            self.dump_one_syscall_table(
                "sys_call_table (arm64)", "arm64", KernelAddressHeuristicFinder.get_sys_call_table_arm64,
                Syscall.get_syscall_table("ARM64", "ARM"),
            )
            self.dump_one_syscall_table(
                "compat_sys_call_table (arm32)", "arm64_32", KernelAddressHeuristicFinder.get_sys_call_table_arm64_compat,
                Syscall.get_syscall_table("ARM", "32"),
            )
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.out = []
        self.dump_syscall_tables()
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelVfsCommand(GenericCommand, BufferingOutput):
    """Display the VFS object graph of a file descriptor or VFS object."""

    _cmdline_ = "kvfs"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("address", nargs="?", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the address of struct file, dentry or inode.")
    parser.add_argument("-t", "--type", choices=["auto", "file", "dentry", "inode"], default="auto",
                        help="the type of ADDRESS. (default: %(default)s)")
    parser.add_argument("-p", "--pid", type=int, help="select a file descriptor from this pid.")
    parser.add_argument("-f", "--fd", type=int, help="select this file descriptor (requires --pid).")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} --pid 1337 --fd 3",
        "{0:s} 0xffff888003b0a000",
        "{0:s} --type inode 0xffff888003b0a000",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "",
        "ADDRESS is detected as struct file, dentry or inode unless --type is specified.",
        "The filesystem type and mount device are best-effort when debug information is unavailable.",
        "",
        "Simplified VFS object graph:",
        "",
        "+-file-----+",
        "| ...      |",
        "| f_path   |",
        "|   mnt    |    +-dentry--+",
        "|   dentry |--->| d_name  |    +-inode-+",
        "| ...      |    | d_inode |--->| i_ino |    +-super_block-+",
        "+----------+    +---------+    | i_sb  |--->| s_type      |",
        "                               +-------+    | s_dev       |",
        "                                            +-------------+",
    ]
    _note_ = "\n".join(_note_)

    FILE_TYPES = {
        0o010000: "p",
        0o020000: "c",
        0o040000: "d",
        0o060000: "b",
        0o100000: "-",
        0o120000: "l",
        0o140000: "s",
    }

    def initialize(self):
        self.meta = []

        kversion = Kernel.version()
        if kversion is None:
            self.meta.append((self.quiet_err, "Could not find Linux kernel"))
            return None

        self.task_command = None
        self.kpath = Kernel.path()

        fd_mode = self.args.pid is not None or self.args.fd is not None
        if fd_mode:
            self.task_command = Kernel.task()
            task_ready = self.task_command.initialize(files=True, threads=True)
            self.meta.extend(Kernel.export_meta(self, self.task_command.meta))
            if not task_ready:
                self.task_command = None
            if self.task_command is None:
                return None
            self.kpath = Kernel.path()

        kind = self.args.type
        address = self.args.address
        if address is not None and not fd_mode:
            try:
                if kind == "inode":
                    if not self.kpath.initialize_inode_offsets(address):
                        self.meta.append((self.quiet_err, "Could not resolve the inode layout"))
                        return None
                elif kind == "file":
                    if not self.kpath.initialize(file=address):
                        self.meta.append((self.quiet_err, "Could not resolve the file layout"))
                        return None
                elif kind == "dentry":
                    if not self.kpath.initialize(dentry=address):
                        self.meta.append((self.quiet_err, "Could not resolve the dentry layout"))
                        return None
            except (gdb.MemoryError, OverflowError, RuntimeError):
                self.meta.append((self.quiet_err, "Could not resolve the VFS object layout"))
                return None

        # KernelFileSystem adds the filesystem name and mount source. It relies on struct
        # mount, introduced in v3.3, so older kernels use the stable super_block fields below.
        self.kfs = None
        if "3.3" <= kversion and kind != "inode":
            kfs = Kernel.file_system()
            if kfs.initialize():
                self.kfs = kfs
            self.meta.extend(Kernel.export_meta(self, kfs.meta, demote_err=True))

        if address is not None and not fd_mode and kind == "auto" and not self.kpath.initialized:
            try:
                if not self.kpath.initialize(file=address) and not self.kpath.initialize(dentry=address):
                    if not self.kpath.initialize_inode_offsets(address) or not self.is_inode(address):
                        self.meta.append((self.quiet_err, "Could not resolve the VFS object layout"))
                        return None
            except (gdb.MemoryError, OverflowError, RuntimeError):
                self.meta.append((self.quiet_err, "Could not resolve the VFS object layout"))
                return None

        if address is not None and not fd_mode and kind != "inode" and not self.kpath.initialized:
            self.meta.append((self.quiet_err, "Could not resolve the VFS object layout"))
            return None
        if fd_mode and not self.kpath.initialized:
            self.meta.append((self.quiet_err, "Could not resolve the VFS object layout"))
            return None

        self.meta.extend(Kernel.export_meta(self, self.kpath.meta))

        self.offset_s_dev = runtime.current_arch.ptrsize * 2
        # loff_t uses 8-byte alignment on ARM32, unlike the i386 ABI.
        loff_t_align = 4
        if is_64bit() or is_arm32():
            loff_t_align = 8
        s_maxbytes_end = runtime.current_arch.ptrsize * 3 + 8
        offset_s_maxbytes = align(s_maxbytes_end, loff_t_align)
        self.offset_s_type = offset_s_maxbytes + 8
        offset_s_dev = GefUtil.offsetof("super_block", "s_dev")
        offset_s_type = GefUtil.offsetof("super_block", "s_type")
        if self.kfs is not None:
            if self.kfs.offset_s_type is not None:
                self.offset_s_type = self.kfs.offset_s_type
            self.offset_s_dev = self.kfs.offset_s_dev
        if offset_s_dev is not None:
            self.offset_s_dev = offset_s_dev
        if offset_s_type is not None:
            self.offset_s_type = offset_s_type
        self.meta.append((self.quiet_info, "offsetof(super_block, s_dev): {:#x}".format(self.offset_s_dev)))
        self.meta.append((self.quiet_info, "offsetof(super_block, s_type): {:#x}".format(self.offset_s_type)))
        return True

    def get_task_by_pid(self, pid):
        task_command = self.task_command
        task_addrs = KernelTask.get_task_list(task_command.init_task, task_command.offset_tasks)
        if task_command.enabled.get("threads"):
            task_addrs = task_command.add_lwp_task(task_addrs)
        for task in task_addrs:
            if read_int32_from_memory(task + task_command.offset_pid) == pid:
                return task
        return None

    def get_file_by_fd(self, pid, fd):
        if fd < 0:
            self.quiet_err("FD must not be negative")
            return None
        if self.task_command.offset_files is None or self.task_command.offset_fdt is None:
            self.quiet_err("Could not find task_struct->files->fdt")
            return None
        task = self.get_task_by_pid(pid)
        if task is None:
            self.quiet_err("Could not find the task of pid {:d}".format(pid))
            return None
        try:
            files = read_int_from_memory(task + self.task_command.offset_files)
            fdt = read_int_from_memory(files + self.task_command.offset_fdt)
            max_fds = read_int32_from_memory(fdt)
            if fd >= max_fds:
                self.quiet_err("FD {:d} is outside the fdtable (max_fds={:d})".format(fd, max_fds))
                return None
            array = read_int_from_memory(fdt + runtime.current_arch.ptrsize)
            file = read_int_from_memory(array + runtime.current_arch.ptrsize * fd)
        except (gdb.MemoryError, OverflowError):
            self.quiet_err("Could not read fd {:d} of pid {:d}".format(fd, pid))
            return None
        if not is_valid_addr(file):
            self.quiet_err("FD {:d} of pid {:d} is not open".format(fd, pid))
            return None
        return file

    def is_inode(self, inode):
        if not is_valid_addr(inode) or inode & (runtime.current_arch.ptrsize - 1):
            return False
        try:
            mode = read_int16_from_memory(inode + self.kpath.offset_i_mode)
            super_block = read_int_from_memory(inode + self.kpath.offset_i_sb)
            read_int_from_memory(inode + self.kpath.offset_i_ino)
        except (gdb.MemoryError, OverflowError):
            return False
        return mode & 0o170000 in self.FILE_TYPES and is_valid_addr(super_block)

    def is_file(self, file):
        kpath = self.kpath
        try:
            if kpath.offset_file_mnt is None and not kpath.initialize_file_offsets(file):
                return False
            vfsmnt = read_int_from_memory(file + kpath.offset_file_mnt)
            dentry = read_int_from_memory(file + kpath.offset_file_dentry)
        except (gdb.MemoryError, OverflowError, RuntimeError):
            return False
        return kpath.is_vfsmount(vfsmnt) and kpath.is_dentry(dentry)

    def detect_type(self, address):
        if self.kpath.initialized and self.is_file(address):
            return "file"
        if self.kpath.initialized and self.kpath.is_dentry(address):
            return "dentry"
        if self.is_inode(address):
            return "inode"
        return None

    @staticmethod
    def mode_string(mode):
        chars = []
        for shift in (6, 3, 0):
            bits = (mode >> shift) & 7
            chars.extend(("r" if bits & 4 else "-", "w" if bits & 2 else "-", "x" if bits & 1 else "-"))
        if mode & 0o4000:
            if chars[2] == "x":
                chars[2] = "s"
            else:
                chars[2] = "S"
        if mode & 0o2000:
            if chars[5] == "x":
                chars[5] = "s"
            else:
                chars[5] = "S"
        if mode & 0o1000:
            if chars[8] == "x":
                chars[8] = "t"
            else:
                chars[8] = "T"
        return KernelVfsCommand.FILE_TYPES.get(mode & 0o170000, "?") + "".join(chars)

    def get_fstype_name(self, super_block):
        if self.kfs is not None:
            name = self.kfs.get_fstype_name(super_block)
            if name:
                return name
        try:
            fst = read_int_from_memory(super_block + self.offset_s_type)
            if not is_valid_addr(fst):
                return "???"
            name_addr = read_int_from_memory(fst)
            if not is_valid_addr(name_addr):
                return "???"
            return read_cstring_from_memory(name_addr, max_length=64, safe=True) or "???"
        except (gdb.MemoryError, OverflowError):
            return "???"

    def dump_inode(self, inode, prefix, mount=None):
        kpath = self.kpath
        mode = read_int16_from_memory(inode + kpath.offset_i_mode)
        ino = read_int_from_memory(inode + kpath.offset_i_ino)
        super_block = read_int_from_memory(inode + kpath.offset_i_sb)
        dev = read_int32_from_memory(super_block + self.offset_s_dev)
        major = dev >> 20
        minor = dev & ((1 << 20) - 1)
        fstype = self.get_fstype_name(super_block)
        if self.kfs is not None and mount is not None:
            devname = self.kfs.get_dev_name(mount)
        else:
            devname = None

        self.out.append(prefix + "struct inode {:#018x}".format(inode))
        self.out.append(prefix + "|- i_ino {:d} ({:#x})".format(ino, ino))
        self.out.append(prefix + "|- i_mode 0{:06o} ({:s})".format(mode, self.mode_string(mode)))
        self.out.append(prefix + "`- struct super_block {:#018x}".format(super_block))
        self.out.append(prefix + "   |- filesystem {:s}".format(fstype))
        self.out.append(prefix + "   |- s_dev {:d}:{:d} ({:#x})".format(major, minor, dev))
        self.out.append(prefix + "   `- mount source {:s}".format(devname or "???"))
        return

    def dump_dentry(self, dentry, prefix="", mount=None, path=None):
        kpath = self.kpath
        inode = read_int_from_memory(dentry + kpath.offset_d_inode)
        name = kpath.get_dentry_name(dentry, "???")
        if path is None:
            path = kpath.decorate_pseudo_path(kpath.dentry_path(dentry), dentry) or "???"
        self.out.append(prefix + "struct dentry {:#018x}".format(dentry))
        self.out.append(prefix + "|- d_name {!r}".format(name))
        self.out.append(prefix + "|- path {!r}".format(path))
        if not self.is_inode(inode):
            self.out.append(prefix + "`- d_inode {:#018x} (unreadable or negative dentry)".format(inode))
            return
        self.out.append(prefix + "`- d_inode")
        self.dump_inode(inode, prefix + "   ", mount)
        return

    def dump_file(self, file):
        kpath = self.kpath
        vfsmnt = read_int_from_memory(file + kpath.offset_file_mnt)
        dentry = read_int_from_memory(file + kpath.offset_file_dentry)
        mount = vfsmnt - kpath.offset_mount_mnt
        path = kpath.get_file_path(file) or "???"
        self.out.append("struct file {:#018x}".format(file))
        self.out.append("`- struct path f_path {:#018x}".format(file + kpath.offset_file_mnt))
        self.out.append("   |- struct vfsmount {:#018x}".format(vfsmnt))
        self.out.append("   `- dentry")
        self.dump_dentry(dentry, "      ", mount, path)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        ret = self.initialize()
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret or args.meta:
            return

        fd_mode = args.pid is not None or args.fd is not None
        if fd_mode:
            if args.pid is None or args.fd is None:
                err("--pid and --fd must be used together")
                return
            if args.address is not None:
                err("ADDRESS cannot be used with --pid/--fd")
                return
            address = self.get_file_by_fd(args.pid, args.fd)
            if address is None:
                return
            kind = "file"
            self.quiet_info("pid {:d}, fd {:d}: struct file {:#x}".format(args.pid, args.fd, address))
        else:
            if args.address is None:
                err("Specify ADDRESS or both --pid and --fd")
                return
            address = args.address
            if not is_valid_addr(address):
                err("Unreadable address: {:#x}".format(address))
                return
            kind = args.type
            if kind == "auto":
                kind = self.detect_type(address)
                if kind is None:
                    err("Could not tell what {:#x} points to; specify it with --type".format(address))
                    return
            self.quiet_info("Interpreted ADDRESS as struct {:s}".format(kind))

        self.out = []
        try:
            if kind == "file" and self.is_file(address):
                self.dump_file(address)
            elif kind == "dentry" and self.kpath.is_dentry(address):
                self.dump_dentry(address)
            elif kind == "inode" and self.is_inode(address):
                self.dump_inode(address, "")
            else:
                err("Could not interpret {:#x} as struct {:s}".format(address, kind))
                return
        except (gdb.MemoryError, OverflowError):
            err("Memory read error while walking the VFS graph")
            return
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelWorkqueueCommand(GenericCommand, BufferingOutput):
    """Dump workqueue items and inspect embedded work_struct objects."""

    _cmdline_ = "kworkqueue"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("--object", type=AddressUtil.parse_address,
                        help="the address of the object to inspect (e.g. the head of a heap object), "
                             "scanned for an embedded work_struct/delayed_work.")
    parser.add_argument("--size", type=AddressUtil.parse_address, default=None,
                        help="the size of the range scanned by --object (default: 0x1000).")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} --object 0xffff888012340000",
        "{0:s} --object 0xffff888012340000 --size 0x400",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified workqueue structures (`==>` shows where each column comes from):",
        "",
        "                   +-workqueue_struct-+",
        "+-workqueues-+     | pwqs             |--+",
        "| list       |<--->| list             |<--->...",
        "+------------+     | name             |  |      ==> `queue`",
        "                   | ...              |  |",
        "                   +------------------+  |",
        "                     ^                   |",
        "                     |                   |",
        "                     |                   v",
        "                     |       +-pool_workqueue-+",
        "                     |       | pool           |---+",
        "                     +-------| wq             |   |",
        "                             | inactive_works |   |  ==> state `inactive`",
        "                             +----------------+   |",
        "                               ^                  |",
        "       work_struct.data -------+                  |",
        "       & WORK_STRUCT_PWQ_MASK (pwq)               |",
        "                    +-work_struct-+               v",
        "                    | data        |         +-worker_pool-+",
        "                    | entry       |-------->| worklist    |  ==> state `pending`",
        "                    | func        |         | busy_hash   |  ==> state `running`",
        "                    +-------------+         | cpu         |  ==> `cpu`",
        "                      ^                     +-------------+",
        "                      |",
        "                    +-delayed_work-+",
        "                    | work         |",
        "                    | timer        |<--- per-cpu timer wheel  ==> state `delayed`",
        "                    | wq           |",
        "                    +--------------+",
        "",
        "- `running` means the work is held in `worker.current_work`.",
        "- When `WORK_STRUCT_PWQ` is set, `queue` and `cpu` are decoded from `work_struct.data`; off-queue work uses it differently.",
        "- For `delayed` work, `cpu` is the CPU whose timer wheel holds the timer.",
        "- `--object` scans `[object, object+size)` for initialized `work_struct`s, including unqueued `idle` work.",
        "  `delayed_work` is recognized by its `delayed_work_timer_fn` timer when available.",
        "  It does not need the workqueue list, though `queue` is then unknown.",
        "- The running work is found from `worker_pool.busy_hash` (`global_cwq` before v3.6).",
        "- `delayed` needs the `ktimer` layout; other states are listed without it.",
        "- The member offsets come from the debug information (vmlinux or `ktypes-load`) when available.",
    ]
    _note_ = "\n".join(_note_)

    BUSY_WORKER_HASH_SIZE = 64

    def is_callback(self, address):
        """Return True if `address` is the entry of a function in the kernel or module text."""
        if not address or not is_valid_addr(address):
            return False
        if self.klayout.text_base <= address < self.klayout.text_end:
            # a work function is a function entry, not an address in the middle of one
            return not self.kallsyms_text or address in self.kallsyms_text
        # the type of kallsyms alone is not enough (e.g., `workqueues` is `t` in some v6.14+ builds)
        return any(start <= address < end for start, end in self.get_module_text_ranges())

    def get_module_text_ranges(self):
        if self.module_text_ranges is None:
            self.module_text_ranges = [(start, end) for start, end, _module, _name in Kernel.modules().get_text_ranges()]
        return self.module_text_ranges

    def read_work(self, work, check_function=True):
        try:
            data = read_int_from_memory(work + self.offset_work_data)
            function = read_int_from_memory(work + self.offset_work_func)
            if check_function and not self.is_callback(function):
                return None
            entry = work + self.offset_work_entry
            next_entry = read_int_from_memory(entry)
            prev_entry = read_int_from_memory(entry + runtime.current_arch.ptrsize)
        except gdb.MemoryError:
            return None
        return {
            "work": work,
            "data": data,
            "function": function,
            "next": next_entry,
            "prev": prev_entry,
        }

    def find_name_offset(self, workqueues):

        def has_names(offset, is_pointer):
            # The window also covers the following objects, where SLAB places the older `events`,
            # so the offset must give a name to every workqueue.
            self.offset_wq_name = offset
            self.name_is_pointer = is_pointer
            return all(self.read_workqueue_name(workqueue) != "???" for workqueue in workqueues)

        offset = GefUtil.offsetof("struct workqueue_struct", "name")
        if offset is not None:
            self.name_is_pointer = False
            return offset

        if Endian.is_little_endian():
            byteorder = "little"
        else:
            byteorder = "big"
        for workqueue in workqueues:
            data = read_memory(workqueue, 0x800, safe=True)
            if data is None:
                continue
            offset = data.find(b"events\x00")
            if offset >= 0 and has_names(offset, False):
                self.system_wq = workqueue
                return offset

            for offset in range(0, len(data) - runtime.current_arch.ptrsize + 1, runtime.current_arch.ptrsize):
                name_address = int.from_bytes(data[offset:offset + runtime.current_arch.ptrsize], byteorder)
                if not is_valid_addr(name_address):
                    continue
                if read_cstring_from_memory(name_address, safe=True) == "events" and has_names(offset, True):
                    self.system_wq = workqueue
                    return offset
        return None

    def read_workqueue_name(self, workqueue):
        if self.offset_wq_name is None:
            return "???"
        try:
            address = workqueue + self.offset_wq_name
            if self.name_is_pointer:
                address = read_int_from_memory(address)
            name = read_cstring_from_memory(address)
            if name and len(name) <= 256 and name.isprintable():
                return name
        except gdb.MemoryError:
            pass
        return "???"

    def find_pwq_from_node(self, node, workqueue):
        if self.offset_pwqs_node is not None:
            candidate = AddressUtil.normalize_address(node - self.offset_pwqs_node)
        else:
            # pool_workqueue is aligned to 1 << WORK_STRUCT_PWQ_SHIFT (at least 256) for work_struct.data,
            # and pwqs_node is within the first 256 bytes
            candidate = node & ~0xff
        owner = read_int_from_memory(candidate + self.offset_pwq_wq, safe=True)
        pool = read_int_from_memory(candidate + self.offset_pwq_pool, safe=True)
        if owner != workqueue or not pool or not is_valid_addr(pool):
            return None
        return candidate

    def work_belongs_to_pool(self, work, pool):
        """Return True if `work` is a queued work whose pool_workqueue belongs to `pool`."""
        parsed = self.read_work(work)
        if parsed is None or not parsed["data"] & 1: # WORK_STRUCT_PENDING
            return False
        if not parsed["data"] & 4: # WORK_STRUCT_PWQ (WORK_STRUCT_CWQ before v3.9)
            return False
        for mask in (0xff, 0x1ff):
            pwq = parsed["data"] & ~mask
            if read_int_from_memory(pwq + self.offset_pwq_pool, safe=True) == pool:
                return True
        return False

    def is_worklist(self, head, pool):
        """Return True if `head` is an empty list or a list of the works queued to `pool`."""
        try:
            if not is_double_link_list(head):
                return False
        except (gdb.MemoryError, OverflowError):
            return False
        works = list(itertools.islice(KernelListHead(head, self.offset_work_entry).iter_entries(), 8))
        return all(self.work_belongs_to_pool(work, pool) for work in works)

    def find_worklist(self, pool):
        if self.offset_pool_worklist is not None:
            return pool + self.offset_pool_worklist

        if self.worklist_offset is None:
            # worklist is the first list_head of worker_pool (global_cwq before v3.6) in every version.
            # It is verified by the works linked there, since the idle workers also form a list.
            pools = sorted({unit["pool"] for unit in self.units})
            for offset in range(0, 0x180, runtime.current_arch.ptrsize):
                if pools and all(self.is_worklist(p + offset, p) for p in pools):
                    self.worklist_offset = offset
                    self.meta.append((self.quiet_info, "offsetof(worker_pool, worklist): {:#x} (heuristic)".format(offset)))
                    break
            else:
                self.worklist_offset = False
                self.meta.append((self.quiet_warn, "offsetof(worker_pool, worklist): Not found"))
        if self.worklist_offset is False:
            return None
        return pool + self.worklist_offset

    def find_pool_cpu(self, pool, worklist):
        if self.offset_pool_cpu is not None:
            return read_int32_from_memory(pool + self.offset_pool_cpu, signed=True, safe=True)

        # a per-cpu pool is in the per-cpu area of its cpu; an unbound one is not
        resolved = Kernel.per_cpu().resolve(pool)
        if resolved is not None and Kernel.per_cpu().is_smp:
            return resolved[0]

        end = worklist - pool
        if self.kversion < "3.9":
            return self.pool_cpu_hints.get(pool)

        # v3.9 has cpu, id and flags before worklist; v3.10 adds node after cpu
        if self.kversion < "3.10":
            field_count = 3
        else:
            field_count = 4
        ptrsize = runtime.current_arch.ptrsize
        for offset in range(0, end, 4):
            tail = end - offset - field_count * 4
            if tail not in (0, ptrsize, align(ptrsize + 4, ptrsize), align(ptrsize + 8, ptrsize)):
                continue
            try:
                values = [read_int32_from_memory(pool + offset + 4 * i, signed=True)
                          for i in range(field_count)]
            except gdb.MemoryError:
                continue
            cpu = values[0]
            if field_count == 4:
                node = values[1]
            else:
                node = -1
            pool_id = values[-2]
            flags = values[-1] & 0xffff_ffff
            if (-1 <= cpu < self.max_cpu and -1 <= node < 0x1_0000 and
                    0 <= pool_id < 0x10_0000 and flags < 0x10_0000):
                return cpu
        return None

    def collect_old_units(self, workqueues):
        percpu = Kernel.per_cpu()

        units = []
        for workqueue in workqueues:
            try:
                flags = read_int32_from_memory(workqueue + self.offset_wq_flags)
                base = read_int_from_memory(workqueue + self.offset_wq_cpu_wq)
            except gdb.MemoryError:
                self.incomplete.append("workqueue {:#x} is unreadable".format(workqueue))
                continue
            # a WQ_UNBOUND workqueue holds one shared pool instead of a per-cpu one
            for cpu, unit in enumerate([base] if flags & 2 else percpu.addrs_of(base)):
                try:
                    if read_int_from_memory(unit + self.offset_pwq_wq) != workqueue:
                        continue
                    pool = read_int_from_memory(unit + self.offset_pwq_pool)
                except gdb.MemoryError:
                    continue
                if not is_valid_addr(pool):
                    continue
                if flags & 2:
                    cpu_number = -1
                else:
                    cpu_number = cpu
                units.append({
                    "address": unit,
                    "wq": workqueue,
                    "name": self.read_workqueue_name(workqueue),
                    "pool": pool,
                    "cpu": cpu_number,
                })
                self.pool_cpu_hints.setdefault(pool, cpu_number)
        return units

    def collect_new_units(self, workqueues):
        units = []
        for workqueue in workqueues:
            head = workqueue + self.offset_wq_pwqs
            lh = KernelListHead(head)
            for node in lh.iter_entries():
                pwq = self.find_pwq_from_node(node, workqueue)
                if pwq is None:
                    continue
                pool = read_int_from_memory(pwq + self.offset_pwq_pool, safe=True)
                if pool is None:
                    continue
                units.append({
                    "address": pwq,
                    "wq": workqueue,
                    "name": self.read_workqueue_name(workqueue),
                    "pool": pool,
                    "cpu": None,
                })
            if lh.broken:
                self.incomplete.append("the pwqs list of {:#x} is broken at {:#x}".format(workqueue, lh.broken_at))
        return units

    def owner_for_data(self, data):
        if not data & 4:
            return None
        for mask in (0xff, 0x1ff, 0x3ff):
            address = data & ~mask
            owner = self.units_by_address.get(address)
            if owner is not None:
                return owner
        return None

    def append_record(self, records, work, state, owner=None, pool=None, timer=None, expires=None, function=None):
        parsed = self.read_work(work, check_function=function is None)
        if parsed is None:
            return
        if function is not None:
            parsed["function"] = function
        if owner is None:
            owner = self.owner_for_data(parsed["data"])
        if owner is not None:
            cpu = owner["cpu"]
        else:
            cpu = None
        if cpu is None and pool is not None:
            worklist = self.find_worklist(pool)
            if worklist is not None:
                cpu = self.find_pool_cpu(pool, worklist)
        records[work] = {
            **parsed,
            "state": state,
            "owner": owner,
            "cpu": cpu,
            "timer": timer,
            "expires": expires,
        }
        return

    def collect_list_records(self, records):
        pools = {}
        for unit in self.units:
            pools.setdefault(unit["pool"], []).append(unit)

        for pool in pools:
            worklist = self.find_worklist(pool)
            if worklist is None:
                self.incomplete.append("the worklist of pool {:#x} is not found".format(pool))
                continue
            lh = KernelListHead(worklist, self.offset_work_entry)
            for work in lh.iter_entries():
                data = read_int_from_memory(work + self.offset_work_data, safe=True)
                if data is None:
                    continue
                owner = self.owner_for_data(data)
                self.append_record(records, work, "pending", owner, pool)
            if lh.broken:
                self.incomplete.append("the worklist of pool {:#x} is broken at {:#x}".format(pool, lh.broken_at))

        # Throttled work is linked from pool_workqueue.delayed_works/inactive_works.
        for unit in self.units:
            heads = []
            if self.offset_pwq_inactive is not None:
                heads.append(unit["address"] + self.offset_pwq_inactive)
            else:
                for offset in range(runtime.current_arch.ptrsize * 2, 0x180, runtime.current_arch.ptrsize):
                    head = unit["address"] + offset
                    try:
                        if is_double_link_list(head, min_len=1):
                            heads.append(head)
                    except gdb.MemoryError:
                        continue
            for head in heads:
                for work in KernelListHead(head, self.offset_work_entry).iter_entries():
                    parsed = self.read_work(work)
                    if parsed is None or self.owner_for_data(parsed["data"]) is not unit:
                        continue
                    self.append_record(records, work, "inactive", unit, unit["pool"])
        return

    def iter_busy_workers(self, pool):
        """Iterate the workers in the busy_hash of `pool`, each linked back through hentry.pprev."""
        ptrsize = runtime.current_arch.ptrsize
        if self.offset_pool_busy_hash is not None:
            buckets = [pool + self.offset_pool_busy_hash + ptrsize * i for i in range(self.BUSY_WORKER_HASH_SIZE)]
        else:
            # busy_hash is in worker_pool since v3.9, and in global_cwq, which contains the pools, before that
            if self.kversion < "3.9":
                start = pool - 0x1000
            else:
                start = pool
            data = read_memory(start, 0x2000, safe=True)
            if data is None:
                start = pool
                data = read_memory(start, 0x1000, safe=True)
                if data is None:
                    self.incomplete.append("the busy_hash of pool {:#x} is unreadable".format(pool))
                    return
            words = slice_unpack(data, ptrsize)
            buckets = [start + ptrsize * i for i, word in enumerate(words) if word and is_valid_addr(word)]

        seen = set()
        for bucket in buckets:
            link = bucket
            worker = read_int_from_memory(bucket, safe=True)
            while worker and worker not in seen and is_valid_addr(worker):
                if read_int_from_memory(worker + ptrsize, safe=True) != link: # hlist_node.pprev
                    break
                seen.add(worker)
                yield worker
                link = worker
                worker = read_int_from_memory(worker, safe=True)
        return

    def read_running_work(self, worker, pools, pool):
        """Return (current_work, current_pwq, the pool, the running function) of a busy worker, or None."""
        work = read_int_from_memory(worker + self.offset_worker_current_work, safe=True)
        if not work or not is_valid_addr(work):
            return None
        worker_layouts = [(self.offset_worker_current_func, self.offset_worker_current_pwq)]
        if self.offset_worker_current_func is None and GefUtil.offsetof("worker", "current_cwq") is None:
            # current_func (v3.9) is also backported to some v3.8.y
            worker_layouts.insert(0, (runtime.current_arch.ptrsize * 3, runtime.current_arch.ptrsize * 4))
        for offset_func, offset_pwq in worker_layouts:
            pwq = read_int_from_memory(worker + offset_pwq, safe=True)
            if not pwq or not is_valid_addr(pwq):
                continue
            # current_pwq links back to the pool (a global_cwq shares one busy_hash between its pools)
            pwq_pool = read_int_from_memory(pwq + self.offset_pwq_pool, safe=True)
            if pwq_pool not in pools or self.kversion >= "3.9" and pwq_pool != pool:
                continue
            if offset_func is not None:
                function = read_int_from_memory(worker + offset_func, safe=True)
            else:
                function = read_int_from_memory(work + self.offset_work_func, safe=True)
            if self.is_callback(function):
                return work, pwq, pwq_pool, function
        return None

    def collect_running_records(self, records):
        pools = {unit["pool"] for unit in self.units}
        seen_workers = set()
        for pool in pools:
            for worker in self.iter_busy_workers(pool):
                if worker in seen_workers:
                    continue
                # the window of a pool may cover the busy_hash of the next one
                running = self.read_running_work(worker, pools, pool)
                if running is None:
                    continue
                seen_workers.add(worker)
                work, pwq, pwq_pool, function = running
                owner = self.units_by_address.get(pwq)
                if owner is None:
                    wq = read_int_from_memory(pwq + self.offset_pwq_wq, safe=True)
                    owner = self.workqueues_by_address.get(wq)
                # current_func is what runs; the work may already be reinitialized or freed
                self.append_record(records, work, "running", owner, pwq_pool, function=function)
        return

    def find_delayed_work(self, timer):
        if self.offset_delayed_timer is not None:
            work = timer - self.offset_delayed_timer
            if self.read_work(work) is not None:
                return work
            return None

        for offset in range(runtime.current_arch.ptrsize * 4, 0x200, runtime.current_arch.ptrsize):
            work = timer - offset
            parsed = self.read_work(work)
            if parsed is not None and parsed["data"] & 1:
                return work
        return None

    def find_delayed_owner(self, work, timer):
        parsed = self.read_work(work)
        if parsed is not None:
            owner = self.owner_for_data(parsed["data"])
            if owner is not None:
                return owner

        if self.offset_delayed_wq is not None:
            try:
                wq = read_int_from_memory(work + self.offset_delayed_wq)
                return self.workqueues_by_address.get(wq)
            except gdb.MemoryError:
                return None

        for offset in range(runtime.current_arch.ptrsize * 4, 0x180, runtime.current_arch.ptrsize):
            wq = read_int_from_memory(timer + offset, safe=True)
            if wq is None:
                continue
            owner = self.workqueues_by_address.get(wq)
            if owner is not None:
                return owner
        return None

    def collect_delayed_records(self, records):
        if not self.delayed_timer_functions:
            return
        timer_command = runtime.CommandRegistry.instances.get("ktimer")
        if timer_command is not None:
            classic_timers = timer_command.get_classic_timers()
        else:
            classic_timers = None
        if classic_timers is None:
            self.incomplete.append("delayed works are not scanned since the timer wheel is not resolved")
            return
        self.incomplete.extend("the timer wheel: {:s}".format(reason) for reason in classic_timers["incomplete"])

        for timer in classic_timers["timers"]:
            if timer["function"] not in self.delayed_timer_functions:
                continue
            work = self.find_delayed_work(timer["timer"])
            if work is None:
                continue
            owner = self.find_delayed_owner(work, timer["timer"])
            self.append_record(records, work, "delayed", owner, None, timer["timer"], timer["expires"])
            records[work]["cpu"] = timer["cpu"]
        return

    def scan_address_range(self, records, address, size):
        end = AddressUtil.normalize_address(address + size)
        for work in range(address, end, runtime.current_arch.ptrsize):
            if work in records:
                continue
            parsed = self.read_work(work)
            if parsed is None:
                continue
            owner = self.owner_for_data(parsed["data"])
            linked = (parsed["next"] == work + self.offset_work_entry and
                      parsed["prev"] == work + self.offset_work_entry)
            pending = bool(parsed["data"] & 1)
            if not pending and not linked:
                continue

            timer = None
            expires = None
            if pending:
                state = "pending"
            else:
                state = "idle"
            limit = min(end, work + 0x300)
            for function_address in range(work + self.offset_work_func + runtime.current_arch.ptrsize,
                                          limit, runtime.current_arch.ptrsize):
                function = read_int_from_memory(function_address, safe=True)
                if function is None:
                    break
                if function not in self.delayed_timer_functions:
                    continue
                candidate_timer = function_address - self.offset_timer_func
                if candidate_timer <= work:
                    continue
                timer = candidate_timer
                expires = read_int_from_memory(timer + self.offset_timer_expires, safe=True)
                if expires is None:
                    timer = None
                    continue
                owner = self.find_delayed_owner(work, timer) or owner
                if pending and read_int_from_memory(timer + self.offset_timer_pending, safe=True):
                    state = "delayed"
                break
            self.append_record(records, work, state, owner, None, timer, expires)
        return

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def resolve_layout(self):
        """Return {name: (offset, source)} of the workqueue structures, preferring the type information.
        An offset that is None is searched in memory at each call."""
        kversion = Kernel.version()
        ptrsize = runtime.current_arch.ptrsize
        layout = {}

        def member(name, candidates, fallback, fallback_source="fixed"):
            label = "offsetof({:s}, {:s})".format(*candidates[0])
            for type_name, member_name in candidates:
                offset = GefUtil.offsetof(type_name, member_name)
                if offset is not None:
                    layout[name] = (offset, "debug info", "offsetof({:s}, {:s})".format(type_name, member_name))
                    return
            layout[name] = (fallback, fallback_source if fallback is not None else "searched", label)
            return

        if kversion >= "3.9":
            pwq_type = "pool_workqueue"
        else:
            pwq_type = "cpu_workqueue_struct"
        if kversion >= "3.6":
            pool_type = "worker_pool"
        else:
            pool_type = "global_cwq"
        member("offset_work_data", [("work_struct", "data")], 0)
        member("offset_work_entry", [("work_struct", "entry")], ptrsize)
        member("offset_work_func", [("work_struct", "func")], ptrsize * 3)
        member("offset_wq_list", [("workqueue_struct", "list")], ptrsize * 2)
        if kversion >= "3.10":
            member("offset_wq_pwqs", [("workqueue_struct", "pwqs")], 0)
            layout["offset_wq_flags"] = layout["offset_wq_cpu_wq"] = (None, "unused", None)
        else:
            layout["offset_wq_pwqs"] = (None, "unused", None)
            member("offset_wq_flags", [("workqueue_struct", "flags")], 0)
            member("offset_wq_cpu_wq", [("workqueue_struct", "pool_wq"), ("workqueue_struct", "cpu_wq")], ptrsize)
        member("offset_pwq_pool", [(pwq_type, "pool"), (pwq_type, "gcwq")], 0)
        member("offset_pwq_wq", [(pwq_type, "wq")], ptrsize)
        if kversion >= "3.10":
            member("offset_pwqs_node", [(pwq_type, "pwqs_node")], None, "aligned pool_workqueue")
        else:
            layout["offset_pwqs_node"] = (None, "unused", None)
        # delayed_works is renamed to inactive_works in v5.15
        member("offset_pwq_inactive", [(pwq_type, "inactive_works"), (pwq_type, "delayed_works")][::1 if kversion >= "5.15" else -1], None)
        member("offset_pool_worklist", [(pool_type, "worklist")], None)
        member("offset_pool_cpu", [(pool_type, "cpu")], None, "per-cpu area")
        if kversion >= "3.9" or kversion < "3.6":
            member("offset_pool_busy_hash", [(pool_type, "busy_hash")], None)
        else:
            layout["offset_pool_busy_hash"] = (None, "searched", "offsetof(global_cwq, busy_hash)")
        member("offset_worker_current_work", [("worker", "current_work")], ptrsize * 2)
        if kversion >= "3.9":
            member("offset_worker_current_func", [("worker", "current_func")], ptrsize * 3)
            member("offset_worker_current_pwq", [("worker", "current_pwq")], ptrsize * 4)
        else:
            layout["offset_worker_current_func"] = (None, "unused", None)
            member("offset_worker_current_pwq", [("worker", "current_cwq")], ptrsize * 3)
        member("offset_delayed_timer", [("delayed_work", "timer")], None)
        member("offset_delayed_wq", [("delayed_work", "wq")], None)
        if kversion < "4.2":
            member("offset_timer_pending", [("timer_list", "entry.next")], 0)
        else:
            member("offset_timer_pending", [("timer_list", "entry.pprev")], ptrsize)
        member("offset_timer_expires", [("timer_list", "expires")], ptrsize * 2)
        # v3.0-v4.1 has `struct tvec_base *base` between `expires` and `function`;
        # v4.2 dropped it when timer_list.entry became an hlist_node.
        member("offset_timer_func", [("timer_list", "function")], ptrsize * (4 if kversion < "4.2" else 3))

        workqueues = KernelAddressHeuristicFinder.get_workqueues()
        layout["workqueues"] = (workqueues, None, None)
        return layout

    def initialize(self):
        self.meta = []
        self.incomplete = []
        self.kversion = Kernel.version()
        self.klayout = Kernel.layout()
        cpu_offsets = Kernel.per_cpu().offsets
        if cpu_offsets:
            self.max_cpu = max(len(cpu_offsets), 1)
        else:
            self.max_cpu = 0x2000
        self.pool_cpu_hints = {}
        self.worklist_offset = None
        self.module_text_ranges = None
        kallsyms = Ksym.get_kallsyms()
        if kallsyms:
            self.kallsyms_text = {
                address: name for address, name, symbol_type in kallsyms[0] if symbol_type.lower() in ("t", "w")
            }
        else:
            self.kallsyms_text = {}

        layout = self.resolve_layout()
        for name, (value, source, label) in layout.items():
            setattr(self, name, value)
            if label is not None:
                if value is not None:
                    value = "{:#x}".format(value)
                else:
                    value = "-"
                self.meta.append((self.quiet_info, "{:s}: {:s} ({:s})".format(label, value, source)))
        self.delayed_timer_functions = set(Ksym.get_addrs("delayed_work_timer_fn") or [])

        self.workqueues_by_address = {}
        self.units = []
        self.units_by_address = {}
        self.system_wq = None
        self.offset_wq_name = None
        self.name_is_pointer = False
        if self.workqueues is None:
            self.meta.append((self.quiet_err, "workqueues: Not found"))
            return None
        self.meta.append((self.quiet_info, "workqueues: {:#x}".format(self.workqueues)))

        lh = KernelListHead(self.workqueues, self.offset_wq_list)
        workqueues = list(lh.iter_entries())
        if lh.broken:
            self.incomplete.append("the workqueues list is broken at {:#x}".format(lh.broken_at))
        system_wq_ptr = Ksym.get_addr("system_wq")
        if system_wq_ptr is not None:
            self.system_wq = read_int_from_memory(system_wq_ptr, safe=True)
        self.offset_wq_name = self.find_name_offset(workqueues)
        if self.offset_wq_name is None:
            self.meta.append((self.quiet_warn, "offsetof(workqueue_struct, name): Not found"))
        else:
            self.meta.append((self.quiet_info, "offsetof(workqueue_struct, name): {:#x}".format(
                self.offset_wq_name,
            )))

        for workqueue in workqueues:
            self.workqueues_by_address[workqueue] = {
                "wq": workqueue,
                "name": self.read_workqueue_name(workqueue),
                "cpu": None,
            }

        if self.kversion < "3.10":
            self.units = self.collect_old_units(workqueues)
        else:
            self.units = self.collect_new_units(workqueues)
        self.units_by_address = {unit["address"]: unit for unit in self.units}

        self.meta.append((self.quiet_info, "workqueue count: {:d}".format(len(workqueues))))
        self.meta.append((self.quiet_info, "pool_workqueue/cpu_workqueue count: {:d}".format(len(self.units))))
        self.meta.append((self.quiet_info, "worker_pool count: {:d}".format(len({unit["pool"] for unit in self.units}))))
        return bool(workqueues)

    def print_records(self, records, object_address=None):
        width = AddressUtil.get_format_address_width()
        work_width = max(width, len("work_struct"))
        queue_width = max([24] + [len(record["owner"]["name"]) for record in records.values() if record["owner"] is not None])
        if not self.args.quiet:
            fmt = "{:<{ww}s}  {:<10s}  {:<5s}  {:<{qw}s}  {:<{w}s} {:s}"
            legend = ["work_struct", "state", "cpu", "queue", "function", "symbol"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend, w=width, ww=work_width, qw=queue_width)))

        state_order = {"running": 0, "pending": 1, "inactive": 2, "delayed": 3, "idle": 4}
        for record in sorted(records.values(), key=lambda item: (
                state_order.get(item["state"], 9), item["cpu"] if item["cpu"] is not None else 0x10000,
                item["work"])):
            owner = record["owner"]
            if owner is not None:
                queue = owner["name"]
            else:
                queue = "???"
            if record["cpu"] is None or record["cpu"] < 0:
                cpu = "-"
            else:
                cpu = str(record["cpu"])
            line = "{:<{ww}s}  {:<10s}  {:<5s}  {:<{qw}s}  {:s}".format(
                "{:#0{w}x}".format(record["work"], w=width), record["state"], cpu, queue,
                Symbol.format(
                    record["function"], missing="NO_SYMBOL", ksym="prefer", show_address=True, nocolor=True,
                ),
                ww=work_width, qw=queue_width,
            ).rstrip()
            extras = []
            if object_address is not None:
                extras.append("object+{:#x}".format(record["work"] - object_address))
            if record["timer"] is not None:
                extras.append("timer={:#x}".format(record["timer"]))
            if record["expires"] is not None:
                extras.append("expires={:#x}".format(record["expires"]))
            if extras:
                line += "  [" + ", ".join(extras) + "]"
            self.out.append(line)
        return

    def collect_records(self):
        records = {}
        if self.units:
            self.collect_list_records(records)
            self.collect_running_records(records)
        self.collect_delayed_records(records)
        return records

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "3.0":
            err("Unsupported before v3.0")
            return
        if args.size is None:
            args.size = 0x1000
        elif args.object is None:
            err("--size needs --object")
            return
        if args.size <= 0:
            err("--size must be positive")
            return

        self.quiet_info("Wait for memory scan")
        ret = self.initialize()
        # --object inspects the given range, so the workqueue list is optional for it
        if not ret and (args.meta or args.object is None):
            for func, line in self.meta:
                func(line)
            return

        if args.object is not None:
            records = {}
            if ret:
                records = self.collect_records()
                end = AddressUtil.normalize_address(args.object + args.size)
                records = {work: record for work, record in records.items() if args.object <= work < end}
            self.scan_address_range(records, args.object, args.size)
        else:
            records = self.collect_records()

        if args.meta:
            for func, line in self.meta:
                func(line)
            self.quiet_info("record count: {:d}".format(len(records)))
            for reason in self.incomplete:
                self.quiet_warn("Incomplete: {:s}".format(reason))
            return

        self.out = []
        self.print_records(records, args.object)
        if not records:
            self.quiet_info_add_out("No pending or running work items found")
        for reason in self.incomplete:
            self.warn_add_out("Incomplete: {:s}".format(reason))
        self.print_output(check_terminal_size=True)
        return


@register_command
class KernelWalkCommand(GenericCommand, BufferingOutput):
    """The base command to dump the entries held by the well-known kernel data structures."""

    _cmdline_ = "kwalk"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=False)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("list")
    subparsers.add_parser("rbtree")
    subparsers.add_parser("radix")
    subparsers.add_parser("xarray")
    subparsers.add_parser("maple")
    _syntax_ = parser.format_help()

    _note_ = [
        "Which sub-command holds the index-to-pointer mapping depends on the kernel version:",
        "",
        "  ~v4.19: radix_tree -> `kwalk radix`",
        "  v4.20~: xarray     -> `kwalk xarray` (radix-tree API remains as a compatibility interface)",
        "  v6.1~ : maple_tree -> `kwalk maple`  (only where it replaced the rbtree or the xarray)",
        "",
        "`kwalk list` and `kwalk rbtree` work on any version, and also outside the kernel.",
        "",
        "Simplified structures:",
        "",
        "+-list_head---+              +-rb_root-------------+",
        "| next        |--> entry     | rb_node             |--+",
        "| prev        |--> entry     +---------------------+  |",
        "+-------------+                                       v",
        "                                   +-rb_node-------------+",
        "                                   | __rb_parent_color   |",
        "                                   | rb_right            |--> sub-tree",
        "                                   | rb_left             |--> sub-tree",
        "                                   +---------------------+",
        "",
        "+-radix_tree_root(~v4.19)-+  +-xarray(v4.20~)-+",
        "| height (~v4.6)          |  | xa_lock        |",
        "| gfp_mask                |  | xa_flags       |",
        "| rnode                   |  | xa_head        |",
        "+-------------------------+  +----------------+",
        "             |                        |",
        "             +------------+-----------+",
        "                          v",
        "           +-radix_tree_node / xa_node-+",
        "           | shift                     |",
        "           | offset                    |",
        "           | count                     |",
        "           | ...                       |",
        "           | slots[0]                  |--> entry",
        "           | slots[1]                  |--> entry or sub-node",
        "           | ...                       |",
        "           | slots[15 or 63]           |",
        "           +---------------------------+",
        "",
        "+-maple_tree(v6.1~)-+  +-->+-maple_node------+",
        "| ma_lock           |  |   | ...             |",
        "| ma_flags          |  |   | mr64|ma64|alloc |",
        "| ma_root           |--+   |   ...           |",
        "+-------------------+      |   slot[]        |--> entry or sub-node",
        "                           +-----------------+",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        complete = kwargs.get("complete", gdb.COMPLETE_NONE)
        super().__init__(prefix=prefix, complete=complete)
        return

    @staticmethod
    def add_common_arguments(parser):
        """Add the arguments which are shared by all sub-commands."""
        parser.add_argument("-C", "--container-of", type=AddressUtil.parse_address, default=0,
                            help="also displays each entry minus this offset, like container_of().")
        parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
        parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
        return parser

    def add_entry_out(self, idx, entry):
        """Append the resolved entry to self.out."""
        la = ProcessMap.lookup(entry)
        if self.args.container_of:
            la_container = ProcessMap.lookup(entry - self.args.container_of)
            self.out.append("[{:d}] -> {!s} (container: {!s})".format(idx, la, la_container))
        else:
            self.out.append("[{:d}] -> {!s}".format(idx, la))
        return

    def dump_entries(self, entries, broken=None):
        """Append the resolved entries to self.out."""
        entries = list(entries)
        if broken:
            for node, reason in broken.items():
                self.err_add_out("Tree is broken at {:#x} ({:s}); results are incomplete".format(node, reason))
            self.info_add_out("Partial entries: {:d}".format(len(entries)))
        elif not entries:
            self.info_add_out("No entry was found")
            return
        else:
            self.quiet_info_add_out("Num of entries: {:d}".format(len(entries)))
        for idx, entry in enumerate(entries, start=1):
            self.add_entry_out(idx, entry)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        self.usage(simple=True)
        return



@register_command
class KernelWalkListCommand(KernelWalkCommand):
    """Walk the link list."""

    _cmdline_ = "kwalk list"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"
    _aliases_ = ["walk-link-list", "chain", "list-dump"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-o", dest="next_offset", type=AddressUtil.parse_address, default=0,
                        help="offset of the next(or prev) pointer in the target structure.")
    parser.add_argument("-A", dest="dump_bytes_after", type=AddressUtil.parse_address, default=0,
                        help="dump bytes after link-list location.")
    parser.add_argument("-B", dest="dump_bytes_before", type=AddressUtil.parse_address, default=0,
                        help="dump bytes before link-list location.")
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="start address to walk.")
    KernelWalkCommand.add_common_arguments(parser)
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffff9c60800597e0                      # walk list_head.next",
        "{0:s} -o 8 0xffff9c60800597e0                 # walk list_head.prev",
        "{0:s} --container-of 0x10 0xffff9c60800597e0  # also show each entry as container_of()",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "`-o` is the offset of the pointer to follow, so it is 0 for list_head.next,",
        "the pointer size for list_head.prev, and offsetof(the struct, next) for a",
        "singly linked list of the structs.",
        "ADDRESS is the starting node or head; the first displayed entry is the pointer",
        "read from ADDRESS+OFFSET, not ADDRESS itself. NULL and a returning sentinel head",
        "are therefore also shown as the final entry.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    def walk_link_list(self, head, offset):
        indent = " " * 12
        current = head
        seen = {current}
        idx = 1
        while True:
            flink = read_int_from_memory(AddressUtil.normalize_address(current + offset), safe=True)
            if flink is None:
                self.err_add_out("memory corrupted")
                return
            for start, size in ((current - self.args.dump_bytes_before, self.args.dump_bytes_before),
                                (current, self.args.dump_bytes_after)):
                if not size:
                    continue
                try:
                    source = read_memory(start, size)
                except gdb.error:
                    self.err_add_out("unreadable dump range {:#x}-{:#x}".format(start, start + size))
                    continue
                dump = hexdump(source, base=start, unit=runtime.current_arch.ptrsize)
                for line in dump.splitlines():
                    self.out.append(indent + line)
            self.add_entry_out(idx, flink)
            if flink == 0:
                break
            if flink == head:
                self.out[-1] += " (head)"
                break
            if flink in seen:
                self.err_add_out("loop detected")
                break
            seen.add(flink)
            current = flink
            idx += 1
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.dump_bytes_before < 0 or args.dump_bytes_after < 0:
            err("Dump size must be >= 0")
            return
        self.out = []
        self.quiet_info_add_out("head address: {:#x}".format(args.address))
        self.quiet_info_add_out("next pointer offset: {:#x}".format(args.next_offset))
        self.walk_link_list(args.address, args.next_offset)
        self.print_output()
        return



@register_command
class KernelWalkRbtreeCommand(KernelWalkCommand):
    """Dump the nodes of the red-black tree."""

    _cmdline_ = "kwalk rbtree"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"
    _aliases_ = ["rbtree-dump"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the address of the struct rb_root (or rb_root_cached).")
    parser.add_argument("-r", "--rb-node", action="store_true",
                        help="treat ADDRESS as a struct rb_node instead of a struct rb_root.")
    KernelWalkCommand.add_common_arguments(parser)
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffff9c6081b3d7a0        # dump the rb_nodes under the rb_root",
        "{0:s} -r 0xffff9c6081b3d7a8     # dump the rb_nodes under the rb_node",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "The entries are dumped in pre-order, not sorted by key.",
        "struct rb_root_cached starts with a struct rb_root, so pass its address as is.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if not is_valid_addr(args.address):
            err("Invalid address")
            return

        rb = KernelRBTree(args.address)
        try:
            if args.rb_node:
                nodes = rb.parse_node(args.address)
            else:
                nodes = rb.parse()
        except gdb.MemoryError:
            err("Memory error while walking the tree")
            return

        self.out = []
        self.quiet_info_add_out("rb_{:s}: {:#x}".format("node" if args.rb_node else "root", args.address))
        self.dump_entries(nodes, rb.broken)
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelWalkRadixTreeCommand(KernelWalkCommand):
    """Dump the entries of the radix tree."""

    _cmdline_ = "kwalk radix"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"
    _aliases_ = ["radix-dump"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the address of the struct including the radix_tree_root.")
    parser.add_argument("-o", "--rnode-offset", type=AddressUtil.parse_address,
                        help="offsetof(the struct, rnode). it is searched if not given.")
    parser.add_argument("-m", "--max-offset", type=AddressUtil.parse_address,
                        help="the search range of offsetof(the struct, rnode). (default: ptrsize*0x20)")
    KernelWalkCommand.add_common_arguments(parser)
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffffffff82640e60        # dump the entries of irq_desc_tree",
        "{0:s} -o 8 0xffffffff82640e60   # skip searching offsetof(the struct, rnode)",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "The radix_tree_root is renamed to xarray at v4.20, so use `kwalk xarray` for v4.20 and later.",
        "A tree holding only one item keeps it in rnode without the tag, which is indistinguishable",
        "from any other pointer. Pass `--rnode-offset` explicitly for such a tree.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion >= "4.20":
            err("Unsupported since v4.20, use `kwalk xarray` instead")
            return

        if not is_valid_addr(args.address):
            err("Invalid address")
            return

        max_offset = args.max_offset or runtime.current_arch.ptrsize * 0x20
        rt = KernelRadixTree(args.address, args.rnode_offset)
        try:
            if rt.find_rnode_offset(max_offset) is None:
                err("Could not find rnode. (maybe uninitialized?)")
                return
            entries = rt.parse()
        except gdb.MemoryError:
            err("Memory error while walking the tree")
            return

        self.out = []
        self.quiet_info_add_out("offsetof(the struct, rnode): {:#x}".format(rt.rnode_offset))
        self.quiet_info_add_out("rnode: {:#x}".format(rt.rnode))
        if rt.height is not None:
            self.quiet_info_add_out("height: {:d}".format(rt.height))
        if rt.offset_slots is not None:
            self.quiet_info_add_out("offsetof(radix_tree_node, count): {:#x}".format(rt.offset_count))
            self.quiet_info_add_out("offsetof(radix_tree_node, slots): {:#x}".format(rt.offset_slots))
            self.quiet_info_add_out("RADIX_TREE_MAP_SIZE: {:d}".format(rt.num_slots))
        self.dump_entries(entries, rt.broken)
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelWalkXArrayCommand(KernelWalkCommand):
    """Dump the entries of the xarray."""

    _cmdline_ = "kwalk xarray"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"
    _aliases_ = ["xarray-dump"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the address of the struct including the xarray.")
    parser.add_argument("-o", "--head-offset", type=AddressUtil.parse_address,
                        help="offsetof(the struct, xa_head). it is searched if not given.")
    parser.add_argument("-m", "--max-offset", type=AddressUtil.parse_address,
                        help="the search range of offsetof(the struct, xa_head). (default: ptrsize*0x20)")
    KernelWalkCommand.add_common_arguments(parser)
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffffffff82640e60        # dump the entries of irq_desc_tree",
        "{0:s} -o 8 0xffffffff82640e60   # skip searching offsetof(the struct, xa_head)",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "The xarray is introduced at v4.20, so use `kwalk radix` for v4.19 and earlier.",
        "struct idr starts with a struct radix_tree_root (or xarray), so pass its address as is.",
        "An empty tree or one holding a single entry stored directly in xa_head cannot be",
        "auto-detected, because no internal node proves the offset; pass `--head-offset` for it.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "4.20":
            err("Unsupported before v4.20, use `kwalk radix` instead")
            return

        if not is_valid_addr(args.address):
            err("Invalid address")
            return

        max_offset = args.max_offset or runtime.current_arch.ptrsize * 0x20
        xa = KernelXArray(args.address, args.head_offset)
        try:
            if xa.find_head_offset(max_offset) is None:
                err("Could not find xa_head. Pass --head-offset (required for an empty or single-entry tree) "
                    "or a larger --max-offset.")
                return
            entries = xa.parse()
        except gdb.MemoryError:
            err("Memory error while walking the tree")
            return

        self.out = []
        self.quiet_info_add_out("offsetof(the struct, xa_head): {:#x}".format(xa.head_offset))
        self.dump_entries(entries, xa.broken)
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelWalkMapleTreeCommand(KernelWalkCommand):
    """Dump the entries of the maple tree."""

    _cmdline_ = "kwalk maple"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"
    _aliases_ = ["maple-dump"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address,
                        help="the address of the struct including the maple_tree.")
    parser.add_argument("-o", "--root-offset", type=AddressUtil.parse_address,
                        help="offsetof(the struct, ma_root). it is searched if not given.")
    parser.add_argument("-m", "--max-offset", type=AddressUtil.parse_address,
                        help="the search range of offsetof(the struct, ma_root). (default: ptrsize*0x20)")
    KernelWalkCommand.add_common_arguments(parser)
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffff972801b78a00          # dump the vm_area_structs of mm_struct.mm_mt",
        "{0:s} -o 0x48 0xffff972801b78a00  # skip searching offsetof(the struct, ma_root)",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "The maple_tree is introduced at v6.1 for mm_struct.mm_mt, and v6.5 for sparse_irqs.",
        "A tree holding a single entry stored directly in ma_root cannot be auto-detected;",
        "pass `--root-offset` for it. With the offset given, the single entry is shown correctly.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_LOCATION)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "6.1":
            err("Unsupported before v6.1")
            return

        if not is_valid_addr(args.address):
            err("Invalid address")
            return

        max_offset = args.max_offset or runtime.current_arch.ptrsize * 0x20
        mt = KernelMapleTree(args.address, args.root_offset)
        try:
            if mt.find_root_offset(max_offset) is None:
                err("Could not find ma_root. Pass --root-offset (required for an empty or single-entry tree).")
                return
            entries = mt.parse()
        except gdb.MemoryError:
            err("Memory error while walking the tree")
            return

        self.out = []
        self.quiet_info_add_out("offsetof(the struct, ma_root): {:#x}".format(mt.root_offset))
        if mt.ma_root is not None and mt.ma_flags is not None:
            self.quiet_info_add_out("ma_root: {:#x}, ma_flags: {:#x}, max_depth: {:d}".format(
                mt.ma_root, mt.ma_flags, mt.max_depth,
            ))
        self.dump_entries(entries, mt.broken)
        self.print_output(check_terminal_size=True)
        return
