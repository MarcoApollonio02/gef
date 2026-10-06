"""GEF kernel commands (category 06-g) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Linux Advanced: kernel module/device/config
inspection (kmod, kblockdevs, kchardevs, kops, ksysctl, kfilesystems,
kclocksource, ktimer, kpcidev, kconfig, kdmesg, syscall-table-view, kpipe,
kbpf, kipcs, kdevio, kdmabuf, kirq, knetdev). Auto-discovered by gef.bootstrap
via pkgutil.walk_packages.
"""
import argparse
import os
import re
import subprocess

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
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err, info, titlify, warn
from gef.core.config import Config
from gef.core.instruction import Disasm, get_insn, get_insn_next
from gef.core.kernel import Kernel
from gef.core.memory import (
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
    u64,
)
from gef.core.pagewalk import KernelAddressHeuristicFinder
from gef.core.process import (
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
from gef.core.utils import GEF_TEMP_DIR, GefUtil, align, align_to_ptrsize, slicer, switch_to_intel_syntax


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
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n.",
        "If there are too many block devices, detection may fail.",
        "This is because block devices are not managed in a single location,",
        "so the list of bdev_cache obtained from the slub-dump results is used.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        self.offset_bd_dev = None
        return

    def get_bdev_list(self):
        allocator = Kernel.get_slab_type()
        if allocator == "SLUB":
            ret = gdb.execute("slub-dump --quiet --no-pager -vv bdev_cache", to_string=True)
        elif allocator == "SLUB_TINY":
            ret = gdb.execute("slub-tiny-dump --quiet --no-pager bdev_cache", to_string=True)
        else:
            self.quiet_err("Unsupported: SLAB, SLOB, Unknown allocator")
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
        """
        [~v5.10]
        struct block_device {
            dev_t                       bd_dev;
            ...
        };

        [v5.11~]
        struct block_device {
            sector_t                    bd_start_sect;      // sector_t: u64
            sector_t                    bd_nr_sectors;      // sector_t: u64, v5.17~
            struct gendisk             *bd_disk;            // v6.4~
            struct request_queue       *bd_queue;           // v6.4~
            struct disk_stats __percpu *bd_stats;
            unsigned long               bd_stamp;
            bool                        bd_read_only;       // 1byte + 3byte padding
            dev_t                       bd_dev;
            ...
        };
        """
        if self.offset_bd_dev is None:
            kversion = Kernel.kernel_version()
            if kversion < "5.11":
                self.offset_bd_dev = 0
            elif kversion < "5.16":
                self.offset_bd_dev = 8 * 1 + runtime.current_arch.ptrsize * 2 + 4
            elif kversion < "6.4":
                self.offset_bd_dev = 8 * 2 + runtime.current_arch.ptrsize * 2 + 4
            else:
                self.offset_bd_dev = 8 * 2 + runtime.current_arch.ptrsize * 4 + 4

        dev = read_int32_from_memory(bdev + self.offset_bd_dev)
        major = dev >> 20
        minor = dev & ((1 << 20) - 1)
        name = KernelBlockDevicesCommand.get_bdev_name(major, minor)
        return major, minor, name

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        bdevs = self.get_bdev_list()
        if not bdevs:
            self.quiet_err("Could not find any bdev")
            return

        self.out = []
        if not args.quiet:
            fmt = "{:<18s} {:<18s} {:<6s} {:<6s}"
            legend = ["bdev", "name (guessed)", "major", "minor"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # ignore bdev if major is 0
        bdevs = [bdev for bdev in bdevs if self.get_dev_num(bdev)[0] != 0]
        if not bdevs:
            self.quiet_err("Could not find any bdev (after filtering major == 0)")
            return

        # parse major, minor and name
        bdevs_with_info = []
        for bdev in bdevs:
            major, minor, name = self.get_dev_num(bdev)
            bdevs_with_info.append([major, minor, name, bdev])

        # print
        for major, minor, name, bdev in sorted(bdevs_with_info):
            self.out.append("{:#018x} {:<18s} {:<6d} {:<6d}".format(bdev, name, major, minor).rstrip())

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelCharacterDevicesCommand(GenericCommand, BufferingOutput):
    """Display character device list."""

    _cmdline_ = "kcdev"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n.",
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
    ]
    _note_ = "\n".join(_note_)

    @staticmethod
    def get_cdev_name(major, minor):
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
                return "/dev/rawctl",
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
        for i in range(255):
            chrdevs_i = chrdevs + i * runtime.current_arch.ptrsize
            if not is_valid_addr(chrdevs_i):
                self.quiet_err("Memory read error")
                return None
            addr = read_int_from_memory(chrdevs_i)
            while addr and addr not in chrdev_addrs:
                chrdev_addrs.append(addr)
                if not is_valid_addr(addr):
                    self.quiet_err("Memory read error")
                    return None
                addr = read_int_from_memory(addr)
        return chrdev_addrs

    def get_cdev_list(self): # [[cdev, major, minor], [...] ...]
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
        seen = []
        for i in range(255):
            addr = read_int_from_memory(cdev_map_ + i * runtime.current_arch.ptrsize)
            while addr:
                cdev = read_int_from_memory(addr + 6 * runtime.current_arch.ptrsize)
                dev = read_int32_from_memory(addr + runtime.current_arch.ptrsize)
                major = dev >> 20
                minor = dev & ((1 << 20) - 1)
                if cdev and cdev not in seen:
                    cdev_addrs.append([cdev, major, minor])
                    seen.append(cdev)
                addr = read_int_from_memory(addr)
        return cdev_addrs

    def get_offset_ops(self, cdevs):
        for i in range(3, 0x20):
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
                if valid:
                    offset_ops = offset_list - runtime.current_arch.ptrsize
                    self.quiet_info("offsetof(cdev, ops): {:#x}".format(offset_ops))
                    return offset_ops

        self.quiet_err("Could not find offsetof(cdev, ops)")
        return None

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
        for chrdev in chrdev_addrs:
            major = read_int32_from_memory(chrdev + runtime.current_arch.ptrsize)
            minor = read_int32_from_memory(chrdev + runtime.current_arch.ptrsize + 4)
            name_string = read_cstring_from_memory(chrdev + runtime.current_arch.ptrsize + 4 * 3) or "<None>"
            off = chrdev + runtime.current_arch.ptrsize + 4 * 3 + 64
            while off % runtime.current_arch.ptrsize: # align
                off += 1
            cdev = read_int_from_memory(off)
            merged[major, minor] = {"chrdev": chrdev, "name": name_string, "cdev": cdev}

        # merge cdev (from cdev_map)
        for cdev, major, minor in cdev_addrs:
            kobj = read_int_from_memory(cdev)
            name_string = read_cstring_from_memory(kobj) or "<None>"

            if (major, minor) in merged:
                if merged[major, minor]["cdev"] == 0:
                    merged[major, minor]["cdev"] = cdev
                if merged[major, minor]["name"] == "<None>":
                    merged[major, minor]["name"] = name_string
            else:
                merged[major, minor] = {"chrdev": 0x0, "name": name_string, "cdev": cdev}

        # add ops info
        off_ops = self.get_offset_ops([v["cdev"] for k, v in merged.items() if v["cdev"]])
        if off_ops is None:
            return
        for k in merged.keys():
            if merged[k]["cdev"]:
                merged[k]["ops"] = read_int_from_memory(merged[k]["cdev"] + off_ops)
            else:
                merged[k]["ops"] = 0x0
            merged[k]["ops_sym"] = Symbol.get_symbol_string(merged[k]["ops"])

        # add parent info
        for k in merged.keys():
            if merged[k]["cdev"]:
                parent = read_int_from_memory(merged[k]["cdev"] + runtime.current_arch.ptrsize * 3)
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
            fmt = "{:<18s} {:<18s} {:<24s} {:<6s} {:<6s} {:<18s} {:<18s} {:18s} {:<s}"
            legend = [
                "chrdev", "name", "name (guessed)", "major", "minor",
                "cdev", "cdev->kobj.parent", "parent_name", "cdev->ops",
            ]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for (major, minor), m in sorted(merged.items()):
            guessed_name = KernelCharacterDevicesCommand.get_cdev_name(major, minor)
            if not args.verbose:
                if m["chrdev"] == 0:
                    continue
            self.out.append("{:#018x} {:<18s} {:<24s} {:<6d} {:<6d} {:#018x} {:#018x} {:<18s} {:#018x}{:s}".format(
                m["chrdev"], m["name"], guessed_name, major, minor,
                m["cdev"], m["parent"], m["parent_name"], m["ops"], m["ops_sym"],
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
            kversion = Kernel.KernelVersion(None, args.version, major, minor, patch)
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
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-v", "--verbose", action="store_true", help="dump zero-sized entries too.")
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

    # Because this may be called repeatedly with different filter conditions,
    # GEF caches the results for a short time.

    @Cache.cache_until_next
    def read_int_from_memory(self, addr):
        return read_int_from_memory(addr)

    @Cache.cache_until_next
    def read_int8_from_memory(self, addr):
        return read_int8_from_memory(addr)

    @Cache.cache_until_next
    def read_int32_from_memory(self, addr):
        return read_int32_from_memory(addr)

    @Cache.cache_until_next
    def read_int64_from_memory(self, addr):
        return read_int64_from_memory(addr)

    @Cache.cache_until_next
    def read_cstring_from_memory(self, addr):
        return read_cstring_from_memory(addr)

    @Cache.cache_until_next
    def is_valid_addr(self, addr):
        return is_valid_addr(addr)

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

    def dump_data(self, ctl_table, param_path, mode):
        if not self.should_be_print(param_path):
            return

        maxlen = self.read_int32_from_memory(ctl_table + self.offset_maxlen)
        # data
        data_addr = self.read_int_from_memory(ctl_table + runtime.current_arch.ptrsize)
        if data_addr and self.is_valid_addr(data_addr):
            # type from handler
            handler = self.read_int_from_memory(ctl_table + self.offset_handler)
            # data length
            if handler in self.str_types:
                data_val = self.read_cstring_from_memory(data_addr)
                self.out.append("{:<56s} {:#018x} {:#07x} {:#010o} {!r}".format(
                    param_path, data_addr, maxlen, mode, data_val,
                )) # allow None
            elif maxlen == 4:
                data_val = self.read_int32_from_memory(data_addr)
                self.out.append("{:<56s} {:#018x} {:#07x} {:#010o} {:#018x}".format(
                    param_path, data_addr, maxlen, mode, data_val,
                ))
            elif maxlen == 8:
                data_val = self.read_int64_from_memory(data_addr)
                self.out.append("{:<56s} {:#018x} {:#07x} {:#010o} {:#018x}".format(
                    param_path, data_addr, maxlen, mode, data_val,
                ))
            elif maxlen == 1:
                data_val = self.read_int8_from_memory(data_addr)
                self.out.append("{:<56s} {:#018x} {:#07x} {:#010o} {:#018x}".format(
                    param_path, data_addr, maxlen, mode, data_val,
                ))
            elif maxlen == 0:
                if self.args.verbose:
                    self.out.append("{:<56s} {:#018x} {:#07x} {:#010o}".format(
                        param_path, data_addr, maxlen, mode,
                    ))
            else:
                # type from heuristic
                data_val = self.read_cstring_from_memory(data_addr)
                if data_val and data_val.isprintable() and len(data_val) >= 2:
                    self.out.append("{:<56s} {:#018x} {:#07x} {:#010o} {!r}".format(
                        param_path, data_addr, maxlen, mode, data_val,
                    ))
                else:
                    data_val = self.read_int_from_memory(data_addr)
                    self.out.append("{:<56s} {:#018x} {:#07x} {:#010o} {:#018x}".format(
                        param_path, data_addr, maxlen, mode, data_val,
                    ))
        else:
            if self.args.verbose:
                self.out.append("{:<56s} {:#018x} {:#07x} {:#010o}".format(
                    param_path, data_addr, maxlen, mode,
                ))

        return

    def redirect_root_for_symlink(self, ctl_table, pbar):
        if self.args.skip_symlink:
            return

        ctset = None
        root = self.read_int_from_memory(ctl_table + runtime.current_arch.ptrsize)
        if self.is_valid_addr(root + self.offset_lookup):
            lookup = self.read_int_from_memory(root + self.offset_lookup)
            if lookup == Symbol.get_ksymaddr("net_ctl_header_lookup"): # net.*
                ctset = self.net_ctset
            elif lookup == Symbol.get_ksymaddr("set_lookup"): # user.*
                ctset = self.user_ctset
        if ctset:
            symlink_rb_node = self.read_int_from_memory(ctset + runtime.current_arch.ptrsize + self.offset_rb_node)
            if ctset not in self.seen_ctset:
                self.seen_ctset.add(ctset)
                self.sysctl_dump(symlink_rb_node, pbar)
        return

    def get_param_path(self, ctl_dir, ctl_table, parent_path):
        procname = self.read_int_from_memory(ctl_table)
        if procname == 0:
            return None

        procname_str = self.read_cstring_from_memory(procname)
        if not procname_str: # None or ""
            return None

        param_path = (parent_path + "." + procname_str).lstrip(".")
        self.parent_paths[ctl_dir] = param_path
        return param_path

    def sysctl_dump(self, rb_node, pbar):
        if not rb_node:
            return
        if self.args.exact and self.exact_found:
            return

        if pbar is not None:
            pbar.update(1)

        # ctl_node.header (=ctl_dir)
        ctl_dir = self.read_int_from_memory(rb_node + runtime.current_arch.ptrsize * 3)
        if ctl_dir not in self.seen_ctl_dir:
            self.seen_ctl_dir.add(ctl_dir)

            # parent
            parent = self.read_int_from_memory(ctl_dir + self.offset_parent)
            parent_path = self.parent_paths.get(parent, "")

            # ctl_table(s)
            ctl_table = self.read_int_from_memory(ctl_dir)
            while ctl_table not in self.seen_ctl_table:
                self.seen_ctl_table.add(ctl_table)

                # param_path
                param_path = self.get_param_path(ctl_dir, ctl_table, parent_path)
                if param_path is None:
                    break

                # mode
                mode = self.read_int32_from_memory(ctl_table + self.offset_mode)

                # dump
                if (mode & 0o0120000) == 0o0120000: # symlink
                    # `net.*` and `user.*` have a symlink attribute and they are redirected to another location.
                    # These must be traced from another root.
                    self.redirect_root_for_symlink(ctl_table, pbar)
                elif (mode & 0o0040000) == 0o0040000: # directory
                    pass
                elif mode > 0o777:
                    break
                else:
                    # If it's not a directory, it should hold data, so dump it.
                    self.dump_data(ctl_table, param_path, mode)
                    if self.args.exact and self.exact_found:
                        return

                # next array element
                ctl_table += self.sizeof_ctl_table

            # ctl_dir.rb_root->rb_node
            ctl_dir_rb_node = self.read_int_from_memory(ctl_dir + self.offset_rb_node) & ~1 # remove RB_BLACK
            self.sysctl_dump(ctl_dir_rb_node, pbar)

        # ctl_node.node.rb_right
        right = self.read_int_from_memory(rb_node + runtime.current_arch.ptrsize * 1) & ~1 # remove RB_BLACK
        self.sysctl_dump(right, pbar)

        # ctl_node.node.rb_left
        left = self.read_int_from_memory(rb_node + runtime.current_arch.ptrsize * 2) & ~1 # remove RB_BLACK
        self.sysctl_dump(left, pbar)
        return

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            return True

        self.sysctl_table_root = KernelAddressHeuristicFinder.get_sysctl_table_root()
        if self.sysctl_table_root is None:
            self.quiet_err("Could not find sysctl_table_root")
            return False
        self.quiet_info("sysctl_table_root: {:#x}".format(self.sysctl_table_root))

        """
        struct ctl_table_root {
            struct ctl_table_set {
                int (*is_seen)(struct ctl_table_set *);
                struct ctl_dir dir;
            } default_set;
            struct ctl_table_set *(*lookup)(struct ctl_table_root *root);
            void (*set_ownership)(struct ctl_table_header *head, struct ctl_table *table, kuid_t *uid, kgid_t *gid);
            int (*permissions)(struct ctl_table_header *head, struct ctl_table *table);
        };

        struct ctl_dir {
            struct ctl_table_header {
                union {
                    struct {
                        struct ctl_table *ctl_table;
                        int ctl_table_size;               // v6.6~
                        int used;
                        int count;
                        int nreg;
                    };
                    struct rcu_head {
                        struct callback_head *next;
                        void (*func)(struct callback_head *head);
                    } rcu;
                };
                struct completion *unregistering;
                struct ctl_table *ctl_table_arg;
                struct ctl_table_root *root;
                struct ctl_table_set *set;
                struct ctl_dir *parent;
                struct ctl_node *node;
                struct hlist_head inodes;                 // v4.12.2~
                struct list_head inodes;                  // v4.11~v4.12.1
                struct hlist_head inodes;                 // v4.9.120~v4.9.337
                enum {
                    SYSCTL_TABLE_TYPE_DEFAULT,
                    SYSCTL_TABLE_TYPE_PERMANENTLY_EMPTY,
                } type;                                   // v6.10~
            } header;
            struct rb_root {
                struct rb_node *rb_node;
            } root;
        };

        struct ctl_node {
            struct rb_node {
                unsigned long  __rb_parent_color;
                struct rb_node *rb_right;
                struct rb_node *rb_left;
            } node;
            struct ctl_table_header *header;
        };

        struct ctl_table {
            const char *procname;
            void *data;
            int maxlen;
            umode_t mode;
            struct ctl_table *child;                      // ~v6.4
            enum {
                SYSCTL_TABLE_TYPE_DEFAULT,
                SYSCTL_TABLE_TYPE_PERMANENTLY_EMPTY
            } type;                                       // v6.5~v6.10
            proc_handler *proc_handler;
            struct ctl_table_poll *poll;
            void *extra1;
            void *extra2;
        };
        """

        kversion = Kernel.kernel_version()

        if is_64bit():
            # struct ctl_dir
            if kversion < "4.9.120":
                self.offset_rb_node = 0x48
            elif "4.9.120" <= kversion < "4.10":
                self.offset_rb_node = 0x50
            elif "4.10" <= kversion < "4.11":
                self.offset_rb_node = 0x48
            elif "4.11" <= kversion < "4.12.2":
                self.offset_rb_node = 0x58
            elif "4.12.2" <= kversion < "6.10":
                self.offset_rb_node = 0x50
            elif "6.10" <= kversion:
                self.offset_rb_node = 0x58
            self.offset_parent = 0x38
            # struct ctl_table
            self.offset_maxlen = 0x10
            self.offset_mode = 0x14
            if kversion < "6.10":
                self.offset_handler = 0x20
                self.sizeof_ctl_table = 0x40
            else:
                self.offset_handler = 0x18
                self.sizeof_ctl_table = 0x38
        else:
            # struct ctl_dir
            if kversion < "4.9.120":
                self.offset_rb_node = 0x28
                self.offset_parent = 0x20
            elif "4.9.120" <= kversion < "4.10":
                self.offset_rb_node = 0x2c
                self.offset_parent = 0x20
            elif "4.10" <= kversion < "4.11":
                self.offset_rb_node = 0x28
                self.offset_parent = 0x20
            elif "4.11" <= kversion < "4.12.2":
                self.offset_rb_node = 0x30
                self.offset_parent = 0x20
            elif "4.12.2" <= kversion < "6.6":
                self.offset_rb_node = 0x2c
                self.offset_parent = 0x20
            elif "6.6" <= kversion < "6.10":
                self.offset_rb_node = 0x30
                self.offset_parent = 0x24
            elif "6.10" <= kversion:
                self.offset_rb_node = 0x34
                self.offset_parent = 0x24
            # struct ctl_table
            self.offset_maxlen = 0x8
            self.offset_mode = 0xc
            if kversion < "6.10":
                self.offset_handler = 0x14
                self.sizeof_ctl_table = 0x24
            else:
                self.offset_handler = 0x10
                self.sizeof_ctl_table = 0x20

        # struct ctl_table_root
        self.offset_lookup = runtime.current_arch.ptrsize + self.offset_rb_node + runtime.current_arch.ptrsize

        # the root for `net.*`; init_nsproxy.net_ns.sysctls
        self.net_ctset = None
        init_net = KernelAddressHeuristicFinder.get_init_net()
        if init_net:
            current = init_net
            is_seen = Symbol.get_ksymaddr("is_seen")
            if is_seen:
                while True:
                    v = self.read_int_from_memory(current)
                    if v == is_seen:
                        self.net_ctset = current
                        break
                    current += runtime.current_arch.ptrsize

        # the root for `user.*`; init_user_ns.set
        self.user_ctset = None
        init_user_ns = KernelAddressHeuristicFinder.get_init_user_ns()
        if init_user_ns:
            current = init_user_ns
            # set_is_seen is found in 3 places (v5.19~), so Symbol.get_ksymaddr should not be used.
            set_is_seen = Symbol.get_ksymaddr_multiple("set_is_seen")
            if set_is_seen:
                while True:
                    v = self.read_int_from_memory(current)
                    if v in set_is_seen:
                        self.user_ctset = current
                        break
                    current += runtime.current_arch.ptrsize

        # handle functions
        known_str_types_handlers = [
            "addrconf_sysctl_stable_secret",
            "cdrom_sysctl_info",
            "devkmsg_sysctl_set_loglvl",
            "numa_zonelist_order_handler",
            "proc_allowed_congestion_control",
            "proc_do_uts_string",
            "proc_dostring",
            "proc_dostring_coredump",
            "proc_tcp_available_congestion_control",
            "proc_tcp_available_ulp",
            "seccomp_actions_logged_handler",
            "set_default_qdisc",
        ]
        self.str_types = []
        for handler in known_str_types_handlers:
            handler_addr = Symbol.get_ksymaddr(handler)
            if handler_addr:
                self.str_types.append(handler_addr)

        self.root_ctl_dir = self.sysctl_table_root + runtime.current_arch.ptrsize
        self.root_rb_node = self.read_int_from_memory(self.root_ctl_dir + self.offset_rb_node)
        self.quiet_info("root_ctl_dir: {:#x}".format(self.root_ctl_dir))
        self.quiet_info("root_rb_node: {:#x}".format(self.root_rb_node))

        self.initialized = True
        return True

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.exact_found = False

        if args.exact and not args.filter:
            self.quiet_err("Filter string is needed")
            return

        if args.rescan:
            self.initialized = False
            Cache.reset_gef_caches(all=True)

        self.quiet_info("Wait for memory scan")

        if not self.initialize():
            return

        # legend
        self.out = []
        if not args.quiet:
            fmt = "{:<56s} {:<18s} {:<7s} {:<10s} {:<s}"
            legend = ["ParamName", "ParamAddress", "MaxLen", "Mode", "ParamValue"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # progress setup
        pbar = None
        if not args.quiet:
            try:
                from tqdm import tqdm
                pbar = tqdm(total=None, leave=False)
            except ImportError:
                pass

        # parse rb_tree
        self.seen_ctl_dir = set()
        self.seen_ctl_table = set()
        self.seen_ctset = set()
        self.parent_paths = {self.root_ctl_dir: ""}
        try:
            # This try-except is a countermeasure to a parse error when CONFIG_RANDSTRUCT=y.
            self.sysctl_dump(self.root_rb_node, pbar)
        except gdb.MemoryError:
            self.quiet_err("Memory read error")
            return
        finally:
            if pbar is not None:
                pbar.close()

        # print
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelFileSystemsCommand(GenericCommand, BufferingOutput):
    """Dump filesystems."""

    _cmdline_ = "kfilesystems"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"
    _aliases_ = ["kmounts"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-s", "--skip-mount-path", action="store_true", help="skip resolving path.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n.",
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
        if hasattr(self, "initialized") and self.initialized:
            return True

        # file_systems
        self.file_systems = KernelAddressHeuristicFinder.get_file_systems()
        if self.file_systems is None:
            self.quiet_err("Could not find file_systems")
            return
        self.quiet_info("file_systems: {:#x}".format(self.file_systems))

        """
        struct file_system_type {
            const char *name;
            int fs_flags;
            int (*init_fs_context)(struct fs_context *); // v5.1~
            const struct fs_parameter_spec *parameters; // v5.1~
            struct dentry *(*mount) (struct file_system_type *, int, const char *, void *);
            void (*kill_sb) (struct super_block *);
            struct module *owner;
            struct file_system_type * next;
            struct hlist_head fs_supers;
            struct lock_class_key s_lock_key;
            struct lock_class_key s_umount_key;
            struct lock_class_key s_vfs_rename_key;
            struct lock_class_key s_writers_key[SB_FREEZE_LEVELS]; // v3.6~
            struct lock_class_key i_lock_key;
            struct lock_class_key i_mutex_key;
            struct lock_class_key invalidate_lock_key; // v5.15~
            struct lock_class_key i_mutex_dir_key;
            struct lock_class_key i_alloc_sem_key; // ~v3.0
        };
        """
        # file_system_type->name
        self.offset_name = 0
        self.quiet_info("offsetof(file_system_type, name): {:#x}".format(self.offset_name))

        # file_system_type->next
        for i in range(10):
            offset_next = runtime.current_arch.ptrsize * i
            valid = True
            current = read_int_from_memory(self.file_systems)
            seen = []
            while current != 0:
                if not is_valid_addr(current):
                    valid = False
                    break
                seen.append(current)
                name_addr = read_int_from_memory(current)
                if not is_valid_addr(name_addr):
                    valid = False
                    break
                name = read_cstring_from_memory(name_addr)
                if len(name) == 0:
                    valid = False
                    break
                current = read_int_from_memory(current + offset_next)
                if current in seen:
                    valid = False
                    break

            if len(seen) == 1:
                valid = False

            if valid:
                self.offset_next = offset_next
                break
        else:
            self.quiet_err("Could not find file_system_type->next")
            return False
        self.quiet_info("offsetof(file_system_type, next): {:#x}".format(self.offset_next))

        self.offset_fs_supers = self.offset_next + runtime.current_arch.ptrsize
        self.quiet_info("offsetof(file_system_type, fs_supers): {:#x}".format(self.offset_fs_supers))

        """
        struct super_block {
            struct list_head s_list;
            dev_t s_dev; // u32
            unsigned char s_dirt; // ~v3.5
            unsigned char s_blocksize_bits;
            unsigned long s_blocksize;
            ...
            struct hlist_node s_instances;  <-- fs_supers points here
            ...
        } __randomize_layout;
        """
        # super_block->s_dev
        self.offset_s_dev = runtime.current_arch.ptrsize * 2
        self.quiet_info("offsetof(super_block, s_dev): {:#x}".format(self.offset_s_dev))

        # super_block->s_instances
        current = read_int_from_memory(self.file_systems)
        while True:
            if current == 0:
                self.quiet_err("Could not find file_systems who has valid fs_supers")
                return False
            fs_supers = read_int_from_memory(current + self.offset_fs_supers)
            if is_valid_addr(fs_supers):
                break
            current = read_int_from_memory(current + self.offset_next)

        for i in range(1, 100):
            offset_base = runtime.current_arch.ptrsize * i
            """
            0xffff8cb085375800|+0x0000|+000: 0xffff8cb085373000  -> // s_list.next
            0xffff8cb085375808|+0x0008|+001: 0xffff8cb088b77000  -> // s_list.prev
            0xffff8cb085375810|+0x0010|+002: 0x0000000c00000021 // s_blocksize_bits, s_dev
            0xffff8cb085375818|+0x0018|+003: 0x0000000000001000 // s_blocksize
            0xffff8cb085375820|+0x0020|+004: 0x7fffffffffffffff
            0xffff8cb085375828|+0x0028|+005: 0xffffffff8c33f260 <shmem_fs_type>
            0xffff8cb085375830|+0x0030|+006: 0xffffffff8ba36da0 <shmem_ops>
            """
            # check s_list
            if not is_double_link_list(fs_supers - offset_base):
                continue

            # check s_blocksize
            x = read_int_from_memory(fs_supers - offset_base + runtime.current_arch.ptrsize * 2 + 4 * 2)
            if x == 0x1000:
                self.offset_s_instances = offset_base
                break
        else:
            self.quiet_err("Could not find super_block->s_instances")
            return False
        self.quiet_info("offsetof(super_block, s_instances): {:#x}".format(self.offset_s_instances))

        """
        struct super_block { // ~v3.11
            ...
            struct list_head s_mounts; // v3.3~ <-- double link list
            struct list_head s_dentry_lru;      <-- double link list
            int s_nr_dentry_unused;
            spinlock_t s_inode_lru_lock ____cacheline_aligned_in_smp;
            struct list_head s_inode_lru;       <-- double link list
            int s_nr_inodes_unused;
            struct block_device *s_bdev;
            struct backing_dev_info *s_bdi;
            struct mtd_info *s_mtd;
            struct hlist_node s_instances;  <-- fs_supers points here
            ...
        };

        struct super_block { // v3.12~
            ...
            struct list_head s_mounts; // v3.12~v6.17
            struct mount *s_mounts; // v6.18~
            struct block_device *s_bdev;
            struct bdev_handle *s_bdev_handle; // v6.6.47~v6.8
            struct file *s_bdev_file; // v6.9~
            struct backing_dev_info *s_bdi;
            struct mtd_info *s_mtd;
            struct hlist_node s_instances;  <-- fs_supers points here
            ...
        }; // ~v4.12
        } __randomize_layout; // v4.13~
        """
        # super_block->s_mounts
        kversion = Kernel.kernel_version()
        if kversion < "3.12":
            current = fs_supers - runtime.current_arch.ptrsize * 2
            double_link_list_count = 0
            while True:
                if is_double_link_list(current):
                    double_link_list_count += 1
                if double_link_list_count == 3:
                    difference = fs_supers - current
                    self.offset_s_mounts = self.offset_s_instances - difference
                    break
                current -= runtime.current_arch.ptrsize
        elif kversion < "6.6.47":
            self.offset_s_mounts = self.offset_s_instances - runtime.current_arch.ptrsize * 5
        elif kversion < "6.18":
            self.offset_s_mounts = self.offset_s_instances - runtime.current_arch.ptrsize * 6
        else:
            self.offset_s_mounts = self.offset_s_instances - runtime.current_arch.ptrsize * 5
        self.quiet_info("offsetof(super_block, s_mounts): {:#x}".format(self.offset_s_mounts))

        """
        struct mount { // <-- s_mounts points here (v6.18~)
            struct hlist_node mnt_hash; // v3.13~ // ptrsize * 2
            struct list_node mnt_hash; // ~v3.12 // ptrsize * 2
            struct mount *mnt_parent;
            struct dentry *mnt_mountpoint;
            struct vfsmount {
                struct dentry *mnt_root;
                struct super_block *mnt_sb;
                int mnt_flags;
                struct user_namespace *mnt_userns; // v5.12~v6.1
                struct mnt_idmap *mnt_idmap; // v6.2~
            } mnt;
            union {
                struct rb_node mnt_node; // v6.12~ // ptrsize * 3
                struct rcu_head mnt_rcu; // v3.13~ // ptrsize * 2
                struct llist_node mnt_llist; // v3.18~ // ptrsize
            };
        #ifdef CONFIG_SMP
            struct mnt_pcp __percpu *mnt_pcp;
        #else
            int mnt_count;
            int mnt_writers;
        #endif
            struct list_head mnt_mounts;
            struct list_head mnt_child;
            struct list_head mnt_instance; // ~v6.17 // <-- s_mounts points here (~v6.17)
            const char *mnt_devname;
            ...
        } __randomize_layout;
        """
        # mount->mnt_instance
        if kversion < "6.18":
            common1 = runtime.current_arch.ptrsize * 4 # mnt_hash ~ mnt_mount_point
            if kversion < "5.12":
                sizeof_vfsmount = runtime.current_arch.ptrsize * 3
            else:
                sizeof_vfsmount = runtime.current_arch.ptrsize * 4
            if kversion < "3.13":
                sizeof_union = 0
            elif kversion < "6.12":
                sizeof_union = runtime.current_arch.ptrsize * 2
            else:
                sizeof_union = runtime.current_arch.ptrsize * 3
            sizeof_ifdef = runtime.current_arch.ptrsize # for x86/x64/ARM/ARM64, CONFIG_SMP is 'y' in almost all cases
            common2 = runtime.current_arch.ptrsize * 4 # mnt_mounts ~ mnt_child
            self.offset_mount_mnt_instance = common1 + sizeof_vfsmount + sizeof_union + sizeof_ifdef + common2
        else:
            self.offset_mount_mnt_instance = 0

        # mount->{mnt_parent,mnt_mountpoint,mnt}
        self.offset_mount_mnt_parent = runtime.current_arch.ptrsize * 2
        self.offset_mount_mnt_mountpoint = runtime.current_arch.ptrsize * 3
        self.offset_mount_mnt = runtime.current_arch.ptrsize * 4

        # vfsmount->mnt_root
        self.offset_vfsmount_mnt_root = 0

        self.initialized = True
        return True

    def get_fst_name(self, fst):
        name_addr = read_int_from_memory(fst + self.offset_name)
        name = read_cstring_from_memory(name_addr)
        return name

    def get_dev_num(self, dev):
        major = dev >> 20
        minor = dev & ((1 << 20) - 1)
        name = KernelBlockDevicesCommand.get_bdev_name(major, minor)
        return major, minor, name

    def get_offset_d_iname(self, dentry):
        if hasattr(self, "offset_d_iname") and self.offset_d_iname is not None:
            return self.offset_d_iname

        """
        struct dentry {
            unsigned int d_flags;
            seqcount_spinlock_t d_seq;
            struct hlist_bl_node d_hash;
            struct dentry *d_parent;
            struct qstr {
                union {
                    struct {
                        HASH_LEN_DECLARE;
                    };
                    u64 hash_len;
                };
                const unsigned char *name; // this points d_iname
            } d_name;
            struct inode *d_inode;
            unsigned char d_iname[DNAME_INLINE_LEN];
            ...
        };
        """
        current = dentry
        while True:
            name = read_int_from_memory(current)
            if 0 < name - current <= 0x20:
                offset_d_iname = name - dentry
                break
            current += runtime.current_arch.ptrsize

        self.offset_d_iname = offset_d_iname
        return offset_d_iname

    def get_offset_d_parent(self, dentry, offset_d_iname):
        if hasattr(self, "offset_d_parent") and self.offset_d_parent is not None:
            return self.offset_d_parent

        offset_dname_name = offset_d_iname - runtime.current_arch.ptrsize * 2
        if read_int_from_memory(dentry + offset_dname_name) == 0: # skip if padding
            offset_dname_name -= runtime.current_arch.ptrsize
        offset_d_parent = offset_dname_name - 0x8 - runtime.current_arch.ptrsize
        if read_int_from_memory(dentry + offset_d_parent) == 0: # skip if padding
            offset_d_parent -= runtime.current_arch.ptrsize

        self.offset_d_parent = offset_d_parent
        return offset_d_parent

    def get_mount(self, mnt_instance):
        mount = mnt_instance - self.offset_mount_mnt_instance
        return mount

    def get_mount_point(self, mnt_instance):
        mount = self.get_mount(mnt_instance)
        vfsmnt = mount + self.offset_mount_mnt
        dentry = read_int_from_memory(vfsmnt + self.offset_vfsmount_mnt_root)

        if not is_valid_addr(dentry):
            return None
        offset_d_iname = self.get_offset_d_iname(dentry)
        offset_d_parent = self.get_offset_d_parent(dentry, offset_d_iname)

        def is_root(dentry):
            return dentry == read_int_from_memory(dentry + offset_d_parent)

        filepath = []
        switched = False
        while True:
            if not is_valid_addr(vfsmnt):
                return None
            if not is_valid_addr(dentry):
                return None

            mnt_root = read_int_from_memory(vfsmnt + self.offset_vfsmount_mnt_root)
            if dentry == mnt_root or is_root(dentry):
                parent = read_int_from_memory(mount + self.offset_mount_mnt_parent)

                # Global root?
                if mount != parent:
                    dentry = read_int_from_memory(mount + self.offset_mount_mnt_mountpoint)
                    mount = parent
                    vfsmnt = mount + self.offset_mount_mnt
                    switched = True
                    continue

                name = read_cstring_from_memory(dentry + offset_d_iname)
                if name is None:
                    name_ptr = read_int_from_memory(dentry + offset_d_iname - runtime.current_arch.ptrsize * 2)
                    name = read_cstring_from_memory(name_ptr)
                filepath.append(name)
                break

            name = read_cstring_from_memory(dentry + offset_d_iname)
            if name is None:
                name_ptr = read_int_from_memory(dentry + offset_d_iname - runtime.current_arch.ptrsize * 2)
                name = read_cstring_from_memory(name_ptr)
            filepath.append(name)

            parent = read_int_from_memory(dentry + offset_d_parent)
            dentry = parent

        filepath = os.path.join(*filepath[::-1])

        # The reason is unclear, but this works.
        if switched is False and filepath == "/":
            next_mnt_instance = read_int_from_memory(mnt_instance)
            if next_mnt_instance:
                ret = self.get_mount_point(next_mnt_instance)
                if ret:
                    return ret
            return "-", "-"

        mount = self.get_mount(mnt_instance)
        return mount, filepath

    def get_dev_name(self, mnt_instance):
        offset_mount_mnt_instance = runtime.current_arch.ptrsize * 14
        offset_mount_mnt_devname = runtime.current_arch.ptrsize * 16

        mnt = mnt_instance - offset_mount_mnt_instance
        devname_p = read_int_from_memory(mnt + offset_mount_mnt_devname)
        devname = read_cstring_from_memory(devname_p)
        return devname

    def parse_super_block(self, fst, super_block):
        # name
        name = self.get_fst_name(fst)

        # dev
        dev = read_int32_from_memory(super_block + self.offset_s_dev)
        major, minor, devname = self.get_dev_num(dev)

        # mount
        s_mounts = read_int_from_memory(super_block + self.offset_s_mounts)
        mount = self.get_mount(s_mounts)

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
            devname = self.get_dev_name(s_mounts)
        else:
            devname += " (guessed)"

        # dump
        self.out.append("{:#018x} {:12s} {:#018x} {:20s} {:<6d} {:<6d} {:#018x} {:18s} {:s}".format(
            fst, name, super_block, devname, major, minor, mount, parsed_mount, mount_point,
        ))
        return

    def parse_file_system_type(self, fst):
        # fs_supers
        fs_supers = read_int_from_memory(fst + self.offset_fs_supers)

        if fs_supers == 0:
            # fast return
            name = self.get_fst_name(fst)
            self.out.append("{:#018x} {:12s} {:18s} {:20s} {:6s} {:6s} {:18s} {:18s} {:s}".format(
                fst, name, "-", "-", "-", "-", "-", "-", "-",
            ))
            return

        s_instances = fs_supers

        # parse more
        while s_instances:
            super_block = s_instances - self.offset_s_instances
            # parse super_block
            self.parse_super_block(fst, super_block)
            # go to next
            s_instances = read_int_from_memory(s_instances)
        return

    def parse_file_systems(self):
        if not self.args.quiet:
            fmt = "{:18s} {:12s} {:18s} {:20s} {:6s} {:6s} {:18s} {:18s} {:s}"
            legend = [
                "file_system_type", "fsname", "super_block", "devname", "major", "minor",
                "s_mount", "(parsed) mount", "mount_point",
            ]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        fst = read_int_from_memory(self.file_systems)
        while fst != 0:
            # parse file_system_type
            self.parse_file_system_type(fst)
            # go to next
            fst = read_int_from_memory(fst + self.offset_next)
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
        if kversion < "3.3":
            err("Unsupported before v3.3")
            return

        if not self.initialize():
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
    ]
    _note_ = "\n".join(_note_)

    def get_offset_list(self, clocksource):
        """
        struct clocksource {
            u64 (*read)(struct clocksource *cs);
            u64 mask;
            u32 mult;
            u32 shift;
            u64 max_idle_ns;
            u32 maxadj;
            u32 uncertainty_margin;
        #ifdef CONFIG_ARCH_CLOCKSOURCE_DATA
            struct arch_clocksource_data archdata;
        #endif
            u64 max_cycles;
            const char *name;
            struct list_head list;
            int rating;
            enum clocksource_ids id;
            enum vdso_clock_mode vdso_clock_mode;
            unsigned long flags;
            int (*enable)(struct clocksource *cs);
            void (*disable)(struct clocksource *cs);
            void (*suspend)(struct clocksource *cs);
            void (*resume)(struct clocksource *cs);
            void (*mark_unstable)(struct clocksource *cs);
            void (*tick_stable)(struct clocksource *cs);
        #ifdef CONFIG_CLOCKSOURCE_WATCHDOG
            struct list_head wd_list;
            u64 cs_last;
            u64 wd_last;
        #endif
            struct module *owner;
        };
        """
        current = read_int_from_memory(clocksource)
        for i in range(7, 20):
            candidate_offset = i * runtime.current_arch.ptrsize
            v = read_int_from_memory(current - candidate_offset)
            if is_valid_addr(v):
                return candidate_offset
        return None

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        clocksource_list = KernelAddressHeuristicFinder.get_clocksource_list()
        if clocksource_list is None:
            self.quiet_err("Could not find clocksource_list")
            return
        self.quiet_info("clocksource_list: {:#x}".format(clocksource_list))

        offset_list = self.get_offset_list(clocksource_list)
        if offset_list is None:
            return
        self.quiet_info("offsetof(clocksource, list): {:#x}".format(offset_list))

        self.out = []
        width = AddressUtil.get_format_address_width()
        if not args.quiet:
            fmt = "{:<{:d}s} {:20s} {:<{:d}s} {:<{:d}s}"
            legend = ["address", width, "name", "read", width, "symbol", width]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        current = read_int_from_memory(clocksource_list)
        while current != clocksource_list:
            cs = current - offset_list
            read = read_int_from_memory(cs)
            read_sym = Symbol.get_symbol_string(read, nosymbol_string=" <NO_SYMBOL>")
            name_addr = read_int_from_memory(current - runtime.current_arch.ptrsize)
            name = read_cstring_from_memory(name_addr)
            self.out.append("{:#0{:d}x} {:20s} {:#0{:d}x}{:s}".format(cs, width, name, read, width, read_sym))
            current = read_int_from_memory(current)

        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelTimerCommand(GenericCommand, BufferingOutput):
    """Dump the timer."""

    _cmdline_ = "ktimer"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified timer structure (per-cpu):",
        "",
        "+-timer_bases[0]----+    +-timer_list--+    +-timer_list--+",
        "| ...               |    | entry       |    | entry       |",
        "| vectors[0]        |--->|   next      |--->|   next      |--->...",
        "| ...               |    |   pprev     |    |   pprev     |",
        "| vectors[512or576] |    | expires     |    | expires     |",
        "| ...               |    | function    |    | function    |",
        "+-timer_bases[1]----+    | ...         |    | ...         |",
        "| ...               |    +-------------+    +-------------+",
        "| vectors[0]        |",
        "| ...               |",
        "| vectors[512or576] |",
        "| ...               |",
        "+-------------------+",
        "",
        "Simplified hrtimer structure (per-cpu):",
        "",
        "+-hrtimer_cpu_bases-+",
        "| ...               |",
        "| clock_bases[0]    |   +--->+-hrtimer------+",
        "|   ...             |   |    | node         |",
        "|   clockid         |   |    |   node       |",
        "|   ...             |   |    |     color    |",
        "|   active          |   |    |     right    |--->hrtimer",
        "|      rb_root      |   |    |     left     |--->hrtimer",
        "|        rb_root    |---+    |   expires    |",
        "|        ...        |        | ...          |",
        "|   get_time        |        | function     |",
        "|   ...             |        | ...          |",
        "| ...               |        +--------------+",
        "| clock_bases[8]    |",
        "|   ...             |",
        "+-------------------+",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self):
        from gef.commands.kernel.basic import KernelCurrentCommand
        if hasattr(self, "initialized") and self.initialized:
            return True

        # resolve __per_cpu_offset
        __per_cpu_offset = KernelAddressHeuristicFinder.get_per_cpu_offset()
        if __per_cpu_offset is None:
            self.quiet_info("__per_cpu_offset: Not found")
            self.cpu_offset = []
        else:
            self.quiet_info("__per_cpu_offset: {:#x}".format(__per_cpu_offset))
            self.cpu_offset = KernelCurrentCommand.get_each_cpu_offset(__per_cpu_offset)

        ### classic timer (unit: tick)

        # timer_bases
        self.timer_bases = KernelAddressHeuristicFinder.get_timer_bases()
        if not self.timer_bases:
            self.quiet_err("timer_bases: Not found")
            return False
        self.quiet_info("timer_bases: {:#x}".format(self.timer_bases))

        # per_cpu_timer_bases
        if self.cpu_offset == []:
            self.per_cpu_timer_bases = [self.timer_bases]
        else:
            self.per_cpu_timer_bases = [AddressUtil.normalize_address(x + self.timer_bases) for x in self.cpu_offset]

        # len(timer_bases)
        if Symbol.get_ksymaddr("sysctl_timer_migration"):
            self.nr_bases = 2
        else:
            self.nr_bases = 1
        self.quiet_info("nr_bases: {:d}".format(self.nr_bases))

        # sizeof(struct timer_base)
        """
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
        self.roughly_sizeof_timer_base = 0
        if self.nr_bases == 2:
            timer_base = self.per_cpu_timer_bases[0]

            i = 512
            while True:
                v = read_int_from_memory(timer_base + runtime.current_arch.ptrsize * i)
                if v != 0 and not is_valid_addr(v):
                    self.roughly_sizeof_timer_base = runtime.current_arch.ptrsize * i
                    break
                i += 1

        # jiffies
        self.jiffies = KernelAddressHeuristicFinder.get_jiffies()
        if not self.jiffies:
            self.quiet_err("jiffies: Not found")
            return False
        self.quiet_info("jiffies: {:#x}".format(self.jiffies))

        ### High-resolution kernel timer (unit: nano seconds)

        # hrtimer_bases
        self.hrtimer_bases = KernelAddressHeuristicFinder.get_hrtimer_bases()
        if not self.hrtimer_bases:
            self.quiet_err("hrtimer_bases: Not found")
            return False
        self.quiet_info("hrtimer_bases: {:#x}".format(self.hrtimer_bases))

        # per_cpu_hrtimer_bases
        if self.cpu_offset == []:
            self.per_cpu_hrtimer_cpu_bases = [self.hrtimer_bases]
        else:
            self.per_cpu_hrtimer_cpu_bases = [AddressUtil.normalize_address(x + self.hrtimer_bases) for x in self.cpu_offset]

        """
        struct hrtimer_cpu_base {
            raw_spinlock_t lock;
            unsigned int cpu;
            unsigned int active_bases;
            unsigned int clock_was_set_seq;
            unsigned int hres_active : 1,
                         in_hrtirq : 1,
                         hang_detected : 1,
                         softirq_activated : 1;
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
            struct hrtimer_clock_base {
                struct hrtimer_cpu_base *cpu_base;
                unsigned int index;
                clockid_t clockid;
                seqcount_raw_spinlock_t seq; // v4.16~
                struct hrtimer *running; // v4.16~
                struct timerqueue_head {
                    struct rb_root_cached {          // v5.4~
                        struct rb_root rb_root;      // v5.4~
                        struct rb_node *rb_leftmost; // v5.4~
                    } rb_root;                       // v5.4~
                    struct rb_root head;             // ~v5.3
                    struct timerqueue_node *next;    // ~v5.3
                } active;
                ktime_t (*get_time)(void); // ~v6.17
                ktime_t offset;
            } __hrtimer_clock_base_align clock_base[HRTIMER_MAX_CLOCK_BASES];
        } ____cacheline_aligned;

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
                {
                    .index = HRTIMER_BASE_TAI,
                    .clockid = CLOCK_TAI,
                    .get_time = &ktime_get_clocktai,
                },
                {                                         // v4.16~
                    .index = HRTIMER_BASE_MONOTONIC_SOFT,
                    .clockid = CLOCK_MONOTONIC,
                    .get_time = &ktime_get,
                },
                {                                         // v4.16~
                    .index = HRTIMER_BASE_REALTIME_SOFT,
                    .clockid = CLOCK_REALTIME,
                    .get_time = &ktime_get_real,
                },
                {                                         // v4.16~
                    .index = HRTIMER_BASE_BOOTTIME_SOFT,
                    .clockid = CLOCK_BOOTTIME,
                    .get_time = &ktime_get_boottime,
                },
                {                                         // v4.16~
                    .index = HRTIMER_BASE_TAI_SOFT,
                    .clockid = CLOCK_TAI,
                    .get_time = &ktime_get_clocktai,
                },
            }
        };
        """

        hrtimer_cpu_base = self.per_cpu_hrtimer_cpu_bases[0]

        ktime_get = Symbol.get_ksymaddr("ktime_get")
        ktime_get_real = Symbol.get_ksymaddr("ktime_get_real")
        ktime_get_ofs = None
        ktime_get_real_ofs = None
        i = 0
        while True:
            ofs = runtime.current_arch.ptrsize * i
            try:
                v = read_int_from_memory(hrtimer_cpu_base + ofs)
            except gdb.MemoryError:
                self.quiet_err("Memory read error")
                return False
            if v == ktime_get:
                ktime_get_ofs = ofs
            elif v == ktime_get_real:
                ktime_get_real_ofs = ofs
            if ktime_get_ofs and ktime_get_real_ofs:
                break
            i += 1
        self.sizeof_hrtimer_clock_base = ktime_get_real_ofs - ktime_get_ofs

        clock_base_1 = ktime_get_ofs + runtime.current_arch.ptrsize + 8 # get_time, offset
        self.offset_clock_base = clock_base_1 - self.sizeof_hrtimer_clock_base
        self.offset_clockid = runtime.current_arch.ptrsize + 4 # cpu_base, index
        self.offset_get_time = ktime_get_ofs - self.offset_clock_base
        self.offset_rb_root = self.offset_get_time - runtime.current_arch.ptrsize * 2

        kversion = Kernel.kernel_version()
        if kversion < "4.16":
            self.num_of_clock_base = 4
        else:
            self.num_of_clock_base = 8

        self.initialized = True
        return True

    def parse_rb_node(self, rb_node):
        if not rb_node or not is_valid_addr(rb_node):
            return []

        right = read_int_from_memory(rb_node + runtime.current_arch.ptrsize * 1) & ~1 # remove RB_BLACK
        left = read_int_from_memory(rb_node + runtime.current_arch.ptrsize * 2) & ~1 # remove RB_BLACK

        ret = [rb_node]
        if right:
            ret += self.parse_rb_node(right)
        if left:
            ret += self.parse_rb_node(left)
        return ret

    def dump_hrtimer(self):
        """
        struct hrtimer {
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
        """

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

        for cpu, hrtimer_cpu_base in enumerate(self.per_cpu_hrtimer_cpu_bases):
            clock_base = hrtimer_cpu_base + self.offset_clock_base
            for base_n in range(self.num_of_clock_base):
                htb = clock_base + self.sizeof_hrtimer_clock_base * base_n
                clockid = read_int32_from_memory(htb + self.offset_clockid)
                get_time = read_int_from_memory(htb + self.offset_get_time)
                self.out.append(titlify("cpu{:d} hrtimer_clock_base[{:d}]: {:#x}  [{:s}; get_time: {:#x}{:s}]".format(
                    cpu, base_n, htb,
                    clockid_dict.get(clockid, "UNKNOWN"),
                    get_time,
                    Symbol.get_symbol_string(get_time, nosymbol_string=" <NO_SYMBOL>"),
                ).rstrip()))

                # print legend
                if not self.args.quiet:
                    fmt = "{:18s}  {:18s}  {:23s}  {:18s} {:s}"
                    legend = ["hrtimer", "expires", "time_to_expired", "function", "symbol"]
                    self.out.append(GefUtil.make_legend(fmt.format(*legend)))

                rb_node = read_int_from_memory(htb + self.offset_rb_root)
                for hrtimer in self.parse_rb_node(rb_node):
                    expires = read_int64_from_memory(hrtimer + runtime.current_arch.ptrsize * 3)
                    function = read_int_from_memory(hrtimer + runtime.current_arch.ptrsize * 3 + 8 * 2)
                    if is_32bit() and not is_valid_addr(function):
                        expires = read_int64_from_memory(hrtimer + runtime.current_arch.ptrsize * 3 + 4)
                        function = read_int_from_memory(hrtimer + runtime.current_arch.ptrsize * 3 + 4 + 8 * 2)
                    self.out.append("{:#018x}  {:#018x}  {:23s}  {:#018x}{:s}".format(
                        hrtimer, expires,
                        "? (too hard to calc)",
                        function,
                        Symbol.get_symbol_string(function, nosymbol_string=" <NO_SYMBOL>"),
                    ).rstrip())
        return

    def dump_timer(self):
        """
        struct timer_list {
            struct hlist_node entry;
            unsigned long expires;
            void (*function)(struct timer_list *);
            u32 flags;
        #ifdef CONFIG_LOCKDEP
            struct lockdep_map lockdep_map;
        #endif
        };
        """

        jiffies = read_int_from_memory(self.jiffies)

        for cpu, timer_base in enumerate(self.per_cpu_timer_bases):
            # dump timer_list
            for base_n in range(self.nr_bases):
                tb = timer_base + self.roughly_sizeof_timer_base * base_n
                self.out.append(titlify("cpu{:d} timer_base[{:d}]: {:#x}".format(cpu, base_n, tb)))

                # print legend
                if not self.args.quiet:
                    fmt = "{:18s}  {:18s}  {:23s}  {:18s} {:s}"
                    legend = ["timer_list", "expires", "time_to_expired", "function", "symbol"]
                    self.out.append(GefUtil.make_legend(fmt.format(*legend)))

                i = 0
                while True:
                    addr = tb + runtime.current_arch.ptrsize * i
                    try:
                        v = read_int_from_memory(addr)
                    except gdb.MemoryError:
                        self.err_add_out("Memory read error")
                        return

                    if v == 0:
                        i += 1
                        continue

                    if i < 512:
                        if not is_valid_addr(v):
                            i += 1
                            continue
                        if read_int_from_memory(v + runtime.current_arch.ptrsize) != addr:
                            i += 1
                            continue
                    else:
                        if not is_valid_addr(v):
                            break
                        if read_int_from_memory(v + runtime.current_arch.ptrsize) != addr:
                            break

                    timer_list = v
                    expires = read_int_from_memory(timer_list + runtime.current_arch.ptrsize * 2)
                    function = read_int_from_memory(timer_list + runtime.current_arch.ptrsize * 3)
                    sym = Symbol.get_symbol_string(function, nosymbol_string=" <NO_SYMBOL>")
                    tte = expires - jiffies
                    self.out.append("{:#018x}  {:#018x}  {:#018x} tick  {:#018x}{:s}".format(
                        v, expires, tte, function, sym,
                    ).rstrip())
                    i += 1
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        kversion = Kernel.kernel_version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "4.8":
            err("Unsupported before v4.8")
            return
        if "6.18" <= kversion:
            # Read-write function pointers have been removed,
            # so there is no longer any point in displaying them with this command.
            err("Unsupported after v6.18")
            return

        self.quiet_info("Wait for memory scan")

        if not self.initialize():
            return

        self.out = []
        self.dump_timer()
        self.dump_hrtimer()
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
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "The information such as [T1] is the thread ID.",
        "Originally, this information is displayed when CONFIG_PRINTK_CALLER=y.",
        "However it is always displayed because it is useful.",
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
        "Simplified dmesg structure (~5.10):",
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
    ]
    _note_ = "\n".join(_note_)

    def dump_printk_ringbuffer(self, ring_buffer_name, ring_buffer_address):
        """
        # [v5.10~]
        struct printk_ringbuffer {
            struct prb_desc_ring {
                unsigned int count_bits;
                struct prb_desc* descs;
                struct printk_info* infos;
                atomic_long_t head_id;
                atomic_long_t tail_id;
                atomic_long_t last_finalized_id; // v5.18~
            } desc_ring;
            struct prb_data_ring {
                unsigned int size_bits;
                char* data;
                atomic_long_t head_lpos;
                atomic_long_t tail_lpos;
            } text_data_ring;
            atomic_long_t fail;
        };
        """

        current = ring_buffer_address
        rb = {}
        rb["desc_ring"] = {}
        rb["desc_ring"]["count_bits"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        rb["desc_ring"]["descs"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        rb["desc_ring"]["infos"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        rb["desc_ring"]["head_id"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        rb["desc_ring"]["tail_id"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        rb["text_data_ring"] = {}
        size_bits = read_int_from_memory(current)
        if size_bits > runtime.current_arch.ptrsize * 8:
            current += runtime.current_arch.ptrsize # last_finalized_id
            size_bits = read_int_from_memory(current)
        rb["text_data_ring"]["size_bits"] = size_bits
        current += runtime.current_arch.ptrsize
        rb["text_data_ring"]["data"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        rb["text_data_ring"]["head_lpos"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        rb["text_data_ring"]["tail_lpos"] = read_int_from_memory(current)
        current += runtime.current_arch.ptrsize
        rb["fail"] = read_int_from_memory(current)

        self.quiet_info("name: {:s}".format(ring_buffer_name))
        self.quiet_info("address: {:#x}".format(ring_buffer_address))
        self.quiet_info("desc_ring.count_bits: {:#x}".format(rb["desc_ring"]["count_bits"]))
        self.quiet_info("desc_ring.descs: {:#x}".format(rb["desc_ring"]["descs"]))
        self.quiet_info("desc_ring.infos: {:#x}".format(rb["desc_ring"]["infos"]))
        self.quiet_info("desc_ring.head_id: {:#x}".format(rb["desc_ring"]["head_id"]))
        self.quiet_info("desc_ring.tail_id: {:#x}".format(rb["desc_ring"]["tail_id"]))
        self.quiet_info("text_data_ring.size_bits: {:#x}".format(rb["text_data_ring"]["size_bits"]))
        self.quiet_info("text_data_ring.data: {:#x}".format(rb["text_data_ring"]["data"]))
        self.quiet_info("text_data_ring.head_lpos: {:#x}".format(rb["text_data_ring"]["head_lpos"]))
        self.quiet_info("text_data_ring.tail_lpos: {:#x}".format(rb["text_data_ring"]["tail_lpos"]))
        self.quiet_info("fail: {:#x}".format(rb["fail"]))

        def read_desc_i(descs_addr, seq):
            """
            struct prb_desc {
                atomic_long_t state_var;
                struct prb_data_blk_lpos {
                    unsigned long begin;
                    unsigned long next;
                } text_blk_lpos;
            };
            """
            sizeof_desc = runtime.current_arch.ptrsize * 3
            current = descs_addr + sizeof_desc * seq
            if not is_valid_addr(current):
                return False
            desc = {}
            desc["state_var"] = read_int_from_memory(current)
            desc["text_blk_lpos"] = {}
            current += runtime.current_arch.ptrsize
            desc["text_blk_lpos"]["begin"] = read_int_from_memory(current)
            current += runtime.current_arch.ptrsize
            desc["text_blk_lpos"]["next"] = read_int_from_memory(current)
            current += runtime.current_arch.ptrsize
            return desc

        kversion = Kernel.kernel_version()
        if "7.0" <= kversion:
            pmsg_load_execution_ctx_size = Kernel.get_func_size_kallsyms("pmsg_load_execution_ctx")
            if pmsg_load_execution_ctx_size and pmsg_load_execution_ctx_size >= 0x20:
                # CONFIG_PRINTK_EXECUTION_CTX=y
                sizeof_info = align_to_ptrsize(8 + 8 + 2 + 1 + 1 + 4 + 4 + 16 + 16 + 48)
            else:
                # CONFIG_PRINTK_EXECUTION_CTX=n
                sizeof_info = 8 + 8 + 2 + 1 + 1 + 4 + 16 + 48
        else:
            sizeof_info = 8 + 8 + 2 + 1 + 1 + 4 + 16 + 48

        def read_info_i(infos_addr, seq):
            """
            struct printk_info {
                u64 seq;        /* sequence number */
                u64 ts_nsec;    /* timestamp in nanoseconds */
                u16 text_len;   /* length of text message */
                u8 facility;    /* syslog facility */
                u8 flags:5;     /* internal record flags */
                u8 level:3;     /* syslog level */
                u32 caller_id;  /* thread id or processor id */
            #ifdef CONFIG_PRINTK_EXECUTION_CTX // v7.0~
                u32 caller_id2; /* caller_id complement */
                char comm[TASK_COMM_LEN]; // 16
            #endif
                struct dev_printk_info {
                    char subsystem[PRINTK_INFO_SUBSYSTEM_LEN]; // 16
                    char device[PRINTK_INFO_DEVICE_LEN]; // 48
                } dev_info;
            };
            """
            current = infos_addr + sizeof_info * seq
            if not is_valid_addr(current):
                return False
            info = {}
            info["seq"] = read_int64_from_memory(current)
            current += 8
            info["ts_nsec"] = read_int64_from_memory(current)
            current += 8
            info["text_len"] = read_int16_from_memory(current)
            current += 2
            info["facility"] = read_int8_from_memory(current)
            current += 1
            info["flags"] = read_int8_from_memory(current) & 0b11111
            info["level"] = (read_int8_from_memory(current) >> 5) & 0b111
            current += 1
            info["caller_id"] = read_int32_from_memory(current)
            current += 4
            info["dev_info"] = {}
            info["dev_info"]["subsystem"] = read_memory(current, 16)
            current += 16
            info["dev_info"]["device"] = read_memory(current, 48)
            current += 48
            return info

        seq_mask = (1 << rb["desc_ring"]["count_bits"]) - 1
        state_var_id_mask = ~(3 << (runtime.current_arch.ptrsize * 8 - 2))
        get_desc_state = lambda sv: (sv >> (runtime.current_arch.ptrsize * 8 - 2)) & 3
        size_bits = rb["text_data_ring"]["size_bits"]
        data_size_mask = (1 << size_bits) - 1

        info("Wait for reading records...")

        DESC_RESERVED = 0
        DESC_COMMITTED = 1
        DESC_FINALIZED = 2
        DESC_REUSABLE = 3

        seq = 0
        while True:
            # prb_read
            # - Read prb_desc and printk_info based on seq number.
            seq_based_desc = read_desc_i(rb["desc_ring"]["descs"], seq & seq_mask)
            seq_based_info = read_info_i(rb["desc_ring"]["infos"], seq & seq_mask)

            # desc_read_finalized_seq, desc_read
            # - Read prb_desc and printk_info based on id number.
            id = seq_based_desc["state_var"] & state_var_id_mask
            id_based_desc = read_desc_i(rb["desc_ring"]["descs"], id & seq_mask)
            id_based_info = read_info_i(rb["desc_ring"]["infos"], id & seq_mask)
            # - Determine whether it is the last entry based on the state and seq values.
            if (id_based_desc["state_var"] & state_var_id_mask) != id: # desc_miss
                break
            state = get_desc_state(id_based_desc["state_var"])
            if state == DESC_RESERVED:
                break
            if state == DESC_REUSABLE:
                if (id_based_desc["text_blk_lpos"]["begin"], id_based_desc["text_blk_lpos"]["next"]) == (1, 1):
                    break
                seq += 1
                continue
            if state not in (DESC_COMMITTED, DESC_FINALIZED):
                break
            if id_based_info["seq"] != seq:
                if seq == 0:
                    # ring buffer is already looping
                    seq = id_based_info["seq"]
                else:
                    break

            # copy_data, get_data
            # - Calculates the start address of text data from the begin and next values.
            begin = id_based_desc["text_blk_lpos"]["begin"]
            next = id_based_desc["text_blk_lpos"]["next"]
            if (begin >> size_bits) == (next >> size_bits) and (begin < next):
                src = rb["text_data_ring"]["data"] + (begin & data_size_mask)
            elif ((begin + (1 << size_bits)) >> size_bits) == (next >> size_bits):
                src = rb["text_data_ring"]["data"]
            else:
                raise
            size = seq_based_info["text_len"]
            src += runtime.current_arch.ptrsize
            if size:
                entry = String.bytes2str(read_memory(src, size))
            else:
                entry = ""

            # timestamp
            sec = seq_based_info["ts_nsec"] // 1000 // 1000 // 1000
            nsec = seq_based_info["ts_nsec"] % (1000 * 1000 * 1000)
            nsec_str = "{:09d}".format(nsec)[:6]
            # thread id. This is displayed when CONFIG_PRINTK_CALLER=y, but always displayed because it is useful.
            caller_id_str = "T{:d}".format(seq_based_info["caller_id"])
            # output
            formatted_entry = "[{:5d}.{:s}] [{:>6s}] {:s}".format(sec, nsec_str, caller_id_str, entry)
            self.out.append(formatted_entry)

            seq += 1
        return

    def dump_printk_log_buffer(self, log_first_idx, log_end_idx, buf_start, buf_end):
        """
        # [~v5.9]
        struct printk_log {
            u64 ts_nsec;        /* timestamp in nanoseconds */
            u16 len;            /* length of entire record */
            u16 text_len;       /* length of text buffer */
            u16 dict_len;       /* length of dictionary buffer */
            u8 facility;        /* syslog facility */
            u8 flags:5;         /* internal record flags */
            u8 level:3;         /* syslog level */
        #ifdef CONFIG_PRINTK_CALLER
            u32 caller_id;      /* thread id or processor id */
        #endif
        };
        """

        CONFIG_PRINTK_CALLER = Symbol.get_ksymaddr("print_caller") is not None
        length_of_caller_id = 4 if CONFIG_PRINTK_CALLER else 0
        sizeof_printk_log = 16 + length_of_caller_id

        pos = buf_start + log_first_idx
        log_end_pos = buf_start + log_end_idx

        while pos != log_end_pos:
            x = read_memory(pos, 16)
            ts_nsec = u64(x[:8])
            rec_len = u16(x[8:10])

            if rec_len == 0:
                pos = buf_start
                continue

            text_len = u16(x[10:12])
            #dict_len = u16(x[12:14])
            #facility = u8(x[14:15])
            #flags = (u8(x[15:16]) >> 0) & 0b11111
            #level = (u8(x[15:16]) >> 5) & 0b111
            text = read_memory(pos + sizeof_printk_log, text_len)

            sec = ts_nsec // 1000 // 1000 // 1000
            nsec = ts_nsec % (1000 * 1000 * 1000)
            nsec_str = "{:09d}".format(nsec)[:6]

            # split from multi-line message
            for t in String.bytes2str(text).splitlines():
                formatted_entry = "[{:5d}.{:s}] {:s}".format(sec, nsec_str, t)
                self.out.append(formatted_entry)

            pos += rec_len
            if pos >= buf_end:
                break # something is wrong
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        if args.use_cache and hasattr(self, "cache") and self.cache:
            self.out = self.cache[::]
            self.print_output()
            return

        self.out = []

        kversion = Kernel.kernel_version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if "5.10" <= kversion:
            # new structure
            printk_rb_static = KernelAddressHeuristicFinder.get_printk_rb_static()
            if printk_rb_static is None:
                err("Could not find printk_rb_static")
                return
            self.dump_printk_ringbuffer("printk_rb_static", printk_rb_static)

        else:
            # old structure
            log_first_idx_ptr = KernelAddressHeuristicFinder.get_log_first_idx()
            if log_first_idx_ptr is None:
                err("Could not find log_first_idx")
                return
            self.quiet_info("log_first_idx: {:#x}".format(log_first_idx_ptr))

            log_next_idx_ptr = KernelAddressHeuristicFinder.get_log_next_idx()
            if log_next_idx_ptr is None:
                err("Could not find log_next_idx")
                return
            self.quiet_info("log_next_idx: {:#x}".format(log_next_idx_ptr))

            log_buf_start = KernelAddressHeuristicFinder.get___log_buf()
            if log_buf_start is None:
                err("Could not find __log_buf")
                return
            self.quiet_info("__log_buf: {:#x}".format(log_buf_start))

            log_buf_len_ptr = KernelAddressHeuristicFinder.get_log_buf_len()
            if log_buf_len_ptr is None:
                err("Could not find log_buf_len")
                return
            self.quiet_info("log_buf_len: {:#x}".format(log_buf_len_ptr))

            log_first_idx = read_int32_from_memory(log_first_idx_ptr)
            log_next_idx = read_int32_from_memory(log_next_idx_ptr)
            log_buf_len = read_int32_from_memory(log_buf_len_ptr)
            log_buf_end = log_buf_start + log_buf_len
            self.quiet_info("*log_first_idx: {:#x}".format(log_first_idx))
            self.quiet_info("*log_next_idx: {:#x}".format(log_next_idx))
            self.quiet_info("*log_buf_len: {:#x}".format(log_buf_len))
            self.dump_printk_log_buffer(log_first_idx, log_next_idx, log_buf_start, log_buf_end)

        self.print_output()
        self.cache = self.out[::]
        return



@register_command
class SyscallTableViewCommand(GenericCommand, BufferingOutput):
    """Display syscall_table entries."""

    _cmdline_ = "syscall-table-view"
    _category_ = "06-g. Qemu-system/KGDB Cooperation - Linux Advanced"
    _aliases_ = ["kst"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="REGEXP filter.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} --filter write",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @switch_to_intel_syntax
    def parse_syscall_table(self, sys_call_table_addr):
        # scan
        cached_table = []
        i = 0
        while True:
            addr = sys_call_table_addr + i * runtime.current_arch.ptrsize
            if not is_valid_addr(addr):
                break
            syscall_function_addr = read_int_from_memory(addr)
            if (is_arm32() or is_arm64()) and syscall_function_addr % 4: # should be aligned
                break
            if not is_valid_addr(syscall_function_addr): # if entry is valid, no error
                break

            # check symbol
            symbol = Symbol.get_symbol_string(syscall_function_addr)
            if symbol is None:
                symbol = Symbol.get_ksymaddr_symbol(syscall_function_addr)
                if symbol is None:
                    symbol = " <NO_SYMBOL>"
            elif "+" in symbol:
                break

            # check if valid insn or not
            insn = get_insn(syscall_function_addr)
            insn2 = get_insn_next(syscall_function_addr)
            if insn is None or insn2 is None:
                break

            if is_x86():
                # detect endbr, so slide
                if insn.mnemonic in ["endbr64", "endbr32"]:
                    codelen = len(insn.opcodes)
                    insn2 = get_insn_next(insn.address + codelen)
                    insn = get_insn(insn.address + codelen)

                # detect `call non-essential-function` e.g., perf, trace, debug, ...
                while insn and insn2 and insn.mnemonic == "call":
                    codelen = len(insn.opcodes)
                    insn2 = get_insn_next(insn.address + codelen)
                    insn = get_insn(insn.address + codelen)

            elif is_arm64():
                # detect bti, so slide
                if insn.mnemonic in ["bti"]:
                    codelen = len(insn.opcodes)
                    insn2 = get_insn_next(insn.address + codelen)
                    insn = get_insn(insn.address + codelen)

                # detect `bl non-essential-function` e.g., perf, trace, debug, ...
                while insn and insn2 and insn.mnemonic == "bl":
                    codelen = len(insn.opcodes)
                    insn2 = get_insn_next(insn.address + codelen)
                    insn = get_insn(insn.address + codelen)

            elif is_arm32():
                # detect `bl non-essential-function` e.g., perf, trace, debug, ...
                while insn and insn2 and insn.mnemonic in ["bl", "blx"]:
                    codelen = len(insn.opcodes)
                    insn2 = get_insn_next(insn.address + codelen)
                    insn = get_insn(insn.address + codelen)

            # check again
            if insn is None or insn2 is None:
                break

            # check if the target system call is disabled
            is_valid = True
            if is_x86():
                if is_x86_64():
                    err = "0xffffffffffffffda"
                else:
                    err = "0xffffffda"
                if len(insn.operands) == 2 and insn.operands[-1] == err:
                    if insn2.mnemonic == "ret":
                        is_valid = False
                    elif insn2.mnemonic == "jmp":
                        try:
                            insn3 = get_insn(AddressUtil.parse_address(insn2.operands[-1]))
                            if insn3 and insn3.mnemonic == "ret":
                                is_valid = False
                        except (gdb.error, ValueError):
                            pass
            elif is_arm64():
                if len(insn.operands) == 2 and insn.operands[-1].split("\t")[0].strip() == "#0xffffffffffffffda":
                    is_valid = False
                elif len(insn.operands) == 3 and insn.operands[-1] == "// #-38":
                    is_valid = False

            cached_table.append([i, addr, syscall_function_addr, symbol, is_valid])
            i += 1
        return cached_table

    def syscall_table_view(self, orig_tag, sys_call_table_addr, syscall_list, nr_base=0):
        if syscall_list is None:
            self.quiet_add_out("{} {}".format(Color.colorify("[+]", "bold red"), "Could not find the syscall table"))
            return

        if sys_call_table_addr is None:
            self.quiet_add_out("{} {}".format(Color.colorify("[+]", "bold red"), "Could not find the symbol"))
            return

        # It maintains the cache both when running with and without symbols.
        try:
            AddressUtil.parse_address("_stext")
            tag = "symboled_" + orig_tag
        except gdb.error:
            tag = orig_tag

        # parse
        if tag not in self.cached_table:
            self.cached_table[tag] = self.parse_syscall_table(sys_call_table_addr)

        # print legend
        if not self.args.quiet:
            fmt = "{:8s} {:5s} {:7s} {:30s} {:18s} {:18s} {:s}"
            legend = ["Tag", "Index", "IsValid", "Syscall Name", "Table Address", "Function Address", "Symbol"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # for duplication check
        seen_count = {}
        for _, _, syscall_function_addr, _, _ in self.cached_table[tag]:
            seen_count[syscall_function_addr] = seen_count.get(syscall_function_addr, 0) + 1

        # print
        for i, addr, syscall_function_addr, symbol, is_valid in self.cached_table[tag]:
            nr = nr_base + i
            if nr in syscall_list.nr_table:
                expected_name = syscall_list.nr_table[nr].name
            else:
                expected_name = "<UNDEFINED_IN_THIS_ARCH>"

            fmt = "{:8s} [{:03d}] {:7s} {:30s} {:#018x} {:#018x}{:s}"
            if seen_count[syscall_function_addr] == 1 and is_valid: # valid entry
                msg = fmt.format(orig_tag, i, "valid", expected_name, addr, syscall_function_addr, symbol)
            if seen_count[syscall_function_addr] > 1 or not is_valid: # invalid entry
                msg = fmt.format(orig_tag, i, "invalid", expected_name, addr, syscall_function_addr, symbol)
                msg = Color.grayify(msg)

            if not self.args.filter:
                self.out.append(msg)
            else:
                for re_pattern in self.args.filter:
                    if re_pattern.search(msg):
                        self.out.append(msg)
        return

    def dump_syscall_table(self):
        if is_x86_32():
            self.quiet_add_out(titlify("sys_call_table (x86)"))
            sys_call_table_addr = KernelAddressHeuristicFinder.get_sys_call_table_x86()
            self.syscall_table_view("x86", sys_call_table_addr, Syscall.get_syscall_table("X86", "N32"))

        elif is_x86_64():
            self.quiet_add_out(titlify("sys_call_table (x64)"))
            sys_call_table_addr = KernelAddressHeuristicFinder.get_sys_call_table_x64()
            self.syscall_table_view("x86_64", sys_call_table_addr, Syscall.get_syscall_table("X86", "64"))

            kversion = Kernel.kernel_version()

            self.quiet_add_out(titlify("ia32_sys_call_table"))
            if kversion < "6.6.26":
                sys_call_table_addr = KernelAddressHeuristicFinder.get_sys_call_table_x86()
                self.syscall_table_view("x86_32", sys_call_table_addr, Syscall.get_syscall_table("X86", "32"))
            else:
                self.quiet_add_out("ia32_sys_call_table is removed from 6.6.26.")
                self.quiet_add_out("each entry is embedded in `ia32_sys_call()` as call instruction.")

            self.quiet_add_out(titlify("x32_sys_call_table"))
            if kversion < "6.6.26":
                sys_call_table_addr = KernelAddressHeuristicFinder.get_sys_call_table_x32()
                self.syscall_table_view("x86_x32", sys_call_table_addr, Syscall.get_syscall_table("X86", "64"), nr_base=0x4000_0000)
            else:
                self.quiet_add_out("x32_sys_call_table is removed from 6.6.26.")
                self.quiet_add_out("each entry is embedded in `x32_sys_call()` as call instruction.")

        elif is_arm32():
            self.quiet_add_out(titlify("sys_call_table (arm32)"))
            sys_call_table_addr = KernelAddressHeuristicFinder.get_sys_call_table_arm32()
            self.syscall_table_view("arm32", sys_call_table_addr, Syscall.get_syscall_table("ARM", "N32"))

        elif is_arm64():
            self.quiet_add_out(titlify("sys_call_table (arm64)"))
            sys_call_table_addr = KernelAddressHeuristicFinder.get_sys_call_table_arm64()
            self.syscall_table_view("arm64", sys_call_table_addr, Syscall.get_syscall_table("ARM64", "ARM"))

            self.quiet_add_out(titlify("compat_sys_call_table (arm32)"))
            sys_call_table_addr = KernelAddressHeuristicFinder.get_sys_call_table_arm64_compat()
            self.syscall_table_view("arm64_32", sys_call_table_addr, Syscall.get_syscall_table("ARM", "32"))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if not hasattr(self, "cached_table"):
            self.cached_table = {}

        self.out = []
        self.dump_syscall_table()
        self.print_output(check_terminal_size=True)
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

    def parse_xarray(self, ptr, root=False):
        if ptr == 0:
            return []

        ptr &= ~3 # untagged

        if root:
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

    def initialize(self):
        # get global address
        prog_idr = KernelAddressHeuristicFinder.get_prog_idr()
        if not prog_idr:
            return False
        self.quiet_info("prog_idr: {:#x}".format(prog_idr))

        map_idr = KernelAddressHeuristicFinder.get_map_idr()
        if not map_idr:
            return False
        self.quiet_info("map_idr: {:#x}".format(map_idr))

        kversion = Kernel.kernel_version()

        """
        struct xarray {
            spinlock_t xa_lock;
            gfp_t xa_flags;
            void __rcu *xa_head;
        };
        """
        # idr->idr_rt->xa_head
        base = prog_idr + 4 * 2
        max_sizeof_idr = abs(prog_idr - map_idr)
        for i in range(20):
            pos = base + runtime.current_arch.ptrsize * i
            if (pos - prog_idr) >= max_sizeof_idr:
                continue
            x = read_int_from_memory(pos)
            if not is_valid_addr(x):
                continue
            if (x & 2) != 2: # tag
                continue
            y = read_cstring_from_memory(x)
            if y and len(y) > 8 or y == "bpf":
                continue
            z = read_int_from_memory(x)
            if is_valid_addr(z):
                continue
            self.offset_xa_head = pos - prog_idr
            self.quiet_info("offsetof(xarray, xa_head): {:#x}".format(self.offset_xa_head))
            break
        else:
            err("Could not find xa_head. (maybe uninitialized?)")
            return False

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
        self.quiet_info("offsetof(xa_node, shift): {:#x}".format(self.offset_shift))
        self.quiet_info("offsetof(xa_node, count): {:#x}".format(self.offset_count))
        self.quiet_info("offsetof(xa_node, slots): {:#x}".format(self.offset_slots))

        # parse progs, maps
        try:
            progs = self.parse_xarray(prog_idr, root=True)
            self.quiet_info("Num of progs: {:#x}".format(len(progs)))
            maps = self.parse_xarray(map_idr, root=True)
            self.quiet_info("Num of maps: {:#x}".format(len(maps)))
        except gdb.MemoryError:
            self.quiet_err("Not found")
            return False

        """
        struct bpf_prog {
            u16 pages;
            u16 jited:1,
                jit_requested:1,
                gpl_compatible:1,
                cb_access:1,
                dst_needed:1,
                blinded:1,
                is_func:1,
                kprobe_override:1,
                has_callchain_buf:1,
                enforce_expected_attach_type:1,
                call_get_stack:1;
            enum bpf_prog_type type;
            enum bpf_attach_type expected_attach_type;
            u32 len;
            u32 jited_len;
            u8 tag[BPF_TAG_SIZE]; // 8 byte
            struct bpf_prog_stats __percpu *stats; // v5.12~
            int __percpu *active;                  // v5.12~
            unsigned int (*bpf_func)(const void *ctx, const struct bpf_insn *insn); // v5.12~
            struct bpf_prog_aux *aux;
            struct sock_fprog_kern *orig_prog;
            unsigned int (*bpf_func)(const void *ctx, const struct bpf_insn *insn); // ~v5.11
            const struct bpf_insn *insn);
            struct sock_filter insns[0];
            struct bpf_insn insnsi[];
        };
        """
        # bpf_prog->{type,expected_attach_type,len,jited_len,tag,aux}
        self.offset_prog_type = 4
        self.offset_expected_attach_type = self.offset_prog_type + 4
        self.offset_len = self.offset_expected_attach_type + 4
        self.offset_jited_len = self.offset_len + 4
        self.offset_tag = self.offset_jited_len + 4
        if "5.12" <= kversion:
            self.offset_aux = align_to_ptrsize(self.offset_tag + 8) + runtime.current_arch.ptrsize * 3
            self.offset_bpf_func = self.offset_aux - runtime.current_arch.ptrsize
        else:
            self.offset_aux = align_to_ptrsize(self.offset_tag + 8)
            self.offset_bpf_func = self.offset_aux + runtime.current_arch.ptrsize * 2
        self.offset_orig_prog = self.offset_aux + runtime.current_arch.ptrsize
        self.quiet_info("offsetof(bpf_prog, type): {:#x}".format(self.offset_prog_type))
        self.quiet_info("offsetof(bpf_prog, expected_attach_type): {:#x}".format(self.offset_expected_attach_type))
        self.quiet_info("offsetof(bpf_prog, len): {:#x}".format(self.offset_len))
        self.quiet_info("offsetof(bpf_prog, jited_len): {:#x}".format(self.offset_jited_len))
        self.quiet_info("offsetof(bpf_prog, tag): {:#x}".format(self.offset_tag))
        self.quiet_info("offsetof(bpf_prog, aux): {:#x}".format(self.offset_aux))
        self.quiet_info("offsetof(bpf_prog, bpf_func): {:#x}".format(self.offset_bpf_func))
        self.quiet_info("offsetof(bpf_prog, orig_prog): {:#x}".format(self.offset_orig_prog))

        try:
            self.seccomp_tools_command = [GefUtil.which("ceccomp"), "disasm", "-c", "always"]
            self.quiet_info("ceccomp is found")
        except FileNotFoundError:
            try:
                self.seccomp_tools_command = [GefUtil.which("seccomp-tools"), "disasm"]
                self.quiet_info("seccomp-tools is found")
                if is_arm32():
                    self.quiet_warn("`seccomp-tools` is not supported on ARM32. "
                                    "Consider using `ceccomp` instead, as it supports ARM32.")
                    self.quiet_info("GEF uses `capstone-disassemble bpf_func`")
                    self.seccomp_tools_command = None
            except FileNotFoundError:
                self.quiet_info("Could not find ceccomp or seccomp-tools, GEF uses `capstone-disassemble bpf_func`")
                self.seccomp_tools_command = None

        if maps:
            """
            struct bpf_map {
                const struct bpf_map_ops *ops ____cacheline_aligned;
                struct bpf_map *inner_map_meta;
            #ifdef CONFIG_SECURITY
                void *security;
            #endif
                enum bpf_map_type map_type;
                u32 key_size;
                u32 value_size;
                u32 max_entries;
                ...
            };
            """
            # bpf_map->{map_type,key_size,value_size,max_entries}
            cand = read_int_from_memory(maps[0] + runtime.current_arch.ptrsize * 2)
            if cand == 0 or is_valid_addr(cand):
                self.offset_map_type = runtime.current_arch.ptrsize * 3
            else:
                self.offset_map_type = runtime.current_arch.ptrsize * 2
            self.offset_key_size = self.offset_map_type + 4
            self.offset_value_size = self.offset_key_size + 4
            self.offset_max_entries = self.offset_value_size + 4
            self.quiet_info("offsetof(bpf_map, map_type): {:#x}".format(self.offset_map_type))
            self.quiet_info("offsetof(bpf_map, key_size): {:#x}".format(self.offset_key_size))
            self.quiet_info("offsetof(bpf_map, value_size): {:#x}".format(self.offset_value_size))
            self.quiet_info("offsetof(bpf_map, max_entries): {:#x}".format(self.offset_max_entries))

            """
            struct bpf_array {
                struct bpf_map map;
                u32 elem_size;
                u32 index_mask;
                struct bpf_array_aux *aux;
                union {
                    char value[0] __aligned(8);
                    void *ptrs[0] __aligned(8);
                    void __percpu *pptrs[0] __aligned(8);
                };
            };
            """
            # bpf_array->union_array
            value_size = read_int32_from_memory(maps[0] + self.offset_value_size)
            value_size_aligned_8 = align(value_size, 8)
            max_entries = read_int32_from_memory(maps[0] + self.offset_max_entries)
            k = 1
            while k < max_entries:
                k <<= 1
            index_mask = k - 1

            sizeof_cache_line = 0x40 # ?
            base = maps[0] + sizeof_cache_line * 3
            for i in range(100):
                pos = base + runtime.current_arch.ptrsize * i
                x = read_int32_from_memory(pos)
                y = read_int32_from_memory(pos + 4)
                if x == value_size_aligned_8 and y == index_mask:
                    self.offset_union_array = (pos - maps[0]) + 4 * 2 + runtime.current_arch.ptrsize
                    self.quiet_info("offsetof(bpf_array, union_array): {:#x}".format(self.offset_union_array))
                    break
            else:
                return False
        return progs, maps

    def dump_bpf_progs(self, progs):
        self.out.append(titlify("prog_idr"))
        fmt = "{:3s} {:18s} {:23s} {:24s} {:18s} {:18s} {:18s} {:9s} {:18s}"
        legend = ["#", "bpf_prog", "bpf_prog_type", "bpf_attach_type", "tag", "bpf_prog_aux", "bpf_func", "jited_len", "orig_prog"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        defined_prog_types = [
            "UNSPEC",
            "SOCKET_FILTER",
            "KPROBE",
            "SCHED_CLS",
            "SCHED_ACT",
            "TRACEPOINT",
            "XDP",
            "PERF_EVENT",
            "CGROUP_SKB",
            "CGROUP_SOCK",
            "LWT_IN",
            "LWT_OUT",
            "LWT_XMIT",
            "SOCK_OPS",
            "SK_SKB",
            "CGROUP_DEVICE",
            "SK_MSG",
            "RAW_TRACEPOINT",
            "CGROUP_SOCK_ADDR",
            "LWT_SEG6LOCAL",
            "LIRC_MODE2",
            "SK_REUSEPORT",
            "FLOW_DISSECTOR",
            "CGROUP_SYSCTL",
            "RAW_TRACEPOINT_WRITABLE",
            "CGROUP_SOCKOPT",
            "TRACING",
            "STRUCT_OPS",
            "EXT",
            "LSM",
            "SK_LOOKUP",
        ]

        defined_attach_types = [
            "CGROUP_INET_INGRESS",
            "CGROUP_INET_EGRESS",
            "CGROUP_INET_SOCK_CREATE",
            "CGROUP_SOCK_OPS",
            "SK_SKB_STREAM_PARSER",
            "SK_SKB_STREAM_VERDICT",
            "CGROUP_DEVICE",
            "SK_MSG_VERDICT",
            "CGROUP_INET4_BIND",
            "CGROUP_INET6_BIND",
            "CGROUP_INET4_CONNECT",
            "CGROUP_INET6_CONNECT",
            "CGROUP_INET4_POST_BIND",
            "CGROUP_INET6_POST_BIND",
            "CGROUP_UDP4_SENDMSG",
            "CGROUP_UDP6_SENDMSG",
            "LIRC_MODE2",
            "FLOW_DISSECTOR",
            "CGROUP_SYSCTL",
            "CGROUP_UDP4_RECVMSG",
            "CGROUP_UDP6_RECVMSG",
            "CGROUP_GETSOCKOPT",
            "CGROUP_SETSOCKOPT",
            "TRACE_RAW_TP",
            "TRACE_FENTRY",
            "TRACE_FEXIT",
            "MODIFY_RETURN",
            "LSM_MAC",
            "TRACE_ITER",
            "CGROUP_INET4_GETPEERNAME",
            "CGROUP_INET6_GETPEERNAME",
            "CGROUP_INET4_GETSOCKNAME",
            "CGROUP_INET6_GETSOCKNAME",
            "XDP_DEVMAP",
            "CGROUP_INET_SOCK_RELEASE",
            "XDP_CPUMAP",
            "SK_LOOKUP",
            "XDP",
        ]

        fmt = "{:<3d} {:#018x} {:23s} {:24s} {:#018x} {:#018x} {:#018x} {:<#9x} {:#018x}"
        for i, prog in enumerate(progs):
            bpf_type = read_int32_from_memory(prog + self.offset_prog_type)
            bpf_attach_type = read_int32_from_memory(prog + self.offset_expected_attach_type)
            jited_len = read_int32_from_memory(prog + self.offset_jited_len)
            orig_prog = read_int_from_memory(prog + self.offset_orig_prog)
            t1 = defined_prog_types[bpf_type]
            t2 = defined_attach_types[bpf_attach_type]
            tag = read_int64_from_memory(prog + self.offset_tag)
            aux = read_int_from_memory(prog + self.offset_aux)
            bpf_func = read_int_from_memory(prog + self.offset_bpf_func)
            self.out.append(fmt.format(i, prog, t1, t2, tag, aux, bpf_func, jited_len, orig_prog))

            if self.args.verbose:
                # dump func
                if self.seccomp_tools_command and is_valid_addr(orig_prog):
                    # use seccomp-tools or ceccomp
                    cnt = read_int16_from_memory(orig_prog)
                    prog = read_int_from_memory(orig_prog + runtime.current_arch.ptrsize)
                    data = read_memory(prog, cnt * 8)
                    tmp_fd, tmp_path = GefUtil.mkstemp(prefix="kbpf")
                    os.fdopen(tmp_fd, "wb").write(data)
                    ret = GefUtil.gef_execute_external(
                        self.seccomp_tools_command + [tmp_path], as_list=True,
                    )
                    self.out.extend(ret)
                    os.unlink(tmp_path)
                elif is_valid_addr(bpf_func):
                    try:
                        __import__("capstone")
                        # use capstone
                        data = read_memory(bpf_func, jited_len)
                        dump_count = 0
                        for insn in Disasm.capstone_disassemble(bpf_func, jited_len, code=data.hex()):
                            msg = insn.colored_text(10)
                            self.out.append(msg)
                            dump_count += insn.size
                            if dump_count >= jited_len:
                                break
                    except ImportError:
                        ret = gdb.execute("x/40i {:#x}".format(bpf_func), to_string=True).rstrip()
                        self.out.append(ret)
                        self.out.append("...")
                else:
                    self.err_add_out("Memory read error")
                self.out.append(titlify(""))
        return

    def dump_bpf_maps(self, maps):
        self.out.append(titlify("map_idr"))
        fmt = "{:3s} {:18s} {:21s} {:10s} {:10s} {:10s} {:18s}"
        legend = ["#", "bpf_map", "bpf_map_type", "key_size", "value_size", "max_ents", "array"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        defined_map_types = [
            "UNSPEC",
            "HASH",
            "ARRAY",
            "PROG_ARRAY",
            "PERF_EVENT_ARRAY",
            "PERCPU_HASH",
            "PERCPU_ARRAY",
            "STACK_TRACE",
            "CGROUP_ARRAY",
            "LRU_HASH",
            "LRU_PERCPU_HASH",
            "LPM_TRIE",
            "ARRAY_OF_MAPS",
            "HASH_OF_MAPS",
            "DEVMAP",
            "SOCKMAP",
            "CPUMAP",
            "XSKMAP",
            "SOCKHASH",
            "CGROUP_STORAGE",
            "REUSEPORT_SOCKARRAY",
            "PERCPU_CGROUP_STORAGE",
            "QUEUE",
            "STACK",
            "SK_STORAGE",
            "DEVMAP_HASH",
            "STRUCT_OPS",
            "RINGBUF",
            "INODE_STORAGE",
        ]

        fmt = "{:<3d} {:#018x} {:21s} {:#010x} {:#010x} {:#010x} {:#018x}"
        for i, m in enumerate(maps):
            map_type = read_int32_from_memory(m + self.offset_map_type)
            t1 = defined_map_types[map_type]
            key_size = read_int32_from_memory(m + self.offset_key_size)
            val_size = read_int32_from_memory(m + self.offset_value_size)
            max_ents = read_int32_from_memory(m + self.offset_max_entries)
            union_array = m + self.offset_union_array
            self.out.append(fmt.format(i, m, t1, key_size, val_size, max_ents, union_array))

            if self.verbose:
                if map_type == 2: # ARRAY
                    res = gdb.execute("dereference -n {:#x} {:#x}".format(union_array, max_ents), to_string=True)
                    self.out.append(res.rstrip())
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

        stv_bpf_ret = gdb.execute("syscall-table-view -f bpf --quiet --no-pager", to_string=True)
        if "bpf" not in stv_bpf_ret:
            self.quiet_err("bpf syscall is unimplemented")
            return
        elif "invalid bpf" in stv_bpf_ret:
            self.quiet_err("bpf syscall is disabled")
            return

        # init
        ret = self.initialize()
        if ret is False:
            self.quiet_err("Failed to initialize")
            return
        progs, maps = ret

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
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified irq structure:",
        "",
        "+-irq_desc_tree(~6.5)-+   +--->+-xa_node---------+   +--->+-irq_desc----+",
        "| xa_lock             |   |    | shift           |   |    | ...         |",
        "| xa_flags            |   |    | ...             |   |    | irq_data    |",
        "| xa_head             |---+    | count           |   |    |   ...       |",
        "+---------------------+        | ...             |   |    |   irq       |",
        "                               | slots[0]        |---+    |   ...       |",
        "                               | slots[1]        |   ^    | ...         |",
        "                               | ...             |   |    | action      |",
        "                               | slots[15 or 63] |   |    |   handler   |",
        "                               | ...             |   |    |   ...       |",
        "                               +-----------------+   |    |   name      |",
        "                                                     |    |   ...       |",
        "+-sparce_irq(6.5~)-+   +-->+-maple_node------+       |    | ...         |",
        "| ...              |   |   | ...             |       |    +-------------+",
        "| ma_root          |---+   | mr64|ma64|alloc |       |",
        "| ...              |       |   ...           |       |",
        "+------------------+       |   slot[]        |-------+",
        "                           +-----------------+",
    ]
    _note_ = "\n".join(_note_)

    def parse_xarray(self, ptr, root=False):
        if ptr == 0:
            return []

        ptr &= ~3 # untagged

        if root:
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

    class MapleTree:
        """Linux v6.5 introduces maple_tree to irq. This is a simple parser."""
        MT_FLAGS_HEIGHT_MASK = 0x7c
        MT_FLAGS_HEIGHT_OFFSET = 0x02
        MAPLE_NODE_TYPE_SHIFT = 0x03
        MAPLE_NODE_TYPE_MASK = 0x0f
        MAPLE_NODE_POINTER_MASK = 0xff
        MAPLE_DENSE = 0
        MAPLE_LEAF_64 = 1
        MAPLE_RANGE_64 = 2
        MAPLE_ARANGE_64 = 3

        def __init__(self, ptr):
            kversion = Kernel.kernel_version()

            # ____cacheline_aligned_in_smp attribute, spinlock_t and lockdep_map_p can be different size
            # in each environment or situation, so search heuristically.
            for i in range(0x10):
                x = read_int_from_memory(ptr + runtime.current_arch.ptrsize * i)
                """
                [x64 v6.4.2]
                0xffff8bedc104db00|+0x0000|+000: 0x0000000000000000   // union
                0xffff8bedc104db08|+0x0008|+001: 0xffff8bedc1a6601e   // ma_root
                0xffff8bedc104db10|+0x0010|+002: 0x000000000000030b   // ma_flags

                [x64 v6.6.1]
                0xffff972801b78a38|+0x0040|+008: 0x0000000000000000   // (the end of cacheline?)
                0xffff972801b78a40|+0x0040|+008: 0x0000030b00000000   // ma_flags || union
                0xffff972801b78a48|+0x0048|+009: 0xffff972801b0cc1e   // ma_root
                """
                if is_valid_addr(x) and (x & 0xff) in [0x1e, 0x0e]:
                    offset_ma_root = runtime.current_arch.ptrsize * i
                    if kversion < "6.6":
                        offset_ma_flags = offset_ma_root + runtime.current_arch.ptrsize
                    else:
                        offset_ma_flags = offset_ma_root - 4
                        if is_64bit() and read_int32_from_memory(ptr + offset_ma_flags) == 0:
                            offset_ma_flags = offset_ma_root - 8
                    break
            else:
                raise

            self.ma_root_raw = read_int_from_memory(ptr + offset_ma_root)
            self.ma_flags = read_int_from_memory(ptr + offset_ma_flags)
            self.max_depth = (self.ma_flags & self.MT_FLAGS_HEIGHT_MASK) >> self.MT_FLAGS_HEIGHT_OFFSET

            if is_64bit():
                self.MAPLE_NODE_SLOTS = 31
                self.MAPLE_RANGE64_SLOTS = 16
                self.MAPLE_ARANGE64_SLOTS = 10
                self.MAPLE_ALLOC_SLOTS = self.MAPLE_NODE_SLOTS - 1
                self.maple_range_64_offset_slot = runtime.current_arch.ptrsize * self.MAPLE_RANGE64_SLOTS
                self.maple_arange_64_offset_slot = runtime.current_arch.ptrsize * self.MAPLE_ARANGE64_SLOTS
                self.maple_alloc_offset_slot = runtime.current_arch.ptrsize * 2
            else:
                self.MAPLE_NODE_SLOTS = 63
                self.MAPLE_RANGE64_SLOTS = 32
                self.MAPLE_ARANGE64_SLOTS = 21
                self.MAPLE_ALLOC_SLOTS = self.MAPLE_NODE_SLOTS - 2
                self.maple_range_64_offset_slot = runtime.current_arch.ptrsize * self.MAPLE_RANGE64_SLOTS
                self.maple_arange_64_offset_slot = runtime.current_arch.ptrsize * self.MAPLE_ARANGE64_SLOTS
                self.maple_alloc_offset_slot = runtime.current_arch.ptrsize * 3

            self.seen = set()
            self.iters = self.parse_node(self.ma_root_raw, 1)
            return

        def parse_node(self, entry, depth):
            if entry in self.seen:
                return
            self.seen.add(entry)

            if self.max_depth < depth:
                return

            pointer = entry & ~(self.MAPLE_NODE_POINTER_MASK)
            node_type = (entry >> self.MAPLE_NODE_TYPE_SHIFT) & self.MAPLE_NODE_TYPE_MASK

            if node_type == self.MAPLE_DENSE:
                slot_top = pointer + self.maple_alloc_offset_slot
                for i in range(self.MAPLE_ALLOC_SLOTS):
                    slot = read_int_from_memory(slot_top + runtime.current_arch.ptrsize * i)
                    if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                        if is_valid_addr(slot):
                            yield slot
            elif node_type == self.MAPLE_LEAF_64:
                slot_top = pointer + self.maple_range_64_offset_slot
                for i in range(self.MAPLE_RANGE64_SLOTS):
                    slot = read_int_from_memory(slot_top + runtime.current_arch.ptrsize * i)
                    if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                        if is_valid_addr(slot):
                            yield slot
            elif node_type == self.MAPLE_RANGE_64:
                slot_top = pointer + self.maple_range_64_offset_slot
                for i in range(self.MAPLE_RANGE64_SLOTS):
                    slot = read_int_from_memory(slot_top + runtime.current_arch.ptrsize * i)
                    if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                        yield from self.parse_node(slot, depth + 1)
            elif node_type == self.MAPLE_ARANGE_64:
                slot_top = pointer + self.maple_arange_64_offset_slot
                for i in range(self.MAPLE_ARANGE64_SLOTS):
                    slot = read_int_from_memory(slot_top + runtime.current_arch.ptrsize * i)
                    if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                        yield from self.parse_node(slot, depth + 1)
            return

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            return True

        kversion = Kernel.kernel_version()

        if kversion < "6.5":
            self.irq_desc_tree = KernelAddressHeuristicFinder.get_irq_desc_tree()
            if self.irq_desc_tree is None:
                self.quiet_err("Could not find irq_desc_tree")
                return False

            for i in range(0, 10):
                # xa_head
                x = read_int_from_memory(self.irq_desc_tree + runtime.current_arch.ptrsize * i)
                if not x:
                    continue
                if not is_valid_addr(x):
                    continue
                if x & 0x2 != 0x2: # xa_head is NULL or tagged address
                    continue
                self.offset_xa_head = runtime.current_arch.ptrsize * i
                self.quiet_info("offsetof(xarray, xa_head): {:#x}".format(self.offset_xa_head))
                break
            else:
                self.quiet_err("Could not find xa_head. (maybe uninitialized?)")
                return False

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

            descs = self.parse_xarray(self.irq_desc_tree, root=True)

        else:
            # "6.5" <= kversion
            self.sparse_irqs = KernelAddressHeuristicFinder.get_sparse_irqs()
            if self.sparse_irqs is None:
                self.quiet_err("Could not find sparse_irqs")
                return False

            descs = list(self.MapleTree(self.sparse_irqs).iters)

        if not descs:
            self.quiet_err("Could not find any valid irq_desc")
            return False

        # irq_desc->{irq,action}
        """
        struct irq_desc {
            struct irq_common_data {
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
                u32 mask;
                unsigned int irq;
                unsigned long hwirq;
                struct irq_common_data *common;
                struct irq_chip *chip;
                struct irq_domain *domain;
            #ifdef CONFIG_IRQ_DOMAIN_HIERARCHY
                struct irq_data *parent_data;
            #endif
                void *chip_data;
            } irq_data;
            unsigned int __percpu *kstat_irqs;
            irq_flow_handler_t handle_irq;
            struct irqaction *action;
            unsigned int status_use_accessors;
            unsigned int core_internal_state__do_not_mess_with_it;
            ...
        };
        """

        if is_x86():
            desc = descs[0]
        else:
            # ARM may have invalid descs[irq=0]
            desc = descs[-1]
        self.quiet_info("desc: {:#x}".format(desc))

        for i in range(100):
            x = read_int_from_memory(desc + runtime.current_arch.ptrsize * i)
            if x == desc:
                if is_32bit():
                    self.offset_irq = runtime.current_arch.ptrsize * i - 8
                else:
                    self.offset_irq = runtime.current_arch.ptrsize * i - 12 # for padding
                self.quiet_info("offsetof(irq_desc, irq_data.irq): {:#x}".format(self.offset_irq))
                break
        else:
            self.quiet_err("Could not find irq_desc->irq_data.irq")
            return False

        ofs_irq = align_to_ptrsize(self.offset_irq + 4 * 2)
        for i in range(100):
            x = read_int_from_memory(desc + ofs_irq + runtime.current_arch.ptrsize * i)
            y = read_int_from_memory(desc + ofs_irq + runtime.current_arch.ptrsize * (i + 1))
            if not is_valid_addr(x) and not is_valid_addr(y):
                ofs_action_candidate = ofs_irq + runtime.current_arch.ptrsize * i - runtime.current_arch.ptrsize
                action_candidate = read_int_from_memory(desc + ofs_action_candidate)
                if is_valid_addr_addr(action_candidate):
                    self.offset_action = ofs_action_candidate
                    self.quiet_info("offsetof(irq_desc, action): {:#x}".format(self.offset_action))
                    break
        else:
            self.quiet_err("Could not find irq_desc->action")
            return False

        # irqaction->{handler,name}
        """
        struct irqaction {
            irq_handler_t handler;
            void *dev_id;
            void __percpu *percpu_dev_id;
            struct irqaction *next;
            irq_handler_t thread_fn;
            struct task_struct *thread;
            struct irqaction *secondary;
            unsigned int irq;
            unsigned int flags;
            unsigned long thread_flags;
            unsigned long thread_mask;
            const char *name;
            struct proc_dir_entry *dir;
        } ____cacheline_internodealigned_in_smp;
        """
        self.offset_handler = 0
        self.quiet_info("offsetof(irqaction, handler): {:#x}".format(self.offset_handler))

        action = read_int_from_memory(desc + self.offset_action)
        for i in range(100):
            x = read_int_from_memory(action + runtime.current_arch.ptrsize * i)
            if not is_valid_addr(x):
                continue
            s = read_cstring_from_memory(x)
            if s and len(s) >= 4:
                self.offset_name = runtime.current_arch.ptrsize * i
                self.quiet_info("offsetof(irqaction, name): {:#x}".format(self.offset_name))
                break
        else:
            self.quiet_err("Could not find irqaction->name")
            return False

        return True

    def dump_irq(self):
        kversion = Kernel.kernel_version()

        if kversion < "6.5":
            descs = self.parse_xarray(self.irq_desc_tree, root=True)
        else:
            descs = list(self.MapleTree(self.sparse_irqs).iters)

        entries = {}
        for desc in descs:
            irq = read_int32_from_memory(desc + self.offset_irq)
            action = read_int_from_memory(desc + self.offset_action)
            if action == 0:
                entries[irq] = [desc, action, None, None]
            else:
                handler = read_int_from_memory(action + self.offset_handler)
                name_ptr = read_int_from_memory(action + self.offset_name)
                name = read_cstring_from_memory(name_ptr) or "???"
                entries[irq] = [desc, action, handler, name]

        fmt = "{:3s} {:18s} {:18s} {:24s} {:18s}"
        legend = ["irq", "irq_desc", "action", "name", "handler"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for i in range(256):
            if i in entries:
                desc, action, handler, name = entries[i]
                if action:
                    symbol = Symbol.get_symbol_string(handler, nosymbol_string=" <NO_SYMBOL>")
                    self.out.append("{:3d} {:#018x} {:#018x} {:24s} {:#018x}{:s}".format(
                        i, desc, action, name, handler, symbol,
                    ).rstrip())
                else:
                    self.out.append("{:3d} {:#018x} {:18s} {:24s} {:18s}".format(
                        i, desc, "unused", "-", "-",
                    ).rstrip())
            else:
                if self.args.verbose:
                    self.out.append("{:3d} {:18s} {:18s} {:24s} {:18s}".format(
                        i, "unused", "unused", "-", "-",
                    ).rstrip())
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

        ret = self.initialize()
        if ret is False:
            return

        self.out = []
        self.dump_irq()
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
