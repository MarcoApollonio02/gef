"""GEF kernel commands (category 06-e) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Linux Symbol/Type: kernel/module loading, kernel
types (ktypes / ktypes-load), remote kallsyms (ksymaddr-remote), vmlinux-to-elf
apply and ksymaddr-remote-apply. Auto-discovered by gef.bootstrap via
pkgutil.walk_packages.
"""
import argparse
import configparser
import hashlib
import os
import re
import struct
import subprocess

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    only_if_in_kernel,
    only_if_in_kernel_or_kpti_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.cache import Cache
from gef.core.color import err, gef_print, info, titlify, warn
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.kernel import Kernel
from gef.core.memory import (
    is_ascii_string,
    is_valid_addr,
    p16,
    p32,
    p64,
    read_cstring_from_memory,
    read_int_from_memory,
    read_memory,
    u32,
)
from gef.core.pagewalk import KernelAddressHeuristicFinder
from gef.core.process import (
    get_pagesize,
    get_pagesize_mask_high,
    get_pagesize_mask_low,
    is_32bit,
    is_arm32,
    is_arm64,
    is_in_kernel,
    is_riscv32,
    is_riscv64,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import to_unsigned_long
from gef.core.strings import String
from gef.core.symbols import Symbol
from gef.core.utils import GEF_TEMP_DIR, GefUtil, align, slice_unpack, slicer


@register_command
class KernelLoadCommand(GenericCommand):
    """Load the vmlinux without a load address."""

    _cmdline_ = "kload"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("path", metavar="VMLINUX_PATH", type=str, help="path of the vmlinux.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    def do_invoke(self, args):
        if not os.path.exists(args.path):
            err("Invalid path")
            return

        info("Wait for memory scan")
        text_base = Kernel.get_kernel_base()
        if text_base is None:
            err("The kernel base is unknown")
            return

        gdb.execute("add-symbol-file {!r} {:#x}".format(args.path, text_base))
        return


@register_command
class KernelModuleLoadCommand(GenericCommand):
    """Load the kernel module without a load address."""

    _cmdline_ = "kmod-load"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("name", type=str, help="name of the loaded module to search for by `kmod`.")
    parser.add_argument("path", type=str, help="path to compiled kernel module.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} sample /path/to/sample.ko",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n.",
        "It is useful if you have a kernel module with debuginfo at hand.",
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
        for i in range(0x100):
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

    def get_offset_sect_attrs(self, module_addr):
        """
        struct module {
            ...
        #ifdef CONFIG_KALLSYMS
            struct mod_kallsyms __rcu *kallsyms;
            struct mod_kallsyms core_kallsyms;
            struct module_sect_attrs *sect_attrs;
            struct module_notes_attrs *notes_attrs;
        #endif
            ...
        };
        """
        # fast path
        try:
            offset_sect_attrs = to_unsigned_long(gdb.parse_and_eval("&((struct module*)0).sect_attrs"))
            # Taking for granted the information we get is accurate we can reliably retrieve module->sect_attrs
            sect_attrs = read_int_from_memory(module_addr + offset_sect_attrs)
            return offset_sect_attrs, sect_attrs
        except gdb.error:
            pass

        # slow_path
        for i in range(0x100):
            offset_sect_attrs = runtime.current_arch.ptrsize * i
            # access check
            if not is_valid_addr(module_addr + offset_sect_attrs):
                continue
            sect_attrs = read_int_from_memory(module_addr + offset_sect_attrs)
            if not self.is_valid_sect_attrs(sect_attrs):
                continue
            return offset_sect_attrs, sect_attrs

        return None, None

    """
    This function looks for the module->sect_attrs.grp.{attrs,bin_attrs} field,
    which is an array of pointers to the various structures `bin_attribute`
    that represent a the various sections. The array is guaranteed to terminate
    with a NULL pointer therefore we can safely use a while True to iterate the
    array in `is_valid_attribute_arr`.
    On recent systems module->sect_attrs.grp.attrs is 0 and the array of
    pointers is found in module->sect_attrs.grp.bin_attrs instead, but the
    logic is the same.
    """
    def is_valid_sect_attrs(self, sect_attrs):
        if not is_valid_addr(sect_attrs):
            return False
        # Check that the pointer is properly aligned
        if sect_attrs & (runtime.current_arch.ptrsize - 1):
            return False
        for offset in range(40):
            attribute_arr_ptr = read_int_from_memory(sect_attrs + offset * runtime.current_arch.ptrsize)
            if self.is_valid_attribute_arr(attribute_arr_ptr):
                return True
        return False

    @Cache.cache_until_next
    def is_valid_attribute_arr(self, attribute_arr_ptr):
        """
        struct module_sect_attrs {
            struct attribute_group {
                const char *name;
                umode_t (*is_visible)(struct kobject *, struct attribute *, int);
                umode_t (*is_bin_visible)(struct kobject *, struct bin_attribute *, int); // v4.4~
                size_t (*bin_size)(struct kobject *, const struct bin_attribute *, int); // v6.13~
                struct attribute **attrs;                          <--- here
                struct bin_attribute **bin_attrs; // v3.11~v6.12   <--- here
                union {
                    struct bin_attribute **bin_attrs;              <--- here
                    const struct bin_attribute *const *bin_attrs_new;
                }; // v6.13~
            } grp;
            unsigned int nsections; // ~v6.13
            struct module_sect_attr {
                struct bin_attribute battr; // v5.7~
                struct module_attribute mattr; // ~v5.6
                char *name; // ~v5.6
                unsigned long address;
            } attrs[]; // ~v6.13
            struct bin_attribute attrs[]; // v6.14~
        };

        struct attribute {
            const char *name;
            umode_t mode;
        #ifdef CONFIG_DEBUG_LOCK_ALLOC
            bool ignore_lockdep:1;
            struct lock_class_key *key;
            struct lock_class_key skey;
        #endif
        };

        struct bin_attribute { // v5.7~
            struct attribute attr;
            size_t size;
            void *private;
            struct address_space *(*f_mapping)(void); // v5.15~
            struct address_space *mapping; // v5.12~5.14
            ssize_t (*read)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
            ssize_t (*read_new)(struct file *, struct kobject *, const struct bin_attribute *, char *, loff_t, size_t); // v6.13~6.17
            ssize_t (*write)(struct file *, struct kobject *, struct bin_attribute *, char *, loff_t, size_t);
            ssize_t (*write_new)(struct file *, struct kobject *, const struct bin_attribute *, char *, loff_t, size_t); // v6.13~6.17
            loff_t (*llseek)(struct file *, struct kobject *, struct bin_attribute *, loff_t, int); // v6.7~
            int (*mmap)(struct file *, struct kobject *, struct bin_attribute *attr, struct vm_area_struct *vma);
        };

        struct module_attribute { // ~v5.6
            struct attribute attr;
            ssize_t (*show)(struct module_attribute *, struct module_kobject *, char *);
            ssize_t (*store)(struct module_attribute *, struct module_kobject *, const char *, size_t count);
            void (*setup)(struct module *, const char *);
            int (*test)(struct module *);
            void (*free)(struct module *);
        };
        """
        found = 0
        while True:
            if found > 0x200:
                # If we got to this point we can definitely return
                break
            if not is_valid_addr(attribute_arr_ptr):
                return False
            attribute = read_int_from_memory(attribute_arr_ptr)
            if attribute == 0:
                break
            if not is_valid_addr(attribute):
                return False
            nameptr = read_int_from_memory(attribute)
            if not self.is_valid_sectname(nameptr):
                return False
            found += 1
            attribute_arr_ptr += runtime.current_arch.ptrsize
        return found > 0

    def is_valid_sectname(self, nameptr):
        if not is_valid_addr(nameptr):
            return False
        sectname = read_cstring_from_memory(nameptr)
        if sectname is None or not sectname.startswith((".", "__", "_")):
            if sectname and len(sectname) >= 4:
                self.quiet_info(
                    "possible section name (rejected for not starting with \".\", \"__\" or \"_\"): {:s}".format(sectname),
                )
            return False
        return True

    def get_offset_bin_attrs(self):
        kversion = Kernel.kernel_version()

        # fast path
        try:
            if kversion < "3.11":
                offset_attrs = to_unsigned_long(gdb.parse_and_eval("&((struct attribute_group*)0).attrs"))
                attrs_arr_ptr = read_int_from_memory(self.cached_sect_attrs + offset_attrs)
                return offset_attrs, attrs_arr_ptr
            else:
                # It is possible to use attrs or bin_attrs, so check both.
                offset_attrs = to_unsigned_long(gdb.parse_and_eval("&((struct attribute_group*)0).attrs"))
                attrs_arr_ptr = read_int_from_memory(self.cached_sect_attrs + offset_attrs)
                if is_valid_addr(attrs_arr_ptr):
                    return offset_attrs, attrs_arr_ptr

                # Avoid relying on GDB's handling of anonymous union members in 6.14+.
                # bin_attrs/bin_attrs_new is immediately after attrs.
                offset_bin_attrs = offset_attrs + runtime.current_arch.ptrsize
                attrs_arr_ptr = read_int_from_memory(self.cached_sect_attrs + offset_bin_attrs)
                return offset_bin_attrs, attrs_arr_ptr
        except gdb.error:
            pass

        # slow path
        for i in range(0x10):
            offset_bin_attrs = runtime.current_arch.ptrsize * i
            attrs_arr_ptr = read_int_from_memory(self.cached_sect_attrs + offset_bin_attrs)
            if not self.is_valid_attribute_arr(attrs_arr_ptr):
                continue
            return offset_bin_attrs, attrs_arr_ptr

        return None, None

    """
    This function aims at locating module_sect_attr->address or bin_attribute->private,
    which stores the address of where the section resides in memory. To do so, it
    performs a statistical analysis on the various section attribute structures to
    identify pointer-sized values that are different for each one. If there is a
    specific offset where a pointer is present and different for every structure,
    it is very probable that the offset is that of the section address field.
    """
    def get_offset_address(self):
        kversion = Kernel.kernel_version()

        # fast path
        try:
            if kversion < "6.14":
                return to_unsigned_long(gdb.parse_and_eval("&((struct module_sect_attr*)0).address"))
            return to_unsigned_long(gdb.parse_and_eval("&((struct bin_attribute*)0).private"))
        except gdb.error:
            pass

        # slow path
        attrs_arr = []
        curr_attr = self.cached_attribute_arr_ptr
        while True:
            attribute = read_int_from_memory(curr_attr)
            if attribute == 0:
                break
            attrs_arr.append(attribute)
            curr_attr += runtime.current_arch.ptrsize

        if len(attrs_arr) < 2:
            self.quiet_err("module->sect_attrs.grp.bin_attrs has too few elements")
            return None

        # Find size of struct bin_attribute by pointer arithmetic from list (assuming they are contiguous and in order)
        attrs_arr.sort()
        bin_attr_size_map = {}
        for i in range(len(attrs_arr) - 1):
            tmp_size = attrs_arr[i + 1] - attrs_arr[i]
            if tmp_size not in bin_attr_size_map:
                bin_attr_size_map[tmp_size] = 1
            else:
                bin_attr_size_map[tmp_size] += 1

        # in fact:
        # ~6.13: sizeof(module_sect_attr)
        # 6.14~: sizeof(bin_attribute)
        bin_attr_size = max(bin_attr_size_map, key=bin_attr_size_map.get)

        # Statistical analysis to find pointers that differ across every structure
        # First we find potential pointers and save their count and offset
        offset_map = {}
        for attr in attrs_arr:
            data = read_memory(attr, bin_attr_size)
            for offset in range(0, bin_attr_size, runtime.current_arch.ptrsize):
                word = int.from_bytes(data[offset:offset + runtime.current_arch.ptrsize], "little")
                # TODO: Find a way to distinguish attrs.attr.{key,skey} from pointers
                #   Maybe we could skip the initial fields by using bin_attribute.size?
                if not AddressUtil.is_msb_on(word):
                    continue
                if offset not in offset_map:
                    offset_map[offset] = {}
                if word not in offset_map[offset]:
                    offset_map[offset][word] = 1
                else:
                    offset_map[offset][word] += 1
                # Remove pointers to strings if possible
                try:
                    maybe_string = read_cstring_from_memory(word)
                    if maybe_string is None:
                        continue
                    if len(maybe_string) > 4:
                        del offset_map[offset][word]
                except gdb.MemoryError:
                    pass

        # Find the best candidate to avoid name pointers that are not deleted (don't know why that happens)
        max_len = 0
        offset_address = None
        for offset, words in offset_map.items():
            for _val, count in words.items():
                # If multiple identical pointers are found, they are not `address` and `private`.
                if count > 1:
                    break
            else:
                if len(words) > max_len:
                    max_len = len(words)
                    offset_address = offset
        if max_len != 0:
            return offset_address

        return None

    def get_requested_module(self, module_addrs):
        for module in module_addrs:
            if read_cstring_from_memory(module + self.offset_name) == self.args.name:
                return module
        return None

    def initialize(self):
        if hasattr(self, "initialized"):
            return True

        kversion = Kernel.kernel_version()
        if kversion is None:
            self.quiet_err("Failed to resolve kernel version")
            return False

        if kversion < "3.0":
            self.quiet_err("Unsupported before v3.0")
            return False

        # modules
        self.modules = KernelAddressHeuristicFinder.get_modules()
        if self.modules is None:
            self.quiet_err("Could not find modules (maybe, CONFIG_MODULES is not set)")
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

        # Find requested module
        self.req_module = self.get_requested_module(self.module_addrs)
        if self.req_module is None:
            self.quiet_err("Could not find requested module")
            return False
        self.quiet_info(f"module: {hex(self.req_module)}")

        # module->sect_attrs
        self.offset_sect_attrs, self.cached_sect_attrs = self.get_offset_sect_attrs(self.req_module)
        if self.offset_sect_attrs is None:
            self.quiet_err("Could not find module->sect_attrs")
            return False
        self.quiet_info("offsetof(module, sect_attrs): {:#x}".format(self.offset_sect_attrs))

        # sect_attrs.grp.{attrs,bin_attrs}
        self.offset_attrs, self.cached_attribute_arr_ptr = self.get_offset_bin_attrs()
        if self.offset_attrs is None:
            self.quiet_err("Could not find module->sect_attrs.grp.{attrs,bin_attrs}")
            return False
        self.quiet_info("offsetof(module_sect_attrs, grp.{{attrs,bin_attrs}}): {:#x}".format(self.offset_attrs))

        # ~6.13: module_sect_attr.address
        # 6.14~: bin_attribute.private
        self.offset_address = self.get_offset_address()
        if self.offset_address is None:
            if kversion < "6.14":
                self.quiet_err("Could not find offset of module_sect_attr.address (section address)")
            else:
                self.quiet_err("Could not find offset of bin_attribute.private (section address)")
            return False
        if kversion < "6.14":
            self.quiet_info("offsetof(module_sect_attr, address): {:#x}".format(self.offset_address))
        else:
            self.quiet_info("offsetof(bin_attribute, private): {:#x}".format(self.offset_address))

        self.initialized = True
        return True

    def kmod_load(self):
        for module in self.module_addrs:
            name_string = read_cstring_from_memory(module + self.offset_name)
            if name_string != self.args.name:
                continue

            # get nsections
            sect_attrs = read_int_from_memory(module + self.offset_sect_attrs)
            attribute_list = read_int_from_memory(sect_attrs + self.offset_attrs)

            # get each section name and address
            sections = []
            while True:
                attribute = read_int_from_memory(attribute_list)
                if attribute == 0:
                    break
                nameptr = read_int_from_memory(attribute)
                name = read_cstring_from_memory(nameptr)
                # self.quiet_info("attr={:#x}".format(attribute))
                addr = read_int_from_memory(attribute + self.offset_address)
                self.quiet_info("name={:s}, addr={:#x}".format(name, addr))
                sections.append((name, addr))
                attribute_list += runtime.current_arch.ptrsize

                # unneeded, but for convenience
                gdb.execute("set ${:s} = {:#x}".format(name.replace(".", "").replace("-", ""), addr))

            # load
            command = " ".join(['-s {:s} {:#x}'.format(name, addr) for (name, addr) in sections])
            gdb.execute("add-symbol-file {!r} {:s}".format(self.args.path, command))
            break
        else:
            self.quiet_err("Could not find {:s}".format(self.args.name))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if not os.path.exists(args.path):
            self.quiet_err("Could not find {:s}".format(args.path))
            return

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

        # doit
        self.kmod_load()
        return


@register_command
class KtypesCommand(GenericCommand, BufferingOutput):
    """Display kernel type information from /sys/kernel/btf/vmlinux."""

    _cmdline_ = "ktypes"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command requires CONFIG_DEBUG_INFO_BTF=y.",
        "CONFIG_KALLSYMS_ALL=y is not required.",
    ]
    _note_ = "\n".join(_note_)

    def check_command(self):
        try:
            GefUtil.which("bpftool")
            if is_x86():
                GefUtil.which("gcc")
            elif is_arm64():
                GefUtil.which("aarch64-linux-gnu-gcc")
            elif is_arm32():
                GefUtil.which("arm-linux-gnueabihf-gcc")
        except FileNotFoundError as e:
            err("{}".format(e))
            return False
        return True

    def get_base_name(self):
        if not hasattr(runtime.CommandRegistry.instances["ksymaddr-remote"], "kernel_version"):
            gdb.execute("ksymaddr-remote --no-pager GEF_DUMMY_STRING", to_string=True)
            if not hasattr(runtime.CommandRegistry.instances["ksymaddr-remote"], "kernel_version"):
                err("Could not find kernel version")
                return None

        ks = runtime.CommandRegistry.instances["ksymaddr-remote"]
        h = hashlib.sha256(String.str2bytes(ks.version_string)).hexdigest()[-16:]
        major, minor, patch = ks.kernel_version
        base_name = os.path.join(GEF_TEMP_DIR, "ktypes-{:d}.{:d}.{:d}-{:s}".format(major, minor, patch, h))
        return base_name

    def get_btf_addr(self):
        start = Symbol.get_ksymaddr("__start_BTF")
        if start is None:
            return None
        end = Symbol.get_ksymaddr("__stop_BTF")
        return start, end - start

    def build_header_file(self):
        base_path = self.get_base_name()
        if base_path is None:
            return None

        raw_path = base_path + ".raw"
        header_path = base_path + ".h"

        # use cache
        if not self.args.rescan:
            if os.path.exists(header_path) and os.path.getsize(header_path) > 0:
                return header_path

        # get address of /sys/kernel/btf/vmlinux
        addr_size = self.get_btf_addr()
        if addr_size is None:
            err("Could not find /sys/kernel/btf/vmlinux")
            return None

        # read /sys/kernel/btf/vmlinux
        try:
            content = read_memory(*addr_size)
        except gdb.MemoryError:
            err("Memory read error")
            return None

        # save it
        open(raw_path, "wb").write(content)

        # raw -> vmlinux.h
        os.system("{!r} btf dump file {!r} format c > {!r}".format(GefUtil.which("bpftool"), raw_path, header_path))
        return header_path

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        if not self.check_command():
            return

        header_path = self.build_header_file()
        if header_path is None:
            warn("This kernel may be CONFIG_DEBUG_INFO_BTF=n")
            return

        content = open(header_path, "r").read()

        self.out = []
        self.out.extend(content.splitlines())
        self.print_output(check_terminal_size=True)
        return


@register_command
class KtypesLoadCommand(KtypesCommand):
    """Load kernel type information from /sys/kernel/btf/vmlinux."""

    _cmdline_ = "ktypes-load"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"
    _aliases_ = ["kt-load"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    _syntax_ = parser.format_help()

    def build_obj_file(self, header_path):
        source_path = header_path[:-2] + ".c"
        obj_path = source_path[:-2]

        # use cache
        if not self.args.rescan:
            if os.path.exists(obj_path) and os.path.getsize(obj_path) > 0:
                return obj_path

        # copy vmlinux.h to vmlinux.c
        open(source_path, "wb").write(open(header_path, "rb").read())

        try:
            if is_x86_64():
                gcc, opt = GefUtil.which("gcc"), ""
            elif is_x86_32():
                gcc, opt = GefUtil.which("gcc"), "-m32"
            elif is_arm64():
                gcc, opt = GefUtil.which("aarch64-linux-gnu-gcc"), ""
            elif is_arm32():
                gcc, opt = GefUtil.which("arm-linux-gnueabihf-gcc"), ""
        except FileNotFoundError as e:
            err("{}".format(e))
            return None

        # build with debug types
        cmd = "{!r} {:s} -std=c11 -g -O0 -fno-eliminate-unused-debug-types -w -c {!r} -o {!r}".format(
            gcc, opt, source_path, obj_path,
        )
        info(cmd)
        os.system(cmd)

        if not os.path.exists(obj_path):
            return None

        return obj_path

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        if not self.check_command():
            return

        header_path = self.build_header_file()
        if header_path is None:
            warn("This kernel may be CONFIG_DEBUG_INFO_BTF=n")
            return

        obj_path = self.build_obj_file(header_path)
        if obj_path is None:
            err("Failed to build")
            return

        info(obj_path)
        gdb.execute("file {:s}".format(obj_path), to_string=True)
        info("Kernel types are loaded successfully")
        return


@register_command
class KsymaddrRemoteCommand(GenericCommand, BufferingOutput):
    """Resolve kernel symbols from kallsyms table."""
    # Thanks to https://github.com/marin-m/vmlinux-to-elf

    _cmdline_ = "ksymaddr-remote"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"
    _aliases_ = ["ks"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("keyword", metavar="KEYWORD", nargs="*", help="filter by specific symbol name.")
    parser.add_argument("-t", "--type", action="append", default=[], help="filter by symbol type.")
    parser.add_argument("-e", "--exact", action="store_true", help="use exact match.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-s", "--smart", action="store_true", help="filter __pfx_*, __ksymtab_*, etc.")
    parser.add_argument("--vmlinux-file", help="force use your vmlinux file which includes symbols.")
    parser.add_argument("-I", "--ignore-loaded-vmlinux", action="store_true", help="force skip parsing loaded vmlinux.")
    parser.add_argument("--print-saved-config", action="store_true", help="print saved (cached) config contents.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} commit_creds prepare_kernel_cred  # OR search",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "GEF caches offset information for parsing kallsyms to speed up this command.",
        "Each cache is used based on kernel version strings.",
        "In other words, in cases where the kernel version is exactly the same and",
        "the CONFIG is slightly different, the offset will be applied incorrectly.",
        "In this case, rescan with `ks -rv` or clear the cache with `gef reset-cache --hard`.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self, *args, **kwargs):
        super().__init__()
        """
        # Do not use dict; There are cases where multiple symbols with the same name exist.
        # cat /proc/kallsyms |grep set_is_seen
        ffffffff812326e0 t set_is_seen
        ffffffff81d58900 t set_is_seen
        ffffffff81d5cab0 t set_is_seen
        #
        """
        self.kallsyms = []
        return

    def get_loaded_vmlinux_path(self):
        if self.args.ignore_loaded_vmlinux:
            return None

        # Check `nm` first for later use (in parse_vmlinux)
        try:
            GefUtil.which(Config.get_gef_setting("gef.nm_command"))
        except FileNotFoundError as e:
            self.quiet_err("{}".format(e))
            return None

        # check vmlinux
        for inf in gdb.inferiors():
            if not hasattr(inf, "progspace"):
                continue
            if not hasattr(inf.progspace, "filename"):
                continue

            filename = str(inf.progspace.filename)
            if not os.path.exists(filename):
                continue

            # Currently, the filename in vmlinux is hard-coded
            if "vmlinux" not in os.path.basename(filename).lower():
                continue

            # it has symbol?
            try:
                elf = Elf(filename)
                if elf.get_shdr(".symtab"):
                    return filename
            except Exception:
                continue
        return None

    def parse_vmlinux(self, filename):
        # read symbols
        try:
            nm = GefUtil.which(Config.get_gef_setting("gef.nm_command"))
        except FileNotFoundError as e:
            self.quiet_err("{}".format(e))
            return
        result = GefUtil.gef_execute_external([nm, filename], as_list=True)

        # distinctive addresses to use for rebasing
        if is_x86():
            target = [
                "asm_exc_divide_error", # 5.8~
                "divide_error", # 3.0 ~ 5.7
            ]
        elif is_arm64() or is_arm32():
            target = [
                "vectors", # 3.7~
            ]
        elif is_riscv64() or is_riscv32():
            target = [
                "handle_exception", # 4.19~
            ]
        else:
            raise

        # parse symbol
        tmp_kallsyms = []
        target_found = {}
        for line in result:
            try:
                addr, typ, name = line.split()
                addr = int(addr, 16)
                typ = typ.strip()
                name = name.strip()
            except ValueError:
                continue
            tmp_kallsyms.append([addr, name, typ])

            if name in target:
                target_found["handler"] = addr

        # rebase
        if target_found:
            text_base_hint = Kernel.get_kernel_base_hint()
            if text_base_hint:
                diff = text_base_hint - target_found["handler"]
                if diff & get_pagesize_mask_low() == 0:
                    self.kallsyms = []
                    for addr, name, typ in tmp_kallsyms:
                        # don't rebase per-cpu offset
                        if addr >= 0x4000_0000:
                            # This value is the lowest boundary between ARM32 kernel and userland.
                            addr += diff
                        self.kallsyms.append([addr, name, typ])
                    return

        # fail, use as is
        self.kallsyms = tmp_kallsyms
        return

    def get_token_table(self):
        # Parse symbol name tokens
        tokens = []
        position = self.offset_kallsyms_token_table
        for _ in range(256):
            token = ""
            while self.kernel_img[position]:
                token += chr(self.kernel_img[position])
                position += 1
            position += 1
            tokens.append(token)
        assert len(tokens) == 256
        return tokens

    def read_kallsyms(self):
        if self.kallsyms: # resolved already
            return

        tokens = self.get_token_table()
        symbol_names = []
        position = self.offset_kallsyms_names
        for _ in range(self.num_symbols):
            # read token length
            length = self.kernel_img[position]
            position += 1

            # check if big symbol (6.1~)
            if self.kernel_version >= (6, 1, 0):
                if length & 0x80:
                    low = length & 0x7f
                    high = self.kernel_img[position]
                    position += 1
                    length = (high << 7) | low

            # make symbol_name
            symbol_name = ""
            for _ in range(length):
                symbol_token_index = self.kernel_img[position]
                symbol_token = tokens[symbol_token_index]
                position += 1
                symbol_name += symbol_token
            symbol_names.append(symbol_name)

        for addr, name in zip(self.kernel_addresses, symbol_names):
            try:
                self.kallsyms.append([addr, name[1:], name[0]])
            except IndexError:
                pass
        return

    def print_kallsyms(self, keywords, types, smart):
        if is_32bit():
            fmt = "{:#010x} {:s} {:s}"
        else:
            fmt = "{:#018x} {:s} {:s}"

        if types:
            types = [t.lower() for t in types]
            kallsyms = [entry for entry in self.kallsyms if entry[2].lower() in types]
        else:
            kallsyms = self.kallsyms

        if smart:
            ignore_list = (
                "__pfx_", # prefix symbols for function padding
                "__kstrtab_",
                "__ksymtab_",
                "__kcrctab_",
                "__tpstrtab_", # tracepoint
                "__initcall__",
                "__traceiter_",
                "__tracepoint_",
                "__probestub_",
                "__already_done.",
                "__flags.",
                "__func__.",
                "__key.",
                "__mkey.",
                "__msg.",
                "__print_once.",
                "__quirk.",
                "__warned.",
                "__wkey.",
                "___done.",
                "___once_key.",
                "___tp_str.",
                "__compound_literal.",
                "__SCT__tp_func_",
                "__SCK__tp_func_",
                "__TRACE_SYSTEM_",
            )
            kallsyms = [entry for entry in kallsyms if not entry[1].startswith(ignore_list)]

        self.out = []
        if not keywords:
            for addr, symbol, typ in kallsyms:
                self.out.append(fmt.format(addr, typ, symbol))

        elif self.args.exact:
            for addr, symbol, typ in kallsyms:
                if symbol in keywords:
                    self.out.append(fmt.format(addr, typ, symbol))

        else:
            for addr, symbol, typ in kallsyms:
                text = fmt.format(addr, typ, symbol)
                for k in keywords:
                    if k in text: # not only symbol search, but also address search
                        self.out.append(text)
                        break
        return

    def get_kernel_version_triplet(self, version_number):
        major = int(version_number.split(".")[0])
        minor = int(version_number.split(".")[1])
        if len(version_number.split(".")) == 2:
            patch = 0
        else:
            patch = int(version_number.split(".")[2])
        return (major, minor, patch)

    def get_kernel_version(self):
        # don't use Kernel.kernel_version, since it refers ksymaddr-remote
        r = re.search(rb"Linux version (\d+\.[\d.]*\d)[ -~]+", self.kernel_img)
        if r is None:
            self.verbose_err("Could not find the kernel version")
            return False
        self.version_string = r.group(0)
        self.version_string_offset = r.span()[0]
        self.verbose_info("linux_banner: {:#x}".format(self.ro_base + self.version_string_offset))
        version_number = r.group(1).decode("ascii")
        self.kernel_version = self.get_kernel_version_triplet(version_number)

        # The important thing for parsing is whether it is 6.1.42 or later.
        # However, some distributions may have a patch version of 0.
        # e.g., debian 6.1.119-1 -> 6.1.0-28-amd64
        # In this case, special processing is required to find a different version string.
        if self.kernel_version[:2] == (6, 1):
            # e.g., Linux version 6.1.0-28-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0,
            # GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22)
            r = re.findall(rb" 6\.1\.(\d+)", self.version_string)
            for patch_version in r:
                patch_version = int(patch_version)
                if patch_version >= 42:
                    self.kernel_version = (self.kernel_version[0], self.kernel_version[1], patch_version)
                    break
        return True

    def get_cfg_name(self):
        h = hashlib.sha256(String.str2bytes(self.version_string)).hexdigest()[-16:]
        major, minor, patch = self.kernel_version
        cfg_file_name = os.path.join(GEF_TEMP_DIR, "ksymaddr-remote-{:d}.{:d}.{:d}-{:s}.cfg".format(major, minor, patch, h))
        return cfg_file_name

    def save_config(self, param_name):
        cfg_file_name = self.get_cfg_name()
        config = configparser.ConfigParser()
        if os.path.exists(cfg_file_name):
            config.read(cfg_file_name)
        else:
            config["parameters"] = {}

        config["parameters"][param_name] = str(getattr(self, param_name))
        with open(cfg_file_name, "w") as cfg_file:
            config.write(cfg_file)
        return

    def get_saved_config(self, param_names):
        if self.args.rescan:
            return False

        cfg_file_name = self.get_cfg_name()
        if not os.path.exists(cfg_file_name):
            return False

        config = configparser.ConfigParser()
        config.read(cfg_file_name)
        for param_name in param_names:
            if param_name not in config["parameters"]:
                return False

        for param_name in param_names:
            param_value = int(config["parameters"][param_name])
            setattr(self, param_name, param_value)
        return True

    def print_saved_config(self):
        if hasattr(self, "version_string"):
            cfg_file_name = self.get_cfg_name()
            info("path: {:s}".format(cfg_file_name))
            if os.path.exists(cfg_file_name):
                gef_print(titlify("content (hexlified)"))
                config = configparser.ConfigParser()
                config.read(cfg_file_name)
                for param_name in config["parameters"]:
                    param_value = config["parameters"][param_name]
                    try:
                        param_value = int(param_value)
                        gef_print("{:s} = {:#x}".format(param_name, param_value))
                    except ValueError:
                        gef_print("{:s} = {:s}".format(param_name, param_value))
                return

        err("Could not find cached config (Run the `ksymaddr-remote` command at least once)")
        return

    def find_kallsyms_token_table(self):
        ret = self.get_saved_config(["offset_kallsyms_token_table"])
        if ret:
            self.verbose_info("kallsyms_token_table: {:#x}".format(self.ro_base + self.offset_kallsyms_token_table))
            return True

        """
        [Search strategy]
        - kallsyms_token_table has unique sequences like "30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00".
        - We search for it from .rodata area, then search backwards for invalid characters to get the top.

        [Positional relationship]
        - ...
        - kallsyms_token_table
        - ...

        [Sample values for 64bit]
        gef> hexdump -n byte kallsyms_token_table
        0xffffffff8b2b51b0:    65 75 00 77 5f 00 61 64 64 00 64 5f 5f 66 75 6e    |  eu.w_.add.d__fun  |
        0xffffffff8b2b51c0:    63 5f 5f 00 74 70 5f 66 75 6e 63 00 33 32 00 6e    |  c__.tp_func.32.n  |
        0xffffffff8b2b51d0:    61 00 66 66 00 69 70 00 78 65 6e 00 70 72 00 73    |  a.ff.ip.xen.pr.s  |
        0xffffffff8b2b51e0:    65 74 00 63 70 75 00 49 44 00 65 64 00 53 43 00    |  et.cpu.ID.ed.SC.  |
        0xffffffff8b2b51f0:    66 72 65 00 76 65 5f 00 70 6f 00 78 5f 00 5f 73    |  fre.ve_.po.x_._s  |
        0xffffffff8b2b5200:    68 00 2e 31 00 62 6c 00 6d 65 6d 00 5f 72 65 67    |  h..1.bl.mem._reg  |
        0xffffffff8b2b5210:    00 74 5f 5f 00 6c 6f 63 6b 00 62 5f 00 72 5f 5f    |  .t__.lock.b_.r__  |
        0xffffffff8b2b5220:    6b 73 74 72 74 61 62 6e 73 00 66 75 6e 63 5f 5f    |  kstrtabns.func__  |
        0xffffffff8b2b5230:    00 69 6e 74 5f 00 72 65 73 00 74 72 61 63 65 00    |  .int_.res.trace.  |
        0xffffffff8b2b5240:    70 61 72 00 2e 30 00 64 65 76 65 6e 74 5f 00 6d    |  par..0.devent_.m  |
        0xffffffff8b2b5250:    75 00 61 63 70 69 5f 00 6d 70 00 73 74 61 00 64    |  u.acpi_.mp.sta.d  |
        0xffffffff8b2b5260:    65 62 75 67 00 5f 5f 5f 00 62 75 67 00 6f 75 00    |  ebug.___.bug.ou.  |
        0xffffffff8b2b5270:    5f 73 74 61 00 77 72 69 74 00 2e 00 67 72 6f 00    |  _sta.writ...gro.  |
        0xffffffff8b2b5280:    30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00    |  0.1.2.3.4.5.6.7.  | <- here unique seqs
        0xffffffff8b2b5290:    38 00 39 00 72 63 00 77 61 00 63 61 6c 00 75 70    |  8.9.rc.wa.cal.up  |
        0xffffffff8b2b52a0:    5f 00 45 5f 00 67 65 5f 00 6d 61 70 00 41 00 42    |  _.E_.ge_.map.A.B  |

        [Sample values for 32bit]
        gef> hexdump -n byte kallsyms_token_table
        0xc6e58efc:    54 52 41 43 45 5f 53 59 53 00 41 43 45 5f 53 59    |  TRACE_SYS.ACE_SY  |
        0xc6e58f0c:    53 00 5f 53 59 53 00 54 45 4d 00 41 43 45 00 69    |  S._SYS.TEM.ACE.i  |
        0xc6e58f1c:    67 00 70 6f 69 6e 74 5f 00 62 75 00 75 74 5f 00    |  g.point_.bu.ut_.  | # codespell:ignore
        0xc6e58f2c:    5f 53 59 00 54 52 00 5f 73 79 00 72 65 61 64 00    |  _SY.TR._sy.read.  |
        0xc6e58f3c:    66 5f 00 75 6c 00 62 6c 00 61 6c 6c 6f 63 00 74    |  f_.ul.bl.alloc.t  |
        0xc6e58f4c:    6c 00 63 6c 00 65 79 00 61 74 61 00 70 63 00 5f    |  l.cl.ey.ata.pc._  |
        0xc6e58f5c:    65 6e 00 76 65 72 00 54 45 00 64 74 72 61 63 65    |  en.ver.TE.dtrace  | # codespell:ignore
        0xc6e58f6c:    5f 65 76 65 6e 74 5f 00 61 70 00 61 74 65 00 74    |  _event_.ap.ate.t  |
        0xc6e58f7c:    6e 00 41 43 00 6d 73 00 72 61 77 5f 00 5f 63 6f    |  n.AC.ms.raw_._co  |
        0xc6e58f8c:    00 73 74 72 00 6d 6f 00 67 69 73 74 65 72 00 69    |  .str.mo.gister.i  |
        0xc6e58f9c:    70 00 63 6f 6e 00 67 69 73 00 69 6e 69 74 00 66    |  p.con.gis.init.f  |
        0xc6e58fac:    75 6e 63 00 65 5f 73 00 75 74 00 5f 73 68 00 70    |  unc.e_s.ut._sh.p  |
        0xc6e58fbc:    6f 00 61 6c 6c 00 2e 00 66 73 5f 00 30 00 31 00    |  o.all...fs_.0.1.  |
        0xc6e58fcc:    32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00    |  2.3.4.5.6.7.8.9.  | <- here unique seqs
        0xc6e58fdc:    6b 5f 00 5f 63 68 00 72 69 74 00 61 63 70 69 00    |  k_._ch.rit.acpi.  |
        0xc6e58fec:    5f 63 6f 6e 00 65 78 74 34 00 61 6d 00 41 00 42    |  _con.ext4.am.A.B  |
        """

        # first, search for unique bytes
        seq_to_find = b"0\x001\x002\x003\x004\x005\x006\x007\x008\x009\x00"
        seq_to_avoid = [b":\0", b"\0\0", b"\0\1", b"\0\2", b"ASCII\0"]
        target_pattern = seq_to_find + b"(?!" + b"|".join(seq_to_avoid) + b")"

        unique_bytes_offset = []
        for r in re.finditer(target_pattern, self.kernel_img):
            unique_bytes_offset.append(r.span()) # (start_pos, end_pos)

        if len(unique_bytes_offset) == 0:
            self.verbose_err("Could not find kallsyms_token_table (0 candidate)")
            return False

        if len(unique_bytes_offset) > 1:
            # strict check
            for i, offsets in enumerate(unique_bytes_offset.copy()):
                self.verbose_info("unique_bytes {:d}: {:#x}".format(i, self.ro_base + offsets[0]))
                follow = self.kernel_img[offsets[1]:offsets[1] + 1]
                if not follow.isalnum() and follow not in [b"_", b"."]:
                    unique_bytes_offset.remove(offsets)
            # re-check
            if len(unique_bytes_offset) == 0:
                self.verbose_err("Could not find kallsyms_token_table (0 candidate)")
                return False
            if len(unique_bytes_offset) > 1:
                self.verbose_err("Could not find kallsyms_token_table (multiple candidates)")
                return False

        position = unique_bytes_offset[0][0]
        self.verbose_info("unique_bytes: {:#x}".format(self.ro_base + position))

        # second, backward search for the top
        position -= 1
        if position < 0:
            self.verbose_err("Could not find kallsyms_token_table (failed to get top: before '0')")
            return False
        if self.kernel_img[position] != 0:
            self.verbose_err("Unexpected byte before '0' entry in kallsyms_token_table")
            return False

        num_tokens_back = ord('0') # 48
        max_token_len = 50

        # find the beginning of a kallsyms_token_table
        for _ in range(num_tokens_back):
            # find the beginning of a token
            for _ in range(max_token_len):
                position -= 1
                if position < 0:
                    self.verbose_err("Could not find kallsyms_token_table (out of range while walking tokens)")
                    return False

                b = self.kernel_img[position]
                if b == 0 or b > ord('z'):
                    break

            else:
                # max_token_len exceeded
                self.verbose_err("This structure is not a kallsyms_token_table (token too long)")
                return False

        position += 1
        position += -position % 4

        self.offset_kallsyms_token_table = position
        self.save_config("offset_kallsyms_token_table")
        self.verbose_info("kallsyms_token_table: {:#x}".format(self.ro_base + self.offset_kallsyms_token_table))
        return True

    def find_kallsyms_token_index(self):
        ret = self.get_saved_config(["offset_kallsyms_token_index"])
        if ret:
            self.verbose_info("kallsyms_token_index: {:#x}".format(self.ro_base + self.offset_kallsyms_token_index))
            return True

        """
        [Search strategy]
        - Find the index where the string appears in kallsyms_token_table.
        - Find where that index is arranged like a table.

        [Positional relationship]
        - ...
        - kallsyms_token_table
        - kallsyms_token_index
        - ...

        [Sample values for 64bit]
        gef> hexdump -n word kallsyms_token_index
        0xffffffff8b2b5540:    0x0000 0x0003 0x0006 0x000a 0x0014 0x001c 0x001f 0x0022    |  ..............".  |
        0xffffffff8b2b5550:    0x0025 0x0028 0x002c 0x002f 0x0033 0x0037 0x003a 0x003d    |  %.(.,./.3.7.:.=.  |
        0xffffffff8b2b5560:    0x0040 0x0044 0x0048 0x004b 0x004e 0x0052 0x0055 0x0058    |  @.D.H.K.N.R.U.X.  |
        0xffffffff8b2b5570:    0x005c 0x0061 0x0065 0x006a 0x006d 0x007a 0x0081 0x0086    |  ..a.e.j.m.z.....  |
        0xffffffff8b2b5580:    0x008a 0x0090 0x0094 0x0097 0x009f 0x00a2 0x00a8 0x00ab    |  ................  |
        0xffffffff8b2b5590:    0x00af 0x00b5 0x00b9 0x00bd 0x00c0 0x00c5 0x00ca 0x00cc    |  ................  |
        0xffffffff8b2b55a0:    0x00d0 0x00d2 0x00d4 0x00d6 0x00d8 0x00da 0x00dc 0x00de    |  ................  |
        0xffffffff8b2b55b0:    0x00e0 0x00e2 0x00e4 0x00e7 0x00ea 0x00ee 0x00f2 0x00f5    |  ................  |

        [Sample values for 32bit]
        gef> hexdump -n word kallsyms_token_index
        0xc6e59274:    0x0000 0x000a 0x0012 0x0017 0x001b 0x001f 0x0022 0x0029    |  ............".).  |
        0xc6e59284:    0x002c 0x0030 0x0034 0x0037 0x003b 0x0040 0x0043 0x0046    |  ,.0.4.7.;.@.C.F.  |
        0xc6e59294:    0x0049 0x004f 0x0052 0x0055 0x0058 0x005c 0x005f 0x0063    |  I.O.R.U.X..._.c.  |
        0xc6e592a4:    0x0067 0x006a 0x0078 0x007b 0x007f 0x0082 0x0085 0x0088    |  g.j.x.{.........  |
        0xc6e592b4:    0x008d 0x0091 0x0095 0x0098 0x009f 0x00a2 0x00a6 0x00aa    |  ................  |
        0xc6e592c4:    0x00af 0x00b4 0x00b8 0x00bb 0x00bf 0x00c2 0x00c6 0x00c8    |  ................  |
        0xc6e592d4:    0x00cc 0x00ce 0x00d0 0x00d2 0x00d4 0x00d6 0x00d8 0x00da    |  ................  |
        0xc6e592e4:    0x00dc 0x00de 0x00e0 0x00e3 0x00e7 0x00eb 0x00f0 0x00f5    |  ................  |
        """

        # create expected kallsyms_token_index byte sequqence
        position = self.offset_kallsyms_token_table
        seq_token_table_head = self.kernel_img[position:position + 256]

        token_offsets = [p16(0)]
        pos = 0
        while True:
            pos = seq_token_table_head.find(b"\0", pos + 1)
            if pos == -1:
                break
            token_offsets.append(p16(pos + 1))
        seq_to_find = b"".join(token_offsets)

        # search for it from memory
        position = self.kernel_img.find(seq_to_find, self.offset_kallsyms_token_table)
        if position == -1:
            self.verbose_err("Could not find kallsyms_token_index (0 candidate)")
            return False

        self.offset_kallsyms_token_index = position
        self.save_config("offset_kallsyms_token_index")
        self.verbose_info("kallsyms_token_index: {:#x}".format(self.ro_base + self.offset_kallsyms_token_index))
        return True

    def find_kallsyms_markers(self):
        # determines the size of table elements depended on kernel version.
        if self.kernel_version < (4, 20, 0):
            # kallsyms_markers is unsigned long[]
            self.kallsyms_markers_table_element_size = runtime.current_arch.ptrsize
        else:
            # kallsyms_markers is unsigned int[]
            self.kallsyms_markers_table_element_size = 4

        if self.kernel_version >= (6, 1, 42) and self.kernel_version < (6, 9, 0):
            ret = self.get_saved_config([
                "offset_kallsyms_token_markers",
                "offset_kallsyms_seqs_of_names",
            ])
            if ret:
                self.verbose_info("kallsyms_markers: {:#x}".format(self.ro_base + self.offset_kallsyms_markers))
                self.verbose_info("kallsyms_seqs_of_names: {:#x}".format(self.ro_base + self.offset_kallsyms_seqs_of_names))
                return True
        else:
            ret = self.get_saved_config([
                "offset_kallsyms_token_markers",
            ])
            if ret:
                self.verbose_info("kallsyms_markers: {:#x}".format(self.ro_base + self.offset_kallsyms_markers))
                return True

        """
        [Search strategy]
        - From kallsyms_token_table, search backwards for 0x00000000.
        - For kernel v6.1.42~v6.8, there is kallsyms_seqs_of_names between kallsyms_markers and kallsyms_token_table,
          so this should be skipped.

        [Positional relationship]
        ...
        - kallsyms_markers
        - kallsyms_seqs_of_names (v6.1.42~v6.8)
        - kallsyms_token_table
        - kallsyms_token_index
        ...
        - kallsyms_seqs_of_names (v6.9~)
        ...

        [Sample values for 64bit ~v6.1.41]
        gef> hexdump -n dword kallsyms_markers
        0xffffffff8b2b4b48:    0x00000000 0x00000ab0 0x000016d3 0x00002316    |  .............#..  | <- kallsyms_markers
        0xffffffff8b2b4b58:    0x00002f38 0x00003cf8 0x00004c4c 0x000059c8    |  8/...<..LL...Y..  |
        0xffffffff8b2b4b68:    0x0000664b 0x00007316 0x00008119 0x00008f2e    |  Kf...s..........  |
        0xffffffff8b2b4b78:    0x00009cc6 0x0000a9ff 0x0000b687 0x0000c20f    |  ................  |
        ...
        0xffffffff8b2b5180:    0x0013fa80 0x001404c6 0x00140f67 0x00141a29    |  ........g...)...  |
        0xffffffff8b2b5190:    0x0014240e 0x00142e25 0x00143a5f 0x0014442a    |  .$..%..._:..*D..  |
        0xffffffff8b2b51a0:    0x00144e55 0x001458d8 0x00146338 0x00000000    |  UN...X..8c......  |
        0xffffffff8b2b51b0:    0x77007565 0x6461005f 0x5f640064 0x6e75665f    |  eu.w_.add.d__fun  | <- kallsyms_token_table

        [Sample values for 64bit v6.1.42~]
        gef> hexdump -n dword kallsyms_markers
        0xffffffff8d5fcde0:    0x00000000 0x00000b55 0x000017bb 0x000024c3    |  ....U........$..  | <- kallsyms_markers
        0xffffffff8d5fcdf0:    0x000030c1 0x00003dca 0x00004983 0x000058aa    |  .0...=...I...X..  |
        0xffffffff8d5fce00:    0x00006785 0x0000760e 0x0000828d 0x00009160    |  .g...v......`...  |
        0xffffffff8d5fce10:    0x00009efa 0x0000ab20 0x0000b73a 0x0000c37d    |  .... ...:...}...  |
        ...
        0xffffffff8d5fd790:    0x00212755 0x002131b8 0x00213af8 0x00214558    |  U'!..1!..:!.XE!.  |
        0xffffffff8d5fd7a0: (*)0x01069d01 0x9d01019d 0x029d0100 0x02039d01    |  ................  | <- kallsyms_seqs_of_names (*)
        0xffffffff8d5fd7b0:    0xa400291c 0x10a50024 0x0154a500 0xaa0116aa    |  .)..$.....T.....  |
        0xffffffff8d5fd7c0:    0x87610214 0x01274902 0xb201cbaf 0xbbbc01c9    |  ..a..I'.........  |

        [Sample values for 32bit v6.1.42~]
        gef> hexdump -n dword kallsyms_markers
        0xc6e0dc98:    0x00000000 0x00000c61 0x0000188f 0x00002641    |  ....a.......A&..  | <- kallsyms_markers
        0xc6e0dca8:    0x00003492 0x000041a7 0x00004e6b 0x00005ace    |  .4...A..kN...Z..  |
        0xc6e0dcb8:    0x0000691b 0x00007703 0x00008411 0x00008fc1    |  .i...w..........  |
        0xc6e0dcc8:    0x00009c98 0x0000a8ea 0x0000b719 0x0000c4dd    |  ................  |
        ...
        0xc6e0e2c8:    0x0014f2fa 0x0014fbeb 0x00150653 0x00634401(*) |  ........S....Dc.  | <- kallsyms_seqs_of_names (*)
        0xc6e0e2d8:    0xd90030d9 0x8bd30032 0x0189d300 0x6a01e97f    |  .0..2..........j  |
        0xc6e0e2e8:    0x31d90063 0x0007e100 0xd600b7e1 0xd1d900cb    |  c..1............  |
        0xc6e0e2f8:    0x0083dd00 0xd90004e9 0x85ef00ab 0x00bfdb00    |  ................  |
        """

        # kallsyms_markers[0] is 0.
        seq_to_find = b"\0" * self.kallsyms_markers_table_element_size

        # ignore the 0 immediately above kallsyms_token_table.
        position = self.offset_kallsyms_token_table - 1
        if len(self.kernel_img) <= position:
            return False
        while position > 0 and self.kernel_img[position] == 0:
            position -= 1

        # aligned search for it from memory
        while position > 0:
            needle = self.kernel_img.rfind(seq_to_find, 0, position)
            if needle == -1:
                self.verbose_err("Could not find kallsyms_markers")
                return False
            # check alignment
            align_diff = needle % self.kallsyms_markers_table_element_size
            if align_diff == 0:
                position = needle
                break # ok
            else:
                position = needle + self.kallsyms_markers_table_element_size - align_diff
                # not aligned, so retry

        if self.kernel_version >= (6, 1, 42) and self.kernel_version < (6, 9, 0):
            # kallsyms_seqs_of_names was introduced in kernel 6.1.42
            # In this case, we may find kallsyms_seqs_of_names instead of kallsyms_markers,
            # so we should search back through memory again.
            #
            # kallsyms_markers        (1) we want to find this
            # kallsyms_seqs_of_names  (3) this may have been found, try the backward search again
            # kallsyms_token_table    (2) backward search from here
            # kallsyms_token_index
            #
            while position > 0:
                # the first some values of kallsyms_markers should be a small number.
                # if not, detected kallsyms_markers is incorrect and we'll go back further.
                first_10_elements = self.kernel_img[position + self.kallsyms_markers_table_element_size:]
                first_10_elements = first_10_elements[:self.kallsyms_markers_table_element_size * 10]
                first_10_elements = slice_unpack(first_10_elements, self.kallsyms_markers_table_element_size)
                if all((x & 0xfff_0000) == 0 for x in first_10_elements):
                    break

                needle = self.kernel_img.rfind(seq_to_find, 0, position)
                if needle == -1:
                    self.verbose_err("Could not find kallsyms_markers")
                    return False
                # check alignment
                align_diff = needle % self.kallsyms_markers_table_element_size
                if align_diff == 0:
                    position = needle
                else:
                    position = needle + self.kallsyms_markers_table_element_size - align_diff

        if position <= 0:
            self.verbose_err("Could not find kallsyms_markers")
            return False

        self.offset_kallsyms_markers = position
        self.save_config("offset_kallsyms_markers")
        self.verbose_info("kallsyms_markers: {:#x}".format(self.ro_base + self.offset_kallsyms_markers))

        if self.kernel_version >= (6, 1, 42) and self.kernel_version < (6, 9, 0):
            # locate kallsyms_seqs_of_names to get the table size of kallsyms_markers (used after).
            #
            # kallsyms_markers        (1) we found this
            # kallsyms_seqs_of_names  (2) to know the end of kallsyms_markers, we need to find this
            # kallsyms_token_table
            # kallsyms_token_index
            #
            position = self.offset_kallsyms_markers + self.kallsyms_markers_table_element_size
            # check MSB of the element of kallsyms_markers
            while self.kernel_img[position + (self.kallsyms_markers_table_element_size - 1)] == 0:
                a = u32(self.kernel_img[position - self.kallsyms_markers_table_element_size:position]) # prev
                b = u32(self.kernel_img[position:position + self.kallsyms_markers_table_element_size]) # current
                # kallsyms_markers are monotonically increasing.
                # and it doesn't increase very dramatically.
                if a > b or b - a > 0x10_0000:
                    break
                position += self.kallsyms_markers_table_element_size
            self.offset_kallsyms_seqs_of_names = position
            self.save_config("offset_kallsyms_seqs_of_names")
            self.verbose_info("kallsyms_seqs_of_names: {:#x}".format(self.ro_base + self.offset_kallsyms_seqs_of_names))

        return True

    def find_kallsyms_names(self):
        ret = self.get_saved_config(["offset_kallsyms_names"])
        if ret:
            return True

        """
        [Search strategy]
        - From kallsyms_markers, go back as far as we can definitively go back.
        - This address is not accurate.

        [Positional relationship]
        ...
        - kallsyms_names (this is not accurate address in this step)
        - kallsyms_markers
        - kallsyms_seqs_of_names (v6.1.42~v6.8)
        - kallsyms_token_table
        - kallsyms_token_index
        ...
        - kallsyms_seqs_of_names (v6.9~)
        ...

        [Sample values for 64bit]
        gef> hexdump -n qword kallsyms_names
        0xffffffff8b16e610:    0x0cf3ec0e78b6410a 0xf370ff4109fe61cb    |  .A.x.....a..A.p.  | <- kallsyms_names
        0xffffffff8b16e620:    0x0c410774722cbdeb 0xa8410df67ef4285f    |  ..,rt.A._(.~..A.  |
        0xffffffff8b16e630:    0x936bed62d8632c71 0x925f0c4107f67ef4    |  q,c.b.k..~..A._.  |
        0xffffffff8b16e640:    0xfb646741067772f1 0x706563a4410add86    |  .rw.Agd....A.cep  |
        ...
        0xffffffff8b2b4b20:    0x616bd977fc6d7364 0x738df5ff440e61f6    |  dsm.w.ka.a.D...s  |
        0xffffffff8b2b4b30:    0x6765625fbfe87263 0x63738df5ff440cf5    |  cr.._beg..D...sc  |
        0xffffffff8b2b4b40:    0x000064ee5fbfe872 0x00000ab000000000    |  r.._.d..........  | <- kallsyms_markers
        0xffffffff8b2b4b50:    0x00002316000016d3 0x00003cf800002f38    |  .....#..8/...<..  |

        [Sample values for 32bit]
        gef> hexdump -n qword kallsyms_names
        0xc6cbce58:    0x335fd57472fb5c08 0x54039974f9540432    |  ...rt._32.T.t..T  | <- kallsyms_names
        0xc6cbce68:    0x63ff72fb5c0799a6 0xd57472fb5c0a30a1    |  .....r.c.0...rt.  |
        0xc6cbce78:    0x177407b6f932335f 0xa0ca0aa1f3796669    |  _32...t.ify.....  |
        0xc6cbce88:    0xd7f49b2d63ecc37f 0x2d63ecc37fa0ca0a    |  ...c-.........c-  |
        ...
        0xc6e0dc78:    0x3a7262fe620d105f 0x10ff67ef796ccf65    |  _..b.br:e.ly.g..  |
        0xc6e0dc88:    0x62fe420964164203 0x0000ec6d699b6b72    |  .B.d.B.brk.im...  |
        0xc6e0dc98:    0x00000c6100000000 0x000026410000188f    |  ....a.......A&..  | <- kallsyms_markers
        0xc6e0dca8:    0x000041a700003492 0x00005ace00004e6b    |  .4...A..kN...Z..  |
        """

        # take the last element of kallsyms_marker
        if hasattr(self, "offset_kallsyms_seqs_of_names"): # maybe 6.1.42~6.8
            kallsyms_markers_end = self.offset_kallsyms_seqs_of_names
        else:
            kallsyms_markers_end = self.offset_kallsyms_token_table

        kallsyms_markers_data = self.kernel_img[self.offset_kallsyms_markers:kallsyms_markers_end]
        kallsyms_markers_entries = slice_unpack(kallsyms_markers_data, self.kallsyms_markers_table_element_size)
        kallsyms_markers_last_entry = list(filter(None, kallsyms_markers_entries))[-1] # filter 0, maybe padding

        # go back that number of bytes
        position = self.offset_kallsyms_markers
        position -= kallsyms_markers_last_entry
        position += -position % self.kallsyms_markers_table_element_size

        if position <= 0:
            self.verbose_err("Could not find kallsyms_names")
            return False

        # This value is provisional. It will be corrected in the next process (=find_kallsyms_num_syms).
        self.offset_kallsyms_names = position
        self.verbose_info("kallsyms_names: {:#x} (candidate)".format(self.ro_base + self.offset_kallsyms_names))
        return True

    def find_kallsyms_num_syms(self):
        ret = self.get_saved_config([
            "num_symbols",
            "offset_kallsyms_names",
            "offset_kallsyms_num_syms",
        ])
        if ret:
            self.verbose_info("num_symbols: {:#x}".format(self.num_symbols))
            self.verbose_info("kallsyms_names: {:#x}".format(self.ro_base + self.offset_kallsyms_names))
            self.verbose_info("kallsyms_num_syms: {:#x}".format(self.ro_base + self.offset_kallsyms_num_syms))
            return True

        """
        [Search strategy]
        - From candidate address of kallsyms_names, search backwards to the top of what can be correctly
          interpreted as kallsyms_names.

        [Positional relationship]
        ...
        - kallsyms_num_syms
        - kallsyms_names (to be fixed in this step)
        - kallsyms_markers
        - kallsyms_seqs_of_names (v6.1.42~v6.8)
        - kallsyms_token_table
        - kallsyms_token_index
        ...
        - kallsyms_seqs_of_names (v6.9~)
        ...

        [Sample values for 64bit]
        gef> hexdump -n qword kallsyms_num_syms
        0xffffffff8b16e608:    0x000000000001982b 0x0cf3ec0e78b6410a    |  +........A.x....  |
        0xffffffff8b16e618:    0xf370ff4109fe61cb 0x0c410774722cbdeb    |  .a..A.p...,rt.A.  |
        0xffffffff8b16e628:    0xa8410df67ef4285f 0x936bed62d8632c71    |  _(.~..A.q,c.b.k.  |
        0xffffffff8b16e638:    0x925f0c4107f67ef4 0xfb646741067772f1    |  .~..A._..rw.Agd.  |

        [Sample values for 32bit]
        gef> hexdump -n dword kallsyms_num_syms
        0xc6cbce54:    0x00018eb8 0x72fb5c08 0x335fd574 0xf9540432    |  .......rt._32.T.  |
        0xc6cbce64:    0x54039974 0x5c0799a6 0x63ff72fb 0x5c0a30a1    |  t..T.....r.c.0..  |
        0xc6cbce74:    0xd57472fb 0xf932335f 0x177407b6 0xf3796669    |  .rt._32...t.ify.  |
        """

        token_table = self.get_token_table()
        possible_symbol_types = "-?ABCDGINPRSTUVWabcdginprstuvw" # from `man nm`
        dp = []
        step = 4

        position = self.offset_kallsyms_names
        # kallsyms_names should be aligned.
        # This optimization is based on experience and is applied for now.
        position += -position % step

        while True:
            if position < 0:
                self.verbose_err("Could not find kallsyms_names")
                return False

            # Do some types of checks.
            # 1: check the token type is likely or not.
            token_index = self.kernel_img[position + 1]
            symbol_type = token_table[token_index][0]
            if symbol_type not in possible_symbol_types:
                position -= step
                continue

            # 2: check the table (kallsyms_names) entirely.
            # Each element of kallsyms_names consists of {number of tokens, tokens[number of tokens]}.
            # tokens[0][0] is symbol type.
            #
            # The following is an example of last elements of kallsyms_names.
            # gef> x/24xb 0xffffffffb46b4b48-0x10
            # 0xffffffffb46b4b38: 0xf5   0x0c*  0x44   0xff   0xf5   0x8d   0x73   0x63 (*: start of last valid elements)
            # 0xffffffffb46b4b40: 0x72   0xe8   0xbf   0x5f   0xee   0x64*  0x00** 0x00 (*: end of last valid elements, **: end marker)
            # 0xffffffffb46b4b48: 0x00*  0x00   0x00   0x00   0xb0   0x0a   0x00   0x00 (*: start of kallsyms_markers)
            #
            # 0x0c: number of tokens
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x44]
            # 'D' (= symbol type)
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xff]
            # '__'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xf5]
            # 'in'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x8d]
            # 'it_'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x73]
            # 's'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x63]
            # 'c'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x72]
            # 'r'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xe8]
            # 'at'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xbf]
            # 'ch'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x5f]
            # '_'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xee]
            # 'en'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x64]
            # 'd'
            # (=`__init_scratch_end`)
            #
            # Finally, 0x00(**) is following, this is the marker that represents the end of kallsyms_names.
            # This can be interpreted that the size of element is 0.
            #
            # However, this 0x00 may not exist.
            # gef> x/16xb 0xffffffffadefc1d8-0x8
            # 0xffffffffadefc1d0: 0x12   0x65   0x05*  0xbf   0x65   0xaf   0x74   0xa5** (*/**: start/end of last valid elements)
            # 0xffffffffadefc1d8: 0x00*  0x00   0x00   0x00   0xb2   0x0b   0x00   0x00   (*: start of kallsyms_markers)
            # Even in this case, the first byte of kallsyms_markers is always 0, so we use it.
            #
            # Check that this structure is correct or not, using bottom-up DP.
            # dp[i] contains num_syms as interpreted from `kallsyms_makers - i` as the start of kallsyms_names.
            # dp[i] == -1 means invalid.
            range_start = position
            range_end = self.offset_kallsyms_markers
            range_end -= len(dp) # shortcut the already checked results.
            for pos in range(range_end, range_start - 1, -1):
                symbol_size = self.kernel_img[pos]
                is_big_symbol = False # default

                # check if big symbol (6.1~)
                if self.kernel_version >= (6, 1, 0):
                    if symbol_size & 0x80:
                        low = symbol_size & 0x7f
                        high = self.kernel_img[pos + 1]
                        symbol_size = (high << 7) | low
                        is_big_symbol = True

                # 0xffffffffb46b4b38: 0xf5     0x0c     0x44     0xff     0xf5     0x8d     0x73     0x63
                # 0xffffffffb46b4b40: 0x72     0xe8     0xbf     0x5f     0xee     0x64     0x00*    0x00*
                #                                                                           dp[2]=0  dp[1]=0
                # 0xffffffffb46b4b48: 0x00*    0x00     0x00     0x00     0xb0     0x0a     0x00     0x00
                #                     dp[0]=0
                if symbol_size == 0:
                    dp.append(0) # maybe it is a last entry
                    continue

                # 0xffffffffb46b4b38: 0xf5     0x0c     0x44     0xff     0xf5     0x8d     0x73     0x63
                # 0xffffffffb46b4b40: 0x72     0xe8     0xbf     0x5f     0xee     0x64*    0x00     0x00
                #                                                                  dp[3]=-1 dp[2]=0  dp[1]=0
                # 0xffffffffb46b4b48: 0x00*    0x00     0x00     0x00     0xb0     0x0a     0x00     0x00
                #                     dp[0]=0
                dp_len = len(dp)
                if is_big_symbol:
                    dp_len = len(dp) - 1
                if symbol_size >= dp_len:
                    dp.append(-1) # exceed the kallsyms_markers
                    continue

                # 0xffffffffb46b4b38: 0xf5     0x0c*    0x44     0xff     0xf5     0x8d     0x73     0x63
                #                              dp[f]=1  dp[e]=-1 dp[d]=-1 dp[c]=-1 dp[b]=-1 dp[a]=-1 dp[9]=-1
                # 0xffffffffb46b4b40: 0x72     0xe8     0xbf     0x5f     0xee     0x64     0x00**   0x00
                #                     dp[8]=-1 dp[7]=-1 dp[6]=-1 dp[5]=-1 dp[4]=-1 dp[3]=-1 dp[2]=0  dp[1]=0
                # 0xffffffffb46b4b48: 0x00*    0x00     0x00     0x00     0xb0     0x0a     0x00     0x00
                #                     dp[0]=0
                # when we see 0x0c(*), next element is 0x00(**).
                # In this case, here, len(dp) == 15 (dp[15] does not exist, but dp[14] exists).
                # dp[-(0xc + 1)] is dp[2]. dp[2] is 0, not -1, so dp[15] is valid. If dp[2] is -1, dp[15] is invalid.
                offset_of_next_element = -symbol_size - 1
                if is_big_symbol:
                    offset_of_next_element -= 1
                if dp[offset_of_next_element] == -1:
                    dp.append(-1)
                    continue
                # seems to be okay, append valid dp
                dp.append(dp[offset_of_next_element] + 1)

            num_symbols = dp[-1]
            if num_symbols < 256:
                # It is judged as NG because there are too few symbols.
                position -= step
                continue

            # 3: Find num_symbols from memory.
            if self.kallsyms_markers_table_element_size == 4:
                seq_to_find = p32(num_symbols)
            elif self.kallsyms_markers_table_element_size == 8:
                seq_to_find = p64(num_symbols)
            # Depending on the environment, there are many zero padding after seq_to_find (=kallsyms_num_syms).
            # This is probably because each variable is aligned in units of 256 bytes.
            MAX_ALIGNMENT = 256
            start = max(0, position - MAX_ALIGNMENT)
            needle = self.kernel_img.rfind(seq_to_find, start, position)
            if needle == -1:
                position -= step
                continue

            # it seems ok.
            self.offset_kallsyms_names = position
            self.offset_kallsyms_num_syms = needle
            break

        self.save_config("offset_kallsyms_names")
        self.save_config("offset_kallsyms_num_syms")
        self.num_symbols = num_symbols
        self.save_config("num_symbols")
        self.verbose_info("num_symbols: {:#x}".format(self.num_symbols))
        self.verbose_info("kallsyms_names: {:#x}".format(self.ro_base + self.offset_kallsyms_names))
        self.verbose_info("kallsyms_num_syms: {:#x}".format(self.ro_base + self.offset_kallsyms_num_syms))
        return True

    def find_kallsyms_offsets(self):
        """
        [Search strategy]
        - ~v6.3
          - From kallsyms_num_syms, go back by num_symbols element sizes.
          - num_symbols offsets are stored, so get them.
        - v6.4~
          - From kallsyms_token_index + 0x200, num_symbols offsets are stored, so get them.

        [Positional relationship]
        - ...
        - kallsyms_offsets (v4.6~v6.3, CONFIG_KALLSYMS_BASE_RELATIVE=y)
        - kallsyms_relative_base (v4.6~v6.3, CONFIG_KALLSYMS_BASE_RELATIVE=y)
        - kallsyms_num_syms
        - kallsyms_names
        - kallsyms_markers
        - kallsyms_seqs_of_names (v6.1.42~v6.8)
        - kallsyms_token_table
        - kallsyms_token_index
        - kallsyms_offsets (v6.4~, CONFIG_KALLSYMS_BASE_RELATIVE=y)
        - kallsyms_relative_base (v6.4~v6.19, CONFIG_KALLSYMS_BASE_RELATIVE=y)
        - kallsyms_seqs_of_names (v6.9~)
        - ...

        [Sample values for 64bit ~v6.3, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n (use positive offset)]
        gef> hexdump -n dword kallsyms_offsets
        0xffffffff8b108550:    0x00000000 0x00000000 0x00001000 0x00002000    |  ............. ..  |
        0xffffffff8b108560:    0x00006000 0x0000b000 0x0000c000 0x00018000    |  .`..............  |
        0xffffffff8b108570:    0x00019000 0x00019008 0x00019010 0x00019020    |  ............ ...  |
        0xffffffff8b108580:    0x00019420 0x00019440 0x00019448 0x00019450    |   ...@...H...P...  |

        [Sample values for 64bit ~v6.3, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y (use negative offset)]
        gef> hexdump -n dword kallsyms_offsets
        0xffffffffa72854b0:    0xffffffff 0xffffffff 0xffffffff 0xffffffbf    |  ................  |
        0xffffffffa72854c0:    0xffffffba 0xfffffeef 0xfffffdef 0xfffffddf    |  ................  |
        0xffffffffa72854d0:    0xfffffdcf 0xfffffa1f 0xfffff9cf 0xfffff9bf    |  ................  |
        0xffffffffa72854e0:    0xfffff99f 0xfffff8ff 0xfffff76f 0xfffff73f    |  ........o...?...  |

        [Sample values for 32bit ~v6.3, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n (use positive offset)]
        gef> hexdump -n dword kallsyms_offsets
        0xc6c59370:    0x00000000 0x00000000 0x00000000 0x00000070    |  ............p...  |
        0xc6c59380:    0x00000080 0x000001d8 0x000002e0 0x00000320    |  ............ ...  |
        0xc6c59390:    0x00000360 0x000003a8 0x000003e8 0x000004a8    |  `...............  |
        0xc6c593a0:    0x000005a8 0x0000066c 0x0000073c 0x000007ac    |  ....l...<.......  |

        [Sample values for 64bit v6.4~, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n (use positive offset)]
        gef> hexdump -n word kallsyms_token_index
        0xffffffff844fa178:    0x0000 0x0003 0x0006 0x000a 0x0010 0x0013 0x0016 0x0019    |  ................  |
        0xffffffff844fa188:    0x001d 0x0029 0x002d 0x0030 0x0034 0x0037 0x003b 0x003e    |  ..).-.0.4.7.;.>.  |
        0xffffffff844fa198:    0x0041 0x0056 0x005a 0x005e 0x0061 0x0064 0x0067 0x006a    |  A.V.Z.^.a.d.g.j.  |
        ...
        0xffffffff844fa358:    0x0386 0x0389 0x038c 0x038f 0x0392 0x0395 0x0398 0x039b    |  ................  |
        0xffffffff844fa368:    0x039e 0x03a1 0x03a5 0x03a8 0x03ab 0x03ae 0x03b1 0x03b4    |  ................  |
        gef> hexdump -n dword kallsyms_offset
        0xffffffff844fa378:    0x00000000 0x00000000 0x00001000 0x00002000    |  ............. ..  |
        0xffffffff844fa388:    0x00006000 0x0000b000 0x0000c000 0x00014000    |  .`...........@..  |
        ...
        0xffffffff8461e44c:    0xf89effff 0xf89dffff 0xf89d9fff 0xf89d9fff    |  ................  |
        0xffffffff8461e45c:    0x00000000 0x81000000 0xffffffff 0x02fa0e02    |  ................  |
        relative_base_address: 0xffffffff81000000

        [Sample values for 64bit v6.4~, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y (use negative offset)]
        gef> hexdump -n word kallsyms_token_index
        0xffffffff86744a38:    0x0000 0x0004 0x000c 0x0010 0x0014 0x0017 0x001b 0x0020    |  .............. .  |
        0xffffffff86744a48:    0x002d 0x0034 0x0039 0x003d 0x0042 0x0045 0x0048 0x004b    |  -.4.9.=.B.E.H.K.  |
        0xffffffff86744a58:    0x004f 0x0053 0x005d 0x0060 0x0064 0x0067 0x006b 0x0072    |  O.S.].`.d.g.k.r.  |
        ...
        0xffffffff86744c18:    0x0338 0x033b 0x033e 0x0341 0x0349 0x034c 0x034f 0x0357    |  8.;.>.A.I.L.O.W.  |
        0xffffffff86744c28:    0x035a 0x035d 0x0360 0x0363 0x0369 0x036e 0x0372 0x0375    |  Z.].`.c.i.n.r.u.  |
        gef> hexdump -n dword kallsyms_offset
        0xffffffff86744c38:    0xffffffff 0xffffffff 0xffffffff 0xffffffaf    |  ................  |
        0xffffffff86744c48:    0xffffffaa 0xfffffe9f 0xfffffe8f 0xfffffd8f    |  ................  |
        ...
        0xffffffff8677ed5c:    0xff09237f 0xff09218f 0xff09217f 0xff0920a9    |  .#...!...!... ..  |
        0xffffffff8677ed6c:    0x00000000 0x85c00000 0xffffffff 0x00f0d800    |  ................  |
        relative_base_address: 0xffffffff85c00000
        """

        # const values
        if Endian.is_big_endian():
            endianness_marker = ">"
            endian_str = "big"
        else:
            endianness_marker = "<"
            endian_str = "little"
        offset_byte_size = 4
        address_byte_size = runtime.current_arch.ptrsize

        if self.kernel_version < (7, 0, 0):
            # get relative_base_address
            if self.kernel_version < (6, 4, 0):
                # ignore the 0 immediately above offset_kallsyms_num_syms.
                position = self.offset_kallsyms_num_syms
                while True:
                    previous_word = self.kernel_img[position - address_byte_size:position]
                    if previous_word != b"\0" * address_byte_size:
                        break
                    position -= address_byte_size

                # Go backward by num_symbols.
                position -= address_byte_size

                # read from kallsyms_relative_base
                relative_base_address = int.from_bytes(self.kernel_img[position:position + address_byte_size], endian_str)

                if relative_base_address and (relative_base_address & get_pagesize_mask_low()) == 0:
                    """
                    some environment has invalid address as relative_base_address.
                    so don't use the logic of is_valid_addr(relative_base_address).

                    gef> hexdump -n qword 0xffffafc5c2adb260-0x10 0x20
                    0xffffafc5c2adb250:    0xffffafc5c1750000 0x0000000000028193    |  ..u.............  |
                    0xffffafc5c2adb260:    0x6474107414bc5404 0x6c7463be6270d277    |  .T..t.tdw.pb.ctl  |
                    gef> x/16xg 0xffffafc5c1750000
                    0xffffafc5c1750000:     Cannot access memory at address 0xffffafc5c1750000
                    """
                    while True:
                        previous_word = self.kernel_img[position - offset_byte_size:position]
                        if previous_word != b"\0" * offset_byte_size:
                            break
                        position -= offset_byte_size
                    position -= self.num_symbols * offset_byte_size

            else: # kernel_version >= (6, 4):
                position = self.offset_kallsyms_token_index + 0x200
                position_relative_base = align(position + self.num_symbols * offset_byte_size, runtime.current_arch.ptrsize)
                relative_base_address_data = self.kernel_img[position_relative_base:position_relative_base + address_byte_size]
                if len(relative_base_address_data) == 0:
                    self.verbose_err("kernel_img is not long enough.")
                    return False
                relative_base_address = int.from_bytes(relative_base_address_data, endian_str)
                if not (relative_base_address and (relative_base_address & get_pagesize_mask_low()) == 0):
                    return True

            # Getting here means that the relative_address and position have been detected correctly.
            self.verbose_info("relative_base_address: {:#x}".format(relative_base_address))

            # Try to parse addresses or offsets.
            fmt = "{:s}{:d}i".format(endianness_marker, self.num_symbols) # signed int
            kallsyms_offsets_data = self.kernel_img[position:position + self.num_symbols * offset_byte_size]
            ksym_offsets = struct.unpack(fmt, kallsyms_offsets_data)

            # Check the ratio of the negative value
            number_of_negative_items = len([offset for offset in ksym_offsets if offset < 0])
            if number_of_negative_items / len(ksym_offsets) >= 0.5:
                # the case CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y.
                kernel_addresses = []
                for offset in ksym_offsets:
                    if offset < 0:
                        x = relative_base_address - 1 - offset
                        kernel_addresses.append(x)
                    else:
                        kernel_addresses.append(offset)
            else:
                # the case CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n.
                kernel_addresses = []
                for offset in ksym_offsets:
                    x = offset + relative_base_address
                    kernel_addresses.append(x)

            # Check the ratio of the null value.
            number_of_null_items = kernel_addresses.count(0)
            if number_of_null_items / len(kernel_addresses) >= 0.2:
                return True

        else: # kernel_version >= (7, 0):
            position = self.offset_kallsyms_token_index + 0x200

            # Try to parse addresses or offsets.
            fmt = "{:s}{:d}i".format(endianness_marker, self.num_symbols) # signed int
            kallsyms_offsets_data = self.kernel_img[position:position + self.num_symbols * offset_byte_size]
            ksym_offsets = struct.unpack(fmt, kallsyms_offsets_data)

            # 7.0+: offset_to_ptr style, no kallsyms_relative_base. CONFIG_KALLSYMS_ABSOLUTE_PERCPU is removed.
            kernel_addresses = []
            for i, offset in enumerate(ksym_offsets):
                element_va = self.ro_base + position + i * offset_byte_size
                kernel_addresses.append(element_va + offset)

        # It seems ok.
        self.offset_kallsyms_addresses_or_offsets = position
        self.kernel_addresses = kernel_addresses
        self.verbose_info("kallsyms_offsets: {:#x}".format(self.ro_base + self.offset_kallsyms_addresses_or_offsets))
        return True

    def find_kallsyms_addresses(self):
        """
        [Search strategy]
        - From kallsyms_num_syms, go back by num_symbols element sizes.
        - num_symbols addresses are stored, so get them.

        [Positional relationship]
        - ...
        - kallsyms_addresses (~v6.3, CONFIG_KALLSYMS_BASE_RELATIVE=n)
        - kallsyms_num_syms
        - kallsyms_names
        - kallsyms_markers
        - kallsyms_seqs_of_names (v6.1.42~v6.8)
        - kallsyms_token_table
        - kallsyms_token_index
        - kallsyms_addresses (v6.4~?, CONFIG_KALLSYMS_BASE_RELATIVE=n) # Unimplemented, as this pattern has not been observed yet.
        - kallsyms_seqs_of_names (v6.9~)
        - ...

        [Sample values for 64bit ~v6.3]
        gef> hexdump -n qword kallsyms_addresses
        0xffffffff81ae3cb8:    0x0000000000000000 0x0000000000000000    |  ................  |
        0xffffffff81ae3cc8:    0x0000000000004000 0x0000000000009000    |  .@..............  |
        ...
        0xffffffff81ae4588:    0xffffffff81000000 0xffffffff81000000    |  ................  |
        0xffffffff81ae4598:    0xffffffff81000110 0xffffffff810001a9    |  ................  |

        [Sample values for 32bit ~v6.3]
        gef> hexdump -n dword kallsyms_addresses
        0xc1940888:    0xc1000000 0xc1000000 0xc10000bc 0xc10000cc    |  ................  |
        0xc1940898:    0xc10000ed 0xc1000165 0xc10001e7 0xc1000239    |  ....e.......9...  |
        0xc19408a8:    0xc1000283 0xc10002c1 0xc10002d0 0xc1000302    |  ................  |
        0xc19408b8:    0xc1000328 0xc100032f 0xc1000338 0xc1000338    |  (.../...8...8...  |
        """

        # const values
        if Endian.is_big_endian():
            endianness_marker = ">"
        else:
            endianness_marker = "<"
        address_byte_size = runtime.current_arch.ptrsize

        # ignore the 0 immediately above offset_kallsyms_num_syms.
        position = self.offset_kallsyms_num_syms
        while True:
            previous_word = self.kernel_img[position - address_byte_size:position]
            if previous_word != b"\0" * address_byte_size:
                break
            position -= address_byte_size

        # Go backward by num_symbols.
        position -= self.num_symbols * address_byte_size

        # Try to parse addresses.
        if address_byte_size == 8:
            fmt = "{:s}{:d}Q".format(endianness_marker, self.num_symbols)
        else:
            fmt = "{:s}{:d}I".format(endianness_marker, self.num_symbols)
        kallsyms_addresses_data = self.kernel_img[position:position + self.num_symbols * address_byte_size]
        self.kernel_addresses = struct.unpack(fmt, kallsyms_addresses_data)
        self.offset_kallsyms_addresses_or_offsets = position
        self.verbose_info("kallsyms_addresses: {:#x}".format(self.ro_base + self.offset_kallsyms_addresses_or_offsets))
        return True

    def initialize(self):
        ret = self.get_kernel_version()
        if not ret:
            return False

        if self.args.rescan:
            cfg_file_name = self.get_cfg_name()
            if os.path.exists(cfg_file_name):
                os.remove(cfg_file_name)
        else:
            # the case of both kernel version string are same, but offset are different.
            current_version_string_offset = self.version_string_offset # keep current
            if self.get_saved_config(["version_string_offset"]): # load temporarily
                if self.version_string_offset != current_version_string_offset:
                    cfg_file_name = self.get_cfg_name()
                    os.remove(cfg_file_name)
                    self.version_string_offset = current_version_string_offset # set current again

        ret = self.find_kallsyms_token_table()
        if not ret:
            return False

        ret = self.find_kallsyms_token_index()
        if not ret:
            return False

        ret = self.find_kallsyms_markers()
        if not ret:
            return False

        ret = self.find_kallsyms_names()
        if not ret:
            return False

        ret = self.find_kallsyms_num_syms()
        if not ret:
            return False

        self.offset_kallsyms_addresses_or_offsets = None
        if self.kernel_version >= (4, 6):
            # On modern kernels, first check the case CONFIG_KALLSYMS_BASE_RELATIVE=y.
            ret = self.find_kallsyms_offsets()
            if not ret:
                return False

        if not self.offset_kallsyms_addresses_or_offsets:
            if self.kernel_version < (7, 0):
                # the case CONFIG_KALLSYMS_BASE_RELATIVE=n.
                self.find_kallsyms_addresses()

        self.save_config("version_string")
        self.save_config("version_string_offset")
        self.save_config("ro_size")
        return True

    def arm64_fast_path(self):
        if not is_in_kernel():
            self.quiet_info("Use slow path")
            return False

        # This path is more faster because it does not use pagewalk.
        # Instead of finding ro_base from pagewalk results, it finds ro_base by scanning the kernel version.
        # It is especially beneficial for ARM64, due to extensive pagetables and pagewalk take a long time.
        # It may work on other architectures but limited to ARM64 as others gain little.

        # First, search for the kernel version string from $pc.
        # It is located at around top of ro_base, and ro_base is aligned by 0x10000.
        current = (runtime.current_arch.pc & ~0xffff) + 0x10000 # Starting address to brute force ro_base
        step_size = 0x10000
        while True:
            try:
                # As kernel version string is near the top of ro_base, it is enough to check the first page.
                candidate_rodata = read_memory(current, get_pagesize())
            except gdb.MemoryError:
                # reached to the end of ro_base
                self.quiet_info("Use slow path")
                return False

            # '\n\0' is needed to avoid false positives in the dmesg buffer.
            r = re.search(rb"Linux version (\d+\.[\d.]*\d)[ -~]+\n\0", candidate_rodata)
            if r:
                # Found kernel version string
                version_string_address = current + r.span()[0]
                self.version_string = r.group(0)[:-2]
                version_number = r.group(1).decode("ascii")
                self.kernel_version = self.get_kernel_version_triplet(version_number)
                break
            current += step_size

        # We can make the hash from the kernel version string and load from saved config.
        # At this point, following two parameters are enough.
        ret = self.get_saved_config([
            "version_string_offset",
            "ro_size",
        ])
        if not ret:
            self.quiet_info("Use slow path")
            return False

        # Restore ro_base with considering kASLR.
        self.quiet_info("Use fast path")
        self.ro_base = version_string_address - self.version_string_offset
        self.verbose_info("ro_base: {:#x}-{:#x}".format(self.ro_base, self.ro_base + self.ro_size))

        # doit
        self.kernel_img = read_memory(self.ro_base, self.ro_size)
        ret = self.initialize()
        if not ret:
            self.quiet_info("Use slow path")
            return False

        self.read_kallsyms()
        return True

    def parse_kallsyms(self):
        if self.kallsyms:
            return True # use cache

        # Fast path when reattaching GDB after executing this command once (ARM64 only).
        if is_arm64():
            ret = self.arm64_fast_path()
            if ret:
                return True

        # Slow path
        try:
            kinfo = Kernel.get_kernel_layout()
            if kinfo.has_none:
                return False
        except gdb.MemoryError:
            self.quiet_err("Memory read error")
            return False

        if not kinfo.rwx:
            # On modern kernels, ro_size can be trusted, so it only tries to parse once.
            self.ro_base = kinfo.ro_base
            self.ro_size = kinfo.ro_size
            self.kernel_img = read_memory(self.ro_base, self.ro_size)
            self.verbose_info("ro_base: {:#x}-{:#x}".format(self.ro_base, self.ro_base + self.ro_size))
            ret = self.initialize()
            if not ret:
                return False
        else:
            # Older kernel that has the RWX attribute don't trust ro_size.
            # Very large values of ro_size can be detected.
            # It will take a long time to parse if you just use it.
            # Gradually increasing ro_size while searching can speed up several times.
            self.ro_base = kinfo.ro_base
            # This value is a heuristic threshold derived through testing across numerous kernel images.
            # Unless there is a compelling reason, do not modify it.
            base_size = 0x10_0000
            step = 0x10_0000
            for candidate_size in range(base_size, kinfo.ro_size, step):
                self.ro_size = candidate_size
                self.kernel_img = read_memory(self.ro_base, self.ro_size)
                self.verbose_info("ro_base: {:#x}-{:#x}".format(self.ro_base, self.ro_base + self.ro_size))
                ret = self.initialize()
                if ret:
                    # found
                    break
            else:
                # not found
                return False

        # here, we got all offsets to read kallsyms
        self.read_kallsyms()
        return True

    def parse_main(self):
        if self.kallsyms:
            return True

        # specified vmlinux parse
        if self.args.vmlinux_file:
            if not os.path.exists(self.args.vmlinux_file):
                self.quiet_err("Could not find vmlinux file")
                return False
            self.quiet_info("Parse from file: {!s}".format(self.args.vmlinux_file))
            self.parse_vmlinux(self.args.vmlinux_file)
            return True

        # loaded vmlinux parse
        loaded_vmlinux = self.get_loaded_vmlinux_path()
        if loaded_vmlinux:
            self.quiet_info("Parse from file: {!s}".format(loaded_vmlinux))
            self.parse_vmlinux(loaded_vmlinux)
            return True

        # normal parse
        self.quiet_info("Wait for memory scan")
        ret = self.parse_kallsyms()
        if ret:
            return True

        # failed, but if args.rescan was not specified originally
        if not self.args.rescan:
            self.quiet_info("Try to rescan (ignore cached config)")
            original_rescan = self.args.rescan
            self.args.rescan = True
            try:
                self.kallsyms = []
                ret = self.parse_kallsyms()
            finally:
                self.args.rescan = original_rescan
            if ret:
                return True

        self.quiet_err("Failed to parse")
        return False

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    def do_invoke(self, args):
        if args.print_saved_config:
            self.print_saved_config()
            return

        if self.args.rescan:
            self.kallsyms = []

        ret = self.parse_main()
        if not ret:
            return

        self.print_kallsyms(args.keyword, args.type, args.smart)
        self.print_output(check_terminal_size=True)
        return


@register_command
class VmlinuxToElfApplyCommand(GenericCommand):
    """Apply symbol from kallsyms in memory using vmlinux-to-elf."""

    _cmdline_ = "vmlinux-to-elf-apply"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true",
                        help="force applying again. (default: reuse vmlinux-to-elf-dump-memory.elf if exists)")
    _syntax_ = parser.format_help()

    @staticmethod
    def dump_kernel_elf(rescan=False):
        """Dump the kernel from the memory, then apply vmlinux-to-elf to create symboled ELF."""
        # check
        try:
            vmlinux2elf = GefUtil.which("vmlinux-to-elf")
        except FileNotFoundError as e:
            err("{}".format(e))
            return None

        # resolve kversion for saved file name
        kversion = Kernel.kernel_version()
        h = hashlib.sha256(String.str2bytes(kversion.version_string)).hexdigest()[-16:]
        dumped_mem_file = os.path.join(GEF_TEMP_DIR, "dump-memory-{:s}.raw".format(h))
        symboled_vmlinux_file = os.path.join(GEF_TEMP_DIR, "dump-memory-{:s}.elf".format(h))

        # check if it can be reused
        if (not rescan) and os.path.exists(symboled_vmlinux_file) and os.path.getsize(symboled_vmlinux_file) > 0:
            info("A previously used file found, will be reused")
            return symboled_vmlinux_file

        # resolve text_base, ro_base
        kinfo = Kernel.get_kernel_layout()
        if None in (kinfo.text_base, kinfo.text_size, kinfo.ro_base, kinfo.ro_size):
            err("Failed to resolve")
            return None
        gef_print("kernel base:   {:#x}-{:#x} ({:#x} bytes)".format(kinfo.text_base, kinfo.text_end, kinfo.text_size))
        gef_print("kernel rodata: {:#x}-{:#x} ({:#x} bytes)".format(kinfo.ro_base, kinfo.ro_end, kinfo.ro_size))

        info("Start memory dump")
        # rodata size detection may be inaccurate on kernels with RWX attribute regions.
        # Since they tend to be very large, we put a size cap on the rodata to make it faster.
        if kinfo.rwx:
            # The number 0x400000 has no basis.
            fixed_ro_base_size = min(0x40_0000, kinfo.ro_size)
        else:
            fixed_ro_base_size = kinfo.ro_size

        # delete old file
        if os.path.exists(dumped_mem_file):
            gef_print("Delete old {:s}".format(dumped_mem_file))
            os.unlink(dumped_mem_file)
        if os.path.exists(symboled_vmlinux_file):
            gef_print("Delete old {:s}".format(symboled_vmlinux_file))
            os.unlink(symboled_vmlinux_file)

        # delete files related to old file
        for f in os.listdir(GEF_TEMP_DIR):
            if os.path.basename(dumped_mem_file) in f:
                remove_file = os.path.join(GEF_TEMP_DIR, f)
                gef_print("Delete old {:s}".format(remove_file))
                os.unlink(remove_file)
            if os.path.basename(symboled_vmlinux_file) in f:
                remove_file = os.path.join(GEF_TEMP_DIR, f)
                gef_print("Delete old {:s}".format(remove_file))
                os.unlink(remove_file)

        # dump text
        start = kinfo.text_base
        end = start + kinfo.text_size
        gef_print("Dumping .text area:   {:#x} - {:#x}".format(start, end))
        try:
            gdb.execute("dump memory {} {:#x} {:#x}".format(dumped_mem_file, start, end), to_string=True)
        except gdb.MemoryError:
            err("Memory read error. Make sure the context is in supervisor mode / Ring-0")
            return None

        # dump sparse
        text_end = kinfo.text_end
        unmapped_size = kinfo.ro_base - text_end
        if unmapped_size:
            gef_print("Non-mapping area:     {:#x} - {:#x} (ZERO fill)".format(text_end, kinfo.ro_base))
            open(dumped_mem_file, "a").write("\0" * unmapped_size)

        # dump rodata
        start = kinfo.ro_base
        end = start + fixed_ro_base_size
        gef_print("Dumping .rodata area: {:#x} - {:#x}".format(start, end))
        try:
            gdb.execute("append memory {} {:#x} {:#x}".format(dumped_mem_file, start, end), to_string=True)
        except gdb.MemoryError:
            err("Memory read error. Make sure the context is in supervisor mode / Ring-0")
            return None

        gef_print("Dumped to {:s}".format(dumped_mem_file))

        # apply vmlinux-to-elf
        cmd = "{!r} {!r} {!r} --base-address={:#x}".format(vmlinux2elf, dumped_mem_file, symboled_vmlinux_file, kinfo.text_base)
        warn("Execute `{:s}`".format(cmd))
        os.system(cmd)

        # Error
        if not os.path.exists(symboled_vmlinux_file) or os.path.getsize(symboled_vmlinux_file) == 0:
            return None

        # Success
        return symboled_vmlinux_file

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel
    def do_invoke(self, args):
        info("Wait for memory scan")

        text_base = Kernel.get_kernel_base()
        if text_base is None:
            err("Failed to resolve kbase")
            return

        symboled_vmlinux_file = self.dump_kernel_elf(args.rescan)
        if symboled_vmlinux_file is None:
            err("Failed to create kernel ELF")
            return

        # load symbol
        info("Adding symbol")
        # Prior to gdb 8.x, add-symbol-file command requires a .text address
        #   gdb 9.x: Usage: add-symbol-file FILE [-readnow | -readnever] [-o OFF] [ADDR] [-s SECT-NAME SECT-ADDR]...
        #   gdb 8.x: Usage: add-symbol-file FILE ADDR [-readnow | -readnever | -s SECT-NAME SECT-ADDR]...
        # But the created ELF has no .text, only a .kernel
        # Applying an empty symbol has no effect, so tentatively specify the same address as the .kernel.
        cmd = "add-symbol-file {!r} {:#x} -s .kernel {:#x}".format(symboled_vmlinux_file, text_base, text_base)
        warn("Execute `{:s}`".format(cmd))
        gdb.execute(cmd)
        return


@register_command
class KsymaddrRemoteApplyCommand(GenericCommand):
    """Apply symbol from kallsyms in memory."""

    _cmdline_ = "ksymaddr-remote-apply"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"
    _aliases_ = ["ks-apply"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    def create_symboled_elf(self, sym_elf_path):
        # get .kernel range
        from gef.commands.debugging.other import AddSymbolTemporaryCommand
        text_base = Symbol.get_ksymaddr("_stext")
        if text_base is None:
            err("Failed to get kernel base (_stext)")
            return False
        res = gdb.execute("ksymaddr-remote --quiet --no-pager", to_string=True)
        text_end = int(res.splitlines()[-1].split()[0], 16)

        # make blank ELF
        text_base &= get_pagesize_mask_high()
        blank_elf = AddSymbolTemporaryCommand.create_blank_elf(text_base, text_end)
        if blank_elf is None:
            err("Failed to create blank ELF")
            return False

        # parse kernel symbol
        cmd_string_arr = []
        for line in res.splitlines():
            addr, typ, func_name = line.split()
            addr = int(addr, 16)

            if addr < text_base:
                # lower address is percpu-relative. It is meaningless to import the address, so it is skipped.
                continue

            if typ in ["T", "t", "W", None]:
                type_flag = "function"
            else:
                type_flag = "object"
            if typ and typ in "abcdefghijklmnopqrstuvwxyz":
                global_flag = "local"
            else:
                global_flag = "global"

            # higher address needs relative
            relative_addr = addr - text_base
            cmd_string_arr.append("--add-symbol")
            cmd_string_arr.append("{:s}=.text:{:#x},{:s},{:s}".format(func_name, relative_addr, global_flag, type_flag))

        self.quiet_info("{:d} entries will be added".format(len(cmd_string_arr) // 2))

        # embedding symbols
        objcopy = GefUtil.which(Config.get_gef_setting("gef.objcopy_command"))
        processed_count = 0
        for cmd_string_arr_sliced in slicer(cmd_string_arr, 10000 * 2):
            subprocess.check_output([objcopy] + cmd_string_arr_sliced + [blank_elf])
            processed_count += len(cmd_string_arr_sliced) // 2

            # debug print
            if processed_count and processed_count % 10000 == 0:
                self.quiet_info("{:d} entries were processed".format(processed_count))

        self.quiet_info("{:d} entries were processed".format(processed_count))
        os.rename(blank_elf, sym_elf_path)
        return True

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel
    def do_invoke(self, args):
        try:
            GefUtil.which(Config.get_gef_setting("gef.objcopy_command"))
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        self.quiet_info("Wait for memory scan")

        # resolve kversion for saved file name
        kversion = Kernel.kernel_version()
        h = hashlib.sha256(String.str2bytes(kversion.version_string)).hexdigest()[-16:]
        sym_elf_path = os.path.join(GEF_TEMP_DIR, "ks-apply-{:s}.elf".format(h))
        if (not args.rescan) and os.path.exists(sym_elf_path) and os.path.getsize(sym_elf_path) > 0:
            self.quiet_info("A previously used file found, will be reused")
        else:
            if os.path.exists(sym_elf_path):
                os.unlink(sym_elf_path)
            ret = self.create_symboled_elf(sym_elf_path)
            if not ret:
                return

        # add symbol to gdb
        text_base = Symbol.get_ksymaddr("_stext") & get_pagesize_mask_high()
        cmd = "add-symbol-file {:s} {:#x}".format(sym_elf_path, text_base)
        self.quiet_warn("Execute `{:s}`".format(cmd))
        gdb.execute(cmd)
        return

