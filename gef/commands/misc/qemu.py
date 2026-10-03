"""GEF misc Qemu-system command (category 07-g) extracted from the
monolithic gef.py.

qemu-system-memory-region-dump: walk QEMU MemoryRegion trees from a
qemu-system target.
Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Permission, Section
from gef.core.color import Color
from gef.core.memory import (
    is_valid_addr,
    read_cstring_from_memory,
    read_int_from_memory,
    read_memory,
)
from gef.core.process import Path, Pid, ProcessMap
from gef.core.symbols import Symbol
from gef.core.utils import slice_unpack


@register_command
class QemuMemoryRegionDumpCommand(GenericCommand, BufferingOutput):
    """Dump memory regions for qemu-system."""

    _cmdline_ = "qemu-system-memory-region-dump"
    _category_ = "07-g. Misc - Qemu-system"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-s", "--smart", action="store_true",
                        help="show only entries where read or write is not the default.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    def get_rw_map(self):
        filepath = Path.get_filepath(append_proc_root_prefix=False)
        maps = ProcessMap.get_process_maps_linux(Pid.get_pid())
        RW = Permission.READ | Permission.WRITE
        rw_maps = []
        for m in maps:
            if m.permission.value != RW:
                continue
            if m.path == filepath:
                rw_maps.append(m)
                continue
            if len(rw_maps) > 0:
                if m.page_start == rw_maps[-1].page_end:
                    # concat
                    new_m = Section(
                        page_start=rw_maps[-1].page_start,
                        page_end=m.page_end,
                        offset=rw_maps[-1].offset,
                        permission=rw_maps[-1].permission,
                        inode=rw_maps[-1].inode,
                        path=rw_maps[-1].path,
                    )
                    rw_maps[-1] = new_m
        if len(rw_maps) == 1:
            return rw_maps[0]
        return None

    def get_memory_region(self, name_target):
        """
        static MemoryRegion *system_memory;
        static MemoryRegion *system_io;

        AddressSpace address_space_io;
        AddressSpace address_space_memory;

        struct AddressSpace {
            struct rcu_head rcu; // ptrsize * 2 bytes
            char *name; // -> "memory" or "I/O"
            MemoryRegion *root;
            struct FlatView *current_map;
            ...
        };
        """
        rw_map = self.get_rw_map()
        if rw_map is None:
            return None

        rw_content = read_memory(rw_map.page_start, rw_map.size)
        rw_content_sliced = slice_unpack(rw_content, runtime.current_arch.ptrsize)

        # Since it is near the end of the RW area, searching in reverse is faster
        for i, val in enumerate(rw_content_sliced[::-1], start=1):
            if not is_valid_addr(val):
                continue

            # name check
            name = read_cstring_from_memory(val)
            if name != name_target:
                continue
            ofs_name = rw_map.size - (runtime.current_arch.ptrsize * i)

            # root check
            ofs_root = ofs_name + runtime.current_arch.ptrsize
            root = read_int_from_memory(rw_map.page_start + ofs_root)
            if not is_valid_addr(root):
                continue
            root = ProcessMap.lookup_address(root)
            if not root.section.is_writable():
                continue

            # current_map check
            ofs_current_map = ofs_root + runtime.current_arch.ptrsize
            current_map = read_int_from_memory(rw_map.page_start + ofs_current_map)
            if not is_valid_addr(current_map):
                continue
            current_map = ProcessMap.lookup_address(current_map)
            if not current_map.section.is_writable():
                continue

            # found
            return root.value
        return None

    def get_system_memory(self):
        # fast path
        try:
            system_memory = AddressUtil.parse_address("&system_memory")
            return read_int_from_memory(system_memory)
        except gdb.error:
            pass
        # slow path
        return self.get_memory_region("memory")

    def get_system_io(self):
        # fast path
        try:
            system_io = AddressUtil.parse_address("&system_io")
            return read_int_from_memory(system_io)
        except gdb.error:
            pass
        # slow path
        return self.get_memory_region("I/O")

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            return True

        # root (system_memory, system_io)
        self.system_memory = self.get_system_memory()
        if self.system_memory is None:
            self.quiet_err("Could not find system_memory")
            return False
        self.quiet_info_add_out("system_memory: {:#x}".format(self.system_memory))

        self.system_io = self.get_system_io()
        if self.system_io is None:
            self.quiet_err("Could not find system_io")
            return False
        self.quiet_info_add_out("system_io: {:#x}".format(self.system_io))

        # name
        for offset in range(0, 0x100, runtime.current_arch.ptrsize):
            name_ptr_addr = self.system_memory + offset
            name_ptr = read_int_from_memory(name_ptr_addr)
            if not is_valid_addr(name_ptr):
                continue
            if read_cstring_from_memory(name_ptr) == "system":
                self.offset_name = offset
                break
        else:
            self.quiet_err("Could not find offsetof(MemoryRegion, name)")
            return False
        self.quiet_info_add_out("offsetof(MemoryRegion, name): {:#x}".format(self.offset_name))

        # ops
        for offset in range(0, 0x80, runtime.current_arch.ptrsize):
            ops_addr = self.system_memory + offset
            ops = read_int_from_memory(ops_addr)
            # ops itself is r-x addr
            if not is_valid_addr(ops):
                continue
            if ProcessMap.lookup_address(ops).section.is_writable():
                continue
            # ops->read: zero or r-x addr
            read_func = read_int_from_memory(ops + runtime.current_arch.ptrsize * 0)
            if read_func:
                if ProcessMap.lookup_address(read_func).section.is_writable():
                    continue
            # ops->write: zero or r-x addr
            write_func = read_int_from_memory(ops + runtime.current_arch.ptrsize * 1)
            if write_func:
                if ProcessMap.lookup_address(write_func).section.is_writable():
                    continue
            self.offset_ops = offset
            break
        else:
            self.quiet_err("Could not find offsetof(MemoryRegion, ops)")
            return False
        self.quiet_info_add_out("offsetof(MemoryRegion, ops): {:#x}".format(self.offset_ops))

        # subregions, subregions_link
        self.offset_subregions = self.offset_name - runtime.current_arch.ptrsize * 6
        self.quiet_info_add_out("offsetof(MemoryRegion, subregions): {:#x}".format(self.offset_subregions))
        self.offset_subregions_link = self.offset_name - runtime.current_arch.ptrsize * 4
        self.quiet_info_add_out("offsetof(MemoryRegion, subregions_link): {:#x}".format(self.offset_subregions_link))

        self.initialized = True
        return

    def make_symbol_string(self, addr):
        addr = ProcessMap.lookup_address(addr)
        sym = Symbol.get_symbol_string(addr.value, nosymbol_string=" <NO_SYMBOL>")
        return "{!s}{:s}".format(addr, sym)

    def print_region_smart(self, name, ops, level):
        # skip if uninteresting
        if not ops:
            return

        # skip if seen
        if ops in self.seen:
            return
        self.seen.append(ops)

        # print
        indent = "  " * level
        read_func = read_int_from_memory(ops + runtime.current_arch.ptrsize * 0)
        write_func = read_int_from_memory(ops + runtime.current_arch.ptrsize * 1)
        if read_func or write_func:
            self.out.append("{:s}MemoryRegion: {:s}".format(indent, Color.boldify(name)))
            self.out.append("{:s}  ops:{:s}".format(indent, self.make_symbol_string(ops)))
            self.out.append("{:s}    read:{:s}, write:{:s}".format(
                indent,
                self.make_symbol_string(read_func),
                self.make_symbol_string(write_func),
            ))
        return

    def print_region(self, name, ops, level):
        # print always
        indent = "  " * level
        self.out.append("{:s}MemoryRegion: {:s}".format(indent, Color.boldify(name)))
        if not ops:
            self.out.append("{:s}  ops:{:#x}".format(indent, ops))
            return

        # print
        self.out.append("{:s}  ops:{:s}".format(indent, self.make_symbol_string(ops)))
        read_func = read_int_from_memory(ops + runtime.current_arch.ptrsize * 0)
        write_func = read_int_from_memory(ops + runtime.current_arch.ptrsize * 1)
        if read_func or write_func:
            self.out.append("{:s}    read:{:s}, write:{:s}".format(
                indent,
                self.make_symbol_string(read_func),
                self.make_symbol_string(write_func),
            ))
        return

    def dump_region(self, mr, level):
        name_ptr = read_int_from_memory(mr + self.offset_name)
        name = read_cstring_from_memory(name_ptr) or ""
        ops = read_int_from_memory(mr + self.offset_ops)

        # dump ops
        if self.args.smart:
            self.print_region_smart(name, ops, level)
        else:
            self.print_region(name, ops, level)

        # parse recursively
        link = read_int_from_memory(mr + self.offset_subregions)
        while link:
            self.dump_region(link, level + 1)
            link = read_int_from_memory(link + self.offset_subregions_link)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        self.out = []
        if self.initialize() is False:
            return

        # dump system_memory
        self.seen = []
        self.quiet_info_add_out("system_memory")
        self.dump_region(self.system_memory, 0)

        # dump system_io
        self.seen = []
        self.quiet_info_add_out("system_io")
        self.dump_region(self.system_io, 0)

        self.print_output(check_terminal_size=True)
        return
