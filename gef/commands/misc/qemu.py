"""GEF misc Qemu-system command (category 07-g) extracted from the
monolithic gef.py.

qemu-system-memory-region-dump: walk QEMU MemoryRegion trees from a
qemu-system target.
Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import re
import subprocess

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
from gef.core.cache import Cache
from gef.core.color import Color
from gef.core.memory import (
    is_valid_addr,
    read_cstring_from_memory,
    read_int32_from_memory,
    read_int_from_memory,
    read_memory,
)
from gef.core.process import Path, Pid, ProcessMap, is_core_file, is_ppc64, is_remote_debug
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil, slice_unpack


@register_command
class QemuMemoryRegionDumpCommand(GenericCommand, BufferingOutput):
    """Dump memory regions for qemu-system."""

    _cmdline_ = "qemu-system-memory-region-dump"
    _category_ = "07-g. Misc - Qemu-system"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-s", "--smart", action="store_true",
                        help="show unique ops with read/write callbacks, including attribute-aware callbacks.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("--qemu-version", metavar="VERSION", help="QEMU version when debug information is unavailable.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    def get_rw_map(self):
        filepath = Path.get_filepath(append_proc_root_prefix=False)
        maps = ProcessMap.get_process_maps()
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
        if name_target == "memory":
            root_name = "system"
        else:
            root_name = "io"
        root_offset = GefUtil.offsetof("AddressSpace", "root")
        if root_offset is None:
            root_offset = runtime.current_arch.ptrsize * 3
        if name_target == "memory":
            symbol = "address_space_memory"
        else:
            symbol = "address_space_io"
        try:
            addr = Symbol.resolve_address(symbol)
            if addr is not None:
                root = read_int_from_memory(addr + root_offset, safe=True)
            else:
                root = None
            if root and self.check_root_name(root, root_name):
                self.meta.append((self.quiet_info_add_out, "Root source: {:s}.root".format(symbol)))
                return root
        except gdb.error:
            pass

        rw_map = self.get_rw_map()
        if rw_map is None:
            self.meta.append((self.quiet_err, "Could not identify the QEMU writable mapping for AddressSpace search"))
            return None

        try:
            rw_content = read_memory(rw_map.page_start, rw_map.size)
        except gdb.MemoryError as e:
            self.meta.append((self.quiet_err, "Could not scan QEMU writable mapping: {}".format(e)))
            return None
        rw_content_sliced = slice_unpack(rw_content, runtime.current_arch.ptrsize)

        # Since it is near the end of the RW area, searching in reverse is faster
        for i, val in enumerate(rw_content_sliced[::-1], start=1):
            if not is_valid_addr(val):
                continue

            # name check
            name = read_cstring_from_memory(val, safe=True)
            if name != name_target:
                continue
            ofs_name = rw_map.size - (runtime.current_arch.ptrsize * i)

            # root check
            ofs_root = ofs_name + runtime.current_arch.ptrsize
            root = read_int_from_memory(rw_map.page_start + ofs_root, safe=True)
            if not is_valid_addr(root):
                continue
            root = ProcessMap.lookup(root)
            if root.section is None or not root.section.is_writable():
                continue

            # current_map check
            ofs_current_map = ofs_root + runtime.current_arch.ptrsize
            current_map = read_int_from_memory(rw_map.page_start + ofs_current_map, safe=True)
            if not is_valid_addr(current_map):
                continue
            current_map = ProcessMap.lookup(current_map)
            if current_map.section is None or not current_map.section.is_writable():
                continue

            if self.check_root_name(root.value, root_name):
                self.meta.append((self.quiet_info_add_out, "Root source: AddressSpace name scan ({:s})".format(name_target)))
                return root.value
        return None

    def check_root_name(self, root, name):
        offset = GefUtil.offsetof("MemoryRegion", "name")
        if offset is not None:
            offsets = (offset,)
        else:
            offsets = range(0, 0x100, runtime.current_arch.ptrsize)
        for offset in offsets:
            pointer = read_int_from_memory(root + offset, safe=True)
            if pointer and read_cstring_from_memory(pointer, safe=True) == name:
                return True
        return False

    def get_system_memory(self):
        # fast path
        try:
            system_memory = Symbol.resolve_address("system_memory")
            if system_memory is not None:
                root = read_int_from_memory(system_memory, safe=True)
            else:
                root = None
            if root and self.check_root_name(root, "system"):
                self.meta.append((self.quiet_info_add_out, "Root source: system_memory symbol"))
                return root
        except gdb.error:
            pass
        # slow path
        return self.get_memory_region("memory")

    def get_system_io(self):
        # fast path
        try:
            system_io = Symbol.resolve_address("system_io")
            if system_io is not None:
                root = read_int_from_memory(system_io, safe=True)
            else:
                root = None
            if root and self.check_root_name(root, "io"):
                self.meta.append((self.quiet_info_add_out, "Root source: system_io symbol"))
                return root
        except gdb.error:
            pass
        # slow path
        return self.get_memory_region("I/O")

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def initialize(self, qemu_version=None):
        self.meta = []
        self.callback_offsets = {}
        self.offset_endianness = GefUtil.offsetof("MemoryRegionOps", "endianness")
        fields = ("name", "ops", "subregions", "subregions_link")
        offsets = {field: GefUtil.offsetof("MemoryRegion", field) for field in fields}
        typed = all(offset is not None for offset in offsets.values())
        self.meta.append((self.quiet_info_add_out, "MemoryRegion layout: {:s}".format(
            "debug information" if typed else "inferred; name-relative QTAILQ layout",
        )))

        self.system_memory = self.get_system_memory()
        self.system_io = self.get_system_io()
        for field in ("system_memory", "system_io"):
            root = getattr(self, field)
            if not root:
                self.meta.append((self.quiet_err, "Could not find {:s}".format(field)))
                return None
            self.meta.append((self.quiet_info_add_out, "{:s}: {:#x}".format(field, root)))

        callbacks = ("read", "write", "read_with_attrs", "write_with_attrs")
        if GefUtil.sizeof("MemoryRegionOps") is not None:
            self.callback_offsets = {
                field: offset for field in callbacks
                if (offset := GefUtil.offsetof("MemoryRegionOps", field)) is not None
            }
            if not all(field in self.callback_offsets for field in callbacks[:2]):
                self.meta.append((self.quiet_err, "Incomplete MemoryRegionOps debug information"))
                return None
            self.meta.append((self.quiet_info_add_out, "MemoryRegionOps layout: debug information"))
        else:
            if qemu_version is not None:
                if re.fullmatch(r"\d+\.\d+(?:\.\d+)?", qemu_version) is None:
                    self.meta.append((self.quiet_err, "Invalid QEMU version; use MAJOR.MINOR or MAJOR.MINOR.PATCH"))
                    return None
                version = "QEMU emulator version " + qemu_version
            else:
                if not is_remote_debug() and not is_core_file():
                    pid = Pid.get_pid()
                else:
                    pid = None
                if pid is None:
                    self.meta.append((self.quiet_err,
                                      "Could not determine QEMU version; use --qemu-version or load debug information"))
                    return None
                try:
                    binary = "/proc/{:d}/exe".format(pid)
                    version = GefUtil.gef_execute_external([binary, "--version"])
                except (OSError, subprocess.CalledProcessError) as e:
                    self.meta.append((self.quiet_err, "Could not determine QEMU callback layout: {}".format(e)))
                    return None
            match = re.search(r"QEMU emulator version (\d+)\.(\d+)", version)
            if match is None:
                self.meta.append((self.quiet_err, "Could not determine QEMU version; load debug information"))
                return None
            if tuple(map(int, match.groups())) >= (2, 4):
                count = 4
            else:
                count = 2
            self.callback_offsets = {field: i * runtime.current_arch.ptrsize for i, field in enumerate(callbacks[:count])}
            self.offset_endianness = count * runtime.current_arch.ptrsize
            self.meta.append((self.quiet_info_add_out, "MemoryRegionOps layout: inferred from {:s}".format(
                match.group(0),
            )))
        for field, offset in self.callback_offsets.items():
            self.meta.append((self.quiet_info_add_out, "offsetof(MemoryRegionOps, {:s}): {:#x}".format(field, offset)))

        if not typed:
            names = []
            for offset in range(0, 0x100, runtime.current_arch.ptrsize):
                values = [read_int_from_memory(root + offset, safe=True) for root in
                          (self.system_memory, self.system_io)]
                if all(values) and [read_cstring_from_memory(value, safe=True) for value in values] == ["system", "io"]:
                    names.append(offset)
            if len(names) != 1:
                self.meta.append((self.quiet_err,
                                  "Could not uniquely resolve MemoryRegion.name; candidates: {!s}".format(names)))
                return None
            offsets["name"] = names[0]
            offsets["subregions"] = names[0] - runtime.current_arch.ptrsize * 6
            offsets["subregions_link"] = names[0] - runtime.current_arch.ptrsize * 4
            candidates = []
            for offset in range(0, min(0x80, offsets["subregions"]), runtime.current_arch.ptrsize):
                ops = [read_int_from_memory(root + offset, safe=True) for root in
                       (self.system_memory, self.system_io)]
                if not all(ops):
                    continue
                sections = [ProcessMap.lookup(value).section for value in ops]
                if any(section is None or section.is_writable() for section in sections):
                    continue
                handlers = [self.get_callbacks(value) for value in ops]
                if all(handler is not None for handler in handlers) and any(any(handler.values()) for handler in handlers):
                    candidates.append(offset)
            if len(candidates) != 1:
                self.meta.append((self.quiet_err,
                                  "Could not uniquely resolve MemoryRegion.ops; candidates: {!s}".format(candidates)))
                return None
            offsets["ops"] = candidates[0]
            self.meta.append((self.quiet_info_add_out,
                              "Inference checks: root names, read-only ops, executable callbacks, endianness, QTAILQ links"))

        for field, offset in offsets.items():
            debug_offset = GefUtil.offsetof("MemoryRegion", field)
            if offset < 0 or (debug_offset is not None and offset != debug_offset):
                self.meta.append((self.quiet_err,
                                  "Inferred MemoryRegion.{:s} offset contradicts debug information".format(field)))
                return None
            setattr(self, "offset_" + field, offset)
            self.meta.append((self.quiet_info_add_out, "offsetof(MemoryRegion, {:s}): {:#x}".format(field, offset)))
        for root, name in ((self.system_memory, "system"), (self.system_io, "io")):
            name_ptr = read_int_from_memory(root + self.offset_name, safe=True)
            ops = read_int_from_memory(root + self.offset_ops, safe=True)
            if not name_ptr or read_cstring_from_memory(name_ptr, safe=True) != name:
                self.meta.append((self.quiet_err, "MemoryRegion layout does not match root {:#x} name".format(root)))
                return None
            if ops is None or (ops and self.get_callbacks(ops) is None):
                self.meta.append((self.quiet_err, "MemoryRegion layout does not match root {:#x} ops".format(root)))
                return None
            if not self.check_subregions(root):
                self.meta.append((self.quiet_err, "MemoryRegion layout does not match root {:#x} QTAILQ".format(root)))
                return None
        return True

    def get_callbacks(self, ops):
        section = ProcessMap.lookup(ops).section
        if section is None or not section.is_readable():
            return None
        if self.offset_endianness is not None:
            endianness = read_int32_from_memory(ops + self.offset_endianness, safe=True)
            if endianness not in (0, 1, 2):
                return None
        handlers = {}
        for field, offset in self.callback_offsets.items():
            handler = read_int_from_memory(ops + offset, safe=True)
            if handler is None:
                return None
            if handler:
                section = ProcessMap.lookup(handler).section
                if section is not None and section.is_readable() and not section.is_executable() and is_ppc64():
                    entry = read_int_from_memory(handler, safe=True)
                    if entry:
                        section = ProcessMap.lookup(entry).section
                    else:
                        section = None
                if section is None or not section.is_executable():
                    return None
            handlers[field] = handler
        return handlers

    def check_subregions(self, mr):
        head = mr + self.offset_subregions
        first = read_int_from_memory(head, safe=True)
        last = read_int_from_memory(head + runtime.current_arch.ptrsize, safe=True)
        if first is None or not last:
            return False
        if not first:
            return last == head
        return (read_int_from_memory(first + self.offset_subregions_link + runtime.current_arch.ptrsize, safe=True) == head
                and read_int_from_memory(last, safe=True) == 0)

    def print_region_smart(self, name, ops, level):
        if not ops or ops in self.seen:
            return
        handlers = self.get_callbacks(ops)
        if handlers is None:
            self.warn_add_out("Invalid or unreadable MemoryRegionOps at {:#x} ({:s})".format(ops, name))
            return
        self.seen.add(ops)
        if any(handlers.values()):
            self.print_region(name, ops, level, handlers)
        return

    def print_region(self, name, ops, level, handlers=None):
        indent = "  " * level
        self.out.append("{:s}MemoryRegion: {:s}".format(indent, Color.boldify(name)))
        if not ops:
            self.out.append("{:s}  ops:{:#x}".format(indent, ops))
            return
        self.out.append("{:s}  ops:{:s}".format(indent, Symbol.format(ops, missing="NO_SYMBOL", show_address=True)))
        if handlers is None:
            handlers = self.get_callbacks(ops)
        if handlers is None:
            self.warn_add_out("Invalid or unreadable MemoryRegionOps at {:#x} ({:s})".format(ops, name))
            return
        for read, write in (("read", "write"), ("read_with_attrs", "write_with_attrs")):
            if handlers.get(read) or handlers.get(write):
                self.out.append("{:s}    {:s}:{:s}, {:s}:{:s}".format(
                    indent, read, Symbol.format(handlers.get(read, 0), missing="NO_SYMBOL", show_address=True),
                    write, Symbol.format(handlers.get(write, 0), missing="NO_SYMBOL", show_address=True),
                ))
        return

    def dump_region(self, mr, level):
        pending = [(mr, level)]
        visited = set()
        while pending:
            mr, level = pending.pop()
            if mr in visited:
                self.warn_add_out("Repeated MemoryRegion at {:#x}; skipping".format(mr))
                continue
            visited.add(mr)
            name_ptr = read_int_from_memory(mr + self.offset_name, safe=True)
            if name_ptr:
                name = read_cstring_from_memory(name_ptr, safe=True)
            else:
                name = None
            ops = read_int_from_memory(mr + self.offset_ops, safe=True)
            if name is None or ops is None:
                self.warn_add_out("Unreadable MemoryRegion fields at {:#x}".format(mr))
            if ops is not None:
                if name is None:
                    name = "<unreadable name at {:#x}>".format(mr)
                if self.args.smart:
                    self.print_region_smart(name, ops, level)
                else:
                    self.print_region(name, ops, level)

            head = mr + self.offset_subregions
            link = read_int_from_memory(head, safe=True)
            previous = head
            children = []
            siblings = set()
            while link:
                if link in siblings or link in visited:
                    self.warn_add_out("Cyclic MemoryRegion link at {:#x}; stopping this list".format(link))
                    break
                siblings.add(link)
                back = read_int_from_memory(link + self.offset_subregions_link + runtime.current_arch.ptrsize, safe=True)
                if back != previous:
                    self.warn_add_out("Broken MemoryRegion link at {:#x}; stopping this list".format(link))
                    break
                children.append((link, level + 1))
                previous = link + self.offset_subregions_link
                link = read_int_from_memory(previous, safe=True)
            else:
                if link is None:
                    self.warn_add_out("Unreadable MemoryRegion link at {:#x}".format(previous))
                elif read_int_from_memory(head + runtime.current_arch.ptrsize, safe=True) != previous:
                    self.warn_add_out("Broken MemoryRegion tail at {:#x}".format(head))
            pending.extend(reversed(children))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        self.out = []
        layout_context = (Cache.inferior_context(), args.qemu_version)
        if getattr(self, "layout_context", None) != layout_context:
            Cache.clear_cache_for(self.initialize)
        self.layout_context = layout_context
        ret = self.initialize(args.qemu_version)
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            self.print_output(check_terminal_size=True)
            return

        if args.meta:
            self.print_output(check_terminal_size=True)
            return

        # dump system_memory
        self.seen = set()
        self.quiet_info_add_out("system_memory")
        self.dump_region(self.system_memory, 0)

        # dump system_io
        self.seen = set()
        self.quiet_info_add_out("system_io")
        self.dump_region(self.system_io, 0)

        self.print_output(check_terminal_size=True)
        return
