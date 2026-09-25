"""GEF process-info commands (category 02-c) extracted from the monolithic gef.py.

Memory/section commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import re

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
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.config import Config
from gef.core.process import (
    Path,
    ProcessMap,
    is_arm32_cortex_m,
    is_in_kernel,
    is_qemu_system,
    is_qemu_user,
    is_vmware,
)
from gef.core.registers import get_register
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil

@register_command
class VMMapCommand(GenericCommand, BufferingOutput):
    """Display a comprehensive layout of the virtual memory mapping."""

    _cmdline_ = "vmmap"
    _category_ = "02-c. Process Information - Memory/Section"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--outer", action="store_true",
                        help="display qemu-user's memory map instead of emulated process's memory map.")
    parser.add_argument("filter", metavar="FILTER", nargs="?", help="filter string.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="do not display register information.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} libc             # show only lines containing the string `libc`",
        "{0:s} binary           # 'binary' means the area executable itself",
        "{0:s} 0x555555577ab0   # show only lines included specified address",
        "{0:s} --outer          # show qemu-user memory map; only valid in qemu-user mode",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def dump_entry(self, entry, print_offset=False):
        # get color
        line_color = ""
        if entry.path.startswith("[stack]"):
            line_color = Config.get_gef_setting("theme.address_stack")
        elif entry.path.startswith("[heap]"):
            line_color = Config.get_gef_setting("theme.address_heap")
        elif entry.permission.value & Permission.EXECUTE:
            line_color = Config.get_gef_setting("theme.address_code")
        elif entry.permission.value & Permission.WRITE:
            line_color = Config.get_gef_setting("theme.address_writable")
        elif entry.permission.value & Permission.READ:
            line_color = Config.get_gef_setting("theme.address_readonly")
        elif entry.permission.value == Permission.NONE:
            line_color = Config.get_gef_setting("theme.address_valid_but_none")
        if entry.permission.value == (Permission.READ | Permission.WRITE | Permission.EXECUTE):
            line_color += " " + Config.get_gef_setting("theme.address_rwx")

        # if qemu-xxx(32bit arch) runs on x86-64 machine, memalign_size does not match
        # AddressUtil.get_memory_alignment()
        memalign_size = 8 if self.args.outer else None

        # make line
        lines = []
        lines.append(Color.colorify(
            AddressUtil.format_address(entry.page_start, memalign_size, long_fmt=True), line_color,
        ))
        lines.append(Color.colorify(
            AddressUtil.format_address(entry.page_end, memalign_size, long_fmt=True), line_color,
        ))
        lines.append(Color.colorify(
            AddressUtil.format_address(entry.size, memalign_size, long_fmt=True), line_color,
        ))
        lines.append(Color.colorify(
            AddressUtil.format_address(entry.offset, memalign_size, long_fmt=True), line_color,
        ))
        lines.append(Color.colorify(
            str(entry.permission), line_color,
        ))
        if entry.path:
            lines.append(Color.colorify(entry.path, line_color))
        line = " ".join(lines)

        # offset info
        if not self.args.quiet:
            if print_offset is not False:
                line += Color.colorify(" {:+#x}".format(print_offset), line_color)

        # register info
        if not self.args.quiet:
            register_hints = []
            for regname in runtime.current_arch.all_registers:
                regvalue = get_register(regname)
                if entry.page_start <= regvalue < entry.page_end:
                    register_hints.append(regname)
            if register_hints:
                m = "  <-  {:s}".format(", ".join(list(register_hints)))
                registers_color = Config.get_gef_setting("theme.dereference_register_value")
                line += Color.colorify(m, registers_color)

        self.out.append(line)
        return

    def show_legend(self):
        legend = "[ Legend: {:s} ]".format(
            " | ".join([
                Color.colorify("Code", Config.get_gef_setting("theme.address_code")),
                Color.colorify("Heap", Config.get_gef_setting("theme.address_heap")),
                Color.colorify("Stack", Config.get_gef_setting("theme.address_stack")),
                Color.colorify("Writable", Config.get_gef_setting("theme.address_writable")),
                Color.colorify("ReadOnly", Config.get_gef_setting("theme.address_readonly")),
                Color.colorify("None", Config.get_gef_setting("theme.address_valid_but_none")),
                Color.colorify("RWX", Config.get_gef_setting("theme.address_rwx")),
            ]),
        )
        self.out.append(legend)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("kgdb",))
    def do_invoke(self, args):
        if is_qemu_system() or is_vmware():
            if is_arm32_cortex_m():
                info("Redirect to `xfiles` (args are ignored)")
                gdb.execute("xfiles")
                return
            elif is_in_kernel():
                info("Redirect to `kvmmap` (args are ignored; use `pagewalk` to show phys addr)")
                gdb.execute("kvmmap")
                return
            else:
                info("Redirect to `pagewalk` (args are ignored)")
                gdb.execute("pagewalk --quiet")
                return

        if args.outer and not is_qemu_user():
            err("Unsupported `--outer` option in this gdb mode")
            return

        if is_qemu_user():
            # the memory map may be changed, so retry memory exploring in get_process_maps()
            Cache.reset_gef_caches(all=True)

        # get maps
        vmmap = ProcessMap.get_process_maps(args.outer)
        if not vmmap:
            for line in gdb.execute("info files", to_string=True).splitlines():
                if line.startswith("Symbols from"):
                    break
            else:
                err("Missing info about architecture. Please set: `file /path/to/target_binary`")
            err("No address mapping information found")
            return

        # color legend
        self.out = []
        if not Config.get_gef_setting("gef.disable_color"):
            self.show_legend()

        # legend
        fmt = "{:{:d}s} {:{:d}s} {:{:d}s} {:{:d}s} {:4s} {:s}"
        memalign_size = 8 if args.outer else AddressUtil.get_memory_alignment()
        width =  memalign_size * 2 + 2
        legend = ["Start", width, "End", width, "Size", width, "Offset", width, "Perm", "Path"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # for filter
        filter_addr1 = None
        filter_addr2 = None
        if args.filter is not None:
            try:
                filter_addr1 = AddressUtil.parse_address(args.filter)
            except gdb.error:
                pass
            try:
                filter_addr2 = int(args.filter, 0)
            except ValueError:
                pass

        # show each entry
        for entry in vmmap:
            # no filter
            if not args.filter:
                self.dump_entry(entry)
                continue

            # includes address
            if filter_addr1 is not None:
                if entry.page_start <= filter_addr1 < entry.page_end:
                    self.dump_entry(entry, print_offset=filter_addr1 - entry.page_start)
                    filter_addr1 = None # It never matches a different region
                    continue

            # range match
            if filter_addr2 is not None:
                if entry.page_start <= filter_addr2 < entry.page_end:
                    self.dump_entry(entry, print_offset=filter_addr2 - entry.page_start)
                    filter_addr2 = None # It never matches a different region
                    continue

            # `binary` case
            if args.filter == "binary":
                if Path.get_filepath(append_proc_root_prefix=False) == entry.path:
                    self.dump_entry(entry)
                    continue

            # A simple match to the filter string
            if args.filter in entry.path:
                self.dump_entry(entry)
                continue

        # warning message
        if is_qemu_user() and not args.outer:
            if ProcessMap.__gef_use_info_proc_mappings__ is False:
                self.info_add_out("Some areas may be undetectable due to heuristic search (auxv, registers, stack)")
                self.info_add_out("Permissions use ELF header or default rw-; dynamic changes undetectable")

        # print
        self.print_output(check_terminal_size=True)
        return


@register_command
class XFilesCommand(GenericCommand, BufferingOutput):
    """Display all libraries (and sections) loaded by binary."""

    _cmdline_ = "xfiles"
    _category_ = "02-c. Process Information - Memory/Section"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("filter", metavar="FILTER", nargs="*", help="regex filter string.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} libc",
        "{0:s} got plt",
        "{0:s} IO_vtables",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        self.out = []

        fmt = "{:{:d}s} {:{:d}s} {:<21s} {:s}"
        width = AddressUtil.get_format_address_width()
        legend = ["Start", width, "End", width, "Name", "File"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for xfile in ProcessMap.get_info_files():
            lines = []
            lines.append(str(ProcessMap.lookup_address(xfile.zone_start)))
            lines.append(str(ProcessMap.lookup_address(xfile.zone_end)))
            lines.append("{:<21s}".format(xfile.name))
            lines.append(xfile.filename)
            line = " ".join(lines)

            if not args.filter:
                self.out.append(line)
                continue

            for filt in args.filter:
                if re.search(filt, line):
                    self.out.append(line)
                    break

        self.print_output(check_terminal_size=True)
        return


@register_command
class XInfoCommand(GenericCommand):
    """Retrieve and display runtime information for the location(s) given as parameter."""

    _cmdline_ = "xinfo"
    _category_ = "02-c. Process Information - Memory/Section"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="*", type=AddressUtil.parse_address,
                        help="the memory address to show the information. (default: current_arch.pc)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $pc",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def xinfo(self, address):
        addr = ProcessMap.lookup_address(address)
        if not addr.valid:
            warn("Cannot reach {:#x} in memory space".format(address))
            return

        gdb.execute("vmmap {:#x}".format(address))

        if addr.section:
            page_start = ProcessMap.lookup_address(addr.section.page_start)
            gef_print("Offset (from mapped):  {!s} + {:#x}".format(
                page_start, addr.value - addr.section.page_start,
            ))

            if addr.section.path and addr.section.path.startswith("/"):
                base_start = ProcessMap.lookup_address(ProcessMap.get_section_base_address(addr.section.path))
                gef_print("Offset (from base):    {!s} + {:#x}".format(
                    base_start, addr.value - base_start.section.page_start,
                ))

        if addr.info:
            zone_start = ProcessMap.lookup_address(addr.info.zone_start)
            gef_print("Offset (from segment): {!s} ({:s}) + {:#x}".format(
                zone_start, addr.info.name, addr.value - addr.info.zone_start,
            ))

        sym = Symbol.get_symbol_string(address)
        if sym:
            msg = "Symbol:                {:s}".format(sym.strip())
            gef_print(msg)

        if addr.section and addr.section.inode:
            gef_print("Inode:                 {:d}".format(addr.section.inode))

        return

    def xinfo_kernel_pagewalk(self, address):
        ret = gdb.execute("pagewalk --vrange {:#x} --no-pager --quiet".format(address), to_string=True)
        ret = [x for x in ret.splitlines() if not Color.remove_color(x).startswith(("---", "[+]"))]

        if not ret:
            err("Not found")
            return

        gef_print("\n".join(ret))

        if ret[-1].startswith("0x"):
            virt, phys, *_ = ret[-1].split()
            vstart = int(virt.split("-")[0], 16)
            pstart = int(phys.split("-")[0], 16)
            offset = address - vstart
            gef_print("Offset (from virt mapped):  {:#x} + {:#x}".format(vstart, offset))
            gef_print("Offset (from phys mapped):  {:#x} + {:#x}".format(pstart, offset))
        return

    def xinfo_kernel_kvmmap(self, address):
        ret = gdb.execute("kvmmap {:#x} --no-pager --quiet".format(address), to_string=True)
        gef_print(ret.rstrip())
        return

    def xinfo_kernel_slab(self, address):
        ret = gdb.execute("slab-contains {:#x}".format(address), to_string=True)
        gef_print(ret.rstrip())
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("kgdb",))
    @require_arch_set
    def do_invoke(self, args):
        if args.location == []:
            locations = [runtime.current_arch.pc]
        else:
            locations = args.location

        # kernel xinfo
        if is_qemu_system() or is_vmware():
            for location in locations:
                gef_print(titlify("xinfo (from pagewalk): {:#x}".format(location)))
                self.xinfo_kernel_pagewalk(location)
                gef_print(titlify("xinfo (from kvmmap): {:#x}".format(location)))
                self.xinfo_kernel_kvmmap(location)
                gef_print(titlify("xinfo (from slab-contains): {:#x}".format(location)))
                self.xinfo_kernel_slab(location)
            return

        # userland xinfo
        for location in locations:
            try:
                gef_print(titlify("xinfo: {:#x}".format(location)))
                self.xinfo(location)
            except gdb.error as gdb_error:
                err(str(gdb_error))
        return

