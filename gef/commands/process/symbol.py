"""GEF process-info commands (category 02-g) extracted from the monolithic gef.py.

Symbol-related commands (magic, symbols).

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
from gef.core.address import AddressUtil
from gef.core.color import gef_print, info, titlify
from gef.core.elf import Elf
from gef.core.memory import (
    is_ascii_string,
    is_valid_addr,
    read_cstring_from_memory,
    read_int_from_memory,
)
from gef.core.process import ProcessMap, is_qemu_system, is_vmware
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil, get_libc_version

@register_command
class MagicCommand(GenericCommand):
    """Display useful userland addresses and offsets."""

    _cmdline_ = "magic"
    _category_ = "02-g. Process Information - Symbol"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-s", "--smart", action="store_true", help="show only the most frequently used items.")
    parser.add_argument("-j", "--print-file-jumps", action="store_true", help="print _IO_xxx_jumps functions.")
    parser.add_argument("filter", metavar="FILTER", nargs="*", help="filter string.")
    _syntax_ = parser.format_help()

    def should_be_print(self, sym):
        if not self.args.filter:
            return True

        for filt in self.args.filter:
            if filt in sym:
                return True
        return False

    def resolve_and_print(self, sym, base):
        if not self.should_be_print(sym):
            return

        width = AddressUtil.get_format_address_width()
        try:
            addr = int(gdb.parse_and_eval(f"&{sym}"))
        except gdb.error:
            gef_print("{:45s} {:>{:d}s}".format(sym, "Not found", width))
            return

        addr = ProcessMap.lookup_address(addr)
        perm = addr.section.permission
        if is_ascii_string(addr.value):
            val = read_cstring_from_memory(addr.value)
            gef_print("{:45s} {!s} [{!s}] (+{:#010x}) -> {:s}".format(
                sym, addr, perm, addr.value - base, val,
            ))
        else:
            val = ProcessMap.lookup_address(read_int_from_memory(addr.value))
            val_sym = Symbol.get_symbol_string(val.value)
            gef_print("{:45s} {!s} [{!s}] (+{:#010x}) -> {:s}{:s}".format(
                sym, addr, perm, addr.value - base, val.long_fmt(), val_sym,
            ))
        return

    def resolve_and_print_fj(self, sym, base):
        self.resolve_and_print(sym, base)

        if not self.should_be_print(sym):
            return

        if not self.args.print_file_jumps:
            return

        try:
            vtable = int(gdb.parse_and_eval(f"&{sym}"))
        except Exception:
            return

        gdb.execute("dereference {:#x} 22 --no-pager".format(vtable))
        return

    def magic(self):
        codebase = ProcessMap.get_codebase()
        libc = ProcessMap.get_section_base_address_by_list(("libc-2.", "libc.so.6"))
        ld = ProcessMap.get_section_base_address_by_list(("ld-2.", "ld-linux-", "ld-linux.so.2"))
        if libc is None or ld is None:
            gef_print("libc/ld not found")
            return

        gef_print(titlify("Legend"))
        fmt = "{:45s} {:{:d}s} {:5s} (+{:10s}) -> {:{:d}s}"
        width = AddressUtil.get_format_address_width()
        legend = ["Symbol", "Addr", width, "Perm", "Offset", "Value", width]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        gef_print(titlify("Heap"))
        if not self.args.smart:
            self.resolve_and_print("main_arena", libc)
            self.resolve_and_print("mp_", libc)
        self.resolve_and_print("__malloc_hook", libc)
        self.resolve_and_print("__free_hook", libc)
        self.resolve_and_print("__realloc_hook", libc)
        if not self.args.smart:
            self.resolve_and_print("__memalign_hook", libc)
            self.resolve_and_print("__after_morecore_hook", libc)
            self.resolve_and_print("_dl_open_hook", libc)
            self.resolve_and_print("global_max_fast", libc)
            self.resolve_and_print("malloc", libc)
            self.resolve_and_print("free", libc)
            self.resolve_and_print("calloc", libc)
            self.resolve_and_print("realloc", libc)

        gef_print(titlify("I/O"))
        self.resolve_and_print("*stdin", libc)
        self.resolve_and_print("*stdout", libc)
        self.resolve_and_print("*stderr", libc)
        self.resolve_and_print("_IO_list_all", libc)

        if not self.args.smart:
            if get_libc_version() < (2, 38):
                self.resolve_and_print_fj("_IO_file_jumps", libc)
                self.resolve_and_print_fj("_IO_file_jumps_mmap", libc)
                self.resolve_and_print_fj("_IO_file_jumps_maybe_mmap", libc)
                self.resolve_and_print_fj("_IO_wfile_jumps", libc)
                self.resolve_and_print_fj("_IO_wfile_jumps_mmap", libc)
                self.resolve_and_print_fj("_IO_wfile_jumps_maybe_mmap", libc)
                self.resolve_and_print_fj("_IO_old_file_jumps", libc)
                self.resolve_and_print_fj("_IO_mem_jumps", libc)
                self.resolve_and_print_fj("_IO_wmem_jumps", libc)
                self.resolve_and_print_fj("_IO_str_jumps", libc)
                self.resolve_and_print_fj("_IO_strn_jumps", libc)
                self.resolve_and_print_fj("_IO_str_chk_jumps", libc)
                self.resolve_and_print_fj("_IO_wstr_jumps", libc)
                self.resolve_and_print_fj("_IO_wstrn_jumps", libc)
                self.resolve_and_print_fj("_IO_streambuf_jumps", libc)
                self.resolve_and_print_fj("_IO_proc_jumps", libc)
                self.resolve_and_print_fj("_IO_old_proc_jumps", libc)
                self.resolve_and_print_fj("_IO_helper_jumps", libc)
                self.resolve_and_print_fj("_IO_cookie_jumps", libc)
                self.resolve_and_print_fj("_IO_obstack_jumps", libc)
            else:
                self.resolve_and_print_fj("__io_vtables[IO_STR_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_WSTR_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_FILE_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_FILE_JUMPS_MMAP]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_FILE_JUMPS_MAYBE_MMAP]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_WFILE_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_WFILE_JUMPS_MMAP]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_WFILE_JUMPS_MAYBE_MMAP]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_COOKIE_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_PROC_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_MEM_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_WMEM_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_PRINTF_BUFFER_AS_FILE_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_WPRINTF_BUFFER_AS_FILE_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_OLD_FILE_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_OLD_PROC_JUMPS]", libc)
                self.resolve_and_print_fj("__io_vtables[IO_OLD_COOKIED_JUMPS]", libc)

        self.resolve_and_print("open", libc)
        self.resolve_and_print("read", libc)
        self.resolve_and_print("write", libc)
        if not self.args.smart:
            self.resolve_and_print("dup", libc)
            self.resolve_and_print("dup2", libc)
            self.resolve_and_print("dup3", libc)
            self.resolve_and_print("puts", libc)
            self.resolve_and_print("gets", libc)
            self.resolve_and_print("fputs", libc)
            self.resolve_and_print("fgets", libc)
            self.resolve_and_print("printf", libc)
            self.resolve_and_print("fprintf", libc)
            self.resolve_and_print("dprintf", libc)
            self.resolve_and_print("sprintf", libc)
            self.resolve_and_print("snprintf", libc)
            self.resolve_and_print("__printf_chk", libc)
            self.resolve_and_print("__fprintf_chk", libc)
            self.resolve_and_print("__dprintf_chk", libc)
            self.resolve_and_print("__sprintf_chk", libc)
            self.resolve_and_print("__snprintf_chk", libc)
            self.resolve_and_print("__printf_function_table", libc)
            self.resolve_and_print("__printf_arginfo_table", libc)
            self.resolve_and_print("scanf", libc)
            self.resolve_and_print("fscanf", libc)
            self.resolve_and_print("sscanf", libc)

        gef_print(titlify("Process"))
        self.resolve_and_print("system", libc)
        if not self.args.smart:
            self.resolve_and_print("do_system", libc)
        self.resolve_and_print("execve", libc)
        self.resolve_and_print("setcontext", libc)
        if not self.args.smart:
            self.resolve_and_print("__libc_start_main", libc)
            self.resolve_and_print("syscall", libc)
            self.resolve_and_print("ptrace", libc)
            self.resolve_and_print("prctl", libc)

        if not self.args.smart:
            gef_print(titlify("Memory"))
            self.resolve_and_print("mmap", libc)
            self.resolve_and_print("munmap", libc)
            self.resolve_and_print("mremap", libc)
            self.resolve_and_print("mprotect", libc)
            gef_print(titlify("Stack"))
            self.resolve_and_print("__libc_argv", libc)
            self.resolve_and_print("__environ", libc)
            gef_print(titlify("Destructor"))
            self.resolve_and_print("_rtld_global->_dl_rtld_lock_recursive", ld)
            self.resolve_and_print("_rtld_global->_dl_rtld_unlock_recursive", ld)
            self.resolve_and_print("error_print_progname", libc)
            gef_print(titlify("Unwind"))
            self.resolve_and_print("'DW.ref.__gxx_personality_v0'", codebase)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("wine", "kgdb"))
    @require_arch_set
    def do_invoke(self, args):
        if is_qemu_system() or is_vmware():
            info("Redirect to kmagic")
            gdb.execute("kmagic {:s}".format(" ".join(args.filter)))
            return

        self.magic()
        return


@register_command
class SymbolsCommand(GenericCommand, BufferingOutput):
    """List all symbols (shortcut for `maintenance print msymbols`) with coloring."""

    _cmdline_ = "symbols"
    _category_ = "02-g. Process Information - Symbol"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-t", "--type", action="append", default=[], help="filter by symbol type.")
    parser.add_argument("-c", "--use-cache", action="store_true", help="use previous result.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    def get_build_id(self, filename):
        e = Elf.get_elf(filename)
        if e is None or not e.is_valid():
            return None
        try:
            build_id = e.read_shdr(".note.gnu.build-id")
        except Exception:
            return None
        return build_id

    def get_build_ids(self):
        build_id_dict = {}
        for filename in ProcessMap.get_loaded_files():
            build_id = self.get_build_id(filename)
            if build_id is None:
                continue
            build_id_dict[build_id] = filename
        return build_id_dict

    def get_symbols(self):
        """Parse and display symbol information from GDB, including file/object info
        and symbol addresses, with filtering."""
        ret = gdb.execute("maintenance print msymbols", to_string=True).strip()
        SYMBOL_INFO_LINE_PATTERN = re.compile(r"^(\[ ?\d+\]) (.) (0x[0-9a-f]+) (.*)")
        SYMBOL_FILE_PATTERN = re.compile(r"^Object file (/.*):$")
        build_id_dict = self.get_build_ids()

        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for line in tqdm(ret.splitlines(), leave=False):
            line = line.strip()

            # blank line
            if not line:
                self.out.append(line)
                continue

            # filename line
            # e.g., Object file /root/.cache/debuginfod_client/1c8db5f83bba514f8fd5f1fb6d7be975be1bb855/debuginfo:
            r = SYMBOL_FILE_PATTERN.search(line)
            if r:
                self.out.append(line)

                filename = r.group(1)
                build_id = self.get_build_id(filename)
                if build_id in build_id_dict:
                    if build_id_dict[build_id] != filename:
                        self.out.append("(={:s})".format(build_id_dict[build_id]))
                continue

            # symbol info line
            # e.g., [2875] T 0x7ffff7cad650 malloc section .text  sofini.c
            r = SYMBOL_INFO_LINE_PATTERN.search(line)
            if r:
                # type filtering
                typ = r.group(2)
                if self.args.type:
                    if typ.lower() not in self.args.type:
                        continue

                # invalid address filtering
                addr = int(r.group(3), 16)
                if not is_valid_addr(addr):
                    self.out.append(line)
                    continue
                addr = ProcessMap.lookup_address(addr)

                index = r.group(1)
                remain = r.group(4)
                self.out.append("{:s} {:s} {!s} {:s}".format(index, typ, addr, remain))
                continue

            # other line
            self.out.append(line)

        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.use_cache and hasattr(self, "cache") and self.cache:
            self.out = self.cache[::]
            self.print_output()
            return

        self.out = []
        self.get_symbols()
        self.print_output()
        self.cache = self.out[::]
        return
