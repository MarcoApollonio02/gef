"""GEF process-info commands (category 02-b) extracted from the monolithic gef.py.

Base address commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import hashlib
import os
import re

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_specific_arch,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import err, gef_print, info, titlify, warn
from gef.core.elf import Elf
from gef.core.memory import is_valid_addr, read_int_from_memory
from gef.core.process import (
    Path,
    ProcessMap,
    is_container_attach,
    is_ppc32,
    is_qemu_user,
    is_remote_debug,
    is_riscv32,
    is_s390x,
    is_sparc64,
    is_x86,
    is_x86_32,
)
from gef.core.strings import String
from gef.core.types import GlibcHeap
from gef.core.utils import GefUtil, get_libc_version

@register_command
class CodeBaseCommand(GenericCommand):
    """Display various base addresses."""

    _cmdline_ = "codebase"
    _category_ = "02-b. Process Information - Base Address"
    _aliases_ = ["base"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-s", "--set", metavar="ADDR", type=AddressUtil.parse_address, help="user specific address.")
    parser.add_argument("-r", "--reset", action="store_true", help="reset user specific address.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    def define_section_variable(self, elf, code_base, section_name):
        sec = elf.get_shdr(section_name)
        if not sec:
            return

        if elf.is_pie():
            addr = sec.sh_addr + code_base
        else:
            addr = sec.sh_addr

        self.quiet_print(titlify(section_name))
        var_name = section_name.lstrip(".")
        self.quiet_print("${:s} = {:#x}".format(var_name, addr))
        gdb.execute("set ${:s} = {:#x}".format(var_name, addr))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    def do_invoke(self, args):
        # user specific
        if args.set is not None:
            self.code_base_user_specific = args.set

        if args.reset:
            if hasattr(self, "code_base_user_specific"):
                delattr(self, "code_base_user_specific")

        code_base = getattr(self, "code_base_user_specific", None)

        # auto estimation
        if not is_valid_addr(code_base):
            # The codebase may be heuristically determined from the memory map.
            code_base = ProcessMap.get_codebase()
            if code_base is None:
                self.quiet_err("Could not find the binary base")
                return

        # print
        self.quiet_print(titlify("code base"))
        gdb.execute(f"set $codebase = {code_base:#x}")
        self.quiet_print(f"$codebase = {code_base:#x}")

        # Any other area should use a section header.
        elf = Elf.get_elf()
        if elf is None or not elf.is_valid():
            self.quiet_err("Failed to load an ELF")
            return
        self.define_section_variable(elf, code_base, ".text")
        self.define_section_variable(elf, code_base, ".rodata")
        self.define_section_variable(elf, code_base, ".data")
        self.define_section_variable(elf, code_base, ".bss")
        return


@register_command
class HeapBaseCommand(GenericCommand):
    """Display heap base address."""

    _cmdline_ = "heapbase"
    _category_ = "02-b. Process Information - Base Address"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-s", "--set", metavar="ADDR", type=AddressUtil.parse_address, help="user specific address.")
    parser.add_argument("-r", "--reset", action="store_true", help="reset user specific address.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    @staticmethod
    def heap_base_from_symbol(force_heuristic=False):
        # The value of mp_->sbrk_base is correct in x86 or x64.
        # However, for architectures that have TLS in the bss area (such as ARM or ARM64),
        # the start position of the heap seems to shift by the amount of the area used as the TLS variable.
        # This method should not be used on ARM or ARM64, as there seems to be no way to predetermine the TLS size.
        if not is_x86():
            return None
        if force_heuristic:
            return None
        try:
            # symbol and type are defined
            return AddressUtil.parse_address("mp_->sbrk_base")
        except gdb.error:
            return None

    @staticmethod
    def heap_base_from_info_proc_map(force_heuristic=False):
        # For non-static binaries, this is mostly sufficient.
        if force_heuristic:
            return None

        try:
            codebase = ProcessMap.get_codebase()
            elf = Elf(codebase)
        except Exception:
            return None

        # In the case of dynamic linking
        if not elf.is_static():
            return ProcessMap.get_section_base_address("[heap]")

        # In the case of static or static-PIE
        ld_targets = (
            "ld-2.", "ld-linux-", "ld-linux.", # glibc
            "ld64-uClibc-", "ld-uClibc-", "ld64-uClibc.", "ld-uClibc.", # uClibc
        )
        ld = ProcessMap.get_section_base_address_by_list(ld_targets)
        if ld and codebase == ld:
            # When a binary is launched through the dynamic linker, the linker itself is treated as
            # the target and is always detected as static (because linker has no .interp always).
            # This result is not meaningful because the actual loaded binary should be checked instead.
            # In practice, binaries launched this way are almost always dynamically linked,
            # so using info proc to determine the heap base is appropriate for this case.
            return ProcessMap.get_section_base_address("[heap]")

        return None

    @staticmethod
    def heap_base_from_tcache():
        # If glibc has tcache, there is tcache_perthread_struct* in TLS.
        # This structure is always allocated in the first chunk,
        # and can be used to find the starting address of the heap.
        # This path is useful for old qemu-user emulation, etc.

        if get_libc_version() < (2, 26):
            return None

        # In 2.42 and later, tcache_perthread_struct is not necessarily the first chunk,
        # so this detection method does not work.
        # However, glibc 2.42 is used in an Ubuntu 25.10 environment, and in this environment qemu-user is 10.1.
        # This version of qemu-user can obtain the exact heap base address via `info proc map`,
        # so the heuristic method should not be necessary.
        if get_libc_version() >= (2, 42):
            return None

        if not runtime.current_arch.tls_supported:
            return None

        main_arena_addr = GlibcHeap.search_for_main_arena()
        if main_arena_addr is None:
            return None

        tcache_perthread_struct = GlibcHeap.search_for_tcache_from_tls(main_arena_addr)
        if tcache_perthread_struct is None:
            return None

        if is_x86_32() or is_riscv32() or is_ppc32():
            chunk_offset = 0x10
        else:
            chunk_offset = runtime.current_arch.ptrsize * 2
        heap_base = tcache_perthread_struct - chunk_offset
        return heap_base

    @staticmethod
    def heap_base_from_mp():
        # However, in the case of qemu-user runs static binary, the heapbase cannot be obtained even with
        # `info proc map`, and this way may be necessary.
        main_arena_addr = GlibcHeap.search_for_main_arena()
        if main_arena_addr is None:
            return None

        try:
            codebase = ProcessMap.get_codebase()
            elf = Elf(codebase)
        except Exception:
            return None

        if not elf.is_static():
            return None

        """
        0x0000004dd160|+0x0000|+000: trim_threshold         : 0x0000000000020000
        0x0000004dd168|+0x0008|+001: top_pad                : 0x0000000000020000
        0x0000004dd170|+0x0010|+002: mmap_threshold         : 0x0000000000020000
        0x0000004dd178|+0x0018|+003: arena_test             : 0x0000000000000008
        0x0000004dd180|+0x0020|+004: arena_max              : 0x0000000000000000
        0x0000004dd188|+0x0028|+005: thp_pagesize           : 0x0000000000000000
        0x0000004dd190|+0x0030|+006: hp_pagesize            : 0x0000000000000000
        0x0000004dd198|+0x0038|+007: n_mmaps+hp_flags       : 0x0000000000000000
        0x0000004dd1a0|+0x0040|+008: max_n_mmaps+n_mmaps_max: 0x0000000000010000
        0x0000004dd1a8|+0x0048|+009: no_dyn_threshold       : 0x0000000000000000
        0x0000004dd1b0|+0x0050|+010: mmaped_mem             : 0x0000000000000000
        0x0000004dd1b8|+0x0058|+011: max_mmaped_mem         : 0x0000000000000000
        0x0000004dd1c0|+0x0060|+012: sbrk_base              : 0x00000000004e5d40 <----- here
        0x0000004dd1c8|+0x0068|+013: tcache_small_bins      : 0x0000000000000040
        0x0000004dd1d0|+0x0070|+014: tcache_max_bytes       : 0x0000000000000411
        0x0000004dd1d8|+0x0078|+015: tcache_count           : 0x0000000000000007
        0x0000004dd1e0|+0x0080|+016: tcache_unsorted_limit  : 0x0000000000000000
        0x0000004dd1e8|+0x0088|+017:                        : 0x0000000000000000
        0x0000004dd1f0|+0x0090|+018:                        : 0x0000000000000000
        0x0000004dd1f8|+0x0098|+019:                        : 0x0000000000000000
        0x0000004dd200|+0x00a0|+020: main_arena             : 0x0000000000000000
        0x0000004dd208|+0x00a8|+021:                        : 0x0000000000000001
        0x0000004dd210|+0x00b0|+022:                        : 0x00000000005165e0
        0x0000004dd218|+0x00b8|+023:                        : 0x0000000000000000
        0x0000004dd220|+0x00c0|+024:                        : 0x0000000000000000
        0x0000004dd228|+0x00c8|+025:                        : 0x0000000000000000
        """
        for i in range(1, 20):
            x = main_arena_addr - runtime.current_arch.ptrsize * i
            if not is_valid_addr(x):
                break
            y = read_int_from_memory(x)
            if is_valid_addr(y):
                return y
        return None

    @staticmethod
    @Cache.cache_this_session_skip_None_cache
    def heap_base(force_heuristic=False):
        heap_base = getattr(HeapBaseCommand, "heap_base_user_specific", None)
        if is_valid_addr(heap_base):
            return heap_base

        heap_base = HeapBaseCommand.heap_base_from_symbol(force_heuristic)
        if is_valid_addr(heap_base):
            return heap_base

        heap_base = HeapBaseCommand.heap_base_from_info_proc_map(force_heuristic)
        if is_valid_addr(heap_base):
            return heap_base

        heap_base = HeapBaseCommand.heap_base_from_tcache()
        if is_valid_addr(heap_base):
            return heap_base

        heap_base = HeapBaseCommand.heap_base_from_mp()
        if is_valid_addr(heap_base):
            return heap_base

        return None

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        # user specific
        if args.set is not None:
            HeapBaseCommand.heap_base_user_specific = args.set
            Cache.reset_gef_caches(all=True)

        if args.reset:
            if hasattr(HeapBaseCommand, "heap_base_user_specific"):
                delattr(HeapBaseCommand, "heap_base_user_specific")

        # auto estimation
        heap_base = HeapBaseCommand.heap_base()
        if heap_base is None:
            err("Could not find the heap")
            return

        # print
        self.quiet_print(titlify("Heap base"))
        gdb.execute(f"set $heapbase = {heap_base:#x}")
        self.quiet_print(f"$heapbase = {heap_base:#x}")
        return


@register_command
class LibcBaseCommand(GenericCommand):
    """Display libc base address."""

    _cmdline_ = "libc"
    _category_ = "02-b. Process Information - Base Address"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-s", "--set", metavar="ADDR", type=AddressUtil.parse_address, help="user specific address.")
    parser.add_argument("-r", "--reset", action="store_true", help="reset user specific address.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.add_setting("assume_version", "()", "The default libc version")
        return

    @staticmethod
    def is_same_filename(a, b):
        # If the file names match, they are considered to be the same file.
        if os.path.basename(a) == os.path.basename(b):
            return True

        # If `a` is the destination of a symbolic link, compare whether resolving `b` results in `a`.
        a_dir = os.path.join(os.path.dirname(a))
        b_file = os.path.basename(b)
        ab_path = os.path.join(a_dir, b_file)
        while os.path.islink(ab_path):
            ab_path = os.path.normpath(os.path.join(os.path.dirname(ab_path), os.readlink(ab_path)))
        return os.path.basename(a) == os.path.basename(ab_path)

    def libc_calc_hash(self, libc_base):
        libc = ProcessMap.process_lookup_address(libc_base)
        real_libc_path = None

        if is_container_attach():
            real_libc_path = Path.append_proc_root(libc.path)
            if not os.path.exists(real_libc_path):
                return
            data = open(real_libc_path, "rb").read()

        elif is_remote_debug():
            if is_qemu_user():
                data = None
                for maps in ProcessMap.get_process_maps(outer=True):
                    if not LibcBaseCommand.is_same_filename(maps.path, libc.path):
                        continue
                    real_libc_path = maps.path
                    data = open(real_libc_path, "rb").read()
                    break
            else:
                data = Path.read_remote_file(libc.path)
            if not data:
                return
        else:
            if not os.path.exists(libc.path):
                return
            data = open(libc.path, "rb").read()

        gef_print("path:\t{:s}{:s}".format(libc.path, " (remote)" if is_remote_debug() else ""))
        if real_libc_path:
            gef_print("path:\t{:s} (real)".format(real_libc_path))
        gef_print("sha512:\t{:s}".format(hashlib.sha512(data).hexdigest()))
        gef_print("sha256:\t{:s}".format(hashlib.sha256(data).hexdigest()))
        gef_print("sha1:\t{:s}".format(hashlib.sha1(data).hexdigest()))
        gef_print("md5:\t{:s}".format(hashlib.md5(data).hexdigest()))

        pos = re.search(b"(GNU C Library|uClibc-ng release) [\x20-\x7e]*", data)
        if pos:
            gef_print("ver:\t{:s}".format(String.bytes2str(pos.group(0))))
        return

    def show_libc_assume_version(self):
        self.quiet_print(titlify("GEF libc info"))
        try:
            v = get_libc_version(verbose=True)
            gef_print("GEF recognized: {}".format(v))
        except Exception:
            gef_print("GEF recognized: None")
        info("If version detection is failing, you can fix it with: `gef config libc.assume_version (2,39)`")
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    def do_invoke(self, args):
        # user specific
        if args.set is not None:
            self.libc_base_user_specific = args.set

        if args.reset:
            if hasattr(self, "libc_base_user_specific"):
                delattr(self, "libc_base_user_specific")

        libc_base = getattr(self, "libc_base_user_specific", None)

        # auto estimation
        if not is_valid_addr(libc_base):
            Cache.reset_gef_caches(all=True) # get_process_maps may be caching old information

            libc_targets = (
                "libc-2.", "libc.so.6", # glibc
                "libuClibc-", "/libc.so.0", # uClibc
            )
            libc_base = ProcessMap.get_section_base_address_by_list(libc_targets)
            if libc_base is None:
                err("Could not find the libc")
                if not args.quiet:
                    self.show_libc_assume_version()
                return

        # print
        self.quiet_print(titlify("libc info"))
        gdb.execute(f"set $libc = {libc_base:#x}")
        self.quiet_print(f"$libc = {libc_base:#x}")

        if not args.quiet:
            self.libc_calc_hash(libc_base)
            self.show_libc_assume_version()
        return


@register_command
class LdBaseCommand(GenericCommand):
    """Display ld base address."""

    _cmdline_ = "ld"
    _category_ = "02-b. Process Information - Base Address"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-s", "--set", metavar="ADDR", type=AddressUtil.parse_address, help="user specific address.")
    parser.add_argument("-r", "--reset", action="store_true", help="reset user specific address.")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    def ld_calc_hash(self, ld_base):
        ld = ProcessMap.process_lookup_address(ld_base)
        real_ld_path = None

        if is_container_attach():
            real_ld_path = Path.append_proc_root(ld.path)
            if not os.path.exists(real_ld_path):
                return
            data = open(real_ld_path, "rb").read()

        elif is_remote_debug():
            if is_qemu_user():
                data = None
                for maps in ProcessMap.get_process_maps(outer=True):
                    if not LibcBaseCommand.is_same_filename(maps.path, ld.path):
                        continue
                    real_ld_path = maps.path
                    data = open(real_ld_path, "rb").read()
                    break
            else:
                data = Path.read_remote_file(ld.path)
            if not data:
                return
        else:
            if not os.path.exists(ld.path):
                return
            data = open(ld.path, "rb").read()

        gef_print("path:\t{:s}{:s}".format(ld.path, " (remote)" if is_remote_debug() else ""))
        if real_ld_path:
            gef_print("path:\t{:s} (real)".format(real_ld_path))
        gef_print("sha512:\t{:s}".format(hashlib.sha512(data).hexdigest()))
        gef_print("sha256:\t{:s}".format(hashlib.sha256(data).hexdigest()))
        gef_print("sha1:\t{:s}".format(hashlib.sha1(data).hexdigest()))
        gef_print("md5:\t{:s}".format(hashlib.md5(data).hexdigest()))

        pos = re.search(b"ld.so [\x20-\x7e]+ version [\x20-\x7e]*", data)
        if pos:
            gef_print("ver:\t{:s}".format(String.bytes2str(pos.group(0))))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    def do_invoke(self, args):
        # user specific
        if args.set is not None:
            self.ld_base_user_specific = args.set

        if args.reset:
            if hasattr(self, "ld_base_user_specific"):
                delattr(self, "ld_base_user_specific")

        ld_base = getattr(self, "ld_base_user_specific", None)

        # auto estimation
        if not is_valid_addr(ld_base):
            Cache.reset_gef_caches(all=True) # get_process_maps may be caching old information

            ld_targets = (
                "ld-2.", "ld-linux-", "ld-linux.", # glibc
                "ld64-uClibc-", "ld-uClibc-", "ld64-uClibc.", "ld-uClibc.", # uClibc
            )
            ld_base = ProcessMap.get_section_base_address_by_list(ld_targets)
            if ld_base is None:
                err("Could not find the ld")
                return

        # print
        self.quiet_print(titlify("ld info"))
        gdb.execute(f"set $ld = {ld_base:#x}")
        self.quiet_print(f"$ld = {ld_base:#x}")

        if not args.quiet:
            self.ld_calc_hash(ld_base)
        return


@register_command
class TlsCommand(GenericCommand, BufferingOutput):
    """Display TLS base address. Requires glibc."""

    _cmdline_ = "tls"
    _category_ = "02-b. Process Information - Base Address"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", "--all", action="store_true", help="show all TLS address.")
    parser.add_argument("-i", "--thread-id", type=AddressUtil.parse_address, help="show specific TLS address.")
    parser.add_argument("-s", "--symbol-hint", action="store_true", help="show hints if symbol is available (x64/x86 only).")
    parser.add_argument("-v", "--verbose", action="count", default=1, help="show more entries (+16).")
    parser.add_argument("-V", "--more-verbose", action="count", default=0, help="show more entries (+256).")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -vvv  # repeat `-v` to display more lines",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @staticmethod
    def get_direction():
        if is_x86() or is_sparc64() or is_s390x():
            direction = -1
        else:
            direction = 1
        return direction

    def get_specific_tls(self, thread_id):
        orig_thread = gdb.selected_thread()
        orig_frame = gdb.selected_frame()
        threads = gdb.selected_inferior().threads()
        threads = [th for th in threads if th.num == thread_id]

        if len(threads) != 1:
            err("Could not find the target thread")
            return

        try:
            threads[0].switch()
            tls = runtime.current_arch.get_tls()
        except Exception:
            tls = None

        orig_thread.switch() # revert
        orig_frame.select()
        return tls

    def print_all_tls(self):
        orig_thread = gdb.selected_thread()
        orig_frame = gdb.selected_frame()
        threads = gdb.selected_inferior().threads()
        threads = sorted(threads, key=lambda th: th.num)

        if not threads:
            err("No thread is detected")
            return

        for thread in threads:
            msg = "Thread Id:{:d}".format(thread.num)
            try:
                thread.switch()
            except gdb.error:
                msg += " - Failed to switch to this thread"
                continue
            tls = runtime.current_arch.get_tls()
            msg += " - {:#x}".format(tls)
            gef_print(msg)

        orig_thread.switch() # revert
        orig_frame.select()
        return

    def get_varnames(self):
        tp = GefUtil.cached_lookup_type("tcbhead_t")
        if tp is None:
            return ""

        aligned_members = []
        for name, field in tp.items():
            if field.bitpos % 8:
                continue
            if (field.bitpos // 8) % runtime.current_arch.ptrsize:
                continue
            aligned_members.append([(field.bitpos // 8) // runtime.current_arch.ptrsize, name])

        args_string = " ".join(["-t {:d} {:s}".format(i, n) for i, n in aligned_members])
        return args_string

    def dump_tls(self, tls):
        self.out.append("$tls = {:#x}".format(tls))
        gdb.execute("p $tls = {:#x}".format(tls), to_string=True)

        n_entries = (16 * self.args.verbose) + (256 * self.args.more_verbose)

        self.out.append(titlify("TLS-{:#x}".format(runtime.current_arch.ptrsize * n_entries)))
        r = gdb.execute("dereference $tls-{:#x} {:d} --no-pager".format(
            runtime.current_arch.ptrsize * n_entries, n_entries,
        ), to_string=True)
        self.out.extend(r.rstrip().splitlines())

        self.out.append(titlify("TLS"))
        if self.args.symbol_hint and is_x86():
            args_string = self.get_varnames()
            r = gdb.execute("dereference $tls {:d} --no-pager {}".format(n_entries, args_string), to_string=True)
        else:
            r = gdb.execute("dereference $tls {:d} --no-pager".format(n_entries), to_string=True)
        self.out.extend(r.rstrip().splitlines())
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @require_arch_set
    def do_invoke(self, args):
        if not runtime.current_arch.tls_supported:
            warn("This command is not supported on this architecture")
            return

        if args.all:
            self.print_all_tls()
            return

        if args.thread_id:
            tls = self.get_specific_tls(args.thread_id)
        else:
            tls = runtime.current_arch.get_tls()
        if tls is None:
            err("Failed to get TLS address")
            return

        if not is_valid_addr(tls):
            err("Cannot access memory at address {:#x}".format(tls))
            return

        self.out = []
        self.dump_tls(tls)
        self.print_output(check_terminal_size=True)
        return


@register_command
class FsbaseCommand(GenericCommand):
    """Display fsbase address."""

    _cmdline_ = "fsbase"
    _category_ = "02-b. Process Information - Base Address"
    _aliases_ = ["fs"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    _note_ = [
        "This command overwrites original \"fs (=tui focus)\" command.",
    ]
    _note_ = "\n".join(_note_)

    @parse_args
    @only_if_gdb_running
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    @exclude_specific_gdb_mode(mode=("qiling", "kgdb"))
    def do_invoke(self, args):
        fsbase = runtime.current_arch.get_fs()
        if fsbase is not None:
            gef_print("$fs_base: {:#x}".format(fsbase))
        return


@register_command
class GsbaseCommand(GenericCommand):
    """Display gsbase address."""

    _cmdline_ = "gsbase"
    _category_ = "02-b. Process Information - Base Address"
    _aliases_ = ["gs"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qiling", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        gsbase = runtime.current_arch.get_gs()
        if gsbase is not None:
            gef_print("$gs_base: {:#x}".format(gsbase))
        return

