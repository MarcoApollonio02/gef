"""GEF process-info commands (category 02-d) extracted from the monolithic gef.py.

Trivial process information commands (auxv, argv, envp, vdso, vvar, pid, tid, filename, errno, stack-frame).

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import re
import struct

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
from gef.core.auxv import Auxv
from gef.core.color import Color, err, gef_print, titlify, warn
from gef.core.elf import Elf
from gef.core.instruction import Disasm
from gef.core.memory import hexdump, is_valid_addr, read_cstring_from_memory, read_int_from_memory
from gef.core.process import (
    Path,
    Pid,
    ProcessMap,
    get_pagesize,
    is_64bit,
    is_alive,
    is_alpha,
    is_hppa32,
    is_hppa64,
    is_mips32,
    is_mips64,
    is_mipsn32,
    is_qemu_system,
    is_qemu_user,
    is_remote_debug,
    is_sparc32,
    is_sparc64,
    is_x86_32,
    is_x86_64,
)
from gef.core.strings import String
from gef.core.utils import GefUtil

@register_command
class AuxvCommand(GenericCommand):
    """Display ELF auxiliary vectors."""

    _cmdline_ = "auxv"
    _category_ = "02-d. Process Information - Trivial Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--force-heuristic", action="store_true", help="use heuristic detection.")
    _syntax_ = parser.format_help()

    AT_CONSTANTS = {
        0  : "AT_NULL",              # End of vector
        1  : "AT_IGNORE",            # Entry should be ignored
        2  : "AT_EXECFD",            # File descriptor of program
        3  : "AT_PHDR",              # Program headers for program
        4  : "AT_PHENT",             # Size of program header entry
        5  : "AT_PHNUM",             # Number of program headers
        6  : "AT_PAGESZ",            # System page size
        7  : "AT_BASE",              # Base address of interpreter
        8  : "AT_FLAGS",             # Flags
        9  : "AT_ENTRY",             # Entry point of program
        10 : "AT_NOTELF",            # Program is not ELF
        11 : "AT_UID",               # Real uid
        12 : "AT_EUID",              # Effective uid
        13 : "AT_GID",               # Real gid
        14 : "AT_EGID",              # Effective gid
        15 : "AT_PLATFORM",          # String identifying platform
        16 : "AT_HWCAP",             # Machine dependent hints about processor capabilities
        17 : "AT_CLKTCK",            # Frequency of times()
        18 : "AT_FPUCW",             #
        19 : "AT_DCACHEBSIZE",       #
        20 : "AT_ICACHEBSIZE",       #
        21 : "AT_UCACHEBSIZE",       #
        22 : "AT_IGNOREPPC",         # A special ignored type value for PPC, for glibc compatibility
        23 : "AT_SECURE",            #
        24 : "AT_BASE_PLATFORM",     # String identifying real platforms
        25 : "AT_RANDOM",            # Address of 16 random bytes
        26 : "AT_HWCAP2",            # extension of AT_HWCAP
        27 : "AT_RSEQ_FEATURE_SIZE", # seq supported feature size
        28 : "AT_RSEQ_ALIGN",        # rseq allocation alignment
        31 : "AT_EXECFN",            # Filename of executable
        32 : "AT_SYSINFO",           #
        33 : "AT_SYSINFO_EHDR",      #
        34 : "AT_L1I_CACHESHAPE",    #
        35 : "AT_L1D_CACHESHAPE",    #
        36 : "AT_L2_CACHESHAPE",     #
        37 : "AT_L3_CACHESHAPE",     #
        40 : "AT_L1I_CACHESIZE",     #
        41 : "AT_L1I_CACHEGEOMETRY", #
        42 : "AT_L1D_CACHESIZE",     #
        43 : "AT_L1D_CACHEGEOMETRY", #
        44 : "AT_L2_CACHESIZE",      #
        45 : "AT_L2_CACHEGEOMETRY",  #
        46 : "AT_L3_CACHESIZE",      #
        47 : "AT_L3_CACHEGEOMETRY",  #
        51 : "AT_MINSIGSTKSZ",       # stack needed for signal delivery
    }

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        auxval = Auxv.get_auxiliary_values(args.force_heuristic)
        if not auxval:
            return None

        reverse_AT_CONSTS = {v: "{:#04x}".format(k) for k, v in self.AT_CONSTANTS.items()}

        gef_print(titlify("ELF auxiliary vector"))
        fmt = "{:6s} {:22s} {:s}"
        legend = ["Const", "Name", "Value"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        for k, v in auxval.items():
            num = reverse_AT_CONSTS.get(k, "?")
            additional_message = ""
            if k == "AT_NULL":
                additional_message = " (End of vector)"
            elif k in ["AT_EXECFN", "AT_PLATFORM"]:
                s = read_cstring_from_memory(v)
                if s is None:
                    s = "Cannot access memory"
                s = Color.yellowify(repr(s))
                additional_message = " -> {:s}".format(s)
            elif k in ["AT_RANDOM"]:
                try:
                    if is_64bit():
                        s1 = read_int_from_memory(v + runtime.current_arch.ptrsize * 0)
                        s2 = read_int_from_memory(v + runtime.current_arch.ptrsize * 1)
                        additional_message = " -> {:#018x}, {:#018x}".format(s1, s2)
                    else:
                        s1 = read_int_from_memory(v + runtime.current_arch.ptrsize * 0)
                        s2 = read_int_from_memory(v + runtime.current_arch.ptrsize * 1)
                        s3 = read_int_from_memory(v + runtime.current_arch.ptrsize * 2)
                        s4 = read_int_from_memory(v + runtime.current_arch.ptrsize * 3)
                        additional_message = " -> {:#010x}, {:#010x}, {:#010x}, {:#010x}".format(
                            s1, s2, s3, s4,
                        )
                except gdb.MemoryError:
                    s = Color.yellowify(repr("Cannot access memory"))
                    additional_message = " -> {:s}".format(s)

            if is_valid_addr(v):
                v = str(ProcessMap.lookup_address(v))
            else:
                v = hex(v)
            gef_print("{:6s} {:22s} {:s}{:s}".format(num, k + ":", v, additional_message))
        return


@register_command
class ArgvCommand(GenericCommand, BufferingOutput):
    """Display the program's argv array."""

    _cmdline_ = "argv"
    _category_ = "02-d. Process Information - Trivial Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print all elements. (default: outputs up to 100)")
    parser.add_argument("-i", "--increase-limit", action="store_true",
                        help="increase rounding limit from 128 bytes to 4096 bytes.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def get_address_from_symbol(self, symbol):
        try:
            return AddressUtil.parse_address(symbol)
        except Exception:
            return None

    def print_from_mem(self, array):
        fmt = "{:3s} {:{:d}s}  {:{:d}s} -> {:s}"
        legend = [
            "#",
            "ArrAddr", AddressUtil.get_format_address_width(),
            "StrAddr", AddressUtil.get_format_address_width(),
            "String",
        ]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        max_size = get_pagesize() if self.args.increase_limit else 128

        i = 0
        while True:
            pos = array + i * runtime.current_arch.ptrsize
            addr = read_int_from_memory(pos)
            if addr == 0:
                break
            if not self.args.verbose and i >= 100:
                self.out.append("...")
                break

            s = read_cstring_from_memory(addr, get_pagesize())
            s = Color.yellowify(repr(s))
            if len(s) > max_size:
                s = s[:max_size] + "[...]"

            self.out.append("{:03d} {!s}: {!s} -> {:s}".format(
                i,
                ProcessMap.lookup_address(pos),
                ProcessMap.lookup_address(addr),
                s,
            ))
            i += 1
        return

    def print_from_proc(self, filename):
        fmt = "{:3s} {:s}"
        legend = ["#", "String"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        max_size = get_pagesize() if self.args.increase_limit else 128

        lines = open(filename, "rb").read()
        lines = String.bytes2str(lines)
        for i, elem in enumerate(lines.split("\0")):
            if not elem:
                break
            if not self.args.verbose and i >= 100:
                self.out.append("...")
                break

            if len(elem) > max_size:
                elem = elem[:max_size] + "[...]"
            self.out.append("{:03d} {!s}".format(i, elem))
        return

    def dump_dl_argv(self):
        paddr = self.get_address_from_symbol("&_dl_argv")
        addr = self.get_address_from_symbol("_dl_argv")
        if paddr and addr:
            self.out.append(titlify("ARGV from _dl_argv"))
            self.info_add_out("_dl_argv @ {}".format(ProcessMap.lookup_address(paddr)))
            self.print_from_mem(addr)
            return
        elif addr == 0:
            self.err_add_out("_dl_argv is 0x0")
        else:
            self.err_add_out("Could not find _dl_argv")
        return

    def dump_libc_argv(self):
        paddr = self.get_address_from_symbol("&__libc_argv")
        addr = self.get_address_from_symbol("__libc_argv")
        if paddr and addr:
            self.out.append(titlify("ARGV from __libc_argv"))
            self.info_add_out("__libc_argv @ {}".format(ProcessMap.lookup_address(paddr)))
            self.print_from_mem(addr)
        elif addr == 0:
            self.err_add_out("__libc_argv is 0x0")
        else:
            self.err_add_out("Could not find __libc_argv")
        return

    def dump_proc_cmdline(self):
        if is_remote_debug():
            return
        self.out.append(titlify("ARGV from /proc/{:d}/cmdline".format(Pid.get_pid())))
        self.print_from_proc("/proc/{:d}/cmdline".format(Pid.get_pid()))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        self.out = []
        self.dump_dl_argv()
        self.dump_libc_argv()
        self.dump_proc_cmdline()
        self.print_output(check_terminal_size=True)
        return


@register_command
class EnvpCommand(GenericCommand, BufferingOutput):
    """Display initial envp from __environ@ld, or modified envp from last_environ@libc."""

    _cmdline_ = "envp"
    _category_ = "02-d. Process Information - Trivial Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="print all elements. (default: outputs up to 100)")
    parser.add_argument("-i", "--increase-limit", action="store_true",
                        help="increase rounding limit from 128 bytes to 4096 bytes.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def get_address_from_symbol(self, symbol):
        try:
            return AddressUtil.parse_address(symbol)
        except Exception:
            return None

    def print_from_mem(self, array):
        fmt = "{:3s} {:{:d}s}  {:{:d}s} -> {:s}"
        legend = [
            "#",
            "ArrAddr", AddressUtil.get_format_address_width(),
            "StrAddr", AddressUtil.get_format_address_width(),
            "String",
        ]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        max_size = get_pagesize() if self.args.increase_limit else 128

        i = 0
        while True:
            pos = array + i * runtime.current_arch.ptrsize
            addr = read_int_from_memory(pos)
            if addr == 0:
                break
            if not self.args.verbose and i >= 100:
                self.out.append("...")
                break

            s = read_cstring_from_memory(addr, get_pagesize())
            s = Color.yellowify(repr(s))
            if len(s) > max_size:
                s = s[:max_size] + "[...]"

            self.out.append("{:03d} {!s}: {!s} -> {:s}".format(
                i,
                ProcessMap.lookup_address(pos),
                ProcessMap.lookup_address(addr),
                s,
            ))
            i += 1
        return

    def print_from_proc(self, filename):
        fmt = "{:3s} {:s}"
        legend = ["#", "Name=Value"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        max_size = get_pagesize() if self.args.increase_limit else 128

        lines = open(filename, "rb").read()
        lines = String.bytes2str(lines)
        for i, elem in enumerate(lines.split("\0")):
            if not elem:
                break
            if not self.args.verbose and i >= 100:
                self.out.append("...")
                break
            elem = re.sub(r"^(.*?=)", Color.boldify("\\1"), elem)
            if len(elem) > max_size:
                elem = elem[:max_size] + "[...]"
            self.out.append("{:03d} {:s}".format(i, elem))
        return

    def dump_environ(self):
        self.out.append(titlify("ENVP from __environ"))
        paddr = self.get_address_from_symbol("&__environ")
        addr = self.get_address_from_symbol("__environ")
        if paddr and addr:
            self.info_add_out("__environ @ {}".format(ProcessMap.lookup_address(paddr)))
            self.print_from_mem(addr)
        elif addr == 0:
            self.err_add_out("___environ is 0x0")
        else:
            self.err_add_out("Could not find __environ")
        return

    def dump_last_environ(self):
        self.out.append(titlify("ENVP from last_environ (for putenv, etc.)"))
        paddr = self.get_address_from_symbol("&last_environ")
        addr = self.get_address_from_symbol("last_environ")
        if paddr and addr:
            self.info_add_out("last_environ @ {}".format(ProcessMap.lookup_address(paddr)))
            self.print_from_mem(addr)
        elif addr == 0:
            self.err_add_out("last_environ is 0x0")
        else:
            self.err_add_out("Could not find last_environ")
        return

    def dump_proc_environ(self):
        if is_remote_debug():
            return
        self.out.append(titlify("ENVP from /proc/{:d}/environ".format(Pid.get_pid())))
        self.print_from_proc("/proc/{:d}/environ".format(Pid.get_pid()))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        self.out = []
        self.dump_environ()
        self.dump_last_environ()
        self.dump_proc_environ()
        self.print_output(check_terminal_size=True)
        return


@register_command
class DumpArgsCommand(GenericCommand):
    """Dump arguments of current function."""

    _cmdline_ = "dumpargs"
    _category_ = "02-d. Process Information - Trivial Information"
    _aliases_ = ["args"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-c", "--count", type=AddressUtil.parse_address,
                        help="number of arguments to guess.")
    parser.add_argument("-o", "--out-of-function", action="store_true",
                        help="assume here is out of the function.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        gef_print(titlify("info args (snapshot)"))
        gdb.execute("info args")

        gef_print(titlify("guessed arguments (current value)"))
        ret = gdb.execute("info args", to_string=True).strip()
        if args.count is not None:
            count = args.count
        elif "No symbol table info available" in ret:
            count = len(runtime.current_arch.function_parameters)
        else:
            count = len(ret.splitlines())

        for i in range(count):
            key, val = runtime.current_arch.get_ith_parameter(i, in_func=not args.out_of_function)

            width = len(key)
            while width % 4:
                width += 1
            gef_print("{:>{:d}s} = {:s}".format(key, width, AddressUtil.recursive_dereference_to_string(val)))
        return


@register_command
class VdsoCommand(GenericCommand, BufferingOutput):
    """Disassemble the text area of vdso smartly."""

    _cmdline_ = "vdso"
    _category_ = "02-d. Process Information - Trivial Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @require_arch_set
    def do_invoke(self, args):
        # get map entry
        maps = ProcessMap.get_process_maps()
        if maps is None:
            err("Failed to get maps")
            return

        for entry in maps:
            if entry.path == "[vdso]":
                break
        else:
            err("Could not find the vdso")
            return

        # get dump area
        elf = Elf.get_elf(entry.page_start)
        if elf is None or not elf.is_valid():
            err("Failed to parse")
            return
        shdr = elf.get_shdr(".text")

        text_start = entry.page_start + shdr.sh_addr
        text_size = shdr.sh_size
        text_end = text_start + text_size

        # disassemble
        try:
            __import__("capstone")
            ret = gdb.execute("capstone-disassemble {:#x} -l {:#x}".format(text_start, text_size), to_string=True)
            result_lines = ret.splitlines()
        except ImportError:
            gen = Disasm.gdb_disassemble(text_start, end_pc=text_end - 1)
            result_lines = [str(x) for x in gen]

        self.out = []
        for line in result_lines:
            if int(Color.remove_color(line.split()[0]), 16) < text_end:
                self.out.append(line)
            else:
                break

        self.print_output(check_terminal_size=True)
        return


@register_command
class VvarCommand(GenericCommand, BufferingOutput):
    """Dump the vvar area (x64/x86 only)."""

    _cmdline_ = "vvar"
    _category_ = "02-d. Process Information - Trivial Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def read(self, addr, size):
        if is_x86_64():
            block_size = 128
            dynamic_read = runtime.current_arch.read128
        elif is_x86_32():
            block_size = 28
            dynamic_read = runtime.current_arch.read28

        out = b""
        pos = 0
        while pos < size:
            out += dynamic_read(addr + pos)
            pos += block_size
        return out[:size]

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "rr"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        # get map entry
        maps = ProcessMap.get_process_maps()
        if maps is None:
            err("Failed to get maps")
            return

        for entry in maps:
            if entry.path == "[vvar]":
                break
        else:
            err("Could not find the vvar")
            return

        # dump
        # arch/x86/include/asm/vvar.h
        self.out = []
        start = entry.page_start + 128 # DECLARE_VVAR(128, struct vdso_data, _vdso_data)
        size = 0x180 # >= sizeof(struct vdso_data)
        data = self.read(start, size)
        hex_data = hexdump(data, base=start, unit=runtime.current_arch.ptrsize)
        self.out.extend(hex_data.splitlines())

        # print
        self.print_output(check_terminal_size=True)
        return


@register_command
class PidCommand(GenericCommand):
    """Display the local PID or remote PID."""

    _cmdline_ = "pid"
    _category_ = "02-d. Process Information - Trivial Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        pid = Pid.get_pid()
        if pid:
            if is_qemu_user() or is_qemu_system():
                gef_print("Local qemu PID: {:d}".format(pid))
            else:
                gef_print("Local PID: {:d}".format(pid))
            return

        if is_remote_debug():
            pid = Pid.get_pid(remote=True)
            if pid:
                gef_print("Remote PID: {:d}".format(pid))
                return

        err("Failed to get pid")
        return


@register_command
class TidCommand(GenericCommand):
    """Display the Thread ID."""

    _cmdline_ = "tid"
    _category_ = "02-d. Process Information - Trivial Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    def do_invoke(self, args):
        ptid = gdb.selected_thread().ptid
        gef_print("TID: {:d}".format(ptid[1] or ptid[2]))
        return


@register_command
class FilenameCommand(GenericCommand):
    """Display current debugged filename."""

    _cmdline_ = "filename"
    _category_ = "02-d. Process Information - Trivial Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    def do_invoke(self, args):
        filepath = Path.get_filepath()
        if filepath:
            gef_print(repr(filepath))
            return

        elif is_remote_debug():
            filepath = gdb.current_progspace().filename
            if filepath and filepath.startswith("target:"):
                filepath = filepath[7:]
            if filepath:
                gef_print(repr(filepath))
                return

        err("Failed to get filename")
        return


@register_command
class ErrnoCommand(GenericCommand, BufferingOutput):
    """Convert errno (or argument) to its string representation."""

    _cmdline_ = "errno"
    _category_ = "02-d. Process Information - Trivial Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("errno", metavar="ERRNO", nargs="?", type=AddressUtil.parse_address,
                        help="show specific errno definitions.")
    parser.add_argument("-a", "--all", action="store_true", help="show all errno definitions.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    @staticmethod
    def get_errno_dict():
        ERRNO_BASE_DICT = {
            0   : ["-",               "No error"],
            # include/uapi/asm-generic/errno-base.h
            1   : ["EPERM",           "Operation not permitted"],
            2   : ["ENOENT",          "No such file or directory"],
            3   : ["ESRCH",           "No such process"],
            4   : ["EINTR",           "Interrupted system call"],
            5   : ["EIO",             "I/O error"],
            6   : ["ENXIO",           "No such device or address"],
            7   : ["E2BIG",           "Argument list too long"],
            8   : ["ENOEXEC",         "Exec format error"],
            9   : ["EBADF",           "Bad file number"],
            10  : ["ECHILD",          "No child processes"],
            11  : ["EAGAIN",          "Try again"],
            12  : ["ENOMEM",          "Out of memory"],
            13  : ["EACCES",          "Permission denied"],
            14  : ["EFAULT",          "Bad address"],
            15  : ["ENOTBLK",         "Block device required"],
            16  : ["EBUSY",           "Device or resource busy"],
            17  : ["EEXIST",          "File exists"],
            18  : ["EXDEV",           "Cross-device link"],
            19  : ["ENODEV",          "No such device"],
            20  : ["ENOTDIR",         "Not a directory"],
            21  : ["EISDIR",          "Is a directory"],
            22  : ["EINVAL",          "Invalid argument"],
            23  : ["ENFILE",          "File table overflow"],
            24  : ["EMFILE",          "Too many open files"],
            25  : ["ENOTTY",          "Not a typewriter"],
            26  : ["ETXTBSY",         "Text file busy"],
            27  : ["EFBIG",           "File too large"],
            28  : ["ENOSPC",          "No space left on device"],
            29  : ["ESPIPE",          "Illegal seek"],
            30  : ["EROFS",           "Read-only file system"],
            31  : ["EMLINK",          "Too many links"],
            32  : ["EPIPE",           "Broken pipe"],
            33  : ["EDOM",            "Math argument out of domain of func"],
            34  : ["ERANGE",          "Math result not representable"],
        }

        ERRNO_DICT = {
            # include/uapi/asm-generic/errno.h
            35  : ["EDEADLK",         "Resource deadlock would occur"],
            36  : ["ENAMETOOLONG",    "File name too long"],
            37  : ["ENOLCK",          "No record locks available"],
            38  : ["ENOSYS",          "Invalid system call number"],
            39  : ["ENOTEMPTY",       "Directory not empty"],
            40  : ["ELOOP",           "Too many symbolic links encountered"],
            # 41
            42  : ["ENOMSG",          "No message of desired type"],
            43  : ["EIDRM",           "Identifier removed"],
            44  : ["ECHRNG",          "Channel number out of range"],
            45  : ["EL2NSYNC",        "Level 2 not synchronized"],
            46  : ["EL3HLT",          "Level 3 halted"],
            47  : ["EL3RST",          "Level 3 reset"],
            48  : ["ELNRNG",          "Link number out of range"],
            49  : ["EUNATCH",         "Protocol driver not attached"],
            50  : ["ENOCSI",          "No CSI structure available"],
            51  : ["EL2HLT",          "Level 2 halted"],
            52  : ["EBADE",           "Invalid exchange"],
            53  : ["EBADR",           "Invalid request descriptor"],
            54  : ["EXFULL",          "Exchange full"],
            55  : ["ENOANO",          "No anode"],
            56  : ["EBADRQC",         "Invalid request code"],
            57  : ["EBADSLT",         "Invalid slot"],
            # 58
            59  : ["EBFONT",          "Bad font file format"],
            60  : ["ENOSTR",          "Device not a stream"],
            61  : ["ENODATA",         "No data available"],
            62  : ["ETIME",           "Timer expired"],
            63  : ["ENOSR",           "Out of streams resources"],
            64  : ["ENONET",          "Machine is not on the network"],
            65  : ["ENOPKG",          "Package not installed"],
            66  : ["EREMOTE",         "Object is remote"],
            67  : ["ENOLINK",         "Link has been severed"],
            68  : ["EADV",            "Advertise error"],
            69  : ["ESRMNT",          "Srmount error"],
            70  : ["ECOMM",           "Communication error on send"],
            71  : ["EPROTO",          "Protocol error"],
            72  : ["EMULTIHOP",       "Multihop attempted"],
            73  : ["EDOTDOT",         "RFS specific error"],
            74  : ["EBADMSG",         "Not a data message"],
            75  : ["EOVERFLOW",       "Value too large for defined data type"],
            76  : ["ENOTUNIQ",        "Name not unique on network"],
            77  : ["EBADFD",          "File descriptor in bad state"],
            78  : ["EREMCHG",         "Remote address changed"],
            79  : ["ELIBACC",         "Can not access a needed shared library"],
            80  : ["ELIBBAD",         "Accessing a corrupted shared library"],
            81  : ["ELIBSCN",         ".lib section in a.out corrupted"],
            82  : ["ELIBMAX",         "Attempting to link in too many shared libraries"],
            83  : ["ELIBEXEC",        "Cannot exec a shared library directly"],
            84  : ["EILSEQ",          "Illegal byte sequence"],
            85  : ["ERESTART",        "Interrupted system call should be restarted"],
            86  : ["ESTRPIPE",        "Streams pipe error"],
            87  : ["EUSERS",          "Too many users"],
            88  : ["ENOTSOCK",        "Socket operation on non-socket"],
            89  : ["EDESTADDRREQ",    "Destination address required"],
            90  : ["EMSGSIZE",        "Message too long"],
            91  : ["EPROTOTYPE",      "Protocol wrong type for socket"],
            92  : ["ENOPROTOOPT",     "Protocol not available"],
            93  : ["EPROTONOSUPPORT", "Protocol not supported"],
            94  : ["ESOCKTNOSUPPORT", "Socket type not supported"],
            95  : ["EOPNOTSUPP",      "Operation not supported on transport endpoint"],
            96  : ["EPFNOSUPPORT",    "Protocol family not supported"],
            97  : ["EAFNOSUPPORT",    "Address family not supported by protocol"],
            98  : ["EADDRINUSE",      "Address already in use"],
            99  : ["EADDRNOTAVAIL",   "Cannot assign requested address"],
            100 : ["ENETDOWN",        "Network is down"],
            101 : ["ENETUNREACH",     "Network is unreachable"],
            102 : ["ENETRESET",       "Network dropped connection because of reset"],
            103 : ["ECONNABORTED",    "Software caused connection abort"],
            104 : ["ECONNRESET",      "Connection reset by peer"],
            105 : ["ENOBUFS",         "No buffer space available"],
            106 : ["EISCONN",         "Transport endpoint is already connected"],
            107 : ["ENOTCONN",        "Transport endpoint is not connected"],
            108 : ["ESHUTDOWN",       "Cannot send after transport endpoint shutdown"],
            109 : ["ETOOMANYREFS",    "Too many references: cannot splice"],
            110 : ["ETIMEDOUT",       "Connection timed out"],
            111 : ["ECONNREFUSED",    "Connection refused"],
            112 : ["EHOSTDOWN",       "Host is down"],
            113 : ["EHOSTUNREACH",    "No route to host"],
            114 : ["EALREADY",        "Operation already in progress"],
            115 : ["EINPROGRESS",     "Operation now in progress"],
            116 : ["ESTALE",          "Stale file handle"],
            117 : ["EUCLEAN",         "Structure needs cleaning"],
            118 : ["ENOTNAM",         "Not a XENIX named type file"],
            119 : ["ENAVAIL",         "No XENIX semaphores available"],
            120 : ["EISNAM",          "Is a named type file"],
            121 : ["EREMOTEIO",       "Remote I/O error"],
            122 : ["EDQUOT",          "Quota exceeded"],
            123 : ["ENOMEDIUM",       "No medium found"],
            124 : ["EMEDIUMTYPE",     "Wrong medium type"],
            125 : ["ECANCELED",       "Operation Canceled"],
            126 : ["ENOKEY",          "Required key not available"],
            127 : ["EKEYEXPIRED",     "Key has expired"],
            128 : ["EKEYREVOKED",     "Key has been revoked"],
            129 : ["EKEYREJECTED",    "Key was rejected by service"],
            130 : ["EOWNERDEAD",      "Owner died"],
            131 : ["ENOTRECOVERABLE", "State not recoverable"],
            132 : ["ERFKILL",         "Operation not possible due to RF-kill"],
            133 : ["EHWPOISON",       "Memory page has hardware error"],
        }

        if is_alpha():
            ERRNO_DICT = {
                # arch/alpha/include/uapi/asm/errno.h
                11  : ["EDEADLK",         "Resource deadlock would occur"], # override
                #
                35  : ["EAGAIN",          "Try again"],
                36  : ["EINPROGRESS",     "Operation now in progress"],
                37  : ["EALREADY",        "Operation already in progress"],
                38  : ["ENOTSOCK",        "Socket operation on non-socket"],
                39  : ["EDESTADDRREQ",    "Destination address required"],
                40  : ["EMSGSIZE",        "Message too long"],
                41  : ["EPROTOTYPE",      "Protocol wrong type for socket"],
                42  : ["ENOPROTOOPT",     "Protocol not available"],
                43  : ["EPROTONOSUPPORT", "Protocol not supported"],
                44  : ["ESOCKTNOSUPPORT", "Socket type not supported"],
                45  : ["EOPNOTSUPP",      "Operation not supported on transport endpoint"],
                46  : ["EPFNOSUPPORT",    "Protocol family not supported"],
                47  : ["EAFNOSUPPORT",    "Address family not supported by protocol"],
                48  : ["EADDRINUSE",      "Address already in use"],
                49  : ["EADDRNOTAVAIL",   "Cannot assign requested address"],
                50  : ["ENETDOWN",        "Network is down"],
                51  : ["ENETUNREACH",     "Network is unreachable"],
                52  : ["ENETRESET",       "Network dropped connection because of reset"],
                53  : ["ECONNABORTED",    "Software caused connection abort"],
                54  : ["ECONNRESET",      "Connection reset by peer"],
                55  : ["ENOBUFS",         "No buffer space available"],
                56  : ["EISCONN",         "Transport endpoint is already connected"],
                57  : ["ENOTCONN",        "Transport endpoint is not connected"],
                58  : ["ESHUTDOWN",       "Cannot send after transport endpoint shutdown"],
                59  : ["ETOOMANYREFS",    "Too many references: cannot splice"],
                60  : ["ETIMEDOUT",       "Connection timed out"],
                61  : ["ECONNREFUSED",    "Connection refused"],
                62  : ["ELOOP",           "Too many symbolic links encountered"],
                63  : ["ENAMETOOLONG",    "File name too long"],
                64  : ["EHOSTDOWN",       "Host is down"],
                65  : ["EHOSTUNREACH",    "No route to host"],
                66  : ["ENOTEMPTY",       "Directory not empty"],
                # 67
                68  : ["EUSERS",          "Too many users"],
                69  : ["EDQUOT",          "Quota exceeded"],
                70  : ["ESTALE",          "Stale file handle"],
                71  : ["EREMOTE",         "Object is remote"],
                # 72-76
                77  : ["ENOLCK",          "No record locks available"],
                78  : ["ENOSYS",          "Function not implemented"],
                # 79
                80  : ["ENOMSG",          "No message of desired type"],
                81  : ["EIDRM",           "Identifier removed"],
                82  : ["ENOSR",           "Out of streams resources"],
                83  : ["ETIME",           "Timer expired"],
                84  : ["EBADMSG",         "Not a data message"],
                85  : ["EPROTO",          "Protocol error"],
                86  : ["ENODATA",         "No data available"],
                87  : ["ENOSTR",          "Device not a stream"],
                88  : ["ECHRNG",          "Channel number out of range"],
                89  : ["EL2NSYNC",        "Level 2 not synchronized"],
                90  : ["EL3HLT",          "Level 3 halted"],
                91  : ["EL3RST",          "Level 3 reset"],
                92  : ["ENOPKG",          "Package not installed"],
                93  : ["ELNRNG",          "Link number out of range"],
                94  : ["EUNATCH",         "Protocol driver not attached"],
                95  : ["ENOCSI",          "No CSI structure available"],
                96  : ["EL2HLT",          "Level 2 halted"],
                97  : ["EBADE",           "Invalid exchange"],
                98  : ["EBADR",           "Invalid request descriptor"],
                99  : ["EXFULL",          "Exchange full"],
                100 : ["ENOANO",          "No anode"],
                101 : ["EBADRQC",         "Invalid request code"],
                102 : ["EBADSLT",         "Invalid slot"],
                # 103
                104 : ["EBFONT",          "Bad font file format"],
                105 : ["ENONET",          "Machine is not on the network"],
                106 : ["ENOLINK",         "Link has been severed"],
                107 : ["EADV",            "Advertise error"],
                108 : ["ESRMNT",          "Srmount error"],
                109 : ["ECOMM",           "Communication error on send"],
                110 : ["EMULTIHOP",       "Multihop attempted"],
                111 : ["EDOTDOT",         "RFS specific error"],
                112 : ["EOVERFLOW",       "Value too large for defined data type"],
                113 : ["ENOTUNIQ",        "Name not unique on network"],
                114 : ["EBADFD",          "File descriptor in bad state"],
                115 : ["EREMCHG",         "Remote address changed"],
                116 : ["EILSEQ",          "Illegal byte sequence"],
                117 : ["EUCLEAN",         "Structure needs cleaning"],
                118 : ["ENOTNAM",         "Not a XENIX named type file"],
                119 : ["ENAVAIL",         "No XENIX semaphores available"],
                120 : ["EISNAM",          "Is a named type file"],
                121 : ["EREMOTEIO",       "Remote I/O error"],
                122 : ["ELIBACC",         "Can not access a needed shared library"],
                123 : ["ELIBBAD",         "Accessing a corrupted shared library"],
                124 : ["ELIBSCN",         ".lib section in a.out corrupted"],
                125 : ["ELIBMAX",         "Attempting to link in too many shared libraries"],
                126 : ["ELIBEXEC",        "Cannot exec a shared library directly"],
                127 : ["ERESTART",        "Interrupted system call should be restarted"],
                128 : ["ESTRPIPE",        "Streams pipe error"],
                129 : ["ENOMEDIUM",       "No medium found"],
                130 : ["EMEDIUMTYPE",     "Wrong medium type"],
                131 : ["ECANCELED",       "Operation Canceled"],
                132 : ["ENOKEY",          "Required key not available"],
                133 : ["EKEYEXPIRED",     "Key has expired"],
                134 : ["EKEYREVOKED",     "Key has been revoked"],
                135 : ["EKEYREJECTED",    "Key was rejected by service"],
                136 : ["EOWNERDEAD",      "Owner died"],
                137 : ["ENOTRECOVERABLE", "State not recoverable"],
                138 : ["ERFKILL",         "Operation not possible due to RF-kill"],
                139 : ["EHWPOISON",       "Memory page has hardware error"],
            }
        elif is_mips32() or is_mips64() or is_mipsn32():
            ERRNO_DICT = {
                35  : ["ENOMSG",          "No message of desired type"],
                36  : ["EIDRM",           "Identifier removed"],
                37  : ["ECHRNG",          "Channel number out of range"],
                38  : ["EL2NSYNC",        "Level 2 not synchronized"],
                39  : ["EL3HLT",          "Level 3 halted"],
                40  : ["EL3RST",          "Level 3 reset"],
                41  : ["ELNRNG",          "Link number out of range"],
                42  : ["EUNATCH",         "Protocol driver not attached"],
                43  : ["ENOCSI",          "No CSI structure available"],
                44  : ["EL2HLT",          "Level 2 halted"],
                45  : ["EDEADLK",         "Resource deadlock would occur"],
                46  : ["ENOLCK",          "No record locks available"],
                # 47-49
                50  : ["EBADE",           "Invalid exchange"],
                51  : ["EBADR",           "Invalid request descriptor"],
                52  : ["EXFULL",          "Exchange full"],
                53  : ["ENOANO",          "No anode"],
                54  : ["EBADRQC",         "Invalid request code"],
                55  : ["EBADSLT",         "Invalid slot"],
                56  : ["EDEADLOCK",       "File locking deadlock error"],
                # 57-58
                59  : ["EBFONT",          "Bad font file format"],
                60  : ["ENOSTR",          "Device not a stream"],
                61  : ["ENODATA",         "No data available"],
                62  : ["ETIME",           "Timer expired"],
                63  : ["ENOSR",           "Out of streams resources"],
                64  : ["ENONET",          "Machine is not on the network"],
                65  : ["ENOPKG",          "Package not installed"],
                66  : ["EREMOTE",         "Object is remote"],
                67  : ["ENOLINK",         "Link has been severed"],
                68  : ["EADV",            "Advertise error"],
                69  : ["ESRMNT",          "Srmount error"],
                70  : ["ECOMM",           "Communication error on send"],
                71  : ["EPROTO",          "Protocol error"],
                # 72
                73  : ["EDOTDOT",         "RFS specific error"],
                74  : ["EMULTIHOP",       "Multihop attempted"],
                # 75-76
                77  : ["EBADMSG",         "Not a data message"],
                78  : ["ENAMETOOLONG",    "File name too long"],
                79  : ["EOVERFLOW",       "Value too large for defined data type"],
                80  : ["ENOTUNIQ",        "Name not unique on network"],
                81  : ["EBADFD",          "File descriptor in bad state"],
                82  : ["EREMCHG",         "Remote address changed"],
                83  : ["ELIBACC",         "Can not access a needed shared library"],
                84  : ["ELIBBAD",         "Accessing a corrupted shared library"],
                85  : ["ELIBSCN",         ".lib section in a.out corrupted"],
                86  : ["ELIBMAX",         "Attempting to link in too many shared libraries"],
                87  : ["ELIBEXEC",        "Cannot exec a shared library directly"],
                88  : ["EILSEQ",          "Illegal byte sequence"],
                89  : ["ENOSYS",          "Function not implemented"],
                90  : ["ELOOP",           "Too many symbolic links encountered"],
                91  : ["ERESTART",        "Interrupted system call should be restarted"],
                92  : ["ESTRPIPE",        "Streams pipe error"],
                93  : ["ENOTEMPTY",       "Directory not empty"],
                94  : ["EUSERS",          "Too many users"],
                95  : ["ENOTSOCK",        "Socket operation on non-socket"],
                96  : ["EDESTADDRREQ",    "Destination address required"],
                97  : ["EMSGSIZE",        "Message too long"],
                98  : ["EPROTOTYPE",      "Protocol wrong type for socket"],
                99  : ["ENOPROTOOPT",     "Protocol not available"],
                # 100-119
                120 : ["EPROTONOSUPPORT", "Protocol not supported"],
                121 : ["ESOCKTNOSUPPORT", "Socket type not supported"],
                122 : ["EOPNOTSUPP",      "Operation not supported on transport endpoint"],
                123 : ["EPFNOSUPPORT",    "Protocol family not supported"],
                124 : ["EAFNOSUPPORT",    "Address family not supported by protocol"],
                125 : ["EADDRINUSE",      "Address already in use"],
                126 : ["EADDRNOTAVAIL",   "Cannot assign requested address"],
                127 : ["ENETDOWN",        "Network is down"],
                128 : ["ENETUNREACH",     "Network is unreachable"],
                129 : ["ENETRESET",       "Network dropped connection because of reset"],
                130 : ["ECONNABORTED",    "Software caused connection abort"],
                131 : ["ECONNRESET",      "Connection reset by peer"],
                132 : ["ENOBUFS",         "No buffer space available"],
                133 : ["EISCONN",         "Transport endpoint is already connected"],
                134 : ["ENOTCONN",        "Transport endpoint is not connected"],
                135 : ["EUCLEAN",         "Structure needs cleaning"],
                # 136
                137 : ["ENOTNAM",         "Not a XENIX named type file"],
                138 : ["ENAVAIL",         "No XENIX semaphores available"],
                139 : ["EISNAM",          "Is a named type file"],
                140 : ["EREMOTEIO",       "Remote I/O error"],
                141 : ["EINIT",           "Reserved"],
                142 : ["EREMDEV",         "Error 142"],
                143 : ["ESHUTDOWN",       "Cannot send after transport endpoint shutdown"],
                144 : ["ETOOMANYREFS",    "Too many references: cannot splice"],
                145 : ["ETIMEDOUT",       "Connection timed out"],
                146 : ["ECONNREFUSED",    "Connection refused"],
                147 : ["EHOSTDOWN",       "Host is down"],
                148 : ["EHOSTUNREACH",    "No route to host"],
                149 : ["EALREADY",        "Operation already in progress"],
                150 : ["EINPROGRESS",     "Operation now in progress"],
                151 : ["ESTALE",          "Stale file handle"],
                # 152-157
                158 : ["ECANCELED",       "AIO operation canceled"],
                159 : ["ENOMEDIUM",       "No medium found"],
                160 : ["EMEDIUMTYPE",     "Wrong medium type"],
                161 : ["ENOKEY",          "Required key not available"],
                162 : ["EKEYEXPIRED",     "Key has expired"],
                163 : ["EKEYREVOKED",     "Key has been revoked"],
                164 : ["EKEYREJECTED",    "Key was rejected by service"],
                165 : ["EOWNERDEAD",      "Owner died"],
                166 : ["ENOTRECOVERABLE", "State not recoverable"],
                167 : ["ERFKILL",         "Operation not possible due to RF-kill"],
                168 : ["EHWPOISON",       "Memory page has hardware error"],
                #
                1133: ["EDQUOT",          "Quota exceeded"],
            }
        elif is_hppa32() or is_hppa64():
            ERRNO_DICT = {
                35 :  ["ENOMSG",          "No message of desired type"],
                36 :  ["EIDRM",           "Identifier removed"],
                37 :  ["ECHRNG",          "Channel number out of range"],
                38 :  ["EL2NSYNC",        "Level 2 not synchronized"],
                39 :  ["EL3HLT",          "Level 3 halted"],
                40 :  ["EL3RST",          "Level 3 reset"],
                41 :  ["ELNRNG",          "Link number out of range"],
                42 :  ["EUNATCH",         "Protocol driver not attached"],
                43 :  ["ENOCSI",          "No CSI structure available"],
                44 :  ["EL2HLT",          "Level 2 halted"],
                45 :  ["EDEADLK",         "Resource deadlock would occur"],
                46 :  ["ENOLCK",          "No record locks available"],
                47 :  ["EILSEQ",          "Illegal byte sequence"],
                # 48-49
                50 :  ["ENONET",          "Machine is not on the network"],
                51 :  ["ENODATA",         "No data available"],
                52 :  ["ETIME",           "Timer expired"],
                53 :  ["ENOSR",           "Out of streams resources"],
                54 :  ["ENOSTR",          "Device not a stream"],
                55 :  ["ENOPKG",          "Package not installed"],
                # 56
                57 :  ["ENOLINK",         "Link has been severed"],
                58 :  ["EADV",            "Advertise error"],
                59 :  ["ESRMNT",          "Srmount error"],
                60 :  ["ECOMM",           "Communication error on send"],
                61 :  ["EPROTO",          "Protocol error"],
                # 62-63
                64 :  ["EMULTIHOP",       "Multihop attempted"],
                # 65
                66 :  ["EDOTDOT",         "RFS specific error"],
                67 :  ["EBADMSG",         "Not a data message"],
                68 :  ["EUSERS",          "Too many users"],
                69 :  ["EDQUOT",          "Quota exceeded"],
                70 :  ["ESTALE",          "Stale file handle"],
                71 :  ["EREMOTE",         "Object is remote"],
                72 :  ["EOVERFLOW",       "Value too large for defined data type"],
                # 73-159
                160 : ["EBADE",           "Invalid exchange"],
                161 : ["EBADR",           "Invalid request descriptor"],
                162 : ["EXFULL",          "Exchange full"],
                163 : ["ENOANO",          "No anode"],
                164 : ["EBADRQC",         "Invalid request code"],
                165 : ["EBADSLT",         "Invalid slot"],
                166 : ["EBFONT",          "Bad font file format"],
                167 : ["ENOTUNIQ",        "Name not unique on network"],
                168 : ["EBADFD",          "File descriptor in bad state"],
                169 : ["EREMCHG",         "Remote address changed"],
                170 : ["ELIBACC",         "Can not access a needed shared library"],
                171 : ["ELIBBAD",         "Accessing a corrupted shared library"],
                172 : ["ELIBSCN",         ".lib section in a.out corrupted"],
                173 : ["ELIBMAX",         "Attempting to link in too many shared libraries"],
                174 : ["ELIBEXEC",        "Cannot exec a shared library directly"],
                175 : ["ERESTART",        "Interrupted system call should be restarted"],
                176 : ["ESTRPIPE",        "Streams pipe error"],
                177 : ["EUCLEAN",         "Structure needs cleaning"],
                178 : ["ENOTNAM",         "Not a XENIX named type file"],
                179 : ["ENAVAIL",         "No XENIX semaphores available"],
                180 : ["EISNAM",          "Is a named type file"],
                181 : ["EREMOTEIO",       "Remote I/O error"],
                182 : ["ENOMEDIUM",       "No medium found"],
                183 : ["EMEDIUMTYPE",     "Wrong medium type"],
                184 : ["ENOKEY",          "Required key not available"],
                185 : ["EKEYEXPIRED",     "Key has expired"],
                186 : ["EKEYREVOKED",     "Key has been revoked"],
                187 : ["EKEYREJECTED",    "Key was rejected by service"],
                # 188-215
                216 : ["ENOTSOCK",        "Socket operation on non-socket"],
                217 : ["EDESTADDRREQ",    "Destination address required"],
                218 : ["EMSGSIZE",        "Message too long"],
                219 : ["EPROTOTYPE",      "Protocol wrong type for socket"],
                220 : ["ENOPROTOOPT",     "Protocol not available"],
                221 : ["EPROTONOSUPPORT", "Protocol not supported"],
                222 : ["ESOCKTNOSUPPORT", "Socket type not supported"],
                223 : ["EOPNOTSUPP",      "Operation not supported on transport endpoint"],
                224 : ["EPFNOSUPPORT",    "Protocol family not supported"],
                225 : ["EAFNOSUPPORT",    "Address family not supported by protocol"],
                226 : ["EADDRINUSE",      "Address already in use"],
                227 : ["EADDRNOTAVAIL",   "Cannot assign requested address"],
                228 : ["ENETDOWN",        "Network is down"],
                229 : ["ENETUNREACH",     "Network is unreachable"],
                230 : ["ENETRESET",       "Network dropped connection because of reset"],
                231 : ["ECONNABORTED",    "Software caused connection abort"],
                232 : ["ECONNRESET",      "Connection reset by peer"],
                233 : ["ENOBUFS",         "No buffer space available"],
                234 : ["EISCONN",         "Transport endpoint is already connected"],
                235 : ["ENOTCONN",        "Transport endpoint is not connected"],
                236 : ["ESHUTDOWN",       "Cannot send after transport endpoint shutdown"],
                237 : ["ETOOMANYREFS",    "Too many references: cannot splice"],
                238 : ["ETIMEDOUT",       "Connection timed out"],
                239 : ["ECONNREFUSED",    "Connection refused"],
                # 240
                241 : ["EHOSTDOWN",       "Host is down"],
                242 : ["EHOSTUNREACH",    "No route to host"],
                # 243
                244 : ["EALREADY",        "Operation already in progress"],
                245 : ["EINPROGRESS",     "Operation now in progress"],
                # 246
                247 : ["ENOTEMPTY",       "Directory not empty"],
                248 : ["ENAMETOOLONG",    "File name too long"],
                249 : ["ELOOP",           "Too many symbolic links encountered"],
                # 250
                251 : ["ENOSYS",          "Function not implemented"],
                # 252
                253 : ["ECANCELLED",      "aio request was canceled before complete (POSIX.4 / HPUX)"],
                254 : ["EOWNERDEAD",      "Owner died"],
                255 : ["ENOTRECOVERABLE", "State not recoverable"],
                256 : ["ERFKILL",         "Operation not possible due to RF-kill"],
                257 : ["EHWPOISON",       "Memory page has hardware error"],
            }
        elif is_sparc32() or is_sparc64():
            ERRNO_DICT = {
                36  : ["EINPROGRESS",     "Operation now in progress"],
                37  : ["EALREADY",        "Operation already in progress"],
                38  : ["ENOTSOCK",        "Socket operation on non-socket"],
                39  : ["EDESTADDRREQ",    "Destination address required"],
                40  : ["EMSGSIZE",        "Message too long"],
                41  : ["EPROTOTYPE",      "Protocol wrong type for socket"],
                42  : ["ENOPROTOOPT",     "Protocol not available"],
                43  : ["EPROTONOSUPPORT", "Protocol not supported"],
                44  : ["ESOCKTNOSUPPORT", "Socket type not supported"],
                45  : ["EOPNOTSUPP",      "Op not supported on transport endpoint"],
                46  : ["EPFNOSUPPORT",    "Protocol family not supported"],
                47  : ["EAFNOSUPPORT",    "Address family not supported by protocol"],
                48  : ["EADDRINUSE",      "Address already in use"],
                49  : ["EADDRNOTAVAIL",   "Cannot assign requested address"],
                50  : ["ENETDOWN",        "Network is down"],
                51  : ["ENETUNREACH",     "Network is unreachable"],
                52  : ["ENETRESET",       "Net dropped connection because of reset"],
                53  : ["ECONNABORTED",    "Software caused connection abort"],
                54  : ["ECONNRESET",      "Connection reset by peer"],
                55  : ["ENOBUFS",         "No buffer space available"],
                56  : ["EISCONN",         "Transport endpoint is already connected"],
                57  : ["ENOTCONN",        "Transport endpoint is not connected"],
                58  : ["ESHUTDOWN",       "No send after transport endpoint shutdown"],
                59  : ["ETOOMANYREFS",    "Too many references: cannot splice"],
                60  : ["ETIMEDOUT",       "Connection timed out"],
                61  : ["ECONNREFUSED",    "Connection refused"],
                62  : ["ELOOP",           "Too many symbolic links encountered"],
                63  : ["ENAMETOOLONG",    "File name too long"],
                64  : ["EHOSTDOWN",       "Host is down"],
                65  : ["EHOSTUNREACH",    "No route to host"],
                66  : ["ENOTEMPTY",       "Directory not empty"],
                67  : ["EPROCLIM",        "SUNOS: Too many processes"],
                68  : ["EUSERS",          "Too many users"],
                69  : ["EDQUOT",          "Quota exceeded"],
                70  : ["ESTALE",          "Stale file handle"],
                71  : ["EREMOTE",         "Object is remote"],
                72  : ["ENOSTR",          "Device not a stream"],
                73  : ["ETIME",           "Timer expired"],
                74  : ["ENOSR",           "Out of streams resources"],
                75  : ["ENOMSG",          "No message of desired type"],
                76  : ["EBADMSG",         "Not a data message"],
                77  : ["EIDRM",           "Identifier removed"],
                78  : ["EDEADLK",         "Resource deadlock would occur"],
                79  : ["ENOLCK",          "No record locks available"],
                80  : ["ENONET",          "Machine is not on the network"],
                81  : ["ERREMOTE",        "SunOS: Too many lvls of remote in path"],
                82  : ["ENOLINK",         "Link has been severed"],
                83  : ["EADV",            "Advertise error"],
                84  : ["ESRMNT",          "Srmount error"],
                85  : ["ECOMM",           "Communication error on send"],
                86  : ["EPROTO",          "Protocol error"],
                87  : ["EMULTIHOP",       "Multihop attempted"],
                88  : ["EDOTDOT",         "RFS specific error"],
                89  : ["EREMCHG",         "Remote address changed"],
                90  : ["ENOSYS",          "Function not implemented"],
                91  : ["ESTRPIPE",        "Streams pipe error"],
                92  : ["EOVERFLOW",       "Value too large for defined data type"],
                93  : ["EBADFD",          "File descriptor in bad state"],
                94  : ["ECHRNG",          "Channel number out of range"],
                95  : ["EL2NSYNC",        "Level 2 not synchronized"],
                96  : ["EL3HLT",          "Level 3 halted"],
                97  : ["EL3RST",          "Level 3 reset"],
                98  : ["ELNRNG",          "Link number out of range"],
                99  : ["EUNATCH",         "Protocol driver not attached"],
                100 : ["ENOCSI",          "No CSI structure available"],
                101 : ["EL2HLT",          "Level 2 halted"],
                102 : ["EBADE",           "Invalid exchange"],
                103 : ["EBADR",           "Invalid request descriptor"],
                104 : ["EXFULL",          "Exchange full"],
                105 : ["ENOANO",          "No anode"],
                106 : ["EBADRQC",         "Invalid request code"],
                107 : ["EBADSLT",         "Invalid slot"],
                108 : ["EDEADLOCK",       "File locking deadlock error"],
                109 : ["EBFONT",          "Bad font file format"],
                110 : ["ELIBEXEC",        "Cannot exec a shared library directly"],
                111 : ["ENODATA",         "No data available"],
                112 : ["ELIBBAD",         "Accessing a corrupted shared library"],
                113 : ["ENOPKG",          "Package not installed"],
                114 : ["ELIBACC",         "Can not access a needed shared library"],
                115 : ["ENOTUNIQ",        "Name not unique on network"],
                116 : ["ERESTART",        "Interrupted syscall should be restarted"],
                117 : ["EUCLEAN",         "Structure needs cleaning"],
                118 : ["ENOTNAM",         "Not a XENIX named type file"],
                119 : ["ENAVAIL",         "No XENIX semaphores available"],
                120 : ["EISNAM",          "Is a named type file"],
                121 : ["EREMOTEIO",       "Remote I/O error"],
                122 : ["EILSEQ",          "Illegal byte sequence"],
                123 : ["ELIBMAX",         "Atmpt to link in too many shared libs"],
                124 : ["ELIBSCN",         ".lib section in a.out corrupted"],
                125 : ["ENOMEDIUM",       "No medium found"],
                126 : ["EMEDIUMTYPE",     "Wrong medium type"],
                127 : ["ECANCELED",       "Operation Cancelled"],
                128 : ["ENOKEY",          "Required key not available"],
                129 : ["EKEYEXPIRED",     "Key has expired"],
                130 : ["EKEYREVOKED",     "Key has been revoked"],
                131 : ["EKEYREJECTED",    "Key was rejected by service"],
                132 : ["EOWNERDEAD",      "Owner died"],
                133 : ["ENOTRECOVERABLE", "State not recoverable"],
                134 : ["ERFKILL",         "Operation not possible due to RF-kill"],
                135 : ["EHWPOISON",       "Memory page has hardware error"],
            }

        return ERRNO_BASE_DICT | ERRNO_DICT

    @parse_args
    @exclude_specific_gdb_mode(mode=("wine",))
    @require_arch_set
    def do_invoke(self, args):
        ERRNO_DICT = ErrnoCommand.get_errno_dict()

        if args.all:
            self.out = []
            for val, (sym, desc) in sorted(ERRNO_DICT.items()):
                self.out.append('{:3d} (={:#4x}): {:<15s}: "{:s}"'.format(val, val, sym, desc))
            self.print_output(check_terminal_size=True)
            return

        if args.errno is None:
            if not is_alive():
                warn("No debugging session active")
                return
            try:
                val = AddressUtil.parse_address("*__errno_location()")
            except gdb.error:
                err("Failed to get *__errno_location()")
                return
        else:
            val = args.errno

        if val > 0xffff:
            if runtime.current_arch and runtime.current_arch.ptrsize == 4:
                val = struct.unpack("<i", struct.pack("<I", val))[0]
            elif runtime.current_arch and runtime.current_arch.ptrsize == 8:
                val = struct.unpack("<q", struct.pack("<Q", val))[0]
            elif runtime.current_arch is None:
                val = struct.unpack("<q", struct.pack("<Q", val))[0]
            else:
                err("Not supported this pointer size")
                return

        if val < 0:
            val = -val

        if val in ERRNO_DICT:
            sym, desc = ERRNO_DICT[val]
            gef_print('{:3d} (={:#4x}): {:<15s}: "{:s}"'.format(val, val, sym, desc))
        else:
            err("Could not find value in ERRNO_DICT")
        return


@register_command
class StackFrameCommand(GenericCommand):
    """Display the entire stack of the current frame."""

    _cmdline_ = "stack-frame"
    _category_ = "02-d. Process Information - Trivial Information"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        from gef.commands.debugging.context import DereferenceCommand
        ptrsize = runtime.current_arch.ptrsize
        try:
            frame = gdb.selected_frame()
        except gdb.error:
            # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
            err("Failed to get frame information")
            return

        if not frame.older():
            reason_str = gdb.frame_stop_reason_string(frame.unwind_stop_reason())
            warn("Cannot determine frame boundary, reason: {:s}".format(reason_str))
            return

        saved_ip = frame.older().pc()
        stack_hi = int(frame.older().read_register("sp"))
        stack_lo = int(frame.read_register("sp"))
        results = []

        if runtime.current_arch.stack_grow_down:
            addr_lo = stack_lo
            addr_hi = stack_hi
        else:
            addr_lo = stack_hi + runtime.current_arch.ptrsize
            addr_hi = stack_lo + runtime.current_arch.ptrsize

        for offset, address in enumerate(range(addr_lo, addr_hi, ptrsize)):
            pprint_str = DereferenceCommand.pprint_dereferenced(addr_lo, offset)
            if AddressUtil.dereference(address) == saved_ip:
                pprint_str += " ($savedip)"
            results.append(pprint_str)

        if not runtime.current_arch.stack_grow_down:
            results.reverse()
            gef_print(titlify("Stack top (higher address)"))
        else:
            gef_print(titlify("Stack top (lower address)"))

        for res in results:
            gef_print(res)

        if not runtime.current_arch.stack_grow_down:
            gef_print(titlify("Stack bottom (lower address)"))
        else:
            gef_print(titlify("Stack bottom (higher address)"))
        return
