"""GEF debugging commands (category 01-g) extracted from the monolithic gef.py.

Syscall commands (depends on gef.core.syscall from Phase 2.0).

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import os
import re
import struct

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_arch,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_specific_arch,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, ok, titlify, warn
from gef.core.events import EventHandler, EventHooking
from gef.core.exec import ExecSyscall
from gef.core.memory import hexdump, p16, read_int_from_memory, read_memory, write_memory
from gef.core.process import (
    ProcessMap,
    get_pagesize,
    is_alive,
    is_alpha,
    is_hppa32,
    is_hppa64,
    is_mips32,
    is_mips64,
    is_mipsn32,
    is_sparc32,
    is_sparc32plus,
    is_sparc64,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import get_register
from gef.core.strings import String
from gef.core.syscall import Syscall
from gef.core.utils import GefUtil


@register_command
class HijackFdCommand(GenericCommand):
    """Redirect the file descriptor during execution."""

    _cmdline_ = "hijack-fd"
    _category_ = "01-g. Debugging Support - Syscall"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("old_fd", metavar="OLD_FD", type=int, help="file descriptor number to redirect.")
    parser.add_argument("new_output", metavar="NEW_OUTPUT", type=str, help="the location redirected data is stored.")
    parser.add_argument("--fd-adjust-connect", type=int, default=0,
                        help="slide value when `connect` syscall result and the actual opened FD differ (for old qemu-user).")
    parser.add_argument("--fd-adjust-dup3", type=int, default=0,
                        help="slide value when `dup3` syscall result and the actual opened FD differ (for old qemu-user).")
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 2 /tmp/gef/stderr.txt",
        "{0:s} 2 localhost:8000  # determined as the socket by the presence of `:`.",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def call_syscall(self, syscall_name, args):
        args = " ".join([hex(x) if x >= 0 else str(x) for x in args])
        cmd = "call-syscall {:s} {:s}".format(syscall_name, args)
        self.quiet_info(cmd)
        res = gdb.execute(cmd, to_string=True)
        output_line = res.splitlines()[-1]
        self.quiet_info(output_line)
        return int(output_line.split()[2], 0)

    def write_stack(self, data):
        data = String.str2bytes(data)

        # get stack address
        vmmap = ProcessMap.get_process_maps()
        stack_addrs = [entry.page_start for entry in vmmap if entry.path == "[stack]"]
        if len(stack_addrs) == 0:
            err("Could not find the stack")
            return None, None
        stack_addr = stack_addrs[0]

        # read original contents
        try:
            original_contents = read_memory(stack_addr, len(data))
        except gdb.MemoryError:
            err("Failed to read stack")
            return None, None

        self.quiet_info("Original contents: {!s} @ {:#x}".format(original_contents, stack_addr))
        self.quiet_info("Overwrite data: {!s}".format(data))

        # overwrite it
        try:
            write_memory(stack_addr, data)
        except Exception:
            err("Failed to write stack")
            return None, None

        # read again and check
        if read_memory(stack_addr, len(data)) != data:
            err("Failed to write stack")
            return None, None

        return stack_addr, original_contents

    def get_fd_from_file_open(self):
        # call open
        stack_addr, original_contents = self.write_stack(self.args.new_output + "\0")
        if stack_addr is None:
            return None

        self.quiet_info("Trying to open {:s}".format(Color.boldify(self.args.new_output)))

        AT_FDCWD = -100
        flags = self.O_APPEND | self.O_CREAT | self.O_RDWR
        mode = 0o666
        # open does not exist in aarch64. So use openat instead of open.
        open_fd = self.call_syscall("openat", [AT_FDCWD, stack_addr, flags, mode])
        write_memory(stack_addr, original_contents) # revert

        if AddressUtil.is_msb_on(open_fd):
            err("Failed to open {:s}".format(self.args.new_output))
            return None

        self.quiet_info("Opened {:s} with 0o666 as fd #{:d}".format(Color.boldify(self.args.new_output), open_fd))
        return open_fd

    def get_fd_from_connect_server(self):
        import socket
        address = socket.gethostbyname(self.args.new_output.split(":")[0])
        port = int(self.args.new_output.split(":")[1])

        # call socket
        sock_fd = self.call_syscall("socket", [self.AF_INET, self.SOCK_STREAM, 0])
        if AddressUtil.is_msb_on(sock_fd):
            err("Failed to create socket")
            return None
        self.quiet_info("Created socket fd #{:d}".format(sock_fd))

        # call connect (Also supports big endian)
        sockaddr_in = p16(self.AF_INET) + struct.pack("<H", socket.htons(port)) + socket.inet_aton(address)
        stack_addr, original_contents = self.write_stack(sockaddr_in)
        if stack_addr is None:
            return None

        self.quiet_info("Trying to connect to {:s}".format(Color.boldify(self.args.new_output)))
        connect_result = self.call_syscall("connect", [sock_fd - self.args.fd_adjust_connect, stack_addr, 16])
        write_memory(stack_addr, original_contents) # revert

        if AddressUtil.is_msb_on(connect_result):
            err("Failed to connect to {:s}:{:d}".format(address, port))
            return

        self.quiet_info("Connected to {:s} as fd #{:d}".format(Color.boldify(self.args.new_output), sock_fd))
        return sock_fd

    def hijack_fd(self):
        if ":" in self.args.new_output:
            new_fd = self.get_fd_from_connect_server()
        else:
            new_fd = self.get_fd_from_file_open()
        if new_fd is None:
            return

        # call dup3
        # dup2 does not exist in aarch64. So use dup3 instead of dup2.
        dup3_result = self.call_syscall("dup3", [new_fd - self.args.fd_adjust_dup3, self.args.old_fd, 0])
        if dup3_result - self.args.fd_adjust_dup3 != self.args.old_fd:
            err("Failed to dup3 (result {:d} != fd #{:d})".format(dup3_result, self.args.old_fd))
            return
        self.quiet_info("Duplicated fd #{:d} -> #{:d}".format(new_fd, self.args.old_fd))

        # call close
        close_result = self.call_syscall("close", [new_fd])
        if AddressUtil.is_msb_on(close_result):
            err("Failed to close fd #{:d}".format(new_fd))
            return
        self.quiet_info("Closed extra fd #{:d}".format(new_fd))

        ok("Success")
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "rr", "wine"))
    @exclude_specific_arch(arch=("CRIS",))
    @require_arch_set
    def do_invoke(self, args):
        # In old version of qemu, the file descriptor was sometimes shifted by a
        # constant value on i386 (fd returned by the syscall == actual opened fd + 80).
        # This had been hard-coded as a workaround, but the issue appears to be fixed,
        # so it should now be specified via a command argument.
        # Currently supported: dup3, connect

        self.AF_INET = 2
        self.SOCK_STREAM = 1
        self.O_APPEND = 0o2000
        self.O_CREAT = 0o100
        self.O_RDWR = 0o2
        # some architecture use different consts.
        if is_mips32() or is_mips64() or is_mipsn32():
            # /usr/mipsel-linux-gnu/include/bits/socket_type.h
            # /usr/mips64el-linux-gnuabi64/include/bits/socket_type.h
            self.SOCK_STREAM = 2
            # /usr/mipsel-linux-gnu/include/bits/fcntl.h
            # /usr/mips64el-linux-gnuabi64/include/bits/fcntl.h
            self.O_APPEND = 0x0008
            self.O_CREAT = 0x0100
        elif is_sparc32() or is_sparc32plus() or is_sparc64():
            # sparcv8--uclibc--stable-2022.08-1/sparc-buildroot-linux-uclibc/sysroot/usr/include/bits/fcntl.h
            # sparc64--glibc--stable-2022.08-1/sparc64-buildroot-linux-gnu/sysroot/usr/include/bits/fcntl.h
            self.O_APPEND = 0x0008
            self.O_CREAT = 0x0200
        elif is_alpha():
            # /usr/alpha-linux-gnu/include/bits/fcntl.h
            self.O_APPEND = 0o0010
            self.O_CREAT = 0o1000
        elif is_hppa32() or is_hppa64():
            # /usr/hppa-linux-gnu/include/bits/fcntl.h
            self.O_APPEND = 0o0010
            self.O_CREAT = 0o0400

        self.hijack_fd()
        return


@register_command
class XtapCommand(GenericCommand):
    """Tap read/write syscalls on specific file descriptors and hexdump the transferred data."""

    _cmdline_ = "xtap"
    _category_ = "01-g. Debugging Support - Syscall"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("fd", metavar="FD", nargs="+", type=AddressUtil.parse_address,
                        help="the file descriptor(s) to tap.")
    parser.add_argument("--max", dest="maxlen", type=AddressUtil.parse_address,
                        help="limit the number of bytes to hexdump per transfer.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0               # tap stdin",
        "{0:s} 4               # tap fd 4 (e.g. a socket)",
        "{0:s} 0 1 2           # tap stdin/stdout/stderr",
        "{0:s} 4 --max 0x40    # tap fd 4, dump at most 0x40 bytes per transfer",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Hooked syscalls:",
        "  read-like: read, recvfrom, recvmsg, recvmmsg, recvmmsg_time64, pread64, preadv, preadv2, readv",
        "  write-like: write, sendto, sendmsg, sendmmsg, pwrite64, pwritev, pwritev2, writev",
        "",
        "- Relies on `catch syscall`.",
        "- Auto-continues; stops on a user breakpoint or Ctrl+C.",
        "- qemu-user is unsupported: its gdbstub does not update the return-value register",
        "  at syscall-return, so read-like sizes are wrong. Use a native target.",
    ]
    _note_ = "\n".join(_note_)

    syscall_spec = {
        "read":             ("in",  "buf"),
        "recvfrom":         ("in",  "buf"),
        "pread64":          ("in",  "buf"),
        "readv":            ("in",  "iovec"),
        "preadv":           ("in",  "iovec"),
        "preadv2":          ("in",  "iovec"),
        "recvmsg":          ("in",  "msghdr"),
        "recvmmsg":         ("in",  "mmsghdr"),
        "recvmmsg_time64":  ("in",  "mmsghdr"),
        "write":            ("out", "buf"),
        "sendto":           ("out", "buf"),
        "pwrite64":         ("out", "buf"),
        "writev":           ("out", "iovec"),
        "pwritev":          ("out", "iovec"),
        "pwritev2":         ("out", "iovec"),
        "sendmsg":          ("out", "msghdr"),
        "sendmmsg":         ("out", "mmsghdr"),
    }

    def read_iovec_array(self, vec_addr, vlen):
        """Return a list of (base, length) tuples from a struct iovec array."""
        entries = []
        cur = vec_addr
        for _ in range(vlen):
            iov_base = read_int_from_memory(cur)
            iov_len = read_int_from_memory(cur + runtime.current_arch.ptrsize)
            entries.append((iov_base, iov_len))
            cur += runtime.current_arch.ptrsize * 2
        return entries

    def gather_iovec_bytes(self, entries, limit):
        """Concatenate bytes described by iovec entries, capped at `limit` bytes total."""
        data = bytearray()
        for base, length in entries:
            if limit is not None and len(data) >= limit:
                break
            want = length
            if limit is not None:
                want = min(want, limit - len(data))
            if want <= 0:
                continue
            try:
                data += read_memory(base, want)
            except gdb.error:
                break
        return bytes(data)

    def read_msghdr(self, msg_addr):
        """Return iovec entries from a struct msghdr.

        struct msghdr layout:
          void*         msg_name        off 0
          socklen_t     msg_namelen     off ptrsize       (padded to ptrsize)
          struct iovec* msg_iov         off ptrsize*2
          size_t        msg_iovlen      off ptrsize*3
          ...
        """
        msg_iov = read_int_from_memory(msg_addr + runtime.current_arch.ptrsize * 2)
        msg_iovlen = read_int_from_memory(msg_addr + runtime.current_arch.ptrsize * 3)
        return self.read_iovec_array(msg_iov, msg_iovlen)

    def read_mmsghdr_entries(self, mmsg_addr, vlen):
        """Return a flat list of iovec entries across a struct mmsghdr array.

        struct mmsghdr layout:
          struct msghdr msg_hdr     off 0
          unsigned int  msg_len     off sizeof(struct msghdr)

        sizeof(struct msghdr) is 7 pointers:
          msg_name, msg_namelen(+pad), msg_iov, msg_iovlen, msg_control, msg_controllen(+pad),
          msg_flags(+pad). We step by that stride.
        """
        msghdr_size = runtime.current_arch.ptrsize * 7
        mmsghdr_stride = msghdr_size + runtime.current_arch.ptrsize  # msg_len is unsigned int but padded to ptrsize
        entries = []
        cur = mmsg_addr
        for _ in range(vlen):
            entries += self.read_msghdr(cur)
            cur += mmsghdr_stride
        return entries

    def extract_entry_data(self, name, arg_regs):
        """Read data for write-like syscalls at entry. Returns (label, bytes) or None."""
        kind = self.syscall_spec[name][1]

        if kind == "buf":
            # buf is 2nd arg, count is 3rd arg
            buf = get_register(arg_regs[1])
            count = get_register(arg_regs[2])
            if self.maxlen is not None:
                count = min(count, self.maxlen)
            try:
                data = read_memory(buf, count)
            except gdb.error:
                return None
            return ("buf={:#x} count={:#x}".format(buf, count), data)

        if kind == "iovec":
            # iov is 2nd arg, iovcnt is 3rd arg
            iov = get_register(arg_regs[1])
            iovcnt = get_register(arg_regs[2])
            entries = self.read_iovec_array(iov, iovcnt)
            data = self.gather_iovec_bytes(entries, self.maxlen)
            return ("iov={:#x} iovcnt={:#x}".format(iov, iovcnt), data)

        if kind == "msghdr":
            # msg is 2nd arg
            msg = get_register(arg_regs[1])
            entries = self.read_msghdr(msg)
            data = self.gather_iovec_bytes(entries, self.maxlen)
            return ("msghdr={:#x}".format(msg), data)

        if kind == "mmsghdr":
            # msgvec is 2nd arg, vlen is 3rd arg
            msgvec = get_register(arg_regs[1])
            vlen = get_register(arg_regs[2])
            entries = self.read_mmsghdr_entries(msgvec, vlen)
            data = self.gather_iovec_bytes(entries, self.maxlen)
            return ("mmsghdr={:#x} vlen={:#x}".format(msgvec, vlen), data)

        return None

    def extract_exit_data(self, name, entry_args, retval):
        """Read data for read-like syscalls at exit. Returns (label, bytes) or None.
        `retval` is the number of bytes actually transferred. `entry_args` carries
        the argument register values captured at entry.
        """
        kind = self.syscall_spec[name][1]

        if retval is None or retval <= 0:
            return ("returned {}".format(retval if retval is not None else "?"), b"")

        limit = retval
        if self.maxlen is not None:
            limit = min(limit, self.maxlen)

        if kind == "buf":
            buf = entry_args[1]
            try:
                data = read_memory(buf, limit)
            except gdb.error:
                return None
            return ("buf={:#x} ret={:#x}".format(buf, retval), data)

        if kind == "iovec":
            iov = entry_args[1]
            iovcnt = entry_args[2]
            entries = self.read_iovec_array(iov, iovcnt)
            data = self.gather_iovec_bytes(entries, limit)
            return ("iov={:#x} ret={:#x}".format(iov, retval), data)

        if kind == "msghdr":
            msg = entry_args[1]
            entries = self.read_msghdr(msg)
            data = self.gather_iovec_bytes(entries, limit)
            return ("msghdr={:#x} ret={:#x}".format(msg, retval), data)

        return None

    def entry_fd(self, arg_regs):
        """All hooked syscalls take fd as their first argument."""
        return get_register(arg_regs[0])

    def close_stdout_stderr(self):
        self.stdout = 1
        self.stdout_bak = os.dup(self.stdout)
        f = open("/dev/null")
        os.dup2(f.fileno(), self.stdout)
        f.close()

        self.stderr = 2
        self.stderr_bak = os.dup(self.stderr)
        f = open("/dev/null")
        os.dup2(f.fileno(), self.stderr)
        f.close()
        return

    def revert_stdout_stderr(self):
        os.dup2(self.stdout_bak, self.stdout)
        os.close(self.stdout_bak)
        os.dup2(self.stderr_bak, self.stderr)
        os.close(self.stderr_bak)
        return

    def force_write_stdout(self, msg):
        open("/proc/self/fd/0", "wb").write(msg)
        return

    def dump_transfer(self, name, direction, fd, label, data):
        arrow = "<-" if direction == "in" else "->"
        head = "[fd {:d}] {:s} {:s} {:s}".format(fd, name, arrow, label)
        lines = [titlify(head)]
        if data:
            lines.append(hexdump(data, base=0))
        else:
            lines.append("(no data)")
        self.force_write_stdout(String.str2bytes("\n".join(lines) + "\n"))
        return

    def setup_catchpoints(self):
        """Set a catch syscall for every supported+available syscall. Returns count set."""
        for name in self.syscall_spec:
            # only attempt syscalls the running target actually knows
            if self.syscall_table and name not in self.syscall_table.name_table:
                warn("syscall '{:s}' is unknown on this target, skipped".format(name))
                continue
            try:
                res = gdb.execute("catch syscall {:s}".format(name), to_string=True)
            except gdb.error as e:
                warn("could not set catch syscall '{:s}': {}".format(name, e))
                continue
            # gdb prints e.g. "Catchpoint 3 (syscall 'read' [0])"
            num = None
            for tok in res.split():
                if tok.isdigit():
                    num = int(tok)
                    break
            if num is None:
                warn("catch syscall '{:s}' did not return a catchpoint number, skipped".format(name))
                # best-effort: it may still have been created; try to clean up later via name match is unreliable,
                # so leave it. but do not track an unknown number.
                continue
            self.catch_numbers.append(num)
            self.hooked_names.append(name)
            self.hooked_set.add(name)
        return len(self.catch_numbers)

    def teardown_catchpoints(self):
        for num in self.catch_numbers:
            try:
                gdb.execute("delete {:d}".format(num), to_string=True)
            except gdb.error:
                pass
        self.catch_numbers = []
        return

    def syscall_nr_register(self):
        if is_x86_64():
            return "$orig_rax"
        if is_x86_32():
            return "$orig_eax"
        return None

    def current_syscall_number(self):
        """Return the syscall number at the current catch-syscall stop, or None."""
        regname = self.syscall_nr_register()
        if regname is None:
            return None
        try:
            nr = get_register(regname)
        except Exception:
            nr = None
        return nr

    def current_syscall_name(self):
        """Return the name of the syscall at the current catch-syscall stop, or None."""
        if self.syscall_table is None:
            return None
        nr = self.current_syscall_number()
        if nr is None:
            return None
        entry = self.syscall_table.nr_table.get(nr, None)
        if entry is None:
            return None
        return entry.name

    def identify_stop(self):
        """Determine if the current stop is one of our tapped syscalls."""
        try:
            tid = gdb.selected_thread().num
        except Exception:
            tid = 0

        pending_name = self.in_syscall_by_thread.get(tid, None)
        if pending_name is not None:
            # this stop is the return matching the previous entry on this thread
            self.in_syscall_by_thread[tid] = None
            if pending_name not in self.hooked_set:
                return None
            return pending_name, False

        # this stop is an entry: resolve the syscall name now and remember it
        name = self.current_syscall_name()
        self.in_syscall_by_thread[tid] = name
        if name is None or name not in self.hooked_set:
            return None
        return name, True

    def handle_entry(self, name):
        try:
            tid = gdb.selected_thread().num
        except Exception:
            tid = 0
        entry = self.syscall_table.name_table[name]
        arg_regs = entry.arg_regs
        fd = self.entry_fd(arg_regs)
        if fd not in self.target_fds:
            self.pending_by_thread.pop(tid, None)
            return
        direction = self.syscall_spec[name][0]
        if direction == "out":
            # write-like: buffer is ready now, dump immediately, nothing to wait for
            extracted = self.extract_entry_data(name, arg_regs)
            if extracted is not None:
                label, data = extracted
                self.dump_transfer(name, direction, fd, label, data)
            self.pending_by_thread.pop(tid, None)
        else:
            # read-like: snapshot args now (they may be clobbered by exit) and wait for the return
            arg_values = [get_register(r) for r in arg_regs]
            self.pending_by_thread[tid] = {"name": name, "fd": fd, "arg_values": arg_values}
        return

    def handle_return(self, name):
        try:
            tid = gdb.selected_thread().num
        except Exception:
            tid = 0
        pending = self.pending_by_thread.pop(tid, None)
        if pending is None or pending["name"] != name:
            return
        entry = self.syscall_table.name_table[name]
        retval = get_register(entry.ret_regs[0])
        # ret value is signed; treat large unsigned as negative error
        if retval >= (1 << (runtime.current_arch.ptrsize * 8 - 1)):
            retval = retval - (1 << (runtime.current_arch.ptrsize * 8))
        direction = self.syscall_spec[name][0]
        fd = pending["fd"]
        extracted = self.extract_exit_data(name, pending["arg_values"], retval)
        if extracted is not None:
            label, data = extracted
            self.dump_transfer(name, direction, fd, label, data)
        return

    def trace(self):
        bp_was_hit = False
        inferior_exited = False
        EventHooking.gef_on_stop_unhook(EventHandler.hook_stop_handler)
        self.close_stdout_stderr()
        try:
            while True:
                gdb.execute("continue", to_string=True)
                if not is_alive():
                    inferior_exited = True
                    break
                hit = self.identify_stop()
                if hit is None:
                    # stopped for some other reason (user breakpoint, signal, etc.)
                    bp_was_hit = True
                    break
                name, is_entry = hit
                if is_entry:
                    self.handle_entry(name)
                else:
                    self.handle_return(name)
        except KeyboardInterrupt:
            bp_was_hit = True
        except gdb.error as e:
            self.err = e
        finally:
            self.revert_stdout_stderr()
            EventHooking.gef_on_stop_hook(EventHandler.hook_stop_handler)
        if inferior_exited:
            info("Inferior exited")
        return bp_was_hit

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "qemu-user", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    def do_invoke(self, args):
        self.target_fds = list(args.fd)
        self.maxlen = args.maxlen
        self.catch_numbers = []
        self.hooked_names = []
        self.hooked_set = set()
        self.in_syscall_by_thread = {}
        self.pending_by_thread = {}
        self.err = None

        if self.current_syscall_number() is None:
            err("Failed to get {:s}".format(self.syscall_nr_register()))
            return

        self.syscall_table = Syscall.get_syscall_table()
        if self.syscall_table is None:
            err("Could not obtain the syscall table for this target")
            return

        count = self.setup_catchpoints()
        if count == 0:
            err("Could not set any catch syscall; this target/gdb does not support syscall catchpoints")
            return

        info("Tapping fd {:s} on {:d} syscalls: {:s}".format(
            ", ".join(str(x) for x in self.target_fds),
            count,
            ", ".join(self.hooked_names),
        ))
        info("Running with auto-continue. Stop with a breakpoint or Ctrl+C.")

        try:
            bp_was_hit = self.trace()
        finally:
            self.teardown_catchpoints()
            Cache.reset_gef_caches()
            warn("xtap stopped, catchpoints removed")

        if self.err:
            err("{}".format(self.err))
        elif bp_was_hit and is_alive():
            gdb.execute("context")
        return


@register_command
class KillThreadsCommand(GenericCommand):
    """Invoke pthread_exit(0) for a specific THREAD_ID."""

    _cmdline_ = "killthreads"
    _category_ = "01-g. Debugging Support - Syscall"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("thread_id", metavar="THREAD_ID", nargs="*", type=int, help="the thread id (not TID) to kill.")
    parser.add_argument("-a", "--all", action="store_true", help="kill all threads except current thread.")
    parser.add_argument("-e", "--exclude", action="append", type=int, default=[], help="the thread id not to kill.")
    parser.add_argument("-c", "--commit", action="store_true", help="commit to kill.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} 2 3   # kill threads that `Thread Id` is 2 or 3',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "qemu-user", "kgdb", "vmware", "wine"))
    @exclude_specific_arch(arch=("CRIS",))
    @require_arch_set
    def do_invoke(self, args):
        # print tid list and exit
        if not args.all and not args.thread_id and not args.exclude:
            info("Non-current `Thread Id`(s) from the list are available")
            gdb.execute("context-threads -i -1")
            return

        # list target thread id
        orig_thread = gdb.selected_thread()
        orig_frame = gdb.selected_frame()
        target_threads = []
        for th in gdb.selected_inferior().threads():
            if th.num == orig_thread.num:
                continue
            if args.all:
                if th.num not in args.exclude:
                    target_threads.append(th)
                continue
            elif args.thread_id:
                if th.num in args.thread_id:
                    if th.num not in args.exclude:
                        target_threads.append(th)
                continue
            else:
                if th.num not in args.exclude:
                    target_threads.append(th)
                continue
        target_threads = sorted(target_threads, key=lambda x: x.num)
        gef_print("target Thread Id(s) to kill: {}".format([th.num for th in target_threads]))

        # kill
        if args.commit:
            # backup
            sched_lock = gdb.parameter("scheduler-locking")
            # change temporarily
            gdb.execute("set scheduler-locking on", to_string=True)
            # kill
            for th in target_threads:
                th.switch()
                try:
                    gdb.execute("call pthread_exit(0)")
                except gdb.error:
                    pass
            # restore
            orig_thread.switch()
            orig_frame.select()
            gdb.execute("set scheduler-locking {:s}".format(sched_lock), to_string=True)
        else:
            warn('This dry run mode skips killing; add "--commit" to proceed')
        return


@register_command
class CallSyscallCommand(GenericCommand):
    """A wrapper for calling syscall easily."""

    _cmdline_ = "call-syscall"
    _category_ = "01-g. Debugging Support - Syscall"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("syscall_name", metavar="SYSCALL_NAME", help="system call name to invoke.")
    parser.add_argument("syscall_args", metavar="SYSCALL_ARG", nargs="*", type=AddressUtil.parse_address,
                        help="arguments of system call.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} write 1 "*(void**)($rsp+0x18)" 15',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "rr", "wine"))
    @exclude_specific_arch(arch=("CRIS",))
    @require_arch_set
    def do_invoke(self, args):
        if runtime.current_arch is None:
            err("current_arch is not set")
            return

        syscall_table = Syscall.get_syscall_table()
        if syscall_table is None:
            err("The syscall table does not exist")
            return

        # get syscall entry
        for nr, entry in syscall_table.nr_table.items():
            if is_x86_64() and nr >= 0x4000_0000:
                continue
            if args.syscall_name == entry.name:
                break
        else:
            err("Could not find the system call `{:s}`".format(args.syscall_name))
            return

        # length check
        if len(args.syscall_args) != len(entry.args_full):
            err("Argument count mismatch")
            params = "(" + ", ".join(entry.args_full) + ");"
            gef_print("Prototype: {:s}{:s}".format(Color.boldify(args.syscall_name), params))
            return

        # title
        title = "{:s}({:s})".format(args.syscall_name, ", ".join(["{:#x}".format(x) for x in args.syscall_args]))
        gef_print(titlify(title))

        ret = ExecSyscall(nr, args.syscall_args).exec_code()

        if isinstance(runtime.current_arch.return_register, list):
            for ret_regs in runtime.current_arch.return_register:
                gef_print("{:s} = {:#x}".format(ret_regs, ret["reg"][ret_regs]))
        else:
            gef_print("{:s} = {:#x}".format(runtime.current_arch.return_register, ret["reg"][runtime.current_arch.return_register]))
        return


@register_command
class MmapMemoryCommand(GenericCommand):
    """Allocate a new memory."""

    _cmdline_ = "mmap"
    _category_ = "01-g. Debugging Support - Syscall"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address, default=None,
                        help="the address to allocate. (default: %(default)s)")
    parser.add_argument("size", metavar="SIZE", nargs="?", type=AddressUtil.parse_address, default=get_pagesize(),
                        help="the size to allocate. (default: %(default)s)")
    parser.add_argument("permission", metavar="PERMISSION", nargs="?", default="rwx",
                        help="the permission to allocate. `_` is interpreted as `-`. (default: %(default)s)")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0x10000 0x1000 r-x",
        "{0:s} 0 0x1000 _wx        # '_' means '-'",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    # On the CRIS architecture, setting a value to a register using the gdb `set` command will cause strange behavior.
    # So even if the assembly code is correct, it should not use this command.

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "rr", "wine"))
    @exclude_specific_arch(arch=("CRIS",))
    @require_arch_set
    def do_invoke(self, args):
        # syscall name (mmap or mmap2 or arch-specific)
        syscall_table = Syscall.get_syscall_table()
        if syscall_table is None:
            err("The syscall table does not exist")
            return

        mmap_syscall_name = None
        for entry in syscall_table.nr_table.values():
            if "mmap" not in entry.name:
                continue
            if len(entry.arg_regs) != 6:
                continue
            mmap_syscall_name = entry.name
            break
        if mmap_syscall_name is None:
            err("Could not find the mmap syscall")
            return

        # location
        if args.location and args.location % get_pagesize():
            err("Address is not a multiple of {:#x}".format(get_pagesize()))
            return

        # size
        if args.size < 0 or AddressUtil.get_vmem_end() <= args.size:
            err("Invalid size")
            return
        if args.size % get_pagesize():
            err("Size is not a multiple of {:#x}".format(get_pagesize()))
            return

        # permission
        if len(args.permission) != 3:
            err("Invalid permission")
            return
        if re.match(r"[-_r][-_w][-_x]", args.permission):
            perm = Permission.NONE
            if args.permission[0] == "r":
                perm |= Permission.READ
            if args.permission[1] == "w":
                perm |= Permission.WRITE
            if args.permission[2] == "x":
                perm |= Permission.EXECUTE
        else:
            err("Invalid permission")
            return

        # flags
        flags = 0x22 # MAP_ANONYMOUS | MAP_PRIVATE
        if args.location is not None:
            flags |= 0x10 # MAP_FIXED
        if is_mips32() or is_mips64() or is_mipsn32():
            flags |= 0x800 # MAP_DENYWRITE (why?)

        # doit
        cmd = "call-syscall {:s} {:#x} {:#x} {:#x} {:#x} -1 0".format(
            mmap_syscall_name, args.location or 0, args.size, perm, flags,
        )
        gdb.execute(cmd)
        Cache.reset_gef_caches()
        return


@register_command
class MunmapMemoryCommand(GenericCommand):
    """Unmap a mapped memory."""

    _cmdline_ = "munmap"
    _category_ = "01-g. Debugging Support - Syscall"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address to unmap.")
    parser.add_argument("size", metavar="SIZE", nargs="?", type=AddressUtil.parse_address,
                        help="the size to unmap.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $sp                    # unmap whole stack area",
        "{0:s} 0x7ffffffde000 0x1000  # unmap specified area",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "By default, the entire map containing the specified address is freed.",
        "If a size is specified, the area from the specified address to that size will be unmapped.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    # On the CRIS architecture, setting a value to a register using the gdb `set` command will cause strange behavior.
    # So even if the assembly code is correct, it should not use this command.

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "rr", "wine"))
    @exclude_specific_arch(arch=("CRIS",))
    @require_arch_set
    def do_invoke(self, args):
        # location
        sect = ProcessMap.process_lookup_address(args.location)
        if sect is None:
            err("Unmapped address")
            return

        # size
        if args.size is not None:
            if args.location % get_pagesize():
                err("Address is not a multiple of {:#x}".format(get_pagesize()))
                return
            if args.location < 0:
                err("Invalid address")
                return
            if args.size % get_pagesize():
                err("Size is not a multiple of {:#x}".format(get_pagesize()))
                return
            if args.size < 0 or AddressUtil.get_vmem_end() <= args.size:
                err("Invalid size")
                return
            # not estimation
            location = args.location
            size = args.size
        else:
            # use estimation
            location = sect.page_start
            size = sect.page_end - sect.page_start

        # doit
        cmd = "call-syscall munmap {:#x} {:#x}".format(location, size)
        gdb.execute(cmd)
        Cache.reset_gef_caches()
        return


@register_command
class MprotectCommand(GenericCommand):
    """Change a page permission (default: RWX)."""

    _cmdline_ = "mprotect"
    _category_ = "01-g. Debugging Support - Syscall"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the address to change the permission.")
    parser.add_argument("permission", metavar="PERMISSION", nargs="?", default="rwx",
                        help="the permission you set to the LOCATION. (default: %(default)s)")
    parser.add_argument("-s", "--size", type=AddressUtil.parse_address,
                        help="the size to change the permission (0x1000 align).")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} $sp rwx",
        "{0:s} 0x7ffff7e1b000 ___           # '_' means '-'",
        "{0:s} 0x7ffff7e1b000 ___ -s 0x1000 # change only first 0x1000 bytes",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "By default, the permissions will be changed for the entire map including the specified address.",
        "If a size is specified, the permissions will only be changed for the range of the specified address up to the size.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    # On the CRIS architecture, setting a value to a register using the gdb `set` command will cause strange behavior.
    # So even if the assembly code is correct, it should not use this command.

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "rr", "wine"))
    @exclude_specific_arch(arch=("CRIS",))
    @require_arch_set
    def do_invoke(self, args):
        # location
        sect = ProcessMap.process_lookup_address(args.location)
        if sect is None:
            err("Unmapped address")
            return

        # size
        if args.size is not None:
            if args.location % get_pagesize():
                err("Address is not a multiple of {:#x}".format(get_pagesize()))
                return
            if args.location < 0:
                err("Invalid address")
                return
            if args.size % get_pagesize():
                err("Size is not a multiple of {:#x}".format(get_pagesize()))
                return
            if args.size < 0 or AddressUtil.get_vmem_end() <= args.size:
                err("Invalid size")
                return
            # not estimation
            location = args.location
            size = args.size
        else:
            # use estimation
            location = sect.page_start
            size = sect.page_end - sect.page_start

        # permission
        if re.match(r"[-_r][-_w][-_x]", args.permission):
            perm = Permission.NONE
            if args.permission[0] == "r":
                perm |= Permission.READ
            if args.permission[1] == "w":
                perm |= Permission.WRITE
            if args.permission[2] == "x":
                perm |= Permission.EXECUTE
        else:
            err("Invalid permission")
            return

        # doit
        cmd = "call-syscall mprotect {:#x} {:#x} {:#x}".format(location, size, perm)
        gdb.execute(cmd)
        Cache.reset_gef_caches()
        return


@register_command
class SyscallSearchCommand(GenericCommand, BufferingOutput):
    """Search for the syscall number for a specified architecture."""

    _cmdline_ = "syscall-search"
    _category_ = "01-g. Debugging Support - Syscall"
    _aliases_ = ["ss"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", dest="arch", help="specify the architecture. (default: current_arch.arch)")
    parser.add_argument("-m", dest="mode", help="specify the mode. (default: current_arch.mode)")
    parser.add_argument("search_pattern", metavar="SYSCALL_NAME|SYSCALL_NUM", nargs="?", default=".",
                        help="syscall name or number to search. Regex is available.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display prototype of syscall.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} -a X86 -m 64       "^writev?"  # amd64',
        '{0:s} -a X86 -m 32       "^writev?"  # i386 on amd64',
        '{0:s} -a X86 -m N32      "^writev?"  # i386 native',
        '{0:s} -a X86 -m x32      "^writev?"  # x32 mode',
        '{0:s} -a ARM64 -m ARM    "^writev?"  # arm64',
        '{0:s} -a ARM -m 32       "^writev?"  # arm32 on arm64',
        '{0:s} -a ARM -m N32      "^writev?"  # arm32 native',
        '{0:s} -a MIPS -m 32      "^writev?"  # mips32',
        '{0:s} -a MIPS -m n32     "^writev?"  # mipsn32',
        '{0:s} -a MIPS -m 64      "^writev?"  # mips64',
        '{0:s} -a PPC -m 32       "^writev?"  # ppc32',
        '{0:s} -a PPC -m 64       "^writev?"  # ppc64',
        '{0:s} -a SPARC -m 32     "^writev?"  # sparc32',
        '{0:s} -a SPARC -m 32PLUS "^writev?"  # sparc32plus',
        '{0:s} -a SPARC -m 64     "^writev?"  # sparc64',
        '{0:s} -a RISCV -m 32     "^writev?"  # riscv32',
        '{0:s} -a RISCV -m 64     "^writev?"  # riscv64',
        '{0:s} -a S390X           "^writev?"  # s390x',
        '{0:s} -a SH4             "^writev?"  # sh4',
        '{0:s} -a M68K -m 32      "^writev?"  # m68k',
        '{0:s} -a ALPHA           "^writev?"  # alpha',
        '{0:s} -a HPPA -m 32      "^writev?"  # hppa32',
        '{0:s} -a HPPA -m 64      "^writev?"  # hppa64',
        '{0:s} -a OR1K            "^writev?"  # or1k',
        '{0:s} -a NIOS2           "^writev?"  # nios2',
        '{0:s} -a MICROBLAZE      "^writev?"  # microblaze',
        '{0:s} -a XTENSA          "^writev?"  # xtensa',
        '{0:s} -a CRIS            "^writev?"  # cris',
        '{0:s} -a LOONGARCH -m 64 "^writev?"  # loongarch64',
        '{0:s} -a ARC -m 32       "^writev?"  # arc32',
        '{0:s} -a ARC -m 64       "^writev?"  # arc64',
        '{0:s} -a CSKY            "^writev?"  # csky',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def make_output(self, syscall_table, syscall_num, syscall_name_pattern, skip_x32):
        self.out.append(titlify("arch={:s}, mode={:s}".format(syscall_table.arch, syscall_table.mode)))

        fmt = "{:<17}{:s}"
        legend = ["Syscall Num", "Syscall Name"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for entry in syscall_table.nr_table.values():
            if not re.search(syscall_name_pattern, entry.name):
                continue
            if syscall_num is not None and entry.nr != syscall_num:
                continue
            if syscall_table.arch == "X86" and syscall_table.mode == "64":
                if skip_x32:
                    if entry.nr >= 0x4000_0000:
                        continue
                else:
                    if entry.nr < 0x4000_0000:
                        continue
            params = ""
            if self.args.verbose:
                params = "(" + ", ".join(entry.args_full) + ");"
            self.out.append("NR={:<#14x}{:s}{:s}".format(entry.nr, Color.boldify(entry.name), params))
        return

    @parse_args
    def do_invoke(self, args):
        syscall_num = None
        syscall_name_pattern = ".*"
        skip_x32 = True

        target_arch = args.arch
        target_mode = args.mode
        # force fixing
        if target_arch and target_mode is None:
            arch_need_not_mode = ["SH4", "ALPHA", "OR1K", "NIOS2", "MICROBLAZE", "XTENSA", "CRIS", "CSKY"]
            if target_arch.upper() in arch_need_not_mode:
                target_arch = target_arch.upper()
                target_mode = target_arch.upper()
            if target_arch.upper() in ["S390X"]:
                target_arch = "S390X"
                target_mode = "64"
            if target_arch.upper() in ["ARM64", "AARCH64"]:
                target_arch = "ARM64"
                target_mode = "ARM"
            if target_arch.upper() in ["ARM", "ARM32"]:
                target_arch = "ARM"
                target_mode = "32"
            if target_arch.upper() in ["X86_64", "X86-64", "X64"]:
                target_arch = "X86"
                target_mode = "64"
            if target_arch.upper() in ["X86_32", "X86-32", "X86"]:
                target_arch = "X86"
                target_mode = "32"
            if target_arch.upper() in ["MIPS32"]:
                target_arch = "MIPS"
                target_mode = "32"
            if target_arch.upper() in ["MIPS64"]:
                target_arch = "MIPS"
                target_mode = "64"
            if target_arch.upper() in ["PPC32"]:
                target_arch = "PPC"
                target_mode = "32"
            if target_arch.upper() in ["PPC64"]:
                target_arch = "PPC"
                target_mode = "64"
            if target_arch.upper() in ["SPARC32"]:
                target_arch = "SPARC"
                target_mode = "32"
            if target_arch.upper() in ["SPARC64"]:
                target_arch = "SPARC"
                target_mode = "64"
            if target_arch.upper() in ["RISCV32"]:
                target_arch = "RISCV"
                target_mode = "32"
            if target_arch.upper() in ["RISCV64"]:
                target_arch = "RISCV"
                target_mode = "64"
            if target_arch.upper() in ["ARC32"]:
                target_arch = "ARC"
                target_mode = "32"
            if target_arch.upper() in ["ARC64"]:
                target_arch = "ARC"
                target_mode = "64"
            if target_arch.upper() in ["LOONGARCH"]:
                target_arch = "LOONGARCH"
                target_mode = "64"
            if target_arch.upper() in ["M68K"]:
                target_arch = "M68K"
                target_mode = "32"

        if target_arch == "X86" and target_mode == "x32":
            target_mode = "64"
            skip_x32 = False

        try:
            syscall_num = int(args.search_pattern, 0)
        except ValueError:
            syscall_name_pattern = args.search_pattern

        syscall_table = Syscall.get_syscall_table(target_arch, target_mode)
        if syscall_table is None:
            err("Please specify the valid architecture.")
            self.usage()
            return

        self.out = []
        self.make_output(syscall_table, syscall_num, syscall_name_pattern, skip_x32)
        self.print_output(check_terminal_size=True)
        return

