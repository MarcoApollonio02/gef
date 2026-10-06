"""GEF process-info commands (category 02-a) extracted from the monolithic gef.py.

General process commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import hashlib
import os
import re
import struct
import subprocess

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_gdb_target_local,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.color import Color, err, gef_print, ok, titlify
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.memory import hexdump, p32
from gef.core.process import Path, Pid, ProcessMap, is_qemu_system, is_remote_debug
from gef.core.strings import String
from gef.core.symbols import Symbol
from gef.core.syscall import Syscall
from gef.core.utils import GefUtil, slice_unpack, slicer

@register_command
class ProcInfoCommand(GenericCommand):
    """Extend the info given by GDB `info proc`."""

    _cmdline_ = "proc-info"
    _category_ = "02-a. Process Information - General"
    _aliases_ = ["pr"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def get_state_of(self, pid):
        try:
            status = open("/proc/{:d}/status".format(pid), "r").read()
        except (FileNotFoundError, OSError):
            return {}
        res = {}
        for line in status.splitlines():
            key, value = line.split(":", 1)
            res[key.strip()] = value.strip()
        return res

    def get_stat_of(self, pid):
        try:
            stat = open("/proc/{:d}/stat".format(pid), "r").read()
        except (FileNotFoundError, OSError):
            return []
        try:
            name = re.search(r"\((.+)\)", stat).group(1)
        except IndexError:
            name = "???"
        other = re.sub(r"\(.+\) ", "", stat).split()
        res = [int(other[0]), name, other[1]] + [int(x) for x in other[2:]]
        return res

    def get_cmdline_of(self, pid):
        try:
            cmdline = open("/proc/{:d}/cmdline".format(pid), "r").read()
        except (FileNotFoundError, OSError):
            return ""
        return cmdline.replace("\0", " ").strip()

    def get_process_path_of(self, pid):
        try:
            return os.readlink("/proc/{:d}/exe".format(pid))
        except (FileNotFoundError, OSError):
            return "Not found"

    def get_process_cwd(self, pid):
        try:
            return os.readlink("/proc/{:d}/cwd".format(pid))
        except (FileNotFoundError, OSError):
            return "Not found"

    def get_process_root(self, pid):
        try:
            return os.readlink("/proc/{:d}/root".format(pid))
        except (FileNotFoundError, OSError):
            return "Not found"

    def get_thread_ids(self, pid):
        try:
            tids = os.listdir("/proc/{:d}/task".format(pid))
            return [int(x) for x in tids]
        except (FileNotFoundError, OSError):
            return []

    def get_children_pids(self, pid):
        try:
            ps = GefUtil.which("ps")
        except FileNotFoundError as e:
            err("{}".format(e))
            return []

        # Trick: If there are no child processes, `ps` exit code will be non-zero,
        # causing a subprocess.CalledProcessError exception to be raised.
        cmd = [ps, "-o", "pid", "--ppid", str(pid), "--noheaders"]
        try:
            return [int(x) for x in GefUtil.gef_execute_external(cmd, as_list=True)]
        except (subprocess.CalledProcessError, ValueError):
            return []

    def get_uid_map(self, pid):
        try:
            uid_map = open("/proc/{:d}/uid_map".format(pid), "r").read().strip()
        except (FileNotFoundError, OSError):
            return []
        return slicer([int(x) for x in uid_map.split()], 3)

    def get_gid_map(self, pid):
        try:
            gid_map = open("/proc/{:d}/gid_map".format(pid), "r").read().strip()
        except (FileNotFoundError, OSError):
            return []
        return slicer([int(x) for x in gid_map.split()], 3)

    def get_tty_str(self, major, minor):
        try:
            devices = open("/proc/devices", "r").read()
        except (FileNotFoundError, OSError):
            return "Not found"
        for line in devices.splitlines():
            if not line or line.endswith(":"):
                continue
            n, name = line.strip().split()
            if major == int(n):
                if not name.startswith("/dev"):
                    name = os.path.join("/dev", name)
                break
        else:
            return "Not found"

        def get_major_minor(name):
            devnum = os.stat(name).st_rdev
            major = (devnum >> 8) & 0xff
            minor = devnum & 0xff
            return major, minor

        if not os.path.exists(name):
            return "Not found"

        if os.path.islink(name):
            return "Not found"

        if os.path.isfile(name):
            if get_major_minor(name) == (major, minor):
                return name

        if os.path.isdir(name):
            for path in GefUtil.walk(name):
                if get_major_minor(path) == (major, minor):
                    return path
        return "Not found"

    def show_info_proc(self):
        gef_print(titlify("Process Information"))

        pid = Pid.get_pid()
        executable = self.get_process_path_of(pid)
        cmdline = self.get_cmdline_of(pid)
        cwd = self.get_process_cwd(pid)
        root = self.get_process_root(pid)
        gef_print("{:30s}  ->  {:d}".format("PID", pid))
        gef_print("{:30s}  ->  {!r}".format("  Executable", executable))
        gef_print("{:30s}  ->  {!r}".format("  Command Line", cmdline))
        gef_print("{:30s}  ->  {!r}".format("  Current Working Directory", cwd))
        gef_print("{:30s}  ->  {!r}".format("  Root Directory", root))
        uids = re.sub(r"\s+", " : ", self.get_state_of(pid)["Uid"])
        gids = re.sub(r"\s+", " : ", self.get_state_of(pid)["Gid"])
        gef_print("{:30s}  ->  {:s}".format("  RUID:EUID:SavedUID:FSUID", uids))
        gef_print("{:30s}  ->  {:s}".format("  RGID:EGID:SavedGID:FSGID", gids))
        seccomp_n = self.get_state_of(pid)["Seccomp"]
        seccomp_s = {"0": "Disabled", "1": "Strict", "2": "CustomFilter"}[seccomp_n]
        gef_print("{:30s}  ->  {:s} ({:s})".format("  Seccomp Mode", seccomp_n, seccomp_s))
        return

    def show_info_proc_extra(self):
        gef_print(titlify("Process Information Additional"))

        pid = Pid.get_pid()
        stat = self.get_stat_of(pid)
        pgid = stat[4]
        pgid_exec = self.get_process_path_of(pgid)
        pgid_cmdline = self.get_cmdline_of(pgid)
        gef_print("{:30s}  ->  {:d}".format("Process Group ID", pgid))
        gef_print("{:30s}  ->  {!r}".format("  Executable", pgid_exec))
        gef_print("{:30s}  ->  {!r}".format("  Command Line", pgid_cmdline))
        sid = stat[5]
        sid_exec = self.get_process_path_of(sid)
        sid_cmdline = self.get_cmdline_of(sid)
        gef_print("{:30s}  ->  {:d}".format("Session ID", sid))
        gef_print("{:30s}  ->  {!r}".format("  Executable", sid_exec))
        gef_print("{:30s}  ->  {!r}".format("  Command Line", sid_cmdline))
        tpgid = stat[7]
        tpgid_exec = self.get_process_path_of(tpgid)
        tpgid_cmdline = self.get_cmdline_of(tpgid)
        gef_print("{:30s}  ->  {:d}".format("TTY Process Group ID", tpgid))
        gef_print("{:30s}  ->  {!r}".format("  Executable", tpgid_exec))
        gef_print("{:30s}  ->  {!r}".format("  Command Line", tpgid_cmdline))
        ttynr = stat[6]
        major, minor = (ttynr >> 8) & 0xff, ((ttynr >> 20) << 8) | (ttynr & 0xff)
        ttystr = self.get_tty_str(major, minor)
        gef_print("{:30s}  ->  {:d} ({!r})".format("  TTY Device Number", ttynr, ttystr))
        return

    def show_parent(self):
        gef_print(titlify("Parent Process Information"))
        ppid = int(self.get_state_of(Pid.get_pid())["PPid"])
        ppid_exec = self.get_process_path_of(ppid)
        ppid_cmdline = self.get_cmdline_of(ppid)
        gef_print("{:30s}  ->  {:d}".format("Parent PID", ppid))
        gef_print("{:30s}  ->  {!r}".format("  Executable", ppid_exec))
        gef_print("{:30s}  ->  {!r}".format("  Command Line", ppid_cmdline))
        return

    def show_childs(self):
        gef_print(titlify("Child Process Information"))

        children = self.get_children_pids(Pid.get_pid())
        if not children:
            gef_print("No child process")
            return

        for i, cpid in enumerate(children, start=1):
            cpid_exec = self.get_process_path_of(cpid)
            cpid_cmdline = self.get_cmdline_of(cpid)
            gef_print("{:30s}  ->  {:d}".format("Child {:d} PID".format(i), cpid))
            gef_print("{:30s}  ->  {!r}".format("  Executable", cpid_exec))
            gef_print("{:30s}  ->  {!r}".format("  Command Line", cpid_cmdline))
        return

    def show_info_thread(self):
        gef_print(titlify("Thread Information"))

        pid = Pid.get_pid()
        nthreads = self.get_state_of(pid)["Threads"]
        tgid = self.get_state_of(pid)["Tgid"]
        gef_print("{:30s}  ->  {:s}".format("Num of Threads", nthreads))
        gef_print("{:30s}  ->  {:s}".format("Thread Group ID", tgid))
        tids = self.get_thread_ids(pid)
        gef_print("{:30s}  ->  {!r}".format("Thread ID List", tids))
        return

    def show_info_proc_ns(self):
        gef_print(titlify("Namespace Information"))

        pid = Pid.get_pid()
        gdb_pid = os.getpid()
        ns_symbols = ["cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"]
        for ns in ns_symbols:
            if not os.path.exists("/proc/{:d}/ns/{:s}".format(pid, ns)):
                continue
            if not os.path.exists("/proc/{:d}/ns/{:s}".format(gdb_pid, ns)):
                continue
            sym1 = os.readlink("/proc/{:d}/ns/{:s}".format(pid, ns))
            sym2 = os.readlink("/proc/{:d}/ns/{:s}".format(gdb_pid, ns))
            m = "{:s} namespace separation".format(ns.upper())
            gef_print("{:30s}  ->  {!s}".format(m, sym1 != sym2))

        gef_print(titlify("Pid Namespace Information"))
        state = self.get_state_of(pid)
        if len(state["NSpid"].split()) > 1:
            gef_print("{:30s}  ->  {:s}".format(
                "Host PID  : Namespace PID", re.sub(r"\s+", " : ", state["NSpid"]),
            ))
            gef_print("{:30s}  ->  {:s}".format(
                "Host PGID : Namespace PGID", re.sub(r"\s+", " : ", state["NSpgid"]),
            ))
            gef_print("{:30s}  ->  {:s}".format(
                "Host SID  : Namespace SID", re.sub(r"\s+", " : ", state["NSsid"]),
            ))
            gef_print("{:30s}  ->  {:s}".format(
                "Host TGID : Namespace TGID", re.sub(r"\s+", " : ", state["NStgid"]),
            ))
        else:
            gef_print("{:30s}".format("No pid namespace"))

        gef_print(titlify("User Namespace Information"))
        for u in self.get_uid_map(pid):
            gef_print("{:30s}  ->  [{:#x} : {:#x} : {:#x}]".format(
                "UID_MAP [NameSpace:Host:Range]", u[0], u[1], u[2],
            ))
        for g in self.get_gid_map(pid):
            gef_print("{:30s}  ->  [{:#x} : {:#x} : {:#x}]".format(
                "GID_MAP [NameSpace:Host:Range]", g[0], g[1], g[2],
            ))
        return

    def get_state_string(self, proto, state):
        if proto in ["tcp", "tcp6"]:
            dic = {
                0x01: "ESTABLISHED",
                0x02: "SYN_SENT",
                0x03: "SYN_RECV",
                0x04: "FIN_WAIT1",
                0x05: "FIN_WAIT2",
                0x06: "TIME_WAIT",
                0x07: "CLOSE",
                0x08: "CLOSE_WAIT",
                0x09: "LAST_ACK",
                0x0a: "LISTEN",
                0x0b: "CLOSING",
                0x0c: "NEW_SYN_RECV",
                0x0d: "BOUND_INACTIVE",
            }
        elif proto in ["udp", "udp6"]:
            dic = {
                0x07: "LISTEN",
            }
        elif proto in ["unix"]:
            dic = {
                0x00: "FREE",
                0x01: "LISTEN", # "UNCONNECTED"
                0x02: "CONNECTING",
                0x03: "CONNECTED",
                0x04: "DISCONNECTING",
            }
        else:
            return str(int(state, 16))
        return dic.get(int(state, 16), "???")

    def get_proto_string(self, proto):
        # proto string (for raw/raw6)
        dic = {
            0x00: "IP",
            0x01: "ICMP",
            0x02: "IGMP",
            0x04: "IPIP",
            0x06: "TCP",
            0x08: "EGP",
            0x0c: "PUP",
            0x11: "UDP",
            0x16: "IDP",
            0x1d: "TP",
            0x21: "DCCP",
            0x29: "IPV6",
            0x2b: "ROUTING",
            0x2c: "FRAGMENT",
            0x2e: "RSVP",
            0x2f: "GRE",
            0x32: "ESP",
            0x33: "AH",
            0x3a: "ICMPV6",
            0x3b: "NONE",
            0x3c: "DSTOPTS",
            0x5c: "MTP",
            0x5e: "BEETPH",
            0x62: "ENCAP",
            0x67: "PIM",
            0x6c: "COMP",
            0x73: "L2TP",
            0x84: "SCTP",
            0x87: "MH",
            0x88: "UDPLITE",
            0x89: "MPLS",
            0x8f: "ETHERNET",
            0x90: "AGGFRAG",
            0xff: "RAW",
            0x100: "SMC",
            0x106: "MPTCP",
        }
        return dic.get(proto, str(proto))

    def parse_ip_port(self, addr, proto):
        # tcp/udp: return (ip, port)
        # other: return (ip, proto)

        ip, port = addr.split(":")

        import socket
        if len(ip) == 8: # ipv4
            # 0100007F -> 127.0.0.1
            ip = bytes.fromhex(ip)[::-1]
            ip = socket.inet_ntop(socket.AF_INET, ip)
        else: # ipv6
            # 00000000000000000000000001000000 -> ::1
            ip = bytes.fromhex(ip)
            ip = b"".join([x[::-1] for x in slicer(ip, 4)])
            ip = socket.inet_ntop(socket.AF_INET6, ip)
            ip = "[{:s}]".format(ip)

        if proto in ["tcp", "tcp6", "udp", "udp6"]:
            port = int(port, 16)
            return ip, port # str, int

        # other protocol
        real_proto = self.get_proto_string(int(port, 16))
        return ip, real_proto # str, str

    def get_extra_info(self):
        # e.g., inode -> "[tcp]           127.0.0.1:34588 -> 127.0.0.1:5001 (ESTABLISHED)"

        # get all sockets
        pid = Pid.get_pid()
        sockets = {}
        path = "/proc/{:d}/fd".format(pid)
        for fname in os.listdir(path):
            fullpath = os.path.join(path, fname)
            if os.path.islink(fullpath) and os.readlink(fullpath).startswith("socket:"):
                inode = os.readlink(fullpath).replace("socket:", "")[1:-1]
                sockets[int(inode)] = fname
        if not sockets:
            return sockets

        # get entries
        protocols = ["tcp", "udp", "tcp6", "udp6", "unix", "raw", "raw6"]
        entries = {}
        for prot in protocols:
            lines = open(f"/proc/{pid}/net/{prot}", "r").readlines()
            entries[prot] = [x.split() for x in lines[1:]]

        extra_info = {}
        for proto, proto_entries in entries.items():
            for proto_entry in proto_entries:
                # parse
                if proto in ["tcp", "tcp6", "udp", "udp6", "raw", "raw6"]:
                    _, local, remote, state, _, _, _, _, _, inode, *_ = proto_entry
                elif proto == "unix":
                    _, _, _, _, _, state, inode, *path = proto_entry
                    path = path[0] if path else ""

                # check if socket
                inode = int(inode)
                if inode not in sockets:
                    continue

                # get state
                state = self.get_state_string(proto, state)

                # make extra info
                if proto in ["tcp", "tcp6", "udp", "udp6"]:
                    local = self.parse_ip_port(local, proto)
                    if state == "LISTEN":
                        extra_info[inode] = "{:14s}  {:s}:{:d} ({:s})".format(
                            "[{:s}]".format(proto),
                            *local, state,
                        )
                    else:
                        remote = self.parse_ip_port(remote, proto)
                        extra_info[inode] = "{:14s}  {:s}:{:d} -> {:s}:{:d} ({:s})".format(
                            "[{:s}]".format(proto),
                            *local, *remote, state,
                        )
                elif proto in ["raw", "raw6"]:
                    local = self.parse_ip_port(local, proto)
                    remote = self.parse_ip_port(remote, proto)
                    extra_info[inode] = "{:14s}  {:s} -> {:s} (st={:s})".format(
                        "[{:s}/{:s}]".format(proto, local[1]),
                        local[0], remote[0], state,
                    )
                elif proto == "unix":
                    extra_info[inode] = "{:14s}  {!r} ({:s})".format(
                        "[{:s}]".format(proto),
                        path, state,
                    )
        return extra_info

    def show_fds(self):
        gef_print(titlify("File Descriptors"))

        pid = Pid.get_pid()
        path = "/proc/{:d}/fd".format(pid)

        gef_print("{:30s}  ->  {:s}".format("Num of FD slots", self.get_state_of(pid)["FDSize"]))
        items = os.listdir(path)
        if not items:
            gef_print("No FD opened")
            return

        extra_info = self.get_extra_info()

        for fname in items:
            fullpath = os.path.join(path, fname)
            if os.path.islink(fullpath):
                content = os.readlink(fullpath)
                if content.startswith("socket:["):
                    inode = int(content.replace("socket:", "")[1:-1])
                    extra = extra_info.get(inode, "")
                    gef_print("{:30s}  ->  {:s}  {:s}".format(fullpath, content, extra))
                else:
                    gef_print("{:30s}  ->  {:s}".format(fullpath, content))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_gdb_target_local
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "rr"))
    def do_invoke(self, args):
        self.show_info_proc()
        self.show_info_proc_extra()
        self.show_parent()
        self.show_childs()
        self.show_info_thread()
        self.show_info_proc_ns()
        self.show_fds()
        return


@register_command
class FileDescriptorsCommand(GenericCommand):
    """Display opened file descriptors."""

    _cmdline_ = "fds"
    _category_ = "02-a. Process Information - General"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def fd_dump(self):
        pid = Pid.get_pid()
        if not pid:
            err("Could not find the local pid")
            return
        path = "/proc/{:d}/fd".format(pid)

        items = os.listdir(path)
        if not items:
            err("No FD opened")
            return

        for fname in items:
            fullpath = os.path.join(path, fname)
            if os.path.islink(fullpath):
                gef_print("{:32s}  ->  {:s}".format(fullpath, os.readlink(fullpath)))
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @require_arch_set
    def do_invoke(self, args):
        self.fd_dump()
        return


@register_command
class ProcDumpCommand(GenericCommand, BufferingOutput):
    """Dump each file under `/proc/PID`."""

    _cmdline_ = "proc-dump"
    _category_ = "02-a. Process Information - General"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def dump_environ(self, path):
        data = open(path, "rb").read()
        for line in sorted(data.split(b"\0")):
            if line:
                line = String.bytes2str(line)
                key, val = line.split("=", 1)
                self.out.append("{:s}={:s}".format(Color.boldify(key), val))
        return

    def dump_cmdline(self, path):
        data = open(path, "rb").read()
        for line in data.split(b"\0"):
            if line:
                self.out.append(String.bytes2str(line))
        return

    def dump_auxv(self, path):
        data = open(path, "rb").read()
        data = slice_unpack(data, runtime.current_arch.ptrsize)
        for i in range(0, len(data), 2):
            typ = data[i]
            val = data[i + 1]
            self.out.append("{:#8x}: {:#x}".format(typ, val))
        return

    def dump_syscall(self, path):
        data = String.bytes2str(open(path, "rb").read())
        self.out.append(data.strip())

        self.out.append("----- parsed -----")

        if int(data.split()[0]) < 0:
            tag = ["NR", "sp", "pc"]
        else:
            tag = ["NR", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "sp", "pc"]

        for i, elem in enumerate(data.split()):
            if i < len(tag):
                elem_name = tag[i]
            else:
                elem_name = "???"
            elem_name = Color.boldify("{:4s}".format(elem_name))

            if i == 0: # NR
                nr = int(elem)
                syscall_table = Syscall.get_syscall_table()
                if syscall_table is None:
                    self.out.append("Could not find the syscall table")
                    return
                if nr >= 0 and syscall_table and nr in syscall_table.nr_table:
                    syscall_name = syscall_table.nr_table[nr].name
                    self.out.append("{:2d} {:s}: {:s} ({:s})".format(i + 1, elem_name, elem, syscall_name))
                else:
                    self.out.append("{:2d} {:s}: {:s}".format(i + 1, elem_name, elem))
            else: # argN, sp, pc
                address = int(elem, 0)
                sym = Symbol.get_symbol_string(address)
                elem = "{!s}{:s}".format(ProcessMap.lookup_address(address), sym)
                self.out.append("{:2d} {:s}: {:s}".format(i + 1, elem_name, elem))
        return

    def dump_stat(self, path):
        data = String.bytes2str(open(path, "rb").read())
        self.out.append(data.strip())

        self.out.append("----- parsed -----")

        tag = [
            "pid", "comm", "state", "ppid", "pgrp", "session", "tty_nr", "tpgid", "flags",
            "minflt", "cminflt", "majflt", "cmajflt", "utime", "stime", "cutime", "cstime",
            "priority", "nice", "num_threads", "itrealvalue", "starttime", "vsize",
            "rss", "rsslim", "startcode", "endcode", "startstack", "kstkesp", "kstkeip",
            "signal", "blocked", "sigignore", "sigcatch", "wchan", "nswap", "cnswap",
            "exit_signal", "processor", "rt_priority", "policy", "delayacct_blkio_ticks",
            "guest_time", "cguest_time", "start_data", "end_data", "start_brk",
            "arg_start", "arg_end", "env_startr", "env_end", "exit_code",
        ]

        max_width = max(len(x) for x in tag)
        lpos = data.find("(")
        rpos = data.rfind(")") + 1
        data = [data[:lpos].strip(), data[lpos:rpos]] + data[rpos:].split()

        for i, elem in enumerate(data):
            if i < len(tag):
                elem_name = tag[i]
            else:
                elem_name = "???"
            elem_name = Color.boldify("{:{:d}s}".format(elem_name, max_width))

            if i + 1 in [25, 26, 27, 28, 29, 30, 45, 46, 47, 48, 49, 50, 51]:
                address = int(elem)
                sym = Symbol.get_symbol_string(address)
                elem = "{!s}{:s}".format(ProcessMap.lookup_address(address), sym)
            elif i + 1 in [23, 33, 34]:
                elem = hex(int(elem))
            self.out.append("{:2d} {:s}: {:s}".format(i + 1, elem_name, elem))
        return

    def dump_statm(self, path):
        data = String.bytes2str(open(path, "rb").read())
        self.out.append(data.strip())

        self.out.append("----- parsed -----")

        tag = ["size", "resident", "shared", "text", "lib", "data", "dt"]
        max_width = max(len(x) for x in tag)

        for i, elem in enumerate(data.split()):
            if i < len(tag):
                elem_name = tag[i]
            else:
                elem_name = "???"
            elem_name = Color.boldify("{:{:d}s}".format(elem_name, max_width))
            self.out.append("{:2d} {:s}: {:s}".format(i + 1, elem_name, elem))
        return

    def dump_status(self, path):
        try:
            column_command = GefUtil.which("column")
        except FileNotFoundError as e:
            self.out.append("{}".format(e))
            return

        ret = GefUtil.gef_execute_external([column_command, "-s:", "-t", path], as_list=True)
        for line in ret:
            r = line.split(maxsplit=1)
            if len(r) == 2:
                k, v = r[0], r[1]
            else:
                k, v = r[0], ""
            k = k.strip() + ":"
            v = v.replace("\t", "").strip()
            self.out.append("{:30s} {:s}".format(k, v))
        return

    def dump_rt_acct(self, path):
        try:
            hexdump_command = GefUtil.which("hexdump")
        except FileNotFoundError as e:
            self.out.append("{}".format(e))
            return

        ret = GefUtil.gef_execute_external([hexdump_command, "-C", path], as_list=True)
        self.out.extend(ret)
        return

    def dump_mounts(self, path):
        try:
            column_command = GefUtil.which("column")
        except FileNotFoundError as e:
            self.out.append("{}".format(e))
            return

        ret = GefUtil.gef_execute_external([column_command, "-t", path], as_list=True)
        self.out.extend(ret)
        return

    def dump_raw(self, path):
        try:
            column_command = GefUtil.which("column")
        except FileNotFoundError as e:
            self.out.append("{}".format(e))
            return

        data = open(path, "rb").read()
        data = data.replace(b"tx_queue ", b"tx_queue:")
        data = data.replace(b" tr ", b" tr:")
        tmp_fd, tmp_filename = GefUtil.mkstemp(prefix="proc-dump")
        os.fdopen(tmp_fd, "wb").write(data)
        ret = GefUtil.gef_execute_external([column_command, "-t", tmp_filename], as_list=True)
        os.unlink(tmp_filename)
        self.out.extend(ret)
        return

    def dump_dev(self, path):
        try:
            column_command = GefUtil.which("column")
        except FileNotFoundError as e:
            self.out.append("{}".format(e))
            return

        data = open(path, "rb").read()
        data = data.replace(b"|", b" |")
        data = re.sub(rb"\|\s*Receive", b"|Receive", data)
        data = re.sub(rb"\|\s*Transmit", b"|Transmit", data)

        tmp_fd, tmp_filename = GefUtil.mkstemp(prefix="proc-dump")
        os.fdopen(tmp_fd, "wb").write(data)
        ret = GefUtil.gef_execute_external([column_command, "-t", tmp_filename], as_list=True)
        os.unlink(tmp_filename)

        wrong = ret[0].rfind("|")
        rright = ret[1].rfind("|")
        lright = ret[1].find("|")
        ret[0] = (ret[0][:wrong] + " " * (rright - wrong) + ret[0][wrong:]).rstrip()

        ret[0] = re.sub(r"\|(\S+)", "| \\1 ", ret[0])
        ret[1] = re.sub(r"\|(\S+)", "| \\1 ", ret[1])
        for i in range(2, len(ret)):
            ret[i] = ret[i][:lright] + "  " + ret[i][lright:]
            ret[i] = ret[i][:rright] + "  " + ret[i][rright:]

        self.out.extend(ret)
        return

    def dump_igmp(self, path):
        fd = open(path, "rb")
        for line in fd.readlines():
            self.out.append(String.bytes2str(line.rstrip())) # no-lstrip
        return

    def dump_netstat(self, path):
        data = String.bytes2str(open(path, "rb").read())
        table = [line.split() for line in data.splitlines()]
        for idx in range(0, len(table), 2):
            for i, (k, v) in enumerate(zip(*table[idx:idx + 2])):
                if i == 0:
                    self.out.append("{:s}".format(k))
                else:
                    self.out.append("  {:30s} {:s}".format(k + ":", v))
        return

    def dump_default(self, path):
        if not os.access(path, os.R_OK):
            self.out.append("{:s} No permission to read".format(Color.colorify("[!]", "bold red")))
            return

        try:
            fd = open(path, "rb")
        except OSError:
            self.out.append("{:s} Failed to open".format(Color.colorify("[!]", "bold red")))
            return

        try:
            for line in fd.readlines():
                self.out.append(String.bytes2str(line).strip())
        except OSError:
            self.out.append("{:s} Parse failed".format(Color.colorify("[!]", "bold red")))
        return

    def proc_dump(self):
        pid = Pid.get_pid()
        for root, dirs, files in os.walk("/proc/{:d}/".format(pid)):
            files = sorted(files)

            if "task" in dirs:
                dirs.remove("task") # in-place change to skip /proc/<pid>/task/

            for f in files:
                path = os.path.join(root, f)
                self.out.append(titlify(path))

                if os.path.islink(path):
                    self.out.append(Color.colorify("{:s} -> {:s}".format(path, os.readlink(path)), "blue"))
                    continue

                if f in ["pagemap", "mem"]:
                    self.out.append("{:s} skipped".format(Color.colorify("[*]", "bold yellow"))) # too large
                    continue

                if f == "environ":
                    self.dump_environ(path)
                    continue

                if f in ["cmdline", "context"]:
                    self.dump_cmdline(path)
                    continue

                if f == "auxv":
                    self.dump_auxv(path)
                    continue

                if f == "syscall":
                    self.dump_syscall(path)
                    continue

                if f == "stat":
                    self.dump_stat(path)
                    continue

                if f == "statm":
                    self.dump_statm(path)
                    continue

                if f == "rt_acct":
                    self.dump_rt_acct(path)
                    continue

                if f == "status":
                    self.dump_status(path)
                    continue

                if f in ["mounts", "mountinfo", "mountstats", "unix", "protocols"]:
                    self.dump_mounts(path)
                    continue

                if f in ["raw", "tcp", "udp", "icmp", "raw6", "tcp6", "udp6", "icmp6", "udplite", "udplite6"]:
                    self.dump_raw(path)
                    continue

                if f == "dev":
                    self.dump_dev(path)
                    continue

                if f in ["igmp", "fib_trie", "wireless"]:
                    self.dump_igmp(path)
                    continue

                if f in ["netstat", "snmp"]:
                    self.dump_netstat(path)
                    continue

                self.dump_default(path)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_gdb_target_local
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @require_arch_set
    def do_invoke(self, args):
        self.out = []
        self.proc_dump()
        self.print_output(check_terminal_size=True)
        return


@register_command
class ProcessSearchCommand(GenericCommand, BufferingOutput):
    """Display a smart list of processes."""

    _cmdline_ = "ps"
    _category_ = "02-a. Process Information - General"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("pattern", metavar="REGEX_PATTERN", nargs="?", help="filter by regex.")
    parser.add_argument("-a", "--attach", type=int, help="attach it.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="include kernel thread, socat, grep, gdb, sshd, bash, systemd, etc.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}",
        "{0:s} ./a.out",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def get_processes(self):
        output = GefUtil.gef_execute_external([GefUtil.which("ps"), "auxww"], as_list=True)
        names = [x.lower().replace("%", "") for x in output[0].split()]

        for line in output[1:]:
            fields = line.split()
            t = {}

            for i, name in enumerate(names):
                if i == len(names) - 1:
                    t[name] = " ".join(fields[i:])
                else:
                    t[name] = fields[i]
            yield t
        return

    @parse_args
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @require_arch_set
    def do_invoke(self, args):
        if args.pattern:
            pattern = re.compile(args.pattern)
        else:
            pattern = re.compile("^.*$")

        self.out = []
        for process in self.get_processes():
            pid = int(process["pid"])
            command = process["command"]
            process["user"] = process["user"].ljust(8)

            if not re.search(pattern, command):
                continue

            if not args.verbose:
                if command.startswith("[") and command.endswith("]"): # kernel thread
                    continue

                skip_list = [
                    # common
                    "socat ",
                    "grep ",
                    "gdb ",
                    "gdb-multiarch",
                    "-bash",
                    "sshd:",
                    "ssh-agent ",
                    # VMware tools
                    "vmhgfs-fuse",
                    "vmware-vmblock-fuse",
                    "fusermount3",
                    # system service
                    "avahi-daemon:",
                    "@dbus-daemon",
                    "(sd-pam)",
                    "gjs ",
                    "gdm-session-worker",
                    "cupsd ",
                    "cups-browsed ",
                    # common path
                    ("/bin/", "/usr/bin/"),
                    ("/sbin/", "/usr/sbin/"),
                    ("/lib/", "/usr/lib/"),
                    "/usr/libexec/",
                    "/snap/",
                    "/var/lib/pcp/pmdas",
                ]
                if any(command.startswith(x) for x in skip_list):
                    continue

            if args.attach:
                if args.attach == pid:
                    ok("Attaching to process='{:s}' pid={:d}".format(process["command"], pid))
                    gdb.execute("attach {:d}".format(pid))
                    return

            line = [process[i] for i in ("pid", "user", "cpu", "mem", "tty", "command")]
            self.out.append("\t".join(line))

        self.print_output()
        return


@register_command
class ElfInfoCommand(GenericCommand):
    """Display a limited subset of ELF header information."""

    _cmdline_ = "elf-info"
    _category_ = "02-a. Process Information - General"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-e", "--use-readelf", action="store_true", help="use readelf.")
    parser.add_argument("-r", "--remote", action="store_true",
                        help="parse remote binary if download feature is available.")
    parser.add_argument("-f", "--file", help="the file path to parse.")
    parser.add_argument("-a", "--address", type=AddressUtil.parse_address,
                        help="the memory address to parse.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="dump the content of each section.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                    # parse binary itself",
        "{0:s} -f /bin/ls         # parse binary",
        "{0:s} -f /bin/ls -r      # parse remote binary",
        "{0:s} -a 0x555555554000  # parse memory",
        "{0:s} -e -f /bin/ls      # show `readelf -a FILE | less`",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self, *args, **kwargs):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    classes = {
        Elf.ELF_CLASS_NONE : "Unknown",
        Elf.ELF_32_BITS    : "32-bit",
        Elf.ELF_64_BITS    : "64-bit",
    }

    endianness = {
        Elf.ELF_DATA_NONE : "Unknown",
        Elf.LITTLE_ENDIAN : "Little-Endian",
        Elf.BIG_ENDIAN    : "Big-Endian",
    }

    osabis = {
        Elf.OSABI_SYSTEMV    : "UNIX System V ABI",
        Elf.OSABI_HPUX       : "Hewlett-Packard HP-UX",
        Elf.OSABI_NETBSD     : "NetBSD",
        Elf.OSABI_LINUX      : "GNU Linux",
        Elf.OSABI_HURD       : "GNU Hurd",
        Elf.OSABI_86OPEN     : "86Open Common IA32 ABI",
        Elf.OSABI_SOLARIS    : "Sun Solaris",
        Elf.OSABI_AIX        : "IBM AIX",
        Elf.OSABI_IRIX       : "SGI IRIX",
        Elf.OSABI_FREEBSD    : "FreeBSD",
        Elf.OSABI_TRU64      : "Compaq TRU64 UNIX",
        Elf.OSABI_MODESTO    : "Novell Modesto",
        Elf.OSABI_OPENBSD    : "OpenBSD",
        Elf.OSABI_OPENVMS    : "OpenVMS",
        Elf.OSABI_NSK        : "Hewlett-Packard Non-Stop Kernel",
        Elf.OSABI_AROS       : "Amiga Research OS",
        Elf.OSABI_FENIXOS    : "The FenixOS highly scalable multi-core OS",
        Elf.OSABI_CLOUDABI   : "Nuxi CloudABI",
        Elf.OSABI_OPENVOS    : "Stratus Technologies OpenVOS",
        Elf.OSABI_ARM_AEABI  : "ARM EABI",
        Elf.OSABI_ARM        : "ARM",
        Elf.OSABI_STANDALONE : "Standalone (embedded) application",
    }

    types = {
        Elf.ET_NONE : "No file type (ET_NONE)",
        Elf.ET_REL  : "Relocatable (ET_REL)",
        Elf.ET_EXEC : "Executable (ET_EXEC)",
        Elf.ET_DYN  : "Shared (ET_DYN)",
        Elf.ET_CORE : "Core (ET_CORE)",
    }

    machines = {
        Elf.EM_NONE                  : "No machine",
        Elf.EM_M32                   : "AT&T WE 32100",
        Elf.EM_SPARC                 : "SUN SPARC",
        Elf.EM_386                   : "Intel 80386",
        Elf.EM_68K                   : "Motorola m68k family",
        Elf.EM_88K                   : "Motorola m88k family",
        Elf.EM_IAMCU                 : "Intel MCU",
        Elf.EM_860                   : "Intel 80860",
        Elf.EM_MIPS                  : "MIPS R3000 big-endian",
        Elf.EM_S370                  : "IBM System/370 Processor",
        Elf.EM_MIPS_RS3_LE           : "MIPS RS3000 Little-endian",
        Elf.EM_PARISC                : "Hewlett-Packard PA-RISC",
        Elf.EM_VPP500                : "Fujitsu VPP500",
        Elf.EM_SPARC32PLUS           : "Enhanced instruction set SPARC",
        Elf.EM_960                   : "Intel 80960",
        Elf.EM_PPC                   : "PowerPC",
        Elf.EM_PPC64                 : "64-bit PowerPC",
        Elf.EM_S390                  : "IBM System/390 Processor",
        Elf.EM_SPU                   : "IBM SPU/SPC",
        Elf.EM_V800                  : "NEC V800",
        Elf.EM_FR20                  : "Fujitsu FR20",
        Elf.EM_RH32                  : "TRW RH-32",
        Elf.EM_RCE                   : "Motorola RCE",
        Elf.EM_ARM                   : "ARM 32-bit architecture (AARCH32)",
        Elf.EM_ALPHA                 : "Digital Alpha",
        Elf.EM_SH                    : "Hitachi SH",
        Elf.EM_SPARCV9               : "SPARC Version 9",
        Elf.EM_TRICORE               : "Siemens TriCore embedded processor",
        Elf.EM_ARC                   : "Argonaut RISC Core, Argonaut Technologies Inc.",
        Elf.EM_H8_300                : "Hitachi H8/300",
        Elf.EM_H8_300H               : "Hitachi H8/300H",
        Elf.EM_H8S                   : "Hitachi H8S",
        Elf.EM_H8_500                : "Hitachi H8/500",
        Elf.EM_IA_64                 : "Intel IA-64 processor architecture",
        Elf.EM_MIPS_X                : "Stanford MIPS-X",
        Elf.EM_COLDFIRE              : "Motorola ColdFire",
        Elf.EM_68HC12                : "Motorola M68HC12",
        Elf.EM_MMA                   : "Fujitsu MMA Multimedia Accelerator",
        Elf.EM_PCP                   : "Siemens PCP",
        Elf.EM_NCPU                  : "Sony nCPU embedded RISC processor",
        Elf.EM_NDR1                  : "Denso NDR1 microprocessor",
        Elf.EM_STARCORE              : "Motorola Star*Core processor",
        Elf.EM_ME16                  : "Toyota ME16 processor",
        Elf.EM_ST100                 : "STMicroelectronics ST100 processor",
        Elf.EM_TINYJ                 : "Advanced Logic Corp. TinyJ embedded processor family",
        Elf.EM_X86_64                : "AMD x86-64 architecture",
        Elf.EM_PDSP                  : "Sony DSP Processor",
        Elf.EM_PDP10                 : "Digital Equipment Corp. PDP-10",
        Elf.EM_PDP11                 : "Digital Equipment Corp. PDP-11",
        Elf.EM_FX66                  : "Siemens FX66 microcontroller",
        Elf.EM_ST9PLUS               : "STMicroelectronics ST9+ 8/16 bit microcontroller",
        Elf.EM_ST7                   : "STMicroelectronics ST7 8-bit microcontroller",
        Elf.EM_68HC16                : "Motorola MC68HC16 Microcontroller",
        Elf.EM_68HC11                : "Motorola MC68HC11 Microcontroller",
        Elf.EM_68HC08                : "Motorola MC68HC08 Microcontroller",
        Elf.EM_68HC05                : "Motorola MC68HC05 Microcontroller",
        Elf.EM_SVX                   : "Silicon Graphics SVx",
        Elf.EM_ST19                  : "STMicroelectronics ST19 8-bit microcontroller",
        Elf.EM_VAX                   : "Digital VAX",
        Elf.EM_CRIS                  : "Axis Communications 32-bit embedded processor",
        Elf.EM_JAVELIN               : "Infineon Technologies 32-bit embedded processor",
        Elf.EM_FIREPATH              : "Element 14 64-bit DSP Processor",
        Elf.EM_ZSP                   : "LSI Logic 16-bit DSP Processor",
        Elf.EM_MMIX                  : "Donald Knuth's educational 64-bit processor",
        Elf.EM_HUANY                 : "Harvard University machine-independent object files",
        Elf.EM_PRISM                 : "SiTera Prism",
        Elf.EM_AVR                   : "Atmel AVR 8-bit microcontroller",
        Elf.EM_FR30                  : "Fujitsu FR30",
        Elf.EM_D10V                  : "Mitsubishi D10V",
        Elf.EM_D30V                  : "Mitsubishi D30V",
        Elf.EM_V850                  : "NEC v850",
        Elf.EM_M32R                  : "Mitsubishi M32R",
        Elf.EM_MN10300               : "Matsushita MN10300",
        Elf.EM_MN10200               : "Matsushita MN10200",
        Elf.EM_PJ                    : "picoJava",
        Elf.EM_OPENRISC              : "OpenRISC 32-bit embedded processor",
        Elf.EM_ARC_COMPACT           : "ARC International ARCompact processor (old spelling/synonym: EM_ARC_A5)",
        Elf.EM_XTENSA                : "Tensilica Xtensa Architecture",
        Elf.EM_VIDEOCORE             : "Alphamosaic VideoCore processor",
        Elf.EM_TMM_GPP               : "Thompson Multimedia General Purpose Processor",
        Elf.EM_NS32K                 : "National Semiconductor 32000 series",
        Elf.EM_TPC                   : "Tenor Network TPC processor",
        Elf.EM_SNP1K                 : "Trebia SNP 1000 processor",
        Elf.EM_ST200                 : "STMicroelectronics ST200 microcontroller",
        Elf.EM_IP2K                  : "Ubicom IP2xxx microcontroller family",
        Elf.EM_MAX                   : "MAX Processor",
        Elf.EM_CR                    : "National Semiconductor CompactRISC microprocessor",
        Elf.EM_F2MC16                : "Fujitsu F2MC16",
        Elf.EM_MSP430                : "Texas Instruments embedded microcontroller msp430",
        Elf.EM_BLACKFIN              : "Analog Devices Blackfin (DSP) processor",
        Elf.EM_SE_C33                : "S1C33 Family of Seiko Epson processors",
        Elf.EM_SEP                   : "Sharp embedded microprocessor",
        Elf.EM_ARCA                  : "Arca RISC Microprocessor",
        Elf.EM_UNICORE               : "Microprocessor series from PKU-Unity Ltd. and MPRC of Peking University",
        Elf.EM_EXCESS                : "eXcess: 16/32/64-bit configurable embedded CPU",
        Elf.EM_DXP                   : "Icera Semiconductor Inc. Deep Execution Processor",
        Elf.EM_ALTERA_NIOS2          : "Altera Nios II soft-core processor",
        Elf.EM_CRX                   : "National Semiconductor CompactRISC CRX microprocessor",
        Elf.EM_XGATE                 : "Motorola XGATE embedded processor",
        Elf.EM_C166                  : "Infineon C16x/XC16x processor",
        Elf.EM_M16C                  : "Renesas M16C series microprocessors",
        Elf.EM_DSPIC30F              : "Microchip Technology dsPIC30F Digital Signal Controller",
        Elf.EM_CE                    : "Freescale Communication Engine RISC core",
        Elf.EM_M32C                  : "Renesas M32C series microprocessors",
        Elf.EM_TSK3000               : "Altium TSK3000 core",
        Elf.EM_RS08                  : "Freescale RS08 embedded processor",
        Elf.EM_SHARC                 : "Analog Devices SHARC family of 32-bit DSP processors",
        Elf.EM_ECOG2                 : "Cyan Technology eCOG2 microprocessor",
        Elf.EM_SCORE7                : "Sunplus S+core7 RISC processor",
        Elf.EM_DSP24                 : "New Japan Radio (NJR) 24-bit DSP Processor",
        Elf.EM_VIDEOCORE3            : "Broadcom VideoCore III processor",
        Elf.EM_LATTICEMICO32         : "RISC processor for Lattice FPGA architecture",
        Elf.EM_SE_C17                : "Seiko Epson C17 family",
        Elf.EM_TI_C6000              : "The Texas Instruments TMS320C6000 DSP family",
        Elf.EM_TI_C2000              : "The Texas Instruments TMS320C2000 DSP family",
        Elf.EM_TI_C5500              : "The Texas Instruments TMS320C55x DSP family",
        Elf.EM_TI_ARP32              : "Texas Instruments Application Specific RISC Processor, 32bit fetch",
        Elf.EM_TI_PRU                : "Texas Instruments Programmable Realtime Unit",
        Elf.EM_MMDSP_PLUS            : "STMicroelectronics 64bit VLIW Data Signal Processor",
        Elf.EM_CYPRESS_M8C           : "Cypress M8C microprocessor",
        Elf.EM_R32C                  : "Renesas R32C series microprocessors",
        Elf.EM_TRIMEDIA              : "NXP Semiconductors TriMedia architecture family",
        Elf.EM_QDSP6                 : "QUALCOMM DSP6 Processor",
        Elf.EM_8051                  : "Intel 8051 and variants",
        Elf.EM_STXP7X                : "STMicroelectronics STxP7x family of configurable and extensible RISC processors",
        Elf.EM_NDS32                 : "Andes Technology compact code size embedded RISC processor family",
        Elf.EM_ECOG1                 : "Cyan Technology eCOG1X family",
        Elf.EM_ECOG1X                : "Cyan Technology eCOG1X family",
        Elf.EM_MAXQ30                : "Dallas Semiconductor MAXQ30 Core Micro-controllers",
        Elf.EM_XIMO16                : "New Japan Radio (NJR) 16-bit DSP Processor",
        Elf.EM_MANIK                 : "M2000 Reconfigurable RISC Microprocessor",
        Elf.EM_CRAYNV2               : "Cray Inc. NV2 vector architecture",
        Elf.EM_RX                    : "Renesas RX family",
        Elf.EM_METAG                 : "Imagination Technologies META processor architecture",
        Elf.EM_MCST_ELBRUS           : "MCST Elbrus general purpose hardware architecture",
        Elf.EM_ECOG16                : "Cyan Technology eCOG16 family",
        Elf.EM_CR16                  : "National Semiconductor CompactRISC CR16 16-bit microprocessor",
        Elf.EM_ETPU                  : "Freescale Extended Time Processing Unit",
        Elf.EM_SLE9X                 : "Infineon Technologies SLE9X core",
        Elf.EM_L10M                  : "Intel L10M",
        Elf.EM_K10M                  : "Intel K10M",
        182                          : "Reserved for future Intel use",
        Elf.EM_AARCH64               : "ARM 64-bit architecture (AARCH64)",
        184                          : "Reserved for future ARM use",
        Elf.EM_AVR32                 : "Atmel Corporation 32-bit microprocessor family",
        Elf.EM_STM8                  : "STMicroeletronics STM8 8-bit microcontroller",
        Elf.EM_TILE64                : "Tilera TILE64 multicore architecture family",
        Elf.EM_TILEPRO               : "Tilera TILEPro multicore architecture family",
        Elf.EM_MICROBLAZE            : "Xilinx MicroBlaze 32-bit RISC soft processor core",
        Elf.EM_CUDA                  : "NVIDIA CUDA architecture",
        Elf.EM_TILEGX                : "Tilera TILE-Gx multicore architecture family",
        Elf.EM_CLOUDSHIELD           : "CloudShield architecture family",
        Elf.EM_COREA_1ST             : "KIPO-KAIST Core-A 1st generation processor family",
        Elf.EM_COREA_2ND             : "KIPO-KAIST Core-A 2nd generation processor family",
        Elf.EM_ARCV2                 : "Synopsys ARCompact V2", # codespell:ignore
        Elf.EM_OPEN8                 : "Open8 8-bit RISC soft processor core",
        Elf.EM_RL78                  : "Renesas RL78 family",
        Elf.EM_VIDEOCORE5            : "Broadcom VideoCore V processor",
        Elf.EM_78KOR                 : "Renesas 78KOR family",
        Elf.EM_56800EX               : "Freescale 56800EX Digital Signal Controller (DSC)",
        Elf.EM_BA1                   : "Beyond BA1 CPU architecture",
        Elf.EM_BA2                   : "Beyond BA2 CPU architecture",
        Elf.EM_XCORE                 : "XMOS xCORE processor family",
        Elf.EM_MCHP_PIC              : "Microchip 8-bit PIC(r) family",
        Elf.EM_INTELGT               : "Intel Graphics Technology",
        Elf.EM_INTEL206              : "Reserved by Intel",
        Elf.EM_INTEL207              : "Reserved by Intel",
        Elf.EM_INTEL208              : "Reserved by Intel",
        Elf.EM_INTEL209              : "Reserved by Intel",
        Elf.EM_KM32                  : "KM211 KM32 32-bit processor",
        Elf.EM_KMX32                 : "KM211 KMX32 32-bit processor",
        Elf.EM_KMX16                 : "KM211 KMX16 16-bit processor",
        Elf.EM_KMX8                  : "KM211 KMX8 8-bit processor",
        Elf.EM_KVARC                 : "KM211 KVARC processor",
        Elf.EM_CDP                   : "Paneve CDP architecture family",
        Elf.EM_COGE                  : "Cognitive Smart Memory Processor",
        Elf.EM_COOL                  : "Bluechip Systems CoolEngine",
        Elf.EM_NORC                  : "Nanoradio Optimized RISC",
        Elf.EM_CSR_KALIMBA           : "CSR Kalimba architecture family",
        Elf.EM_Z80                   : "Zilog Z80",
        Elf.EM_VISIUM                : "Controls and Data Services VISIUMcore processor",
        Elf.EM_FT32                  : "FTDI Chip FT32 high performance 32-bit RISC architecture",
        Elf.EM_MOXIE                 : "Moxie processor family",
        Elf.EM_AMDGPU                : "AMD GPU architecture",
        Elf.EM_RISCV                 : "RISC-V",
        Elf.EM_LANAI                 : "Lanai 32-bit processor",
        Elf.EM_CEVA                  : "CEVA Processor Architecture Family",
        Elf.EM_CEVA_X2               : "CEVA X2 Processor Family",
        Elf.EM_BPF                   : "Linux BPF - in-kernel virtual machine",
        Elf.EM_GRAPHCORE_IPU         : "Graphcore Intelligent Processing Unit",
        Elf.EM_IMG1                  : "Imagination Technologies",
        Elf.EM_NFP                   : "Netronome Flow Processor",
        Elf.EM_VE                    : "NEC Vector Engine",
        Elf.EM_CSKY                  : "C-SKY processor family",
        Elf.EM_ARC_COMPACT3_64       : "Synopsys ARCv2.3 64-bit", # codespell:ignore
        Elf.EM_MCS6502               : "MOS Technology MCS 6502 processor",
        Elf.EM_ARC_COMPACT3          : "Synopsys ARCv2.3 32-bit", # codespell:ignore
        Elf.EM_KVX                   : "Kalray VLIW core of the MPPA processor family",
        Elf.EM_65816                 : "WDC 65816/65C816",
        Elf.EM_LOONGARCH             : "LoongArch",
        Elf.EM_KF32                  : "ChipON KungFu32",
        Elf.EM_U16_U8CORE            : "LAPIS nX-U16/U8",
        Elf.EM_TACHYUM               : "Tachyum",
        Elf.EM_56800EF               : "NXP 56800EF Digital Signal Controller (DSC)",

        Elf.EM_AVR_UNOFFICIAL        : "AVR (unofficial)",
        Elf.EM_MSP430_UNOFFICIAL     : "MSP430 (unofficial)",
        Elf.EM_EPIPHANY_UNOFFICIAL   : "Adapteva Epiphany (unofficial)",
        Elf.EM_AVR32_UNOFFICIAL      : "Atmel AVR32 (unofficial)",
        Elf.EM_MT_UNOFFICIAL         : "Morpho MT (unofficial)",
        Elf.EM_FR30_UNOFFICIAL       : "FR30 (unofficial)",
        Elf.EM_OPENRISC_OLD          : "OpenRISC (obsolete)",
        Elf.EM_WEBASSEMBLY           : "Web Assembly binaries (unofficial)",
        Elf.EM_C166_UNOFFICIAL       : "Infineon C166 (unofficial)",
        Elf.EM_S12Z                  : "Freescale S12Z",
        Elf.EM_FRV_UNOFFICIAL        : "Cygnus FR-V (unofficial)",
        Elf.EM_DLX_UNOFFICIAL        : "DLX (unofficial)",
        Elf.EM_D10V_UNOFFICIAL       : "Cygnus D10V (unofficial)",
        Elf.EM_D30V_UNOFFICIAL       : "Cygnus D30V (unofficial)",
        Elf.EM_IP2K_UNOFFICIAL       : "Ubicom IP2xxx (unofficial)",
        Elf.EM_OPENRISC_OLD2         : "OpenRISC (obsolete)",
        Elf.EM_PPC_UNOFFICIAL        : "Cygnus PowerPC (unofficial)",
        Elf.EM_ALPHA_UNOFFICIAL      : "Digital Alpha (unofficial)",
        Elf.EM_M32R_UNOFFICIAL       : "Cygnus M32R (unofficial)",
        Elf.EM_V850_UNOFFICIAL       : "Cygnus V859 (unofficial)",
        Elf.EM_S390_OLD              : "IBM S/390 (obsolete)",
        Elf.EM_XTENSA_UNOFFICIAL     : "Old Xtensa (unofficial)",
        Elf.EM_XSTORMY_UNOFFICIAL    : "xstormy16 (unofficial)",
        Elf.EM_MICROBLAZE_UNOFFICIAL : "Old MicroBlaze (unofficial)",
        Elf.EM_MN10300_UNOFFICIAL    : "Cygnus MN10300 (unofficial)",
        Elf.EM_MN10200_UNOFFICIAL    : "Cygnus MN10200 (unofficial)",
        Elf.EM_MEP_UNOFFICIAL        : "Toshiba MeP (unofficial)",
        Elf.EM_M32C_UNOFFICIAL       : "Renesas M32C (unofficial)",
        Elf.EM_IQ2000_UNOFFICIAL     : "Vitesse IQ2000 (unofficial)",
        Elf.EM_NIOS_UNOFFICIAL       : "NIOS (unofficial)",
        Elf.EM_MOXIE_UNOFFICIAL      : "Moxie (unofficial)",
    }

    versions = {
        Elf.EV_NONE    : "Invalid version",
        Elf.EV_CURRENT : "Current version",
    }

    ptype = {
        Elf.Phdr.PT_NULL          : "NULL",
        Elf.Phdr.PT_LOAD          : "LOAD",
        Elf.Phdr.PT_DYNAMIC       : "DYNAMIC",
        Elf.Phdr.PT_INTERP        : "INTERP",
        Elf.Phdr.PT_NOTE          : "NOTE",
        Elf.Phdr.PT_SHLIB         : "SHLIB",
        Elf.Phdr.PT_PHDR          : "PHDR",
        Elf.Phdr.PT_TLS           : "TLS",
        Elf.Phdr.PT_GNU_EH_FRAME  : "GNU_EH_FLAME",
        Elf.Phdr.PT_GNU_STACK     : "GNU_STACK",
        Elf.Phdr.PT_GNU_RELRO     : "GNU_RELRO",
        Elf.Phdr.PT_GNU_PROPERTY  : "GNU_PROPERTY",
        Elf.Phdr.PT_GNU_SFRAME    : "SFRAME",
        Elf.Phdr.PT_SUNWBSS       : "SUNWBSS",
        Elf.Phdr.PT_SUNWSTACK     : "SUNWSTACK",
    }

    pflags = {
        0                                             : "---",
        Elf.Phdr.PF_X                                 : "--X",
        Elf.Phdr.PF_W                                 : "-W-",
        Elf.Phdr.PF_R                                 : "R--",
        Elf.Phdr.PF_W | Elf.Phdr.PF_X                 : "-WX",
        Elf.Phdr.PF_R | Elf.Phdr.PF_X                 : "R-X",
        Elf.Phdr.PF_R | Elf.Phdr.PF_W                 : "RW-",
        Elf.Phdr.PF_R | Elf.Phdr.PF_W | Elf.Phdr.PF_X : "RWX",
    }

    stype = {
        Elf.Shdr.SHT_NULL                     : "NULL",
        Elf.Shdr.SHT_PROGBITS                 : "PROGBITS",
        Elf.Shdr.SHT_SYMTAB                   : "SYMTAB",
        Elf.Shdr.SHT_STRTAB                   : "STRTAB",
        Elf.Shdr.SHT_RELA                     : "RELA",
        Elf.Shdr.SHT_HASH                     : "HASH",
        Elf.Shdr.SHT_DYNAMIC                  : "DYNAMIC",
        Elf.Shdr.SHT_NOTE                     : "NOTE",
        Elf.Shdr.SHT_NOBITS                   : "NOBITS",
        Elf.Shdr.SHT_REL                      : "REL",
        Elf.Shdr.SHT_SHLIB                    : "SHLIB",
        Elf.Shdr.SHT_DYNSYM                   : "DYNSYM",
        Elf.Shdr.SHT_INIT_ARRAY               : "INIT_ARRAY",
        Elf.Shdr.SHT_FINI_ARRAY               : "FINI_ARRAY",
        Elf.Shdr.SHT_PREINIT_ARRAY            : "PREINIT_ARRAY",
        Elf.Shdr.SHT_GROUP                    : "GROUP",
        Elf.Shdr.SHT_SYMTAB_SHNDX             : "SYMTAB_SHNDX",
        Elf.Shdr.SHT_RELR                     : "RELR",
        Elf.Shdr.SHT_ANDROID_REL              : "ANDROID_REL",
        Elf.Shdr.SHT_ANDROID_RELA             : "ANDROID_RELA",
        Elf.Shdr.SHT_GNU_INCREMENTAL_INPUTS   : "GNU_INCREMENTAL_INPUTS",
        Elf.Shdr.SHT_LLVM_ODRTAB              : "LLVM_ODRTAB",
        Elf.Shdr.SHT_LLVM_LINKER_OPTIONS      : "LLVM_LINKER_OPTIONS",
        Elf.Shdr.SHT_LLVM_CALL_GRAPH_PROFILE  : "LLVM_CALL_GRAPH_PROFILE",
        Elf.Shdr.SHT_LLVM_ADDRSIG             : "LLVM_ADDRSIG",
        Elf.Shdr.SHT_LLVM_DEPENDENT_LIBRARIES : "LLVM_DEPENDENT_LIBRARIES",
        Elf.Shdr.SHT_LLVM_SYMPART             : "LLVM_SYMPART",
        Elf.Shdr.SHT_LLVM_PART_EHDR           : "LLVM_PART_EHDR",
        Elf.Shdr.SHT_LLVM_PART_PHDR           : "LLVM_PART_PHDR",
        Elf.Shdr.SHT_LLVM_BB_ADDR_MAP_V0      : "LLVM_BB_ADDR_MAP_V0",
        Elf.Shdr.SHT_LLVM_CALL_GRAPH_PROFILE  : "LLVM_CALL_GRAPH_PROFILE",
        Elf.Shdr.SHT_LLVM_BB_ADDR_MAP         : "LLVM_BB_ADDR_MAP",
        Elf.Shdr.SHT_LLVM_OFFLOADING          : "LLVM_OFFLOADING",
        Elf.Shdr.SHT_LLVM_LTO                 : "LLVM_LTO",
        Elf.Shdr.SHT_ANDROID_RELR             : "ANDROID_RELR",
        Elf.Shdr.SHT_GNU_ATTRIBUTES           : "GNU_ATTRIBUTES",
        Elf.Shdr.SHT_GNU_HASH                 : "GNU_HASH",
        Elf.Shdr.SHT_GNU_LIBLIST              : "GNU_LIBLIST",
        Elf.Shdr.SHT_CHECKSUM                 : "CHECKSUM",
        Elf.Shdr.SHT_SUNW_move                : "SUNW_move",
        Elf.Shdr.SHT_SUNW_COMDAT              : "SUNW_COMDAT",
        Elf.Shdr.SHT_SUNW_syminfo             : "SUNW_syminfo",
        Elf.Shdr.SHT_GNU_verdef               : "GNU_verdef",
        Elf.Shdr.SHT_GNU_verneed              : "GNU_verneed",
        Elf.Shdr.SHT_GNU_versym               : "GNU_versym",
    }

    def elf_info(self, elf, orig_filepath=None):
        if elf.filename:
            if orig_filepath:
                filename = "{:s} (remote: {:s})".format(elf.filename, orig_filepath)
            else:
                filename = elf.filename
        elif elf.addr is not None:
            filename = "{:#x}".format(elf.addr)

        magic_hex = " ".join(slicer(struct.pack(">I", elf.e_magic).hex(), 2))
        if Endian.is_big_endian():
            magic_str = repr(p32(elf.e_magic).decode())
        else:
            magic_str = repr(p32(elf.e_magic).decode()[::-1])
        data = [
            ("Magic", "{:s} ({:s})".format(magic_hex, magic_str)),
            ("Class", "{:#x} - {:s}".format(elf.e_class, self.classes[elf.e_class])),
            ("Endianness", "{:#x} - {:s}".format(elf.e_endianness, self.endianness[elf.e_endianness])),
            ("ELF Version", "{:#x} - {:s}".format(elf.e_eiversion, self.versions[elf.e_eiversion])),
            ("OS ABI", "{:#x} - {:s}".format(elf.e_osabi, self.osabis[elf.e_osabi])),
            ("ABI Version", "{:#x}".format(elf.e_abiversion)),
            ("Type", "{:#x} - {:s}".format(elf.e_type, self.types[elf.e_type])),
            ("Machine", "{:#x} - {:s}".format(elf.e_machine, self.machines.get(elf.e_machine, "Unknown"))),
            ("Version", "{:#x} - {:s}".format(elf.e_version, self.versions[elf.e_version])),
            ("Entry point", "{:s}".format(AddressUtil.format_address(elf.e_entry))),
            ("Program Header Table", "{:s}".format(AddressUtil.format_address(elf.e_phoff))),
            ("Program Header Entry Size", "{0:d} ({0:#x})".format(elf.e_phentsize)),
            ("Number of Program Headers", "{:d}".format(elf.e_phnum)),
            ("Section Header Table", "{:s}".format(AddressUtil.format_address(elf.e_shoff))),
            ("Section Header Entry Size", "{0:d} ({0:#x})".format(elf.e_shentsize)),
            ("Number of Section Headers", "{:d}".format(elf.e_shnum)),
            ("ELF Header Size", "{0:d} ({0:#x})".format(elf.e_ehsize)),
            ("Section Header String Table Index", "{0:d} ({0:#x})".format(elf.e_shstrndx)),
            ("Processor Specific Flags", "{:#x}".format(elf.e_flags)),
        ]

        self.out.append(titlify("ELF Header - {:s}".format(filename)))
        for title, content in data:
            self.out.append("{:<34s}: {}".format(title, content))

        self.out.append(titlify("Program Header - {:s}".format(filename)))
        self.phdr_info(elf)

        self.out.append(titlify("Section Header - {:s}".format(filename)))
        self.shdr_info(elf)
        return

    def phdr_info(self, elf):
        name_width = max([len(self.ptype.get(p.p_type, "UNKNOWN")) for p in elf.phdrs])

        fmt = "[{:>2s}] {:{:d}s} {:>12s} {:>12s} {:>12s} {:>12s} {:>12s} {:5s} {:>8s}"
        legend = [
            "#", "Type", name_width, "Offset", "Virtaddr",
            "Physaddr", "FileSiz", "MemSiz", "Flags", "Align",
        ]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for i, p in enumerate(elf.phdrs):
            p_type = self.ptype.get(p.p_type, "UNKNOWN")
            p_flags = self.pflags.get(p.p_flags, "???")
            fmt = "[{:2d}] {:{:d}s} {:#12x} {:#12x} {:#12x} {:#12x} {:#12x} {:5s} {:#8x}"
            args = [
                i, p_type, name_width, p.p_offset, p.p_vaddr,
                p.p_paddr, p.p_filesz, p.p_memsz, p_flags, p.p_align,
            ]
            self.out.append(fmt.format(*args))
        return

    def shdr_info(self, elf):
        if not elf.shdrs:
            self.out.append("Not loaded")
            return

        name_width = max([len(s.sh_name) for s in elf.shdrs])

        fmt = "[{:>2s}] {:{:d}s} {:>15s} {:>12s} {:>12s} {:>12s} {:>12s} {:>5s} {:>5s} {:>5s} {:>8s}"
        legend = ["#", "Name", name_width, "Type", "Address", "Offset", "Size", "EntSiz", "Flags", "Link", "Info", "Align"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for i, s in enumerate(elf.shdrs):
            sh_type = self.stype.get(s.sh_type, "UNKNOWN")
            sh_flags = ""
            if s.sh_flags & Elf.Shdr.SHF_WRITE:
                sh_flags += "W"
            if s.sh_flags & Elf.Shdr.SHF_ALLOC:
                sh_flags += "A"
            if s.sh_flags & Elf.Shdr.SHF_EXECINSTR:
                sh_flags += "X"
            if s.sh_flags & Elf.Shdr.SHF_MERGE:
                sh_flags += "M"
            if s.sh_flags & Elf.Shdr.SHF_STRINGS:
                sh_flags += "S"
            if s.sh_flags & Elf.Shdr.SHF_INFO_LINK:
                sh_flags += "I"
            if s.sh_flags & Elf.Shdr.SHF_LINK_ORDER:
                sh_flags += "L"
            if s.sh_flags & Elf.Shdr.SHF_OS_NONCONFORMING:
                sh_flags += "O"
            if s.sh_flags & Elf.Shdr.SHF_GROUP:
                sh_flags += "G"
            if s.sh_flags & Elf.Shdr.SHF_TLS:
                sh_flags += "T"
            if s.sh_flags & Elf.Shdr.SHF_EXCLUDE:
                sh_flags += "E"
            if s.sh_flags & Elf.Shdr.SHF_COMPRESSED:
                sh_flags += "C"

            fmt = "[{:2d}] {:{:d}s} {:>15s} {:#12x} {:#12x} {:#12x} {:#12x} {:5s} {:#5x} {:#5x} {:#8x}"
            args = [
                i, s.sh_name, name_width, sh_type, s.sh_addr, s.sh_offset, s.sh_size,
                s.sh_entsize, sh_flags, s.sh_link, s.sh_info, s.sh_addralign,
            ]
            self.out.append(fmt.format(*args))

            if self.args.verbose:
                if s.sh_size > 0x1000: # heuristic value
                    self.out.append("Skip because too large ({:#x} > 0x1000)".format(s.sh_size))
                else:
                    fd = open(elf.filename, "rb")
                    fd.seek(s.sh_offset, 0)
                    section_data = fd.read(s.sh_size)
                    self.out.append(hexdump(section_data, show_symbol=False, base=s.sh_offset))
        return

    @parse_args
    def do_invoke(self, args):
        local_filepath = None
        remote_filepath = None
        tmp_filepath = None
        self.out = []

        # memory parse pattern
        if args.address is not None:
            try:
                elf = Elf.get_elf(args.address)
            except gdb.MemoryError:
                err("Memory read error")
                return

            if elf is None or not elf.is_valid():
                err("Failed to parse ELF")
            else:
                self.elf_info(elf)
                gef_print("\n".join(self.out), less=not args.no_pager)
            return

        # file parse pattern
        if args.remote:
            if not is_remote_debug():
                err("-r option is allowed only remote debug")
                return
            if is_qemu_system():
                err("-r option is unsupported under qemu-system")
                return

            if args.file:
                remote_filepath = args.file # if specified, assume it is remote
            elif gdb.current_progspace().filename:
                f = gdb.current_progspace().filename
                if f.startswith("target:"): # gdbserver
                    f = f[7:]
                remote_filepath = f
            elif Pid.get_pid(remote=True):
                remote_filepath = "/proc/{:d}/exe".format(Pid.get_pid(remote=True))
            else:
                err("File name could not be determined")
                return

            data = Path.read_remote_file(remote_filepath, as_byte=True) # qemu-user is failed here, it is ok
            if not data:
                err("Failed to read remote filepath")
                return
            tmp_fd, tmp_filepath = GefUtil.mkstemp(prefix="elf-info", suffix=".elf")
            os.fdopen(tmp_fd, "wb").write(data)
            local_filepath = tmp_filepath
            del data

        elif args.file:
            local_filepath = args.file

        elif args.file is None:
            if is_qemu_system():
                err("Argument-less calls are unsupported under qemu-system")
                return
            local_filepath = Path.get_filepath()

        if local_filepath is None:
            err("File name could not be determined")
            return

        # readelf pattern
        if args.use_readelf:
            try:
                readelf = GefUtil.which(Config.get_gef_setting("gef.readelf_command"))
            except FileNotFoundError:
                err("Could not find readelf")
                return
            try:
                less = GefUtil.which("less")
            except FileNotFoundError:
                less = False
            if args.no_pager or not less:
                os.system("LANG=C {!r} -a --wide {!r}".format(readelf, local_filepath))
            else:
                os.system("LANG=C {!r} -a --wide {!r} | {!r}".format(readelf, local_filepath, less))
            if tmp_filepath and os.path.exists(tmp_filepath):
                os.unlink(tmp_filepath)
            return

        # self parse pattern
        elf = Elf.get_elf(local_filepath)
        if elf is None or not elf.is_valid():
            err("Failed to parse ELF")
        else:
            data = open(local_filepath, "rb").read()
            self.out.append("size: {:d} bytes, sha1: {:s}".format(len(data), hashlib.sha1(data).hexdigest()))
            self.elf_info(elf, remote_filepath)
            gef_print("\n".join(self.out), less=not args.no_pager)

        if tmp_filepath and os.path.exists(tmp_filepath):
            os.unlink(tmp_filepath)
        return

