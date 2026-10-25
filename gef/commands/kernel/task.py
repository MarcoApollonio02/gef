"""GEF kernel commands (category 06-f) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Linux Task: the `ktask`/`kfiles` task-state
family (task, files, saved-regs, signals, namespaces). Auto-discovered by
gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import collections
import os
import re

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
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, info, titlify, warn
from gef.core.instruction import Disasm
from gef.core.display import ProgressBar
from gef.core.kernel import Kernel, KernelSeccomp, KernelTask, Ksym
from gef.core.memory import (
    is_ascii_string,
    is_double_link_list,
    is_valid_addr,
    is_valid_addr_addr,
    p32,
    p64,
    read_cstring_from_memory,
    read_int16_from_memory,
    read_int32_from_memory,
    read_int64_from_memory,
    read_int_from_memory,
    read_memory,
)
from gef.core.pagewalk import KernelAddressHeuristicFinder
from gef.core.process import (
    LinuxSignal,
    get_pagesize,
    is_32bit,
    is_64bit,
    is_arm32,
    is_arm64,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import get_register, to_unsigned_long
from gef.core.syscall import Syscall
from gef.core.symbols import Symbol
from gef.core.utils import GefUtil, align, align_to_ptrsize, slice_unpack


@register_command
class KernelTaskCommand(GenericCommand, BufferingOutput):
    """Display process list."""

    _cmdline_ = "ktask"
    _category_ = "06-f. Qemu-system/KGDB Cooperation - Linux Task"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="comm string REGEXP filter.")
    parser.add_argument("-T", "--task-filter", action="append", type=AddressUtil.parse_address, default=[],
                        help="task address filter.")
    parser.add_argument("-m", "--print-maps", action="store_true", help="print memory map for each user-land process.")
    parser.add_argument("-r", "--print-regs", action="store_true",
                        help="print general registers saved on kstack for each user-land process.")
    parser.add_argument("-i", "--print-all-id", action="store_true", help="print suid, sgid, euid, egid, fsuid and fsgid.")
    parser.add_argument("-t", "--print-thread", action="store_true", help="display by thread (LWP), not by process.")
    parser.add_argument("-F", "--print-fd", action="store_true", help="print file descriptors for each user process.")
    parser.add_argument("-s", "--print-sighand", action="store_true", help="print signal handlers for each user process.")
    parser.add_argument("-S", "--print-seccomp", action="store_true",
                        help="dump the seccomp filter. If the tool is available, it dumps orig_prog; "
                             "otherwise, it disassembles bpf_func.")
    parser.add_argument("-N", "--print-namespace", action="store_true", help="print namespaces for each user process.")
    parser.add_argument("-u", "--user-process-only", action="store_true", help="display user-land process (+ thread) only.")
    parser.add_argument("--init-task", type=AddressUtil.parse_address, help="specifies the address of init_task.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("--all", action="store_true", help="enable all option.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -T 0xffff888012345000  # task address filter",
        "{0:s} -f bash                # comm string filter",
        "{0:s} --all                  # it means -mritFsSN",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "",
        "Simplified task_struct structure:",
        "",
        "    +-init_task-+",
        "    | list_head |---+    +-->+-kstack----------+    +--->+-vm_area_struct--+",
        "    +-----------+   |    |   | (thread_info)   |    |    | vm_start        |",
        "                    |    |   | STACK_END_MAGIC |    |    | vm_end          |",
        "+-------------------+    |   | ...             |    |    | vm_next (~6.1)  |",
        "|                        |   | ...             |    |    | ...             |",
        "|   +-task_struct---+    |   | ...             |    |    | vm_flags        |",
        "|   | (thread_info) |    |   | ...             |    |    | vm_file         |-----+",
        "|   | ...           |    |   | pt_regs         |    |    | ...             |     |",
        "|   | stack         |----+   +-----------------+    |    +-----------------+     |",
        "|   | ...           |                               |                            |",
        "+-->| tasks         |-->...               +---------+<------------------------+  |",
        "    | ...           |                     |                                   |  |",
        "    | mm            |-->+-mm_struct----+  |  +-------->+-maple_node(6.1~)--+  |  |",
        "    | ...           |   | mmap (~6.1)  |--+  |         | ...               |  |  |",
        "    | pid           |   | ...          |     |         | mr64|ma64|alloc   |  |  |",
        "    | tid           |   | mm_mt (6.1~) |     |         |   ...             |  |  |",
        "    | ...           |   |   ma_root    |-----+         |   slot[]          |--+  |",
        "    | stack_canary  |   | ...          |               +-------------------+     |",
        "    | ...           |   +--------------+                                         |",
        "    | group_leader  |                                         +------------------+       +-mount----------+",
        "    | ...           |         +-->+-cred--------------+       |                          | ...            |",
        "    | thread_group  |-->...   |   | ...               |       |                          | mnt_parent     |-->mount",
        "    | ...           |         |   | uid, gid          |       |                          | mnt_mountpoint |-->dentry",
        "    | cred          |---------+   | suid, sgid        |       |                       +->| mnt (vfsmount) |",
        "    | ...           |             | euid, egid        |       |                       |  |   mnt_root     |-->dentry",
        "    | comm[16]      |             | fsuid, fsgid      |       |                       |  |   ...          |",
        "    | ...           |             | ..., user_ns, ... |       |                       |  | ...            |",
        "    | files         |--+          +-------------------+       |                       |  +----------------+",
        "    | ...           |  |                                      |                       |",
        "    | nsproxy       |------->+-nsproxy----------------+       |                       | +--->+-dentry-----+",
        "    | ...           |  |     | count                  |       |                       | |    | ...        |",
        "    | sighand       |-----+  | uts_ns, ipc_ns, mnt_ns |       |                       | |    | d_parent   |-->dentry",
        "    | ...           |  |  |  | pid_ns_for_children    |       |                       | |    | ...        |",
        "    | seccomp       |  |  |  | net_ns, time_ns, ...   |       |                       | |    | d_inode    |--+",
        "    | ...           |  |  |  +------------------------+       |                       | |    | d_iname    |  |",
        "    +---------------+  |  |                                   |                       | |    | ...        |  |",
        "                       |  +->+-sighand_struct----+            |                       | |    +------------+  |",
        "                       |     | ...               |            v                       | |                    |",
        "                       |     | action[64]        |            +-->+-file-----------+  | | +------------------+",
        "+----------------------+     +-------------------+            |   | ...            |  | | |",
        "|                                                             |   | f_path         |  | | v",
        "+-->+-files_struct-+  +-->+-fdtable---+  +-->+-file*[]-----+  |   |   mnt          |--+ | +->+-inode------+",
        "    | ...          |  |   | max_fds   |  |   | [0]         |--+   |   dentry       |----+ |  | ...        |",
        "    | fdt          |--+   | fd        |--+   | ...         |      | f_inode (3.9~) |------+  | i_ino      |",
        "    | ...          |      | ...       |      | [max_fds-1] |      | ...            |         | ...        |",
        "    +--------------+      +-----------+      +-------------+      +----------------+         +------------+",
        "",
        "This command will only track tasks that can be tracked from `init_task` or the result of `kcurrent` command.",
        "Other tasks (such as `swapper/1` if thread 1 is running some task) will not be detected.",
    ]
    _note_ = "\n".join(_note_)

    def show_init_task_recovery_hint(self, init_task):
        if init_task is not None:
            return

        if self.ktask.init_task is not None:
            try:
                klayout = Kernel.layout()
            except (gdb.error, gdb.MemoryError):
                klayout = None
            if klayout is None:
                image_starts = []
            else:
                image_starts = [x for x in (klayout.text_base, klayout.ro_base, klayout.rw_base) if x]
            if klayout is None:
                image_ends = []
            else:
                image_ends = [x for x in (klayout.text_end, klayout.ro_end, klayout.rw_end) if x]
            if image_starts and image_ends:
                image_start = min(image_starts)
                image_end = max(image_ends)
                if image_start <= self.ktask.init_task < image_end:
                    return
                self.quiet_warn("Hint: init_task looks outside the kernel image (kbase: {:#x} - {:#x}).".format(
                    image_start, image_end,
                ))

        self.quiet_warn("Retry with: ktask --init-task <addr>")
        return

    def append_task_legend(self):
        if self.args.quiet:
            return
        fmt = "{:<18s} {:7s} {:3s} {:<7s} {:<16s} {:<18s} [{:s}] {:<8s} {:<18s} {:<18s}"
        if self.args.print_all_id:
            id_names = ["uid", "gid", "suid", "sgid", "euid", "egid", "fsuid", "fsgid"]
            ids_fmt = "{:>5s} {:>5s} {:>5s} {:>5s} {:>5s} {:>5s} {:>5s} {:>5s}"
        else:
            id_names = ["uid", "gid"]
            ids_fmt = "{:>5s} {:>5s}"
        legend = [
            "task", "current", "K/U", "lwpid", "task->comm", "task->cred",
            ids_fmt.format(*id_names), "seccomp", "kstack", "kcanary",
        ]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))
        return

    def get_namespace_detail(self, ns_type, ns, context):
        info = self.ktask.get_namespace_info(ns_type, ns, context)
        if info["inum"] is None:
            inum = "-"
        else:
            inum = "{:s}:[{:d}]".format(ns_type, info["inum"])
        detail = ""
        if info["level"] is not None:
            if ns_type == "pid":
                detail = "level={:d} parent={:#x}".format(info["level"], info["parent"])
            else:
                detail = "level={:d} owner={:d} parent={:#x}".format(info["level"], info["owner"], info["parent"])
        return inum, detail

    def dump_maps(self, task, comm_string):
        maps = self.ktask.kmm.get_task_maps(task)
        if not maps:
            return
        self.out.append(titlify("memory map of `{:s}`".format(comm_string)))
        for vm_area in maps:
            self.out.append("{:#018x}-{:#018x} {:s} {:s}".format(
                vm_area.start, vm_area.end, vm_area.flags, vm_area.file,
            ).rstrip())
        return

    def dump_regs(self, kstack, comm_string):
        regs = self.ktask.get_regs(kstack, self.ktask.offset_ptregs)
        if not regs:
            return
        self.out.append(titlify("registers of `{:s}`".format(comm_string)))
        nr_table = Syscall.get_syscall_table().nr_table
        syscall_nr_regs = ["orig_rax", "orig_eax", "r7", "x8", "a7"]
        for name, value in regs.items():
            if name in syscall_nr_regs and value in nr_table:
                self.out.append("{:16s}: {:s} ({:s})".format(
                    name, AddressUtil.format_address(value, long_fmt=True), nr_table[value].name,
                ))
            else:
                self.out.append("{:16s}: {:s}".format(
                    name, AddressUtil.format_address(value, long_fmt=True),
                ))
        return

    def dump_files(self, task, comm_string):
        self.out.append(titlify("file descriptors of `{:s}`".format(comm_string)))
        fmt = "{:4s} {:7s} {:18s} {:18s} {:18s} {:s}"
        legend = ["fd", "cloexec", "struct file", "struct dentry", "struct inode", "path"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))
        entries, warnings = self.ktask.get_file_details(task)
        for entry in entries:
            self.out.append("{:<4d} {:7s} {:#018x} {:#018x} {:#018x} {:s}".format(
                entry["fd"], "?" if entry["cloexec"] is None else str(entry["cloexec"]),
                entry["file"], entry["dentry"], entry["inode"], entry["path"],
            ))
        for warning in warnings:
            self.warn_add_out(warning)
        return

    def dump_sighands(self, task, comm_string):
        info = self.ktask.get_sighands(task)
        libc = info["libc"]
        libc_names = LinuxSignal.LIBC_NAMES.get(libc, {})
        if libc:
            self.out.append(titlify("sighandlers of `{:s}` ({:s})".format(comm_string, libc)))
        else:
            self.out.append(titlify("sighandlers of `{:s}`".format(comm_string)))
        fmt = "{:14s} {:11s} {:18s} {:18s} {:18s} {:42s} {:s}"
        legend = ["sig", "libc name", "sigaction", "handler", "restorer", "flags", "mask"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))
        for action in info["actions"]:
            number = action["number"]
            signame = self.ktask.signame_list.get(number, "???")
            handler = action["handler"]
            if handler == 0:
                handler = "SIG_DFL"
            elif handler == 1:
                handler = "SIG_IGN"
            elif handler == AddressUtil.get_vmem_end_mask():
                handler = "SIG_ERR"
            else:
                handler = "{:#018x}".format(handler)
            if action["restorer"] is None:
                restorer = "-"
            else:
                restorer = "{:#018x}".format(action["restorer"])
            self.out.append("{:<2d} {:11s} {:11s} {:#018x} {:18s} {:18s} {:42s} {:s}".format(
                number, signame, libc_names.get(number, "-"), action["address"], handler, restorer,
                LinuxSignal.format_flags(action["flags"], self.ktask.sa_flags_extra),
                LinuxSignal.format_mask(action["mask"], self.ktask.signame_list, compact=True),
            ).rstrip())
        return

    def dump_namespace(self, task, comm_string, namespace_context):
        self.out.append(titlify("namespace of `{:s}`".format(comm_string)))
        fmt = "{:30s} {:18s} {:8s} {:24s} {:s}"
        legend = ["name", "value", "init_ns?", "inum", "detail"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))
        for entry in self.ktask.get_namespace_entries(task, namespace_context):
            value = entry["value"]
            if value is None:
                self.out.append("{:30s} {:18s} {:8s}".format(entry["name"], "unknown", "-").rstrip())
                continue
            if entry["is_init"] is None:
                is_init = "-"
            else:
                is_init = str(entry["is_init"])
            inum, detail = "-", ""
            if entry["type"] is not None:
                inum, detail = self.get_namespace_detail(entry["type"], value, namespace_context)
            self.out.append("{:30s} {:#018x} {:8s} {:24s} {:s}".format(
                entry["name"], value, is_init, inum, detail,
            ).rstrip())
        return

    def dump_seccomp(self, task, comm_string):
        if not KernelSeccomp.is_enabled(task, self.ktask.offset_stack):
            return False
        self.out.append(titlify("seccomp of `{:s}`".format(comm_string)))
        fmt = "{:18s} {:25s} {:12s} {:18s}"
        legend = ["&task.seccomp", "mode", "filter_count", "filter"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        task_info = self.ktask.kseccomp.parse_task(task)
        mode_str = "{:d} ({:s})".format(task_info.mode, task_info.mode_name)
        self.out.append("{:#018x} {:25s} {:<12d} {:#018x}".format(
            task_info.address, mode_str, task_info.filter_count, task_info.first_filter,
        ))

        filters = iter(self.ktask.kseccomp.iter_filters(task_info))
        for i in ProgressBar(range(task_info.filter_count), desc="filter", disable=self.args.quiet):
            try:
                filter_info = next(filters)
            except StopIteration:
                break
            self.out.append("")
            self.out.append(
                "[{:d}/{:d}] filter:{:#x} prev:{:#x} prog:{:#x} bpf_func:{:#x} jited_len:{:#x} orig_prog:{:#x}".format(
                    i + 1, task_info.filter_count, filter_info.address, filter_info.previous,
                    filter_info.prog, filter_info.bpf_func, filter_info.jited_len, filter_info.orig_prog,
                )
            )
            disassembly = self.ktask.kseccomp.disassemble(filter_info)
            if disassembly is None:
                self.warn_add_out("Could not read seccomp filter {:#x}".format(filter_info.address))
            else:
                self.out.extend(disassembly)
        return True

    def dump_task_details(self, task_info, namespace_context):
        task = task_info["task"]
        comm_string = task_info["comm"]
        is_user = task_info["mm"] != 0 and task_info["pid"] != 0
        additional = False

        if self.args.print_maps:
            additional = True
            self.dump_maps(task, comm_string)
        if is_user and self.args.print_regs and task_info["kstack"] is not None and (
            self.ktask.offset_ptregs is not None
        ):
            additional = True
            self.dump_regs(task_info["kstack"], comm_string)
        if is_user and self.args.print_fd:
            additional = True
            self.dump_files(task, comm_string)
        if is_user and self.args.print_sighand:
            additional = True
            self.dump_sighands(task, comm_string)
        if is_user and self.args.print_namespace:
            additional = True
            self.dump_namespace(task, comm_string, namespace_context)
        if is_user and self.args.print_seccomp:
            additional = self.dump_seccomp(task, comm_string) or additional

        if additional:
            self.out.append(titlify(""))
        return

    def dump_task(self, info):
        task = info["task"]
        comm_string = info["comm"]
        pid, cred, kstack = info["pid"], info["cred"], info["kstack"]
        if info["mm"] == 0 or pid == 0:
            proctype = "K"
        else:
            proctype = "U"
        if self.args.print_thread and info["is_thread"]:
            proctype += "T"
        if self.args.print_all_id:
            ids_fmt = "{:>5d},{:>5d},{:>5d},{:>5d},{:>5d},{:>5d},{:>5d},{:>5d}"
        else:
            ids_fmt = "{:>5d},{:>5d}"
        ids_str = ids_fmt.format(*info["ids"])
        if kstack is None:
            kstack_str = "-"
        else:
            kstack_str = "{:#018x}".format(kstack)
        if info["kcanary"] is None:
            kcanary = "None"
        else:
            kcanary = "{:#018x}".format(info["kcanary"])
        seccomp_enabled = info["seccomp_enabled"]
        if seccomp_enabled is None:
            seccomp = "Unknown"
        elif seccomp_enabled:
            seccomp = "Enabled"
        else:
            seccomp = "Disabled"
        self.out.append("{:#018x} {:<7s} {:<3s} {:<7d} {:<16s} {:#018x} [{:s}] {:<8s} {:<18s} {:<18s}".format(
            task, info["current"] or "-", proctype, pid, comm_string, cred,
            ids_str, seccomp, kstack_str, kcanary,
        ).rstrip())
        if pid:
            self.dump_task_details(info, info["namespace_context"])
        return

    def dump(self):
        tasks = self.ktask.get_tasks(
            include_current=True, threads=self.args.print_thread, all_ids=self.args.print_all_id,
            comm_filter=self.args.filter, task_filter=self.args.task_filter, user_only=self.args.user_process_only,
        )
        self.append_task_legend()
        for task in ProgressBar(tasks, desc="task", disable=self.args.quiet):
            self.dump_task(task)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        if args.all:
            args.print_maps = True
            args.print_regs = True
            args.print_all_id = True
            args.print_thread = True
            args.print_fd = True
            args.print_sighand = True
            args.print_seccomp = True
            args.print_namespace = True

        # initialize
        self.ktask = Kernel.task(args.init_task)
        ret = self.ktask.initialize(**{name: getattr(args, option) for name, option in KernelTask.OPTIONS.items()})
        self.meta = Kernel.export_meta(self, self.ktask.meta)
        for name in self.ktask.disabled:
            setattr(args, KernelTask.OPTIONS[name], False)
        if "files" in self.ktask.disabled and not args.meta:
            warn("Disabled --print-fd: {:s} (see `ktask --print-fd --meta`)".format(self.ktask.disabled["files"]))

        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            self.show_init_task_recovery_hint(args.init_task)
            return

        # skip real parse if specified --meta option
        if args.meta:
            return

        # parse
        self.out = []
        self.dump()
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelFilesCommand(GenericCommand):
    """Display open files for each process (shortcut for `ktask -quF`)."""

    _cmdline_ = "kfiles"
    _category_ = "06-f. Qemu-system/KGDB Cooperation - Linux Task"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        info("Redirect to `ktask -quF`")

        no_pager = ""
        if args.no_pager:
            no_pager = "--no-pager"
        gdb.execute("ktask --user-process-only --print-fd --quiet {:s}".format(no_pager))
        return


@register_command
class KernelSavedRegsCommand(GenericCommand):
    """Display saved registers for each process (shortcut for `ktask -qur`)."""

    _cmdline_ = "kregs"
    _category_ = "06-f. Qemu-system/KGDB Cooperation - Linux Task"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        info("Redirect to `ktask -qur`")

        no_pager = ""
        if args.no_pager:
            no_pager = "--no-pager"
        gdb.execute("ktask --user-process-only --print-regs --quiet {:s}".format(no_pager))
        return


@register_command
class KernelSignalsCommand(GenericCommand):
    """Display signal handlers for each process (shortcut for `ktask -qus`)."""

    _cmdline_ = "ksighands"
    _category_ = "06-f. Qemu-system/KGDB Cooperation - Linux Task"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        info("Redirect to `ktask -qus`")

        no_pager = ""
        if args.no_pager:
            no_pager = "--no-pager"
        gdb.execute("ktask --user-process-only --print-sighand --quiet {:s}".format(no_pager))
        return


@register_command
class KernelNamespacesCommand(GenericCommand):
    """Display namespaces for each process (shortcut for `ktask -quN`)."""

    _cmdline_ = "knamespaces"
    _category_ = "06-f. Qemu-system/KGDB Cooperation - Linux Task"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        info("Redirect to `ktask -quN`")

        no_pager = ""
        if args.no_pager:
            no_pager = "--no-pager"
        gdb.execute("ktask --user-process-only --print-namespace --quiet {:s}".format(no_pager))
        return


@register_command
class KernelCredCommand(GenericCommand, BufferingOutput):
    """Dump the credentials of each task."""

    _cmdline_ = "kcred"
    _category_ = "06-f. Qemu-system/KGDB Cooperation - Linux Task"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("pid", metavar="PID", nargs="?", type=lambda x: int(x, 0), help="the pid of the task to display.")
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-T", "--task-filter", action="append", type=AddressUtil.parse_address, default=[], help="task address filter.")
    parser.add_argument("-c", "--cred-filter", action="append", type=AddressUtil.parse_address, default=[], help="cred address filter.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="comm string REGEXP filter.")
    parser.add_argument("-s", "--shared", action="store_true", help="list the tasks that share the same cred, instead of dumping each cred.")
    parser.add_argument("-v", "--verbose", action="store_true", help="dump each cred in detail even if no task is specified.")
    parser.add_argument("-t", "--print-thread", action="store_true", help="display by thread (LWP), not by process.")
    parser.add_argument("-u", "--user-process-only", action="store_true", help="display user-land process (+ thread) only.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
        "{0:s} 1337",
        "{0:s} 1337 --shared",
        "{0:s} -f 'sh$' -v",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "",
        "Simplified credential structure:",
        "",
        "+-task_struct---+    +--->+-cred--------------------+",
        "| ...           |    |    | usage                   |",
        "| real_cred     |----+    | uid, gid                |",
        "| cred          |----+    | suid, sgid              |",
        "| comm[16]      |         | euid, egid              |",
        "| ...           |         | fsuid, fsgid            |",
        "+---------------+         | securebits              |",
        "                          | cap_inheritable         |",
        "                          | cap_permitted           |",
        "                          | cap_effective           |",
        "                          | cap_bset                |",
        "                          | cap_ambient (v4.3~)     |",
        "                          | (keyrings; CONFIG_KEYS) |",
        "                          | security                |--->LSM blob",
        "                          | user                    |",
        "                          | user_ns                 |--->user_namespace",
        "                          | ucounts (branch/config) |",
        "                          | group_info              |--->+-group_info-+",
        "                          | ...                     |    | usage      |",
        "                          +-------------------------+    | ngroups    |",
        "                                                         | gid[]      |",
        "                                                         +------------+",
        "",
        "`real_cred` is the objective credential, `cred` is the subjective one. They differ only",
        "while the task acts on behalf of another (e.g., inside override_creds()).",
    ]
    _note_ = "\n".join(_note_)

    @Cache.cache_this_session(cache_None=False, per_inferior=True, until_new_objfile=True)
    def initialize(self, print_thread):
        self.meta = []

        task_command = Kernel.task()
        task_ready = task_command.initialize(threads=print_thread)
        self.meta.extend(Kernel.export_meta(self, task_command.meta))
        if not task_ready:
            task_command = None
        if task_command is None:
            return None
        self.task_command = task_command

        self.kcred = task_command.kcred
        if self.kcred.offset_cap is None:
            self.meta.append((self.quiet_err, "Could not find cred->cap_inheritable"))
            return None
        return True

    def dump_cred(self, task, pid, comm, cred, real_cred):
        kcred = self.kcred
        info = kcred.parse(cred)
        if info is None:
            self.err_add_out("Failed to read cred {:#x} of task {:#x}".format(cred, task))
            return

        self.out.append('task: {:#018x} (pid: {:d}, comm: "{:s}")'.format(task, pid, comm))
        self.out.append("  `- cred " + Symbol.format(cred, ksym="prefer", show_address=True, nocolor=True))

        lines = []
        lines.append(("real_cred", Symbol.format(real_cred, ksym="prefer", show_address=True, nocolor=True)))
        lines.append(("usage", "{:d}".format(info.usage)))
        for i, name in enumerate(["uid/gid", "suid/sgid", "euid/egid", "fsuid/fsgid"]):
            lines.append((name, "{:d}/{:d}".format(info.ids[i * 2], info.ids[i * 2 + 1])))
        lines.append(("securebits", "{:#010x} ({:s})".format(info.securebits, kcred.securebits_to_str(info.securebits))))
        for name, value in zip(kcred.cap_members, info.caps):
            lines.append((name, "{:#018x} ({:s})".format(value, kcred.cap_to_str(value))))
        if info.security is not None:
            lines.append(("security", Symbol.format(info.security, ksym="prefer", show_address=True, nocolor=True)))
        if info.user_ns is not None:
            lines.append(("user_ns", Symbol.format(info.user_ns, ksym="prefer", show_address=True, nocolor=True)))
        if info.group_info is not None:
            value = Symbol.format(info.group_info, ksym="prefer", show_address=True, nocolor=True)
            groups = kcred.get_groups_str(info.group_info)
            if groups:
                value += " ({:s})".format(groups)
            lines.append(("group_info", value))

        for i, (name, value) in enumerate(lines):
            if i == len(lines) - 1:
                mark = "`-"
            else:
                mark = "|-"
            self.out.append("     {:s} {:<15s} {:s}".format(mark, name, value))
        self.out.append("")
        return

    def dump_table(self, entries):
        if not self.args.quiet:
            fmt = "{:18s} {:>7s} {:16s} {:18s} {:18s} {:>7s} {:>6s} {:>6s} {:>6s} {:>6s} {:s}"
            legend = ["task", "pid", "comm", "cred", "real_cred", "usage", "uid", "gid", "euid", "egid", "cap_effective"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for task, pid, comm, cred, real_cred in entries:
            info = self.kcred.parse(cred)
            if info is None:
                self.err_add_out("Failed to read cred {:#x} of task {:#x}".format(cred, task))
                continue
            self.out.append("{:#018x} {:>7d} {:16s} {:#018x} {:#018x} {:>7d} {:>6d} {:>6d} {:>6d} {:>6d} {:#018x}".format(
                task, pid, comm, cred, real_cred, info.usage,
                info.ids[0], info.ids[1], info.ids[4], info.ids[5], info.caps[2],
            ))
        return

    def dump_shared(self, entries, cred_map):
        seen = []
        for _task, _pid, _comm, cred, _real_cred in entries:
            if cred not in seen:
                seen.append(cred)

        for cred in seen:
            sharers = cred_map.get(cred, [])
            info = self.kcred.parse(cred)
            if info is None:
                usage = "?"
            else:
                usage = "{:d}".format(info.usage)
            self.out.append("cred: {:s} (usage: {:s}, tasks: {:d})".format(
                Symbol.format(cred, ksym="prefer", show_address=True, nocolor=True), usage, len(sharers),
            ))
            for task, pid, comm, _cred, real_cred in sharers:
                if real_cred == cred:
                    note = ""
                else:
                    note = " (real_cred: {:#x})".format(real_cred)
                self.out.append('     {:#018x} pid: {:<7d} comm: "{:s}"{:s}'.format(task, pid, comm, note))
            self.out.append("")
        return

    def lwp_available(self):
        task_command = self.task_command
        if getattr(task_command, "offset_thread_group", None) is None:
            return False
        if "6.7" <= Kernel.version():
            if getattr(task_command, "offset_signal", None) is None:
                return False
            if getattr(task_command, "offset_thread_head", None) is None:
                return False
        return True

    def collect_entries(self):
        task_command = self.task_command
        task_addrs = KernelTask.get_task_list(task_command.init_task, task_command.offset_tasks)
        if self.args.print_thread and self.lwp_available():
            task_addrs = task_command.add_lwp_task(task_addrs)

        entries = []
        for task in task_addrs:
            try:
                pid = read_int32_from_memory(task + task_command.offset_pid)
                comm = read_cstring_from_memory(task + task_command.offset_comm)
                cred = read_int_from_memory(task + task_command.offset_cred)
                real_cred = read_int_from_memory(task + task_command.offset_real_cred)
                if self.args.user_process_only:
                    mm = read_int_from_memory(task + task_command.offset_mm)
                    if mm == 0 or pid == 0:
                        continue
            except gdb.MemoryError:
                continue
            if not is_valid_addr(cred):
                continue
            entries.append((task, pid, comm, cred, real_cred))
        return entries

    def filter_entries(self, entries):
        args = self.args
        filtered = []
        for entry in entries:
            task, pid, comm, cred, _real_cred = entry
            if args.pid is not None and pid != args.pid:
                continue
            if args.task_filter and task not in args.task_filter:
                continue
            if args.cred_filter and cred not in args.cred_filter:
                continue
            if not GefUtil.matches_regex(comm, args.filter):
                continue
            filtered.append(entry)
        return filtered

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        ret = self.initialize(args.print_thread)
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            return

        if args.meta:
            return

        entries = self.collect_entries()
        if not entries:
            self.quiet_info("Nothing to dump")
            return

        selected = self.filter_entries(entries)
        if not selected:
            err("No task matched")
            return

        self.out = []
        if args.shared:
            cred_map = {}
            for entry in entries:
                cred_map.setdefault(entry[3], []).append(entry)
            self.dump_shared(selected, cred_map)
        elif args.verbose or len(selected) != len(entries):
            for task, pid, comm, cred, real_cred in selected:
                self.dump_cred(task, pid, comm, cred, real_cred)
        else:
            self.dump_table(selected)
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelKeyringCommand(GenericCommand, BufferingOutput):
    """Display the keyrings referenced by tasks, or inspect an arbitrary struct key."""

    _cmdline_ = "kkeyring"
    _category_ = "06-f. Qemu-system/KGDB Cooperation - Linux Task"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("key", metavar="KEY_ADDR", nargs="?", type=AddressUtil.parse_address,
                        help="inspect this `struct key` directly instead of walking task credentials.")
    parser.add_argument("-p", "--pid", type=lambda x: int(x, 0), help="filter by task pid.")
    parser.add_argument("-T", "--task-filter", action="append", type=AddressUtil.parse_address, default=[],
                        help="filter by specific task_struct address.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="comm string REGEXP filter.")
    parser.add_argument("-d", "--max-depth", type=lambda x: int(x, 0), default=6, help="maximum nested keyring depth (default: 6).")
    parser.add_argument("--max-keys", type=lambda x: int(x, 0), default=0x1000, help="maximum number of keys to walk (default: 0x1000).")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display ownership and internal key details.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -p 1337",
        "{0:s} -p 1337 -v",
        "{0:s} -f 'bash$'",
        "{0:s} 0xffff888012345000",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified keyring structures:",
        "",
        "[v3.8~]",
        "+-task_struct-+    +-cred-------------+",
        "| cred        |--->| session_keyring  |----+",
        "+-------------+    | process_keyring  |----+",
        "                   | thread_keyring   |----+--->struct key",
        "                   | request_key_auth |----+",
        "                   +------------------+",
        "[~v3.7]",
        "+-task_struct-+    +-cred-------------+",
        "| cred        |--->| thread_keyring   |---------------------------->struct key",
        "+-------------+    | request_key_auth |---------------------------->struct key",
        "                   | tgcred           |--->+-thread_group_cred-+",
        "                   +------------------+    | session_keyring   |--->struct key",
        "                                           | process_keyring   |--->struct key",
        "                                           +-------------------+",
        "+-key----------------------------+",
        "| usage                          |",
        "| serial                         |",
        "| uid, gid, perm                 |",
        "| expiry                         |",
        "| flags                          |",
        "| state (v4.14~)                 |",
        "| type                           |",
        "| description                    |",
        "| payload.subscriptions (~v3.12) |---->struct keyring_list",
        "| payload.data[0] (auth key)     |---->struct request_key_auth",
        "| keys.root (v3.13~)             |---->assoc_array_ptr",
        "+--------------------------------+",
        "",
        "+-request_key_auth-+",
        "| rcu (v5.3~)      |",
        "| usage (v7.2~)    |",
        "| target_key       |---->struct key (being constructed)",
        "| dest_keyring     |---->struct key",
        "| cred             |---->struct cred (requester)",
        "| callout_info     |",
        "| callout_len      |",
        "| pid              |",
        "| op[8] (v5.0~)    |",
        "+------------------+",
        "",
        "[~v3.12]",
        "+-keyring_list-+",
        "| nkeys        |",
        "| keys[]       |---->struct key ...",
        "+--------------+",
        "",
        "[v3.13~]",
        "keys.root ---> assoc_array_ptr (tagged)",
        "                +-- leaf -----> struct key (bit 1 is set if it is a keyring)",
        "                +-- node -----> +-assoc_array_node-----+",
        "                |               | slots[16]            |---> assoc_array_ptr ...",
        "                |               +----------------------+",
        "                +-- shortcut -> +-assoc_array_shortcut-+",
        "                                | next_node            |---> assoc_array_ptr",
        "                                +----------------------+",
        "",
        "A keyring leaf may itself be another keyring, so the command walks child keys recursively.",
        "The request-key authorisation key held by an upcall helper is shown as the `request` root.",
    ]
    _note_ = "\n".join(_note_)

    KeyInfo = collections.namedtuple(
        "KeyInfo", "address usage serial type_addr type_name description expiry uid gid perm datalen state flags payload",
    )
    KeyRecord = collections.namedtuple("KeyRecord", "root depth parent address info status")
    RequestAuth = collections.namedtuple("RequestAuth", "target target_info dest dest_info cred callout callout_len pid op")

    def type_name(self, type_addr):
        if not type_addr or not is_valid_addr(type_addr):
            return None
        offset = GefUtil.offsetof("key_type", "name")
        name_addr = read_int_from_memory(type_addr + (offset or 0), safe=True)
        if name_addr is None:
            return None
        if not is_valid_addr(name_addr):
            return None
        name = read_cstring_from_memory(name_addr, max_length=0x40)
        if name and re.fullmatch(r"[A-Za-z0-9_.-]{1,63}", name):
            return name
        return None

    def find_type_offset(self, key):
        offset = GefUtil.offsetof("key", "type")
        if offset is not None:
            return offset
        if key is None:
            return None

        keyring_type = Ksym.get_addr("key_type_keyring")
        candidates = []
        for offset in range(0, 0x120, runtime.current_arch.ptrsize):
            type_addr = read_int_from_memory(key + offset, safe=True)
            if type_addr is None:
                break
            if keyring_type is not None and type_addr == keyring_type:
                return offset
            name = self.type_name(type_addr)
            if name:
                symbol = Ksym.get_name(type_addr) or ""
                if symbol.startswith("key_type_"):
                    score = 2
                else:
                    score = 0
                candidates.append((score, -offset, offset))
        if candidates:
            return max(candidates)[2]
        return None

    def find_description_offset(self, key):
        offset = GefUtil.offsetof("key", "description")
        if offset is not None:
            return offset

        kversion = self.kversion
        if "3.13" <= kversion < "5.3":
            return self.offset_type + runtime.current_arch.ptrsize
        if "5.3" <= kversion:
            return self.offset_type + 2 * runtime.current_arch.ptrsize
        if key is None:
            return None

        # Before v3.13 type lived near the front of struct key, while description
        # followed the accounting fields.  It is the first direct printable-string
        # pointer after type on normal and CONFIG_DEBUG_KEYS layouts.
        start = self.offset_type + runtime.current_arch.ptrsize
        for offset in range(start, 0x120, runtime.current_arch.ptrsize):
            address = read_int_from_memory(key + offset, safe=True)
            if address is None:
                break
            if not is_valid_addr(address):
                continue
            value = read_cstring_from_memory(address, max_length=0x100)
            if value and all(c.isprintable() for c in value):
                return offset
        return None

    def find_datalen_offset(self):
        offset = GefUtil.offsetof("key", "datalen")
        if offset is not None:
            return offset

        flags = self.offset_flags
        try:
            magic4 = read_int32_from_memory(self.sample_key + flags - 4)
            magic8 = read_int32_from_memory(self.sample_key + flags - 8)
        except (gdb.MemoryError, OverflowError, TypeError):
            magic4 = magic8 = 0
        if "4.14" <= self.kversion:
            # `state` makes the tail uid/gid/perm/quotalen/datalen/state 18
            # bytes long.  unsigned long alignment adds six bytes of padding
            # on 64-bit targets, but only two on 32-bit targets.  KEY_DEBUGGING
            # consumes that padding on 64-bit and grows the 32-bit layout.
            return flags - (10 if runtime.current_arch.ptrsize == 8 or magic4 == 0x18273645 else 6)
        if magic4 == 0x18273645:
            return flags - 6
        if magic8 == 0x18273645:
            return flags - 10
        return flags - 2

    def initialize_key_layout(self, sample_key=None):
        self.sample_key = sample_key
        self.key_type_keyring = Ksym.get_addr("key_type_keyring") # noqa: V101
        self.offset_type = self.find_type_offset(sample_key)
        if self.offset_type is None:
            self.meta.append((self.quiet_err, "Could not find key->type"))
            return None

        self.offset_description = self.find_description_offset(sample_key)
        if self.offset_description is None:
            self.meta.append((self.quiet_err, "Could not find key->description"))
            return None

        self.offset_flags = GefUtil.offsetof("key", "flags")
        if self.offset_flags is None:
            if self.kversion < "3.13":
                self.offset_flags = self.offset_description - runtime.current_arch.ptrsize
            elif self.kversion < "5.3":
                self.offset_flags = self.offset_type - runtime.current_arch.ptrsize
            else:
                self.offset_flags = self.offset_type - 3 * runtime.current_arch.ptrsize

        self.offset_datalen = self.find_datalen_offset()
        self.offset_perm = GefUtil.offsetof("key", "perm")
        if self.offset_perm is None:
            self.offset_perm = self.offset_datalen - 6
        self.offset_uid = GefUtil.offsetof("key", "uid")
        if self.offset_uid is None:
            self.offset_uid = self.offset_datalen - 14
        self.offset_gid = GefUtil.offsetof("key", "gid")
        if self.offset_gid is None:
            self.offset_gid = self.offset_datalen - 10

        self.offset_expiry = GefUtil.offsetof("key", "expiry")
        if self.offset_expiry is None:
            if "4.15" <= self.kversion:
                time_size = 8
            else:
                time_size = runtime.current_arch.ptrsize
            if "3.5" <= self.kversion:
                time_fields = 2
            else:
                time_fields = 1
            self.offset_expiry = self.offset_uid - time_size * time_fields
        if "4.15" <= self.kversion:
            self.sizeof_expiry = 8
        else:
            self.sizeof_expiry = runtime.current_arch.ptrsize

        self.offset_state = GefUtil.offsetof("key", "state")
        if self.offset_state is None and "4.14" <= self.kversion:
            self.offset_state = self.offset_datalen + 2

        self.offset_payload = GefUtil.offsetof("key", "payload")
        if self.offset_payload is None:
            if self.kversion < "3.13":
                self.offset_payload = self.offset_description + 3 * runtime.current_arch.ptrsize
            elif self.kversion < "4.4":
                # desc_len and the two-word type_data precede payload.
                self.offset_payload = self.offset_description + 4 * runtime.current_arch.ptrsize
            elif self.kversion < "5.3":
                # keyring_index_key has an extra desc_len word after description.
                self.offset_payload = self.offset_description + 2 * runtime.current_arch.ptrsize
            else:
                self.offset_payload = self.offset_description + runtime.current_arch.ptrsize

        self.offset_keys_root = GefUtil.offsetof("key", "keys.root")
        if self.offset_keys_root is None and "3.13" <= self.kversion:
            # keys follows desc_len and either type_data (~v4.3) or name_link (v4.4~).
            if self.kversion < "5.3":
                self.offset_keys_root = self.offset_description + 4 * runtime.current_arch.ptrsize
            else:
                self.offset_keys_root = self.offset_description + 3 * runtime.current_arch.ptrsize

        for name in ("type", "description", "expiry", "uid", "gid", "perm", "datalen", "flags", "payload"):
            self.meta.append((self.quiet_info, "offsetof(key, {:s}): {:#x}".format(name, getattr(self, "offset_" + name))))
        if self.offset_keys_root is not None:
            self.meta.append((self.quiet_info, "offsetof(key, keys.root): {:#x}".format(self.offset_keys_root)))
        return True

    def initialize_tasks(self):
        task_command = Kernel.task()
        task_ready = task_command.initialize(threads=True)
        self.meta.extend(Kernel.export_meta(self, task_command.meta))
        if not task_ready:
            task_command = None
        if task_command is None:
            return None
        self.task_command = task_command
        kcred = task_command.kcred
        if kcred.offset_cap is None:
            self.meta.append((self.quiet_err, "Could not resolve the credential keyring layout"))
            return None

        ptrsize = runtime.current_arch.ptrsize
        if self.kversion < "3.8":
            key_count = 3
        else:
            key_count = 4
        base = align_to_ptrsize(kcred.offset_cap + 8 * len(kcred.cap_members) + 1)
        end = base + key_count * ptrsize
        expected_user_ns = {end + ptrsize, end + 2 * ptrsize}
        # Data symbols may be omitted when CONFIG_KALLSYMS_ALL=n, so use the
        # globally visible key allocator as a second signal and retain the cred
        # tail check where ktask could resolve user_ns.  The function-symbol
        # path is especially important on v3.x targets with sparse namespace
        # state, while the layout path handles heavily stripped CTF kernels.
        has_keys = any(Ksym.get_addr(name) is not None for name in ("key_type_keyring", "key_alloc"))
        has_keys |= kcred.offset_user_ns in expected_user_ns
        if not has_keys:
            self.meta.append((self.quiet_info, "CONFIG_KEYS seems to be n"))
            self.cred_key_offsets = None
            return True

        self.meta.append((self.quiet_info, "CONFIG_KEYS seems to be y"))
        if self.kversion < "3.8":
            offsets = {
                "thread": self.cred_member_offset("thread_keyring", base),
                "request": self.cred_member_offset("request_key_auth", base + ptrsize),
                "tgcred": self.cred_member_offset("tgcred", base + 2 * ptrsize),
            }
            self.cred_key_offsets = offsets
            self.tgcred_session_offset = self.tgcred_member_offset("session_keyring", align(12, ptrsize))
            self.tgcred_process_offset = self.tgcred_member_offset("process_keyring", self.tgcred_session_offset + ptrsize)
            self.meta.append((self.quiet_info, "offsetof(cred, thread_keyring): {:#x}".format(offsets["thread"])))
            self.meta.append((self.quiet_info, "offsetof(cred, request_key_auth): {:#x}".format(offsets["request"])))
            self.meta.append((self.quiet_info, "offsetof(cred, tgcred): {:#x}".format(offsets["tgcred"])))
            self.meta.append((self.quiet_info, "offsetof(thread_group_cred, session_keyring): {:#x}".format(self.tgcred_session_offset)))
            self.meta.append((self.quiet_info, "offsetof(thread_group_cred, process_keyring): {:#x}".format(self.tgcred_process_offset)))
        else:
            self.cred_key_offsets = {
                "session": self.cred_member_offset("session_keyring", base),
                "process": self.cred_member_offset("process_keyring", base + ptrsize),
                "thread": self.cred_member_offset("thread_keyring", base + 2 * ptrsize),
                "request": self.cred_member_offset("request_key_auth", base + 3 * ptrsize),
            }
            for name in ("session", "process", "thread"):
                self.meta.append((self.quiet_info, "offsetof(cred, {:s}_keyring): {:#x}".format(name, self.cred_key_offsets[name])))
            self.meta.append((self.quiet_info, "offsetof(cred, request_key_auth): {:#x}".format(self.cred_key_offsets["request"])))
        return True

    @staticmethod
    def cred_member_offset(member, fallback):
        offset = GefUtil.offsetof("cred", member)
        if offset is not None:
            return offset
        else:
            return fallback

    @staticmethod
    def tgcred_member_offset(member, fallback):
        offset = GefUtil.offsetof("thread_group_cred", member)
        if offset is not None:
            return offset
        else:
            return fallback

    def task_roots(self, cred):
        if self.cred_key_offsets is None:
            return [("thread", 0), ("process", 0), ("session", 0), ("request", 0)]
        try:
            if self.kversion < "3.8":
                thread = read_int_from_memory(cred + self.cred_key_offsets["thread"])
                tgcred = read_int_from_memory(cred + self.cred_key_offsets["tgcred"])
                if tgcred and is_valid_addr(tgcred):
                    session = read_int_from_memory(tgcred + self.tgcred_session_offset)
                    process = read_int_from_memory(tgcred + self.tgcred_process_offset)
                else:
                    session = process = 0
            else:
                thread = read_int_from_memory(cred + self.cred_key_offsets["thread"])
                process = read_int_from_memory(cred + self.cred_key_offsets["process"])
                session = read_int_from_memory(cred + self.cred_key_offsets["session"])
            request = read_int_from_memory(cred + self.cred_key_offsets["request"])
        except (gdb.MemoryError, OverflowError):
            return None
        return [("thread", thread), ("process", process), ("session", session), ("request", request)]

    def collect_tasks(self):
        command = self.task_command
        task_addrs = KernelTask.get_task_list(command.init_task, command.offset_tasks)
        if getattr(command, "offset_thread_group", None) is not None:
            if self.kversion < "6.7" or (getattr(command, "offset_signal", None) is not None and
                                         getattr(command, "offset_thread_head", None) is not None):
                task_addrs = command.add_lwp_task(task_addrs)

        entries = []
        for task in task_addrs:
            try:
                pid = read_int32_from_memory(task + command.offset_pid)
                comm = read_cstring_from_memory(task + command.offset_comm) or "???"
                cred = read_int_from_memory(task + command.offset_cred)
            except (gdb.MemoryError, OverflowError):
                continue
            if self.args.pid is not None and pid != self.args.pid:
                continue
            if self.args.task_filter and task not in self.args.task_filter:
                continue
            if not GefUtil.matches_regex(comm, self.args.filter):
                continue
            roots = self.task_roots(cred)
            if roots is not None:
                entries.append((task, pid, comm, cred, roots))
        return entries

    def read_key(self, address):
        try:
            usage = read_int32_from_memory(address)
            serial = read_int32_from_memory(address + 4, signed=True)
            type_addr = read_int_from_memory(address + self.offset_type)
            type_name = self.type_name(type_addr)
            description_addr = read_int_from_memory(address + self.offset_description)
            if description_addr:
                description = read_cstring_from_memory(description_addr, max_length=0x100)
            else:
                description = None
            if self.sizeof_expiry == 8:
                expiry = read_int64_from_memory(address + self.offset_expiry, signed=True)
            else:
                expiry = read_int32_from_memory(address + self.offset_expiry, signed=True)
            uid = read_int32_from_memory(address + self.offset_uid)
            gid = read_int32_from_memory(address + self.offset_gid)
            perm = read_int32_from_memory(address + self.offset_perm)
            datalen = read_int16_from_memory(address + self.offset_datalen)
            state = None
            if self.offset_state is not None:
                state = read_int16_from_memory(address + self.offset_state, signed=True)
            flags = read_int_from_memory(address + self.offset_flags)
            payload = read_int_from_memory(address + self.offset_payload)
        except (gdb.MemoryError, OverflowError):
            return None
        if type_name is None:
            return None
        return self.KeyInfo(address, usage, serial, type_addr, type_name, description or "[anon]",
                            expiry, uid, gid, perm, datalen, state, flags, payload)

    def read_request_key_auth(self, info):
        if not info.payload or not is_valid_addr(info.payload):
            return None
        try:
            target_serial = int(info.description, 16)
        except ValueError:
            return None

        ptrsize = runtime.current_arch.ptrsize
        fields = ("target_key", "dest_keyring", "cred", "callout_info", "callout_len", "pid", "op")
        offsets = [GefUtil.offsetof("request_key_auth", name) for name in fields]
        if offsets[0] is not None:
            bases = [offsets[0]]
        else:
            # rcu_head was added in front of target_key in v5.3, and refcount_t usage in v7.2.
            bases = [0, 2 * ptrsize, 3 * ptrsize]
        for base in bases:
            positions = [offset if offset is not None else base + delta for offset, delta in zip(
                offsets, (0, ptrsize, 2 * ptrsize, 3 * ptrsize, 4 * ptrsize, 5 * ptrsize, 5 * ptrsize + 4)
            )]
            address = info.payload
            try:
                target = read_int_from_memory(address + positions[0])
                dest = read_int_from_memory(address + positions[1])
                cred = read_int_from_memory(address + positions[2])
                callout_info = read_int_from_memory(address + positions[3])
                callout_len = read_int_from_memory(address + positions[4])
                pid = read_int32_from_memory(address + positions[5])
                op = read_memory(address + positions[6], 8)
            except (gdb.MemoryError, OverflowError):
                continue
            # The auth key is described by the target key serial in hex.
            if is_valid_addr(target):
                target_info = self.read_key(target)
            else:
                target_info = None
            if target_info is None or target_info.serial != target_serial:
                continue
            if dest and is_valid_addr(dest):
                dest_info = self.read_key(dest)
            else:
                dest_info = None
            callout = None
            if callout_info and is_valid_addr(callout_info):
                callout = read_memory(callout_info, min(callout_len, 0x40), safe=True)
            # op[] was added in v5.0.
            if b"\0" in op:
                op = op.split(b"\0")[0]
            else:
                op = b""
            if re.fullmatch(rb"[a-z]{1,7}", op):
                op = op.decode()
            else:
                op = None
            return self.RequestAuth(target, target_info, dest, dest_info, cred, callout, callout_len, pid, op)
        return None

    @staticmethod
    def permission_string(perm):
        names = "vrwsla"
        groups = []
        for label, shift in (("pos", 24), ("usr", 16), ("grp", 8), ("oth", 0)):
            bits = (perm >> shift) & 0x3f
            groups.append("{:s}={:s}".format(label, "".join(name if bits & (1 << i) else "-" for i, name in enumerate(names))))
        return "{:#010x} {:s}".format(perm, "/".join(groups))

    def walk_assoc_array(self, root):
        leaves = []
        if root and not root & 1:
            self.walk_error = "invalid assoc_array root {:#x}".format(root)
            return leaves
        stack = [(root, 0)]
        seen = set()
        ptrsize = runtime.current_arch.ptrsize
        while stack and len(leaves) < self.args.max_keys:
            pointer, parent = stack.pop()
            if not pointer:
                continue
            if not pointer & 1:
                # Keyring leaves are tagged with KEYRING_PTR_SUBTYPE (bit 1).
                leaf = pointer & ~2
                if leaf not in leaves:
                    leaves.append(leaf)
                continue
            base = pointer & ~3
            if base in seen:
                self.walk_error = "assoc_array node at {:#x} is linked twice".format(base)
                continue
            if len(seen) >= self.args.max_keys:
                self.walk_error = "too many assoc_array nodes"
                break
            seen.add(base)
            try:
                back_pointer = read_int_from_memory(base)
                if back_pointer != parent:
                    self.walk_error = "assoc_array node at {:#x} has back_pointer {:#x} (expected {:#x})".format(
                        base, back_pointer, parent,
                    )
                    continue
                if pointer & 2:
                    if ptrsize == 8:
                        offset_next = 2 * ptrsize
                    else:
                        offset_next = 3 * ptrsize
                    stack.append((read_int_from_memory(base + offset_next), pointer))
                else:
                    offset_slots = 2 * ptrsize
                    for slot in range(15, -1, -1):
                        stack.append((read_int_from_memory(base + offset_slots + slot * ptrsize), pointer))
            except (gdb.MemoryError, OverflowError):
                self.walk_error = "unreadable assoc_array node at {:#x}".format(base)
        return leaves

    def keyring_children(self, info):
        if info.type_name != "keyring":
            return []
        try:
            if self.kversion < "3.13":
                keylist = info.payload
                if not keylist:
                    return []
                nkeys = read_int16_from_memory(keylist + 2 * runtime.current_arch.ptrsize + 2)
                if nkeys > self.args.max_keys:
                    self.walk_error = "keyring_list has implausible nkeys={:d}".format(nkeys)
                    nkeys = self.args.max_keys
                keys_offset = align_to_ptrsize(2 * runtime.current_arch.ptrsize + 6)
                return [read_int_from_memory(keylist + keys_offset + i * runtime.current_arch.ptrsize) for i in range(nkeys)]
            root = read_int_from_memory(info.address + self.offset_keys_root)
            return self.walk_assoc_array(root)
        except (gdb.MemoryError, OverflowError):
            self.walk_error = "unreadable keyring payload at {:#x}".format(info.address + self.offset_payload)
            return []

    def collect_key(self, records, root, address, depth, parent, ancestors, seen):
        if self.collect_count >= self.args.max_keys:
            self.key_limit_reached = True
            return
        self.collect_count += 1

        info = self.read_key(address)
        if info is None:
            records.append(self.KeyRecord(root, depth, parent, address, None, "unreadable"))
            return
        if address in ancestors:
            records.append(self.KeyRecord(root, depth, parent, address, info, "cycle"))
            return
        if address in seen:
            records.append(self.KeyRecord(root, depth, parent, address, info, "seen"))
            return

        seen.add(address)
        records.append(self.KeyRecord(root, depth, parent, address, info, None))
        children = self.keyring_children(info)
        if depth >= self.args.max_depth:
            if children:
                self.depth_limit_reached = True
            return

        next_ancestors = ancestors | {address}
        for child in children:
            self.collect_key(records, root, child, depth + 1, address, next_ancestors, seen)
        if self.walk_error:
            self.walk_errors.append("{:s}: {:s}".format(root, self.walk_error))
            self.walk_error = None
        return

    def collect_roots(self, roots):
        records = []
        seen = set()
        for name, address in roots:
            if address:
                self.collect_key(records, name, address, 0, 0, set(), seen)
        return records

    @staticmethod
    def record_description(record):
        if record.info is None:
            description = "[unreadable struct key]"
        else:
            description = repr(record.info.description)
        if record.status:
            description += " [{:s}]".format(record.status)
        return description

    @staticmethod
    def serial_string(serial):
        return "{:d} ({:#x})".format(serial, serial & 0xffff_ffff)

    def append_records(self, records):
        address_width = 2 + 2 * runtime.current_arch.ptrsize
        root_width = max([len("root")] + [len(record.root) for record in records])
        serial_width = max(
            [len("serial (dec/hex)")] + [len(self.serial_string(record.info.serial)) for record in records if record.info],
        )
        type_width = max([len("type")] + [len(record.info.type_name) for record in records if record.info])
        fmt = "{{:{:d}s}} {{:5s}} {{:{:d}s}} {{:{:d}s}} {{:{:d}s}} {{:6s}} {{:s}}".format(
            root_width, address_width, serial_width, type_width,
        )
        if not self.args.quiet:
            self.out.append(GefUtil.make_legend(fmt.format(
                "root", "depth", "key", "serial (dec/hex)", "type", "size", "description",
            )))

        for record in records:
            info = record.info
            self.out.append(fmt.format(
                record.root,
                str(record.depth),
                "{:#x}".format(record.address),
                self.serial_string(info.serial) if info else "-",
                info.type_name if info else "-",
                str(info.datalen) if info else "-",
                self.record_description(record),
            ))
            if self.args.verbose and info:
                if not record.parent:
                    parent = "none"
                else:
                    parent = "{:#x}".format(record.parent)
                # Newer kernels use TIME64_MAX instead of 0 for keys that never expire.
                if info.expiry in (0, (1 << 63) - 1):
                    expiry = "never"
                else:
                    expiry = str(info.expiry)
                self.out.append("  link:  parent={:s} type={:#x}".format(parent, info.type_addr))
                self.out.append("  owner: uid={:d} gid={:d} refcount={:d}".format(info.uid, info.gid, info.usage))
                self.out.append("  perm:  {:s}".format(self.permission_string(info.perm)))
                if info.state is None:
                    state = "n/a"
                else:
                    state = str(info.state)
                self.out.append("  state: expiry={:s} state={:s} flags={:#x}".format(expiry, state, info.flags))
                if info.type_name != "keyring":
                    self.out.append("  data:  payload={:#x}".format(info.payload))
                if info.type_name == ".request_key_auth":
                    self.append_request_key_auth(info)
        return

    def append_request_key_auth(self, info):
        auth = self.read_request_key_auth(info)
        if auth is None:
            self.out.append("  auth:  [could not decode struct request_key_auth]")
            return

        def key_string(address, key_info):
            if not address:
                return "none"
            if key_info is None:
                return "{:#x} [unreadable struct key]".format(address)
            return "{:#x} ({:s} {:s} {!r})".format(address, self.serial_string(key_info.serial), key_info.type_name, key_info.description)

        self.out.append("  auth:  target={:s}".format(key_string(auth.target, auth.target_info)))
        self.out.append("  auth:  dest_keyring={:s}".format(key_string(auth.dest, auth.dest_info)))
        if auth.op is None:
            op = "n/a"
        else:
            op = auth.op
        self.out.append("  auth:  cred={:#x} pid={:d} op={:s}".format(auth.cred, auth.pid, op))
        if auth.callout is None:
            callout = "none"
        else:
            callout = "{!r} ({:d} bytes)".format(auth.callout, auth.callout_len)
        self.out.append("  auth:  callout_info={:s}".format(callout))
        return

    def append_walk_warnings(self):
        if self.key_limit_reached:
            self.out.append("[!] key limit reached ({:d})".format(self.args.max_keys))
        if self.depth_limit_reached:
            self.out.append("[!] depth limit reached ({:d})".format(self.args.max_depth))
        self.out.extend("[!] " + message for message in self.walk_errors)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")
        if args.max_depth < 0 or args.max_keys <= 0:
            err("--max-depth must be non-negative and --max-keys must be positive")
            return

        self.args = args
        self.meta = []
        self.kversion = Kernel.version()
        if self.kversion is None:
            self.quiet_err("Could not find Linux kernel")
            return

        entries = []
        sample_key = args.key
        if args.key is None:
            if not self.initialize_tasks():
                for func, line in self.meta:
                    func(line)
                return
            entries = self.collect_tasks()
            sample_key = next((address for entry in entries for _name, address in entry[4] if address), None)

        if sample_key is not None:
            key_layout = self.initialize_key_layout(sample_key)
        else:
            key_layout = None
        if args.meta:
            for func, line in self.meta:
                func(line)
            return
        if sample_key is not None and not key_layout:
            for func, line in self.meta:
                func(line)
            return

        self.out = []
        self.collect_count = 0
        self.key_limit_reached = False
        self.depth_limit_reached = False
        self.walk_errors = []
        self.walk_error = None
        if args.key is not None:
            records = []
            self.collect_key(records, "direct", args.key, 0, 0, set(), set())
            self.append_records(records)
        else:
            selected = [entry for entry in entries if any(address for _name, address in entry[4])]
            if not selected:
                self.quiet_info("No task has an attached keyring")
                return
            for task, pid, comm, cred, roots in selected:
                title = 'task {:#x} pid={:d} comm="{:s}"'.format(task, pid, comm)
                if args.verbose:
                    title += " cred={:#x}".format(cred)
                self.out.append(titlify(title))
                self.append_records(self.collect_roots(roots))
                self.out.append("")
        self.append_walk_warnings()
        self.print_output(check_terminal_size=True)
        return



@register_command
class KernelSchedCommand(GenericCommand, BufferingOutput):
    """Dump the scheduler state of each task (cpu, state, class, priority, policy)."""

    _cmdline_ = "ksched"
    _category_ = "06-f. Qemu-system/KGDB Cooperation - Linux Task"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("target", metavar="PID|TASK_ADDRESS", nargs="?",
                        help="dump a single task in detail, selected by its pid or task_struct address.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[], help="comm string REGEXP filter.")
    parser.add_argument("-t", "--print-thread", action="store_true", help="display by thread (LWP), not by process.")
    parser.add_argument("-u", "--user-process-only", action="store_true", help="display user-land process (+ thread) only.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}            # per-cpu current tasks and a table of every task",
        "{0:s} 1337       # dump the scheduler state of the task whose pid is 1337",
        "{0:s} -f bash    # filter the table by comm",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n unless vmlinux with debug information is loaded.",
        "",
        "Without debug information, `state`, the prio cluster and the scheduler class are resolved on",
        "every supported version, `on_rq` up to v7.1, and `policy` on v5.3 or later. The scheduler class",
        "needs the `*_sched_class` symbols (CONFIG_KALLSYMS_ALL=y). The other fields (`on_cpu`, `cpu`)",
        "are shown only when debug information is loaded. The running cpu of each current task comes from",
        "`kcurrent`, which reads it from the cpu context rather than from `task_struct`.",
        "The exit state is included when its offset can be resolved; `--meta` reports a warning otherwise.",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self):
        self.meta = []
        task_command = Kernel.task()
        task_ready = task_command.initialize(threads=self.args.print_thread)
        self.meta.extend(Kernel.export_meta(self, task_command.meta))
        if not task_ready:
            task_command = None
        if task_command is None:
            return None
        self.task_command = task_command

        self.ksched = Kernel.sched()
        task_addrs = KernelTask.get_task_list(task_command.init_task, task_command.offset_tasks)
        ret = self.ksched.initialize(task_command, task_addrs)
        self.meta.extend(Kernel.export_meta(self, self.ksched.meta))
        if not ret:
            return None
        return True

    def get_current_map(self):
        """Run `kcurrent` once, returning its "current" lines and a {task: cpu_label} map."""
        try:
            res = gdb.execute("kcurrent --quiet", to_string=True)
        except gdb.error:
            res = ""

        lines = []
        current_map = {}
        for line in Color.remove_color(res).splitlines():
            line = line.strip()
            r = re.search(r"current \(([^)]+)\): (0x\S+) (.*)", line)
            if r:
                lines.append(line)
                current_map[int(r.group(2), 16)] = r.group(1)
                continue
            r = re.search(r"current: (0x\S+) (.*)", line)
            if r:
                lines.append("current (cpu0): " + line[len("current: "):])
                current_map[int(r.group(1), 16)] = "cpu0"
            elif line.startswith("current ("):
                lines.append(line) # "unavailable (...)"
        return lines, current_map

    def collect_entries(self):
        task_command = self.task_command
        task_addrs = KernelTask.get_task_list(task_command.init_task, task_command.offset_tasks)
        if self.args.print_thread and self.lwp_available():
            task_addrs = task_command.add_lwp_task(task_addrs)

        entries = []
        for task in task_addrs:
            try:
                pid = read_int32_from_memory(task + task_command.offset_pid)
                comm = read_cstring_from_memory(task + task_command.offset_comm)
                if self.args.user_process_only:
                    mm = read_int_from_memory(task + task_command.offset_mm)
                    if mm == 0 or pid == 0:
                        continue
            except gdb.MemoryError:
                continue
            entries.append((task, pid, comm))
        return entries

    def lwp_available(self):
        task_command = self.task_command
        if getattr(task_command, "offset_thread_group", None) is None:
            return False
        if "6.7" <= Kernel.version():
            if getattr(task_command, "offset_signal", None) is None:
                return False
            if getattr(task_command, "offset_thread_head", None) is None:
                return False
        return True

    def cpu_str(self, task, info, current_map):
        if task in current_map:
            label = current_map[task]
            if label.startswith("cpu"):
                return label[3:]
            return label
        if info.cpu is not None:
            return "{:d}".format(info.cpu)
        if Kernel.per_cpu().is_up:
            return "0" # CONFIG_SMP=n runs every task on cpu0
        return "?"

    def dump_table(self, entries, current_map):
        ksched = self.ksched
        if not self.args.quiet:
            fmt = "{:1s} {:18s} {:>7s} {:16s} {:>5s} {:>5s} {:>4s} {:>8s} {:>5s} {:>3s}"
            legend = ["", "task", "pid", "comm", "state", "class", "prio", "policy", "on_rq", "cpu"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for task, pid, comm in entries:
            info = ksched.parse(task)
            if task in current_map:
                mark = "*"
            else:
                mark = " "
            class_name = info.class_name or "?"
            if info.prio is None:
                prio = "?"
            else:
                prio = "{:d}".format(info.prio)
            if info.policy_name is None:
                policy = "?"
            else:
                policy = info.policy_name.replace("SCHED_", "")
            if info.on_rq is None:
                on_rq = "?"
            else:
                on_rq = "{:d}".format(info.on_rq)
            self.out.append("{:1s} {:#018x} {:>7d} {:16s} {:>5s} {:>5s} {:>4s} {:>8s} {:>5s} {:>3s}".format(
                mark, task, pid, comm, ksched.state_to_letter(info.state), class_name,
                prio, policy, on_rq, self.cpu_str(task, info, current_map),
            ))
        return

    def dump_one(self, task, pid, comm, current_map):
        ksched = self.ksched
        info = ksched.parse(task)
        lines = [("task", "{:#018x}".format(task)), ("comm", comm), ("pid", "{:d}".format(pid))]
        if info.state is not None:
            lines.append(("state", "{:s} ({:#x})".format(info.state_name, info.state)))
        if info.class_name is not None:
            name = next((n for a, n in ksched.class_addrs.items() if a == info.sched_class), "")
            lines.append(("class", "{:s} ({:s})".format(info.class_name, name)))
        for name in ("prio", "static_prio", "normal_prio", "rt_priority"):
            value = getattr(info, name)
            if value is not None:
                lines.append((name, "{:d}".format(value)))
        if info.policy is not None:
            lines.append(("policy", "{:s} ({:d})".format(info.policy_name, info.policy & ~ksched.SCHED_RESET_ON_FORK)))
        if info.on_rq is not None:
            lines.append(("on_rq", "{:d}".format(info.on_rq)))
        if info.on_cpu is not None:
            lines.append(("on_cpu", "{:d}".format(info.on_cpu)))
        cpu = self.cpu_str(task, info, current_map)
        if cpu != "?":
            lines.append(("cpu", cpu))
        for name, value in lines:
            self.out.append("{:<12s} {:s}".format(name, value))
        return

    def resolve_target(self, entries, current_map):
        target = self.args.target
        try:
            addr = AddressUtil.parse_address(target)
        except Exception:
            addr = None
        for task, pid, comm in entries:
            if addr is not None and task == addr:
                return task, pid, comm
        try:
            pid_want = int(target, 10 if target.isdigit() else 0)
        except ValueError:
            pid_want = None
        if pid_want is not None:
            for task, pid, comm in entries:
                if pid == pid_want:
                    return task, pid, comm
        # the idle task of each secondary cpu is not linked from init_task, but kcurrent shows it
        if addr is not None and addr in current_map:
            task_command = self.task_command
            pid = read_int32_from_memory(addr + task_command.offset_pid, safe=True)
            comm = read_cstring_from_memory(addr + task_command.offset_comm)
            if pid is not None:
                return addr, pid, comm
        return None

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        ret = self.initialize()
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            return
        if args.meta:
            return

        entries = self.collect_entries()
        if not entries:
            self.quiet_info("Nothing to dump")
            return

        self.out = []
        current_lines, current_map = self.get_current_map()

        if args.target is not None:
            found = self.resolve_target(entries, current_map)
            if found is None:
                err("No task matched `{:s}`".format(args.target))
                return
            self.dump_one(found[0], found[1], found[2], current_map)
            self.print_output(check_terminal_size=True)
            return

        if current_lines and not args.quiet:
            self.out.append("current:")
            for line in current_lines:
                self.out.append("  " + line)
            self.out.append("")

        selected = entries
        if args.filter:
            selected = [e for e in entries if GefUtil.matches_regex(e[2], args.filter)]
        if not selected:
            err("No task matched")
            return
        self.dump_table(selected, current_map)
        self.print_output(check_terminal_size=True)
        return
