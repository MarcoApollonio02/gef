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
from gef.core.color import info, titlify
from gef.core.instruction import Disasm
from gef.core.kernel import Kernel
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
from gef.core.utils import GefUtil, align_to_ptrsize, slice_unpack


@register_command
class KernelTaskCommand(GenericCommand, BufferingOutput):
    """Display process list."""

    _cmdline_ = "ktask"
    _category_ = "06-f. Qemu-system/KGDB Cooperation - Linux Task"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[],
                        help="comm string REGEXP filter.")
    parser.add_argument("-T", "--task-filter", action="append", type=AddressUtil.parse_address, default=[],
                        help="task address filter.")
    parser.add_argument("-m", "--print-maps", action="store_true",
                        help="print memory map for each user-land process.")
    parser.add_argument("-r", "--print-regs", action="store_true",
                        help="print general registers saved on kstack for each user-land process.")
    parser.add_argument("-i", "--print-all-id", action="store_true",
                        help="print suid, sgid, euid, egid, fsuid and fsgid.")
    parser.add_argument("-t", "--print-thread", action="store_true",
                        help="display by thread (LWP), not by process.")
    parser.add_argument("-F", "--print-fd", action="store_true",
                        help="print file descriptors for each user process.")
    parser.add_argument("-s", "--print-sighand", action="store_true",
                        help="print signal handlers for each user process.")
    parser.add_argument("-S", "--print-seccomp", action="store_true",
                        help="dump the seccomp filter. If the tool is available, it dumps orig_prog; otherwise, it disassembles bpf_func.")
    parser.add_argument("-N", "--print-namespace", action="store_true",
                        help="print namespaces for each user process.")
    parser.add_argument("-u", "--user-process-only", action="store_true",
                        help="display user-land process (+ thread) only.")
    parser.add_argument("--init-task", type=AddressUtil.parse_address,
                        help="specifies the address of init_task.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("--all", action="store_true", help="enable all option.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n.",
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

    def __init__(self):
        super().__init__()
        # task_struct
        self.offset_tasks = None
        self.offset_mm = None
        self.offset_stack = None
        self.offset_pid = None
        self.offset_kcanary = None
        self.offset_group_leader = None
        self.offset_thread_group = None
        self.offset_comm = None
        self.offset_cred = None
        self.offset_files = None
        self.offset_sighand = None
        self.offset_nsproxy = None
        self.offset_signal = None
        self.offset_seccomp = None
        # files_struct
        self.offset_fdt = None
        # kstack
        self.offset_ptregs = None
        # cred
        self.offset_uid = None
        self.offset_user_ns = None
        # vm_area_struct
        self.offset_vm_mm = None
        self.offset_vm_flags = None
        self.offset_vm_file = None
        # file
        self.offset_mnt = None
        self.offset_dentry = None
        # dentry
        self.offset_d_iname = None
        self.offset_d_parent = None
        self.offset_d_inode = None
        # inode
        self.offset_i_ino = None
        # signal
        self.offset_thread_head = None
        # sighand_struct
        self.offset_action = None
        self.sizeof_action = None
        # seccomp_filter
        self.offset_prev = None
        self.offset_prog = None
        # bpf_prog
        self.offset_bpf_func = None
        self.offset_orig_prog = None
        return

    def get_offset_tasks(self, init_task):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).tasks")
            )
        except gdb.error:
            pass

        # slow path
        # search for init_task->tasks
        for i in range(0x200):
            offset_tasks = runtime.current_arch.ptrsize * i
            if is_double_link_list(init_task + offset_tasks, min_len=5):
                return offset_tasks
        return None

    def get_task_list(self, init_task, offset_tasks):
        pos = init_task + offset_tasks
        task_list = [pos]
        # validating candidate offset
        while True:
            try:
                pos = read_int_from_memory(pos)
            except gdb.MemoryError:
                return None
            if pos in task_list:
                break
            task_list.append(pos)
        return [x - offset_tasks for x in task_list]

    def get_offset_mm(self, task_addr, offset_tasks):
        """
        struct task_struct {
            ...
            struct list_head tasks;
        #ifdef CONFIG_SMP
            struct plist_node {
                int prio;
                struct list_head prio_list;
                struct list_head node_list;
            } pushable_tasks;
            struct rb_node {
                unsigned long __rb_parent_color;
                struct rb_node *rb_right;
                struct rb_node *rb_left;
            } pushable_dl_tasks; // v3.14~
        #endif
            struct mm_struct *mm;
            struct mm_struct *active_mm;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).mm")
            )
        except gdb.error:
            pass

        # slow path
        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        if kversion < "6.17":
            offset_mm = offset_tasks + 2 * runtime.current_arch.ptrsize
            r = read_int_from_memory(task_addr + offset_mm)
            if 0 < r <= 0xffff:
                # maybe prio, so CONFIG_SMP is y
                if "3.14" <= kversion:
                    offset_mm = offset_tasks + 10 * runtime.current_arch.ptrsize
                else:
                    offset_mm = offset_tasks + 7 * runtime.current_arch.ptrsize
        else:
            offset_mm = offset_tasks + 10 * runtime.current_arch.ptrsize
        return offset_mm

    def get_offset_comm(self, task_addrs):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).comm")
            )
        except gdb.error:
            pass

        # slow path
        for i in range(0x300):
            offset_comm = i * runtime.current_arch.ptrsize
            valid = True
            for task in task_addrs:
                if not is_ascii_string(task + offset_comm):
                    valid = False
                    break
                s = read_cstring_from_memory(task + offset_comm)
                # very common name, so for speeding up, we assume that offset is found
                if s == "swapper/0":
                    break
                if len(s) < 2:
                    valid = False
                    break
            if valid:
                return offset_comm
        return None

    def get_offset_cred(self, task_addrs, offset_comm):
        """
        struct task_struct {
            ...
            const struct cred __rcu *real_cred; // These may point to the same address
            const struct cred __rcu *cred;      // These may point to the same address
        #ifdef CONFIG_KEYS
            struct key *cached_requested_key;
        #endif
            char comm[TASK_COMM_LEN];
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).cred")
            )
        except gdb.error:
            pass

        # slow path
        # backward search from `comm`
        for i in range(0x2):
            offset_cred = offset_comm - ((i + 1) * runtime.current_arch.ptrsize)
            for task in task_addrs:
                val1 = read_int_from_memory(task + offset_cred)
                val2 = read_int_from_memory(task + offset_cred - runtime.current_arch.ptrsize)
                if val1 == val2 and val1 != 0:
                    return offset_cred
        return None

    def get_offset_stack(self, task_addrs):
        """
        struct task_struct {
            ...
        #ifdef CONFIG_THREAD_INFO_IN_TASK
            struct thread_info thread_info;
        #endif
            volatile long state;
            void *stack;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).stack")
            )
        except gdb.error:
            pass

        # slow path
        for i in range(0x100):
            found = False
            zcount = 0
            for task in task_addrs:
                v = read_int_from_memory(task + runtime.current_arch.ptrsize * i)
                if v == 0:
                    zcount += 1
                    continue
                if (v & 0x1fff) != 0:
                    break
                if not is_valid_addr(v):
                    break
            else:
                found = True

            # For unknown reasons, processes without a stack are sometimes observed.
            # 0xffffa122c17db000 U   106     chal.sh ... 0xffffa43100218000 0xd16ef01535a35500
            # 0xffffa122c17da000 U   108     socat   ... 0xffffa43100278000 0x3d378b9e6f59bf00
            # 0xffffa122c17dc000 U   109     chal    ... 0xffffa431002d4000 0x277c67d5e5854500
            # 0xffffa122c17dd000 K   110     3       ... 0x0000000000000000 0x22a999743f180500 <-- here
            # Therefore, a small number of NULL pointers are allowed.
            if zcount > len(task_addrs) // 10:
                found = False

            if found is False:
                continue

            offset_stack = runtime.current_arch.ptrsize * i
            return offset_stack
        return None

    def get_thread_info(self, task_addr, offset_stack):
        # fast path
        try:
            return task_addr + to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).thread_info")
            )
        except gdb.error:
            try:
                # task_struct exists but has no thread_info member
                gdb.parse_and_eval("(struct task_struct*)0")
                return read_int_from_memory(task_addr + offset_stack)
            except gdb.error:
                pass

        # slow path
        kstack = read_int_from_memory(task_addr + offset_stack)
        if not is_valid_addr(kstack):
            return None
        stack_top_val = read_int32_from_memory(kstack)
        if stack_top_val == 0x57ac6e9d: # STACK_END_MAGIC
            """
            struct task_struct {
            #ifdef CONFIG_THREAD_INFO_IN_TASK
                struct thread_info thread_info;
            #endif
                ...
            """
            return task_addr # CONFIG_THREAD_INFO_IN_TASK=y
        else:
            return kstack # CONFIG_THREAD_INFO_IN_TASK=n

    def has_seccomp(self, task_addr):
        thread_info = self.get_thread_info(task_addr, self.offset_stack)
        if thread_info is None:
            return None
        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        if is_x86():
            if "5.11" <= kversion:
                syscall_work = read_int_from_memory(thread_info + runtime.current_arch.ptrsize)
                return bool(syscall_work & (1 << 0)) # SYSCALL_WORK_SECCOMP
            elif "4.9" <= kversion:
                flags = read_int_from_memory(thread_info)
                return bool(flags & (1 << 8)) # TIF_SECCOMP
            elif "4.1" <= kversion:
                flags = read_int32_from_memory(thread_info + runtime.current_arch.ptrsize)
                return bool(flags & (1 << 8)) # TIF_SECCOMP
            else:
                flags = read_int32_from_memory(thread_info + runtime.current_arch.ptrsize * 2)
                return bool(flags & (1 << 8)) # TIF_SECCOMP
        elif is_arm32():
            if "6.0" <= kversion:
                flags = read_int_from_memory(thread_info)
                return bool(flags & (1 << 23)) # TIF_SECCOMP
            elif "5.16" <= kversion:
                flags = read_int_from_memory(thread_info)
                return bool(flags & (1 << 7)) # TIF_SECCOMP
            elif "5.15" <= kversion:
                flags = read_int_from_memory(thread_info)
                return bool(flags & (1 << 23)) # TIF_SECCOMP
            elif "5.11" <= kversion:
                flags = read_int_from_memory(thread_info)
                return bool(flags & (1 << 7)) # TIF_SECCOMP
            elif "5.10" <= kversion:
                flags = read_int_from_memory(thread_info)
                return bool(flags & (1 << 23)) # TIF_SECCOMP
            elif "4.3" <= kversion:
                flags = read_int_from_memory(thread_info)
                return bool(flags & (1 << 7)) # TIF_SECCOMP
            elif "3.8" <= kversion:
                flags = read_int_from_memory(thread_info)
                return bool(flags & (1 << 11)) # TIF_SECCOMP
            else:
                flags = read_int_from_memory(thread_info)
                return bool(flags & (1 << 21)) # TIF_SECCOMP
        elif is_arm64():
            if "3.16" <= kversion:
                flags = read_int_from_memory(thread_info)
                return bool(flags & (1 << 11)) # TIF_SECCOMP
            else:
                # unimplemented
                return None
        return None

    def get_offset_ptregs(self, task_addrs, offset_stack):
        # calc kstack address pattern
        kstacks_raw = []
        for task in task_addrs:
            kstack = read_int_from_memory(task + offset_stack)
            if kstack == 0:
                continue
            kstacks_raw.append(kstack)

        # calc kstack size
        kstacks = sorted({x & 0xffff for x in kstacks_raw}) # uniq and sort
        diffs = []
        for i in range(len(kstacks) - 1):
            diff = kstacks[i + 1] - kstacks[i]
            diffs.append(diff)
        if len(diffs) == 0:
            kstack_size = get_pagesize() * 2
        else:
            kstack_size = min(diffs)

        # check
        while kstack_size >= 0x2000:
            for kstack in kstacks_raw:
                if not is_valid_addr(kstack + kstack_size - runtime.current_arch.ptrsize):
                    kstack_size //= 2
                    break # for, then retry while
            else:
                break # while

        if is_x86_64():
            """
            struct pt_regs {
                unsigned long r15;
                unsigned long r14;
                unsigned long r13;
                unsigned long r12;
                unsigned long rbp;
                unsigned long rbx;
                unsigned long r11;
                unsigned long r10;
                unsigned long r9;
                unsigned long r8;
                unsigned long rax;
                unsigned long rcx;
                unsigned long rdx;
                unsigned long rsi;
                unsigned long rdi;
                unsigned long orig_rax;
                unsigned long rip;
                unsigned long cs;
                unsigned long eflags;
                unsigned long rsp;
                unsigned long ss;
            };
            """
            ptregs_size = runtime.current_arch.ptrsize * 21

            # Sometimes register values are stored a short distance away from the bottom of the kstack.
            # It is unclear whether this depends on the kernel version.
            # In 6.10.11 it was at offset 0, and in 6.10.0-rc2 it was at offset 16.
            # For this reason, dynamic detection is used.
            # TODO: Dynamic detection may also be necessary for x86, ARM, and ARM64.
            for i in range(8):
                init_process_kstack = read_int_from_memory(task_addrs[1] + offset_stack)
                init_process_kstack_end = init_process_kstack + kstack_size
                v = read_int_from_memory(init_process_kstack_end - runtime.current_arch.ptrsize * (i + 1))
                if v == 0x2b: # ss segment default value
                    bottom_offset = runtime.current_arch.ptrsize * i
                    break
            else:
                bottom_offset = 0
        elif is_x86_32():
            """
            struct pt_regs {
                long ebx;
                long ecx;
                long edx;
                long esi;
                long edi;
                long ebp;
                long eax;
                int xds;
                int xes;
                int xfs;
                int xgs;
                long orig_eax;
                long eip;
                int xcs;
                long eflags;
                long esp;
                int xss;
            };
            """
            ptregs_size = runtime.current_arch.ptrsize * 17
            bottom_offset = runtime.current_arch.ptrsize * 2 # ?
        elif is_arm64():
            """
            struct pt_regs {
                u64 regs[31];
                u64 sp;
                u64 pc;
                u64 pstate;
                u64 orig_x0;
                u64 syscallno;
                u64 orig_addr_limit;
                u64 pmr_save;
                u64 stackframe[2];
                u64 lockdep_hardirqs;
                u64 exit_rcu;
            };
            """
            ptregs_size = runtime.current_arch.ptrsize * 35
            bottom_offset = runtime.current_arch.ptrsize * 7
        elif is_arm32():
            """
            struct pt_regs {
                unsigned long uregs[18];
            };
            """
            ptregs_size = runtime.current_arch.ptrsize * 18
            bottom_offset = runtime.current_arch.ptrsize * 2 # ?
        else:
            return None

        offset_ptregs = kstack_size - ptregs_size - bottom_offset
        return kstack_size, offset_ptregs

    def get_regs(self, kstack, offset_ptregs):
        if is_x86_64():
            regs_name = [
                "r15", "r14", "r13", "r12", "rbp", "rbx", "r11", "r10",
                "r9", "r8", "rax", "rcx", "rdx", "rsi", "rdi", "orig_rax",
                "rip", "cs", "eflags", "rsp", "ss",
            ]
        elif is_x86_32():
            regs_name = [
                "ebx", "ecx", "edx", "esi", "edi", "ebp", "eax", "ds",
                "es", "fs", "gs", "orig_eax", "eip", "cs", "eflags", "esp", "ss",
            ]
        elif is_arm64():
            regs_name = [
                "x0", "x1", "x2", "x3", "x4", "x5", "x6", "x7",
                "x8", "x9", "x10", "x11", "x12", "x13", "x14", "x15",
                "x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
                "x24", "x25", "x26", "x27", "x28", "x29", "x30",
                "sp", "pc", "pstate", "orig_x0",
            ]
        elif is_arm32():
            regs_name = [
                "r0", "r1", "r2", "r3", "r4", "r5", "r6",
                "r7", "r8", "r9", "r10", "r11", "r12",
                "sp", "lr", "pc", "cpsr", "orig_r0",
            ]

        ptregs_addr = kstack + offset_ptregs
        ptregs_size = len(regs_name) * runtime.current_arch.ptrsize
        regs_data = read_memory(ptregs_addr, ptregs_size)

        # maybe kernel thread
        if is_x86():
            if regs_data == b"\0" * len(regs_data):
                return None
        elif is_arm32():
            kernel_thread_regs = p32(0) * (len(regs_name) - 2) + p32(0x13) + p32(0)
            if regs_data == kernel_thread_regs:
                return None
        elif is_arm64():
            kernel_thread_regs = p64(0) * (len(regs_name) - 2) + p64(0x5) + p64(0)
            if regs_data == kernel_thread_regs:
                return None

        # get regs value
        regs_data = slice_unpack(regs_data, runtime.current_arch.ptrsize)
        regs = {}
        for name, value in zip(regs_name, regs_data):
            regs[name] = value
        return regs

    def get_offset_pid(self, task_addrs):
        """
        struct task_struct {
            ...
            pid_t pid; // int
            pid_t tgid; // int
            ...
        };

        0xc6d1e888:     0xc6d1f048      0xc6d1c1c8      0x0000008c      0xc6d1e894
        0xc6d1e898:     0xc6d1e894      0xc6d1e89c      0xc6d1e89c      0xc6d1e8a4
        0xc6d1e8a8:     0x00000000      0x00000000      0xc7830660      0xc7830660
        0xc6d1e8b8:     0x00000008      0x00000000      0xc6d51300      0x00000000
        0xc6d1e8c8:     0x00000000      0xc6d514e0      0x00000017      0x000000a9
        0xc6d1e8d8:     0x00000005      0x00000000      0x00000000      0x00000000
        0xc6d1e8e8:     0x00000000      0x00000011      0x00000000      0x00000000
        0xc6d1e8f8:     0x00000000      0x00000000      0x00000000      0x00000000
        0xc6d1e908:     0xc245a8d0      0x00000000      0x00000000      0x00000000
        0xc6d1e918:     0x00000000      0x00000000      0x00000000      0x00000000
        0xc6d1e928:     0x00000031*     0x00000031      0xc7834000      0xc7834000
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).pid")
            )
        except gdb.error:
            pass

        # slow path
        pid_max = 0x400000 if is_64bit() else 0x8000
        for i in range(0x400):
            found = False
            seen_pid = []
            # swapper/0 has pid 0. Don't use it as it will cause false positives.
            for j, task in enumerate(task_addrs[1:]):
                v1 = read_int32_from_memory(task + (i + 0) * 4)
                v2 = read_int32_from_memory(task + (i + 1) * 4)
                if j == 0 and v1 != 1: # init process has always 1
                    break
                if v1 == 0 or pid_max < v1: # pid is 1 ~ pid_max
                    break
                if v2 == 0 or pid_max < v2: # tgid is 1 ~ pid_max
                    break
                if v1 in seen_pid:
                    break
                seen_pid.append(v1)
            else:
                found = True

            if found is False:
                continue

            offset_pid = i * 4
            return offset_pid
        return None

    def get_offset_canary(self, task_addrs, offset_pid):
        """
        struct task_struct {
            ...
            pid_t pid;
            pid_t tgid;
        #ifdef CONFIG_STACKPROTECTOR
            unsigned long stack_canary;
        #endif
            struct task_struct __rcu *real_parent;
            struct task_struct __rcu *parent;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).stack_canary")
            )
        except gdb.error:
            try:
                # task_struct exists but has no stack_canary member
                gdb.parse_and_eval("(struct task_struct*)0")
                return None
            except gdb.error:
                pass

        # slow path
        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        offset_stack_canary = align_to_ptrsize(offset_pid + 4 + 4)
        found = True
        for task in task_addrs:
            v1 = read_int_from_memory(task + offset_stack_canary)
            v2 = read_int_from_memory(task + offset_stack_canary + runtime.current_arch.ptrsize)

            if v1 == v2: # stack canary != real_parent
                found = False
                break

            if kversion and "4.13" <= kversion:
                if is_64bit() and (v1 & 0xff) != 0: # 32-bit canary does not have 0xXXXXXX00
                    found = False
                    break

        if found:
            return offset_stack_canary
        return None

    def get_offset_group_leader(self, offset_pid, offset_kcanary):
        """
        struct task_struct {
            ...
            pid_t pid;
            pid_t tgid;
        #ifdef CONFIG_STACKPROTECTOR
            unsigned long stack_canary;
        #endif
            struct task_struct __rcu *real_parent;
            struct task_struct __rcu *parent;
            struct list_head children;
            struct list_head sibling;
            struct task_struct *group_leader;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).group_leader")
            )
        except gdb.error:
            pass

        # slow path
        if offset_kcanary is None:
            offset_real_parent = align_to_ptrsize(offset_pid + 4 + 4)
        else:
            offset_real_parent = offset_kcanary + runtime.current_arch.ptrsize
        offset_group_leader = offset_real_parent + runtime.current_arch.ptrsize * (1 + 1 + 2 + 2)
        return offset_group_leader

    def get_offset_thread_group(self, offset_group_leader):
        """
        struct task_struct {
            ...
            struct task_struct *group_leader;
            struct list_head ptraced;
            struct list_head ptrace_entry;
            struct pid *thread_pid;           // v4.19~
            struct hlist_node pid_links[4];   // v4.19~
            struct pid_link pids[3];          // ~v4.18
            struct list_head thread_group;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).thread_group")
            )
        except gdb.error:
            pass

        # slow path
        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        if "4.19" <= kversion:
            offset_thread_group = offset_group_leader + runtime.current_arch.ptrsize * (1 + 2 + 2 + 1 + (2 * 4))
        else:
            offset_thread_group = offset_group_leader + runtime.current_arch.ptrsize * (1 + 2 + 2 + (3 * 3))
        return offset_thread_group

    def get_offset_signal(self, offset_nsproxy):
        """
        struct task_struct {
            ...
            struct nsproxy *nsproxy;
            struct signal_struct *signal;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).signal")
            )
        except gdb.error:
            pass

        # slow path
        return offset_nsproxy + runtime.current_arch.ptrsize

    def get_offset_seccomp(self, task_addrs, offset_signal):
        """
        struct task_struct {
            ...
            struct signal_struct *signal;
            struct sighand_struct __rcu *sighand;
            sigset_t blocked;
            sigset_t real_blocked;
            sigset_t saved_sigmask;
            struct sigpending {
                struct list_head list;
                sigset_t signal;
            } pending;
            unsigned long sas_ss_sp;
            size_t sas_ss_size;
            unsigned int sas_ss_flags;
            struct callback_head *task_works;
        #ifdef CONFIG_AUDIT
        #ifdef CONFIG_AUDITSYSCALL
            struct audit_context *audit_context;
        #endif
            kuid_t loginuid;
            unsigned int sessionid;
        #endif
            struct seccomp {
                int mode;
                atomic_t filter_count;
                struct seccomp_filter *filter;
            } seccomp;
            ...
        }
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).seccomp")
            )
        except gdb.error:
            pass

        # slow path
        # search for seccomped process
        for task in task_addrs:
            if self.has_seccomp(task):
                seccomped_task = task
                break
        else:
            # Not found
            return None

        """
        0xffff99353fe721d8|+0x0000|+000: 0xffff99353fe6e600 <- &task_struct.signal
        0xffff99353fe721e0|+0x0008|+001: 0x0000000000004002
        0xffff99353fe721e8|+0x0010|+002: 0x0000000000000000
        0xffff99353fe721f0|+0x0018|+003: 0x0000000000000000
        0xffff99353fe721f8|+0x0020|+004: 0xffff99353fe721f8 <- &task_struct.pending.list
        0xffff99353fe72200|+0x0028|+005: 0xffff99353fe721f8
        0xffff99353fe72208|+0x0030|+006: 0x0000000000000000
        0xffff99353fe72210|+0x0038|+007: 0x0000000000000000
        0xffff99353fe72218|+0x0040|+008: 0x0000000000000000
        0xffff99353fe72220|+0x0048|+009: 0x0000000000000002
        0xffff99353fe72228|+0x0050|+010: 0x0000000000000000
        0xffff99353fe72230|+0x0058|+011: 0x0000000000000000
        0xffff99353fe72238|+0x0060|+012: 0xffffffffffffffff
        0xffff99353fe72240|+0x0068|+013: 0x0000002300000002 <- &task_struct.seccomp
        0xffff99353fe72248|+0x0070|+014: 0xffff9934c39e2300 <- &task_struct.seccomp.filter
        0xffff99353fe72250|+0x0078|+015: 0x0000000000000003
        0xffff99353fe72258|+0x0080|+016: 0x0000000000000004
        """
        # search for sigpending
        base = offset_signal + runtime.current_arch.ptrsize
        for i in range(0x100):
            if is_double_link_list(seccomped_task + base + runtime.current_arch.ptrsize * i):
                base += runtime.current_arch.ptrsize * i * 2
                break
        else:
            # Could not find sigpending
            return None

        # search for seccomp
        for i in range(0x100):
            offset_filter = base + runtime.current_arch.ptrsize * i

            filt = read_int_from_memory(seccomped_task + offset_filter)
            if not is_valid_addr(filt):
                continue

            mode = read_int32_from_memory(seccomped_task + offset_filter - 4 * 2)
            filtcnt = read_int32_from_memory(seccomped_task + offset_filter - 4)

            """
            #define SECCOMP_MODE_DISABLED 0
            #define SECCOMP_MODE_STRICT   1
            #define SECCOMP_MODE_FILTER   2
            """
            if mode == 0 or filtcnt == 0:
                continue
            offset_seccomp = offset_filter - 4 * 2
            return offset_seccomp

        return None

    def get_offset_prev(self, task_addrs, offset_seccomp):
        """
        struct seccomp_filter {
            refcount_t refs; // v5.9~
            refcount_t users; // v5.9~
            refcount_t usage; // ~v5.8
            bool log; // v4.14~
            bool wait_killable_recv; // v5.19~
            struct action_cache cache; // v5.11~
            struct seccomp_filter *prev;
            struct bpf_prog *prog;
            struct notification *notif; // v5.0~
            struct mutex notify_lock; // v5.0~
            wait_queue_head_t wqh; // v5.9~
        };

        [Example x64; v6.12.3]
        0xffff976901e9a300|+0x0000|+000: 0x0000000100000001 // refs, users
        0xffff976901e9a308|+0x0008|+001: 0x0000000000000000 // log, wait_killable_recv
        0xffff976901e9a310|+0x0010|+002: 0x1000000000000007 // cache
        0xffff976901e9a318|+0x0018|+003: 0x0000000000000000 // ...
        0xffff976901e9a320|+0x0020|+004: 0x0000000000000000
        0xffff976901e9a328|+0x0028|+005: 0x0000008000000000
        0xffff976901e9a330|+0x0030|+006: 0x0000000000000000
        0xffff976901e9a338|+0x0038|+007: 0x0000000000000000
        0xffff976901e9a340|+0x0040|+008: 0x0000000000000000
        0xffff976901e9a348|+0x0048|+009: 0xffffffffffff8000
        0xffff976901e9a350|+0x0050|+010: 0x0000000000000000
        0xffff976901e9a358|+0x0058|+011: 0x0000000000000000
        0xffff976901e9a360|+0x0060|+012: 0x0000000000000000
        0xffff976901e9a368|+0x0068|+013: 0x0000000000000000
        0xffff976901e9a370|+0x0070|+014: 0x0000000000000000
        0xffff976901e9a378|+0x0078|+015: 0x0000000000000000
        0xffff976901e9a380|+0x0080|+016: 0x0000000000000000 // ...
        0xffff976901e9a388|+0x0088|+017: 0xffffffffffff8000 // cache
        0xffff976901e9a390|+0x0090|+018: 0x0000000000000000 // prev
        0xffff976901e9a398|+0x0098|+019: 0xffffaf7c0008d000  ->  0x0000000000030001 // bpf_prog
        0xffff976901e9a3a0|+0x00a0|+020: 0x0000000000000000
        0xffff976901e9a3a8|+0x00a8|+021: 0x0000000000000000
        0xffff976901e9a3b0|+0x00b0|+022: 0x0000000000000000
        0xffff976901e9a3b8|+0x00b8|+023: 0xffff976901e9a3b8  ->  [loop detected]
        0xffff976901e9a3c0|+0x00c0|+024: 0xffff976901e9a3b8  ->  [loop detected]

        [Example x64; v5.10.0]
        0xffff8c1f827f39c0|+0x0000|+000: 0x0000000100000001 // refs, users
        0xffff8c1f827f39c8|+0x0008|+001: 0x0000000000000000 // log
        0xffff8c1f827f39d0|+0x0010|+002: 0xffff8c1f827f3780  ->  0x0000000100000001 // prev
        0xffff8c1f827f39d8|+0x0018|+003: 0xffffa1b3c032b000  ->  0x0000000000030001 // bpf_prog
        0xffff8c1f827f39e0|+0x0020|+004: 0x0000000000000000
        0xffff8c1f827f39e8|+0x0028|+005: 0x0000000000000000
        0xffff8c1f827f39f0|+0x0030|+006: 0x0000000000000000
        0xffff8c1f827f39f8|+0x0038|+007: 0xffff8c1f827f39f8  ->  [loop detected]
        0xffff8c1f827f3a00|+0x0040|+008: 0xffff8c1f827f39f8  ->  [loop detected]
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct seccomp_filter*)0).prev")
            )
        except gdb.error:
            pass

        # slow path
        if offset_seccomp is None:
            return None

        for task in task_addrs:
            if not self.has_seccomp(task):
                continue

            mode = read_int32_from_memory(task + self.offset_seccomp)
            if mode != 2: # SECCOMP_MODE_FILTER
                continue

            filter_count = read_int32_from_memory(task + self.offset_seccomp + 4)
            if filter_count == 0:
                continue # something is wrong

            filter_ = read_int_from_memory(task + self.offset_seccomp + 4 + 4)
            for i in range(0x100):
                # prev
                x = read_int_from_memory(filter_ + runtime.current_arch.ptrsize * i)
                if (x & 0x7) or (x != 0 and not is_valid_addr(x)): # must be aligned or NULL
                    continue
                # prog
                y = read_int_from_memory(filter_ + runtime.current_arch.ptrsize * (i + 1))
                if (y & 0xfff) or not is_valid_addr(y): # must be page aligned
                    continue
                bpf_prog = read_int_from_memory(y)
                if is_valid_addr(bpf_prog): # not address
                    continue

                return runtime.current_arch.ptrsize * i
        return None

    def get_offset_prog(self, offset_prev):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct seccomp_filter*)0).prog")
            )
        except gdb.error:
            pass

        # slow path
        if offset_prev is None:
            return None

        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        if kversion < "3.16":
            return None

        return offset_prev + runtime.current_arch.ptrsize

    def get_offset_bpf_func(self, task_addrs, offset_seccomp, offset_prog):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct bpf_prog*)0).bpf_func")
            )
        except gdb.error:
            pass

        # slow path
        if offset_seccomp is None:
            return None
        if offset_prog is None:
            return None

        def is_executable(x):
            maps = Kernel.get_maps()
            for start, size, perm in maps:
                if start <= x and x < start + size:
                    return perm.endswith("X")
            return False

        for task in task_addrs:
            if not self.has_seccomp(task):
                continue

            filter_ = read_int_from_memory(task + offset_seccomp + 4 + 4)
            bpf_prog = read_int_from_memory(filter_ + offset_prog)
            for i in range(0x100):
                x = read_int_from_memory(bpf_prog + runtime.current_arch.ptrsize * i)
                if is_valid_addr(x) and is_executable(x):
                    if read_int_from_memory(x) == 0: # something is wrong
                        continue
                    return runtime.current_arch.ptrsize * i
        return None

    def get_offset_orig_prog(self, offset_bpf_func):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct bpf_prog*)0).orig_prog")
            )
        except gdb.error:
            pass

        # slow path
        if offset_bpf_func is None:
            return None

        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        if "5.12" <= kversion:
            return offset_bpf_func + runtime.current_arch.ptrsize * 2
        elif "4.1" <= kversion:
            return offset_bpf_func - runtime.current_arch.ptrsize
        elif "3.18" <= kversion:
            return offset_bpf_func - runtime.current_arch.ptrsize * 2
        elif "3.16" <= kversion:
            return offset_bpf_func - runtime.current_arch.ptrsize
        return None

    def get_offset_thread_head(self, task_addr, offset_signal):
        """
        struct signal_struct {
            refcount_t sigcnt;
            atomic_t live;
            int nr_threads;
            int quick_threads;
            struct list_head thread_head;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct signal_struct*)0).thread_head")
            )
        except gdb.error:
            pass

        # slow path
        signal = read_int_from_memory(task_addr + offset_signal)
        for i in range(10):
            x = read_int_from_memory(signal + runtime.current_arch.ptrsize * i)
            y = read_int_from_memory(signal + runtime.current_arch.ptrsize * (i + 1))
            if is_valid_addr(x) and is_valid_addr(y):
                offset_thread_head = runtime.current_arch.ptrsize * i
                return offset_thread_head
        return None

    def get_offset_files(self, task_addrs, offset_comm):
        """
        struct task_struct {
            ...
            char comm[TASK_COMM_LEN];
            struct nameidata *nameidata;
        #ifdef CONFIG_SYSVIPC
            struct sysv_sem {
                struct sem_undo_list *undo_list;
            } sysvsem;
            struct sysv_shm {
                struct list_head shm_clist;
            } sysvshm;
        #endif
        #ifdef CONFIG_DETECT_HUNG_TASK
            unsigned long last_switch_count;
            unsigned long last_switch_time;
        #endif
            struct thread_struct thread; // ~v4.1
            struct fs_struct *fs;
            struct files_struct *files; <-- here
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).files")
            )
        except gdb.error:
            pass

        # slow path
        base = offset_comm + 16 # comm
        base += runtime.current_arch.ptrsize # nameidata
        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        if "4.2" <= kversion:
            repeat_times = 6
        else:
            # sizeof(struct thread_struct) is very large, need more exproring
            repeat_times = 100
        for i in range(repeat_times):
            # check fs
            v1 = read_int_from_memory(task_addrs[0] + base + runtime.current_arch.ptrsize * i)
            if not is_valid_addr(v1):
                continue
            if is_valid_addr(read_int_from_memory(v1)):
                continue
            # check files
            v2 = read_int_from_memory(task_addrs[0] + base + runtime.current_arch.ptrsize * (i + 1))
            if not is_valid_addr(v2):
                continue
            if is_valid_addr(read_int_from_memory(v2)):
                continue
            # found
            offset_files = base + runtime.current_arch.ptrsize * (i + 1)
            return offset_files
        return None

    def get_offset_fdt(self, task_addrs, offset_files):
        """
        struct files_struct {
            atomic_t count; // int
            bool resize_in_progress;   // v4.2~
            wait_queue_head_t {        // v4.2~
                spinlock_t lock;       // v4.2~
                struct list_head head; // v4.2~
            } resize_wait;             // v4.2~
            struct fdtable __rcu *fdt; <-- here
            struct fdtable {
                unsigned int max_fds;
                struct file __rcu **fd;
                unsigned long *close_on_exec;
                unsigned long *open_fds;
                unsigned long *full_fds_bits;
                struct rcu_head rcu;
            } fdtab;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct files_struct*)0).fdt")
            )
        except gdb.error:
            pass

        # slow path
        MAX_FDS_DEFAULT = AddressUtil.get_memory_alignment(in_bits=True)
        files = read_int_from_memory(task_addrs[0] + offset_files)
        for i in range(1, 0x100):
            v = read_int_from_memory(files + runtime.current_arch.ptrsize * i)
            if v != MAX_FDS_DEFAULT:
                continue
            offset_fdt = runtime.current_arch.ptrsize * (i - 1)
            return offset_fdt
        return None

    def get_offset_uid(self, init_task_cred_ptr):
        """
        struct cred {
            atomic_t usage; // ~v6.1.69, v6.2~v6.6.7
            atomic_long_t usage; // v6.1.69~v6.1.143, v6.6.8~
        #ifdef CONFIG_DEBUG_CREDENTIALS // ~v6.6.7
            atomic_t subscribers; // ~v6.6.7
            void *put_addr; // ~v6.6.7
            unsigned magic; // ~v6.6.7
        #endif // ~v6.6.7
            kuid_t uid;
            kgid_t gid;
            kuid_t suid;
            kgid_t sgid;
            kuid_t euid;
            kgid_t egid;
            kuid_t fsuid;
            kgid_t fsgid;
            unsigned securebits;
            kernel_cap_t cap_inheritable;
            kernel_cap_t cap_permitted;
            kernel_cap_t cap_effective;
            kernel_cap_t cap_bset;
            kernel_cap_t cap_ambient;
            ...
        };

        [Example x64]
            0xffffffff820460c0:     0x0000000000000004      0x0000000000000000
            0xffffffff820460d0:     0x0000000000000000      0x0000000000000000
            0xffffffff820460e0:     0x0000000000000000      0x0000000000000000
            0xffffffff820460f0:     0x0000003fffffffff      0x0000003fffffffff
            0xffffffff82046100:     0x0000003fffffffff      0x0000000000000000
            0xffffffff82046110:     0x0000000000000000      0x0000000000000000
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct cred*)0).uid")
            )
        except gdb.error:
            pass

        # slow path

        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        if kversion < "6.1.69":
            offset_uid = 4
        elif kversion < "6.2":
            offset_uid = runtime.current_arch.ptrsize
        elif kversion < "6.6.8":
            offset_uid = 4
        else:
            offset_uid = runtime.current_arch.ptrsize

        if kversion < "6.6.8":
            init_task_cred = read_int_from_memory(init_task_cred_ptr)
            uid_gid_size = 4 * 8 # uid_t:4byte. len([uid,gid,suid,sgid,euid,egid,fsuid,fsgid]) == 8
            ret = read_memory(init_task_cred + offset_uid, uid_gid_size)
            if ret == b"\0" * uid_gid_size:
                pass
            else:
                offset_uid += 4 + runtime.current_arch.ptrsize + 4
        return offset_uid

    def get_offset_user_ns(self, init_task_cred_ptr, offset_uid):
        """
        struct cred {
            ...
            kernel_cap_t cap_bset;
            kernel_cap_t cap_ambient; // v4.3~
        #ifdef CONFIG_KEYS
            unsigned char jit_keyring;
            struct key *session_keyring;
            struct key *process_keyring;
            struct key *thread_keyring;
            struct key *request_key_auth;
        #endif
        #ifdef CONFIG_SECURITY
            void *security;
        #endif
            struct user_struct *user;
            struct user_namespace *user_ns;
            struct ucounts *ucounts; // v5.12.17~
            struct group_info *group_info;
            union {
                int non_rcu;
                struct rcu_head rcu;
            };
        } __randomize_layout;

        [Example x64; CONFIG_KEYS=y, CONFIG_SECURITY=y]
        0xffffffffbb454580|+0x0000|+000: 0x0000000000000004
        0xffffffffbb454588|+0x0008|+001: 0x0000000000000000
        0xffffffffbb454590|+0x0010|+002: 0x0000000000000000
        0xffffffffbb454598|+0x0018|+003: 0x0000000000000000
        0xffffffffbb4545a0|+0x0020|+004: 0x0000000000000000
        0xffffffffbb4545a8|+0x0028|+005: 0x0000000000000000
        0xffffffffbb4545b0|+0x0030|+006: 0x000001ffffffffff
        0xffffffffbb4545b8|+0x0038|+007: 0x000001ffffffffff
        0xffffffffbb4545c0|+0x0040|+008: 0x000001ffffffffff  // cap_bset
        0xffffffffbb4545c8|+0x0048|+009: 0x0000000000000000  // cap_ambilent
        0xffffffffbb4545d0|+0x0050|+010: 0x0000000000000000  // jit_keyring
        0xffffffffbb4545d8|+0x0058|+011: 0x0000000000000000  // session_keyring
        0xffffffffbb4545e0|+0x0060|+012: 0x0000000000000000  // process_keyring
        0xffffffffbb4545e8|+0x0068|+013: 0x0000000000000000  // thread_keyring
        0xffffffffbb4545f0|+0x0070|+014: 0x0000000000000000  // request_key_auth
        0xffffffffbb4545f8|+0x0078|+015: 0xffff998d8106cb68  ->  0xffff998d81052eb0 // security
        0xffffffffbb454600|+0x0080|+016: 0xffffffffbb44c6c0  ->  0x0000004e00000075 // user
        0xffffffffbb454608|+0x0088|+017: 0xffffffffbb44c740  ->  0x0000000000000001 // user_ns

        [Example x64; CONFIG_KEYS=y, CONFIG_SECURITY=y]
        0xffff9ec6c88379c0|+0x0000|+000: 0x000000000000000a
        0xffff9ec6c88379c8|+0x0008|+001: 0x0000000000000000
        0xffff9ec6c88379d0|+0x0010|+002: 0x0000000000000000
        0xffff9ec6c88379d8|+0x0018|+003: 0x0000000000000000
        0xffff9ec6c88379e0|+0x0020|+004: 0x0000000000000000
        0xffff9ec6c88379e8|+0x0028|+005: 0x0000000000000000
        0xffff9ec6c88379f0|+0x0030|+006: 0x000001ffffffffff
        0xffff9ec6c88379f8|+0x0038|+007: 0x000001ffffffffff
        0xffff9ec6c8837a00|+0x0040|+008: 0x000001ffffffffff  // cap_bset
        0xffff9ec6c8837a08|+0x0048|+009: 0x0000000000000000  // cap_ambient
        0xffff9ec6c8837a10|+0x0050|+010: 0x0000000000000000  // jit_keyring
        0xffff9ec6c8837a18|+0x0058|+011: 0xffff9ec6c4643700  ->  0x182031ce00000006 // session_keyring
        0xffff9ec6c8837a20|+0x0060|+012: 0x0000000000000000  // process_keyring
        0xffff9ec6c8837a28|+0x0068|+013: 0x0000000000000000  // thread_keyring
        0xffff9ec6c8837a30|+0x0070|+014: 0x0000000000000000  // request_key_auth
        0xffff9ec6c8837a38|+0x0078|+015: 0xffff9ec6c8873fe0  ->  0xffff9ec6c1052eb0 // security
        0xffff9ec6c8837a40|+0x0080|+016: 0xffffffffbb64c5c0  ->  0x0000004f00000084 // user
        0xffff9ec6c8837a48|+0x0088|+017: 0xffff9ec6c820eaa0  ->  0x0000000000000001 // user_ns

        [Example ARM64; CONFIG_KEYS=n, CONFIG_SECURITY=y]
        0xffffd9e53efef538|+0x0000|+000: 0x0000000000000004
        0xffffd9e53efef540|+0x0008|+001: 0x0000000000000000
        0xffffd9e53efef548|+0x0010|+002: 0x0000000000000000
        0xffffd9e53efef550|+0x0018|+003: 0x0000000000000000
        0xffffd9e53efef558|+0x0020|+004: 0x0000000000000000
        0xffffd9e53efef560|+0x0028|+005: 0x0000000000000000
        0xffffd9e53efef568|+0x0030|+006: 0x000001ffffffffff
        0xffffd9e53efef570|+0x0038|+007: 0x000001ffffffffff
        0xffffd9e53efef578|+0x0040|+008: 0x000001ffffffffff  // cap_bset
        0xffffd9e53efef580|+0x0048|+009: 0x0000000000000000  // cap_ambient
        0xffffd9e53efef588|+0x0050|+010: 0x0000000000000000  // security
        0xffffd9e53efef590|+0x0058|+011: 0xffffd9e53efeeb10  ->  0x000000000000002a // user
        0xffffd9e53efef598|+0x0060|+012: 0xffffd9e53efeeb98  ->  0x0000000000000001 // user_ns

        [Example x86; CONFIG_KEYS=y, CONFIG_SECURITY=y]
        0xc1aabbe0|+0x0000|+000: 0x00000004
        0xc1aabbe4|+0x0004|+001: 0x00000000
        0xc1aabbe8|+0x0008|+002: 0x00000000
        0xc1aabbec|+0x000c|+003: 0x00000000
        0xc1aabbf0|+0x0010|+004: 0x00000000
        0xc1aabbf4|+0x0014|+005: 0x00000000
        0xc1aabbf8|+0x0018|+006: 0x00000000
        0xc1aabbfc|+0x001c|+007: 0x00000000
        0xc1aabc00|+0x0020|+008: 0x00000000
        0xc1aabc04|+0x0024|+009: 0x00000000
        0xc1aabc08|+0x0028|+010: 0x00000000
        0xc1aabc0c|+0x002c|+011: 0x00000000
        0xc1aabc10|+0x0030|+012: 0xffffffff
        0xc1aabc14|+0x0034|+013: 0x000001ff
        0xc1aabc18|+0x0038|+014: 0xffffffff
        0xc1aabc1c|+0x003c|+015: 0x000001ff
        0xc1aabc20|+0x0040|+016: 0xffffffff  // cap_bset
        0xc1aabc24|+0x0044|+017: 0x000001ff
        0xc1aabc28|+0x0048|+018: 0x00000000  // cap_abmient
        0xc1aabc2c|+0x004c|+019: 0x00000000
        0xc1aabc30|+0x0050|+020: 0x00000000  // jit_keyring
        0xc1aabc34|+0x0054|+021: 0x00000000  // session_keyring
        0xc1aabc38|+0x0058|+022: 0x00000000  // process_keyring
        0xc1aabc3c|+0x005c|+023: 0x00000000  // thread_keyring
        0xc1aabc40|+0x0060|+024: 0x00000000  // request_key_auth
        0xc1aabc44|+0x0064|+025: 0xc201e8b0  ->  0xc20ecd94 // security
        0xc1aabc48|+0x0068|+026: 0xc1aa6b80  ->  0x00000068 // user
        0xc1aabc4c|+0x006c|+027: 0xc1aa6be0  ->  0x00000001 // user_ns
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct cred*)0).user_ns")
            )
        except gdb.error:
            pass

        # slow path
        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        # uid_t:4byte. len([uid,gid,suid,sgid,euid,egid,fsuid,fsgid]) == 8
        uid_gid_size = 4 * 8
        sizeof_securebits = 4
        if "4.3" <= kversion:
            # cap_t:8byte. len([cap_inheritable,cap_permitted,cap_effective,cap_bset,cap_ambient]) == 5
            cap_size = 8 * 5
        else:
            # cap_t:8byte. len([cap_inheritable,cap_permitted,cap_effective,cap_bset]) == 4
            cap_size = 8 * 4

        """
        struct user_namespace {
            struct uid_gid_map uid_map;
            ...
        };

        struct uid_gid_map { /* 64 bytes -- 1 cache line */
            u32 nr_extents; // ~v6.11
            union {
                struct {
                    struct uid_gid_extent extent[UID_GID_MAP_MAX_BASE_EXTENTS];
                    u32 nr_extents; v6.12~
                };
                struct {
                    struct uid_gid_extent *forward;
                    struct uid_gid_extent *reverse;
                };
            };
        };
        """
        if kversion < "6.12":
            offset_nr_extents = 0
        else:
            offset_nr_extents = 60

        for i in range(10):
            offset_user_ns = offset_uid + uid_gid_size + sizeof_securebits
            offset_user_ns = align_to_ptrsize(offset_user_ns)
            offset_user_ns += cap_size + runtime.current_arch.ptrsize * i
            v = read_int_from_memory(init_task_cred_ptr + offset_user_ns)
            if not is_valid_addr(v):
                continue
            w = read_int_from_memory(v + offset_nr_extents)
            if w == 1:
                return offset_user_ns
        return None

    class MapleTree:
        """Linux v6.1 introduces maple_tree. This is a simple parser."""
        MT_FLAGS_HEIGHT_MASK = 0x7c
        MT_FLAGS_HEIGHT_OFFSET = 0x02
        MAPLE_NODE_TYPE_SHIFT = 0x03
        MAPLE_NODE_TYPE_MASK = 0x0f
        MAPLE_NODE_POINTER_MASK = 0xff
        MAPLE_DENSE = 0
        MAPLE_LEAF_64 = 1
        MAPLE_RANGE_64 = 2
        MAPLE_ARANGE_64 = 3

        def __init__(self, mm, quiet):
            self.quiet = quiet
            kversion = Kernel.kernel_version()
            """
            struct mm_struct {
                struct {
                    struct {
                        atomic_t mm_count;
                    } ____cacheline_aligned_in_smp; // v6.4~
                    struct maple_tree {
                        union {
                            spinlock_t ma_lock;
                            lockdep_map_p ma_external_lock;
                        };
                        unsigned int ma_flags; // v6.6~
                        void __rcu *ma_root; // this points root maple_node. (lower 8-bits are some flags)
                        unsigned int ma_flags; // ~v6.5
                    } mm_mt;
                    ...
                } __randomize_layout;
                ...
            };
            """

            # ____cacheline_aligned_in_smp attribute, spinlock_t and lockdep_map_p can be different size
            # in each environment or situation, so search for it heuristically.
            for i in range(0x20):
                x = read_int_from_memory(mm + runtime.current_arch.ptrsize * i)
                """
                [x64 v6.4.2]
                0xffff8bedc104db00|+0x0000|+000: 0x0000000000000000   // union  <-- mm_mt
                0xffff8bedc104db08|+0x0008|+001: 0xffff8bedc1a6601e   // ma_root
                0xffff8bedc104db10|+0x0010|+002: 0x000000000000030b   // ma_flags

                [x64 v6.6.1]
                0xffff972801b78a38|+0x0040|+008: 0x0000000000000000   // (the end of cacheline?)
                0xffff972801b78a40|+0x0040|+008: 0x0000030b00000000   // ma_flags || union  <-- mm_mt
                0xffff972801b78a48|+0x0048|+009: 0xffff972801b0cc1e   // ma_root
                """
                if is_valid_addr(x) and (x & 0xff) in [0x1e, 0x0e]:
                    offset_ma_root = runtime.current_arch.ptrsize * i
                    if kversion < "6.6":
                        offset_ma_flags = offset_ma_root + runtime.current_arch.ptrsize
                    else:
                        offset_ma_flags = offset_ma_root - 4
                        if is_64bit() and read_int32_from_memory(mm + offset_ma_flags) == 0:
                            offset_ma_flags = offset_ma_root - 8
                    break
            else:
                raise

            self.ma_root_raw = read_int_from_memory(mm + offset_ma_root)
            self.ma_flags = read_int32_from_memory(mm + offset_ma_flags)
            self.max_depth = (self.ma_flags & self.MT_FLAGS_HEIGHT_MASK) >> self.MT_FLAGS_HEIGHT_OFFSET

            if is_64bit():
                self.MAPLE_NODE_SLOTS = 31
                self.MAPLE_RANGE64_SLOTS = 16
                self.MAPLE_ARANGE64_SLOTS = 10
                self.MAPLE_ALLOC_SLOTS = self.MAPLE_NODE_SLOTS - 1
                self.maple_range_64_offset_slot = runtime.current_arch.ptrsize * self.MAPLE_RANGE64_SLOTS
                self.maple_arange_64_offset_slot = runtime.current_arch.ptrsize * self.MAPLE_ARANGE64_SLOTS
                self.maple_alloc_offset_slot = runtime.current_arch.ptrsize * 2
            else:
                self.MAPLE_NODE_SLOTS = 63
                self.MAPLE_RANGE64_SLOTS = 32
                self.MAPLE_ARANGE64_SLOTS = 21
                self.MAPLE_ALLOC_SLOTS = self.MAPLE_NODE_SLOTS - 2
                self.maple_range_64_offset_slot = runtime.current_arch.ptrsize * self.MAPLE_RANGE64_SLOTS
                self.maple_arange_64_offset_slot = runtime.current_arch.ptrsize * self.MAPLE_ARANGE64_SLOTS
                self.maple_alloc_offset_slot = runtime.current_arch.ptrsize * 3

            self.seen = set()
            self.iters = self.parse_node(self.ma_root_raw, 1)
            return

        def get_next(self, _=None):
            # iterate all `vm_area_struct` pointers
            for addr in self.iters:
                return addr
            return None

        def parse_node(self, entry, depth):
            if entry in self.seen:
                return
            self.seen.add(entry)

            if self.max_depth < depth:
                return

            pointer = entry & ~(self.MAPLE_NODE_POINTER_MASK)
            node_type = (entry >> self.MAPLE_NODE_TYPE_SHIFT) & self.MAPLE_NODE_TYPE_MASK

            if node_type == self.MAPLE_DENSE:
                slot_top = pointer + self.maple_alloc_offset_slot
                for i in range(self.MAPLE_ALLOC_SLOTS):
                    slot = read_int_from_memory(slot_top + runtime.current_arch.ptrsize * i)
                    if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                        if is_valid_addr(slot):
                            yield slot
            elif node_type == self.MAPLE_LEAF_64:
                slot_top = pointer + self.maple_range_64_offset_slot
                for i in range(self.MAPLE_RANGE64_SLOTS):
                    slot = read_int_from_memory(slot_top + runtime.current_arch.ptrsize * i)
                    if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                        if is_valid_addr(slot):
                            yield slot
            elif node_type == self.MAPLE_RANGE_64:
                slot_top = pointer + self.maple_range_64_offset_slot
                for i in range(self.MAPLE_RANGE64_SLOTS):
                    slot = read_int_from_memory(slot_top + runtime.current_arch.ptrsize * i)
                    if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                        yield from self.parse_node(slot, depth + 1)
            elif node_type == self.MAPLE_ARANGE_64:
                slot_top = pointer + self.maple_arange_64_offset_slot
                for i in range(self.MAPLE_ARANGE64_SLOTS):
                    slot = read_int_from_memory(slot_top + runtime.current_arch.ptrsize * i)
                    if (slot & ~(self.MAPLE_NODE_TYPE_MASK)) != 0:
                        yield from self.parse_node(slot, depth + 1)
            return

    def get_vm_area_struct(self, mm):
        kversion = Kernel.kernel_version()
        if kversion is None:
            return None, None
        if kversion < "6.1":
            """
            struct mm_struct {
                struct {
                    struct vm_area_struct *mmap;
                    ...
                } __randomize_layout;
            };
            """
            offset_mmap = 0
            vm_area_struct = read_int_from_memory(mm + offset_mmap)

            """
            struct vm_area_struct {
                unsigned long vm_start;
                unsigned long vm_end;
                struct vm_area_struct *vm_next, *vm_prev;
                struct rb_node vm_rb;
                unsigned long rb_subtree_gap;
                struct mm_struct *vm_mm;
                pgprot_t vm_page_prot;
                unsigned long vm_flags;
                struct {
                    struct rb_node rb;
                    unsigned long rb_subtree_last;
                } shared;
                struct list_head anon_vma_chain;
                struct anon_vma *anon_vma;
                const struct vm_operations_struct *vm_ops;
                unsigned long vm_pgoff;
                struct file *vm_file;
                ...
            };
            """

            def get_next_vma_area_struct(current):
                return read_int_from_memory(current + runtime.current_arch.ptrsize * 2)

        else: # "6.1" <= kversion
            """
            struct mm_struct {
                struct {
                    struct {
                        atomic_t mm_count;
                    } ____cacheline_aligned_in_smp; // v6.4~
                    struct maple_tree {
                        union {
                            spinlock_t ma_lock;
                            lockdep_map_p ma_external_lock;
                        };
                        unsigned int ma_flags; // v6.6~
                        void __rcu *ma_root; // this points root maple_node. (lower 8-bits are some flags)
                        unsigned int ma_flags; // ~v6.5
                    } mm_mt;
                    ...
                } __randomize_layout;
                ...
            };

            struct maple_node {
                union {
                    struct {
                        struct maple_pnode *parent;
                        void __rcu *slot[MAPLE_NODE_SLOTS]; // 64-bit: 31; 32-bit: 63
                    };
                    struct {
                        void *pad;
                        struct rcu_head rcu;
                        struct maple_enode *piv_parent;
                        unsigned char parent_slot;
                        enum maple_type type;
                        unsigned char slot_len;
                        unsigned int ma_flags;
                    };
                    struct maple_range_64 {
                        struct maple_pnode *parent;
                        unsigned long pivot[MAPLE_RANGE64_SLOTS - 1];     // 64-bit: 15; 32-bit: 31
                        union {
                            void __rcu *slot[MAPLE_RANGE64_SLOTS];        // 64-bit: 16; 32-bit: 32
                            struct {
                                void __rcu *pad[MAPLE_RANGE64_SLOTS - 1]; // 64-bit: 15; 32-bit: 31
                                struct maple_metadata meta;
                            };
                        };
                    } mr64;
                    struct maple_arange_64 {
                        struct maple_pnode *parent;
                        unsigned long pivot[MAPLE_ARANGE64_SLOTS - 1]; // 64-bit: 9;  32-bit: 20
                        void __rcu *slot[MAPLE_ARANGE64_SLOTS];        // 64-bit: 10; 32-bit: 21
                        unsigned long gap[MAPLE_ARANGE64_SLOTS];       // 64-bit: 10; 32-bit: 21
                        struct maple_metadata meta;
                    } ma64;
                    struct maple_alloc {
                        unsigned long total;
                        unsigned char node_count;
                        unsigned int request_count;
                        struct maple_alloc *slot[MAPLE_ALLOC_SLOTS]; // 64-bit: 30; 32-bit: 31
                    } alloc;
                };
            };
            """
            get_next_vma_area_struct = self.MapleTree(mm, self.args.quiet).get_next
            vm_area_struct = get_next_vma_area_struct()

            """
            struct vm_area_struct {
                unsigned long vm_start;
                unsigned long vm_end;
                struct mm_struct *vm_mm;
                pgprot_t vm_page_prot;
                unsigned long vm_flags;
            #ifdef CONFIG_PER_VMA_LOCK                 // v6.4~
                int vm_lock_seq;                       // v6.4~
                struct vma_lock *vm_lock;              // v6.4~
                bool detached;                         // v6.4~
            #endif                                     // v6.4~
                struct {                               // v6.2~
                    struct rb_node rb;                 // v6.2~
                    unsigned long rb_subtree_last;     // v6.2~
                } shared;                              // v6.2~
                union {                                // ~v6.1
                    struct {                           // ~v6.1
                        struct rb_node rb;             // ~v6.1
                        unsigned long rb_subtree_last; // ~v6.1
                    } shared;                          // ~v6.1
                    struct anon_vma_name *anon_name;   // ~v6.1
                };                                     // ~v6.1
                struct list_head anon_vma_chain;
                struct anon_vma *anon_vma;
                const struct vm_operations_struct *vm_ops;
                unsigned long vm_pgoff;
                struct file *vm_file;
                ...
            };
            """
        return vm_area_struct, get_next_vma_area_struct

    def get_offset_vm_mm(self, task_addrs, offset_mm):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct vm_area_struct*)0).vm_mm")
            )
        except gdb.error:
            pass

        # slow path
        for task in task_addrs:
            mm = read_int_from_memory(task + offset_mm)
            if mm == 0:
                continue

            vm_area_struct, _ = self.get_vm_area_struct(mm)
            if vm_area_struct is None:
                return None

            current = vm_area_struct
            while True:
                x = read_int_from_memory(current)
                if x == mm:
                    break
                current += runtime.current_arch.ptrsize
            offset_vm_mm = current - vm_area_struct
            return offset_vm_mm
        return None

    def get_offset_vm_flags(self, offset_vm_mm):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct vm_area_struct*)0).vm_flags")
            )
        except gdb.error:
            pass

        # slow path
        if is_64bit():
            offset_vm_flags = offset_vm_mm + 8 * 2
        elif is_x86_32():
            cr4 = get_register("cr4", use_monitor=True)
            if (cr4 >> 5) & 1: # PAE check
                offset_vm_flags = offset_vm_mm + 8 * 2
            else:
                offset_vm_flags = offset_vm_mm + 4 * 2
        elif is_arm32():
            ret = gdb.execute("pagewalk --no-pager --disable-color", to_string=True)
            if "using long description" in ret:
                offset_vm_flags = offset_vm_mm + 8 * 2
            else:
                offset_vm_flags = offset_vm_mm + 4 * 2
        return offset_vm_flags

    def get_offset_vm_file(self, task_addrs, offset_mm, offset_vm_flags):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct vm_area_struct*)0).vm_file")
            )
        except gdb.error:
            pass

        # slow path
        for i in range(50):
            found = True
            for task in task_addrs:
                # skip kernel thread
                mm = read_int_from_memory(task + offset_mm)
                if mm == 0:
                    continue

                """
                normal case:
                [x64 5.10.127; corjail; sh]
                0xffff9df049f75cc0|+0x0000|+000: 0x0000564e44351000 // vm_start
                0xffff9df049f75cc8|+0x0008|+001: 0x0000564e4437f000 // vm_end
                0xffff9df049f75cd0|+0x0010|+002: 0xffff9df049f75000 // vm_next
                0xffff9df049f75cd8|+0x0018|+003: 0x0000000000000000 // vm_prev
                0xffff9df049f75ce0|+0x0020|+004: 0xffff9df049f75021 // vm_rb.__rb_parent_color
                0xffff9df049f75ce8|+0x0028|+005: 0x0000000000000000 // vm_rb.rb_right
                0xffff9df049f75cf0|+0x0030|+006: 0x0000000000000000 // vm_rb.rb_left
                0xffff9df049f75cf8|+0x0038|+007: 0x0000564e44351000 // rb_subtree_gap
                0xffff9df049f75d00|+0x0040|+008: 0xffff9df0426c8800 // vm_mm
                0xffff9df049f75d08|+0x0048|+009: 0x8000000000000025 // vm_page_prot
                0xffff9df049f75d10|+0x0050|+010: 0x0000000008000871 // vm_flags
                0xffff9df049f75d18|+0x0058|+011: 0xffff9df049f75059 // shared.rb.__rb_parent_color
                0xffff9df049f75d20|+0x0060|+012: 0x0000000000000000 // shared.rb.rb_right
                0xffff9df049f75d28|+0x0068|+013: 0x0000000000000000 // shared.rb.rb_left
                0xffff9df049f75d30|+0x0070|+014: 0x000000000000002d // shared.rb_subtree_last
                0xffff9df049f75d38|+0x0078|+015: 0xffff9df049f75d38 // anon_vma_chain.next
                0xffff9df049f75d40|+0x0080|+016: 0xffff9df049f75d38 // anon_vma_chain.prev
                0xffff9df049f75d48|+0x0088|+017: 0x0000000000000000 // anon_vma
                0xffff9df049f75d50|+0x0090|+018: 0xffffffff9b034380 // vm_ops
                0xffff9df049f75d58|+0x0098|+019: 0x0000000000000000 // vm_pgoff
                0xffff9df049f75d60|+0x00a0|+020: 0xffff9df0427a5800 // vm_file

                rare case: both vm_ops and vm_file are NULL
                [x64; 5.10.127; corjail; dockerd]
                0xffff9df04678aa80|+0x0000|+000: 0x000000c000000000 // vm_start
                0xffff9df04678aa88|+0x0008|+001: 0x000000c000400000 // vm_end
                0xffff9df04678aa90|+0x0010|+002: 0xffff9df04670d9c0 // vm_next
                0xffff9df04678aa98|+0x0018|+003: 0x0000000000000000 // vm_prev
                0xffff9df04678aaa0|+0x0020|+004: 0xffff9df04670d9e1 // vm_rb.__rb_parent_color
                0xffff9df04678aaa8|+0x0028|+005: 0x0000000000000000 // vm_rb.rb_right
                0xffff9df04678aab0|+0x0030|+006: 0x0000000000000000 // vm_rb.rb_left
                0xffff9df04678aab8|+0x0038|+007: 0x000000c000000000 // rb_subtree_gap
                0xffff9df04678aac0|+0x0040|+008: 0xffff9df0426ca800 // vm_mm
                0xffff9df04678aac8|+0x0048|+009: 0x8000000000000025 // vm_page_prot
                0xffff9df04678aad0|+0x0050|+010: 0x0000000008100073 // vm_flags
                0xffff9df04678aad8|+0x0058|+011: 0x0000000000000000 // shared.rb.__rb_parent_color
                0xffff9df04678aae0|+0x0060|+012: 0x0000000000000000 // shared.rb.rb_right
                0xffff9df04678aae8|+0x0068|+013: 0x0000000000000000 // shared.rb.rb_left
                0xffff9df04678aaf0|+0x0070|+014: 0x0000000000000000 // shared.rb_subtree_last
                0xffff9df04678aaf8|+0x0078|+015: 0xffff9df04676ea90 // anon_vma_chain.next
                0xffff9df04678ab00|+0x0080|+016: 0xffff9df04676ea90 // anon_vma_chain.prev
                0xffff9df04678ab08|+0x0088|+017: 0xffff9df04279e318 // anon_vma
                0xffff9df04678ab10|+0x0090|+018: 0x0000000000000000 // vm_ops
                0xffff9df04678ab18|+0x0098|+019: 0x000000000c000000 // vm_pgoff
                0xffff9df04678ab20|+0x00a0|+020: 0x0000000000000000 // vm_file

                normal case:
                [x64 6.6.0; trust_storage; init]
                0xffff000001ee6630|+0x0000|+000: 0x0000aaaac690d000 // vm_start
                0xffff000001ee6638|+0x0008|+001: 0x0000aaaac69d4000 // vm_end
                0xffff000001ee6640|+0x0010|+002: 0xffff0000010a84c0 // vm_mm
                0xffff000001ee6648|+0x0018|+003: 0x0020000000000fc3 // vm_page_prot
                0xffff000001ee6650|+0x0020|+004: 0x0000000000000075 // vm_flags
                0xffff000001ee6658|+0x0028|+005: 0x0000000000000003 // vm_lock_seq
                0xffff000001ee6660|+0x0030|+006: 0xffff000001ee7168 // vm_lock
                0xffff000001ee6668|+0x0038|+007: 0x0000000000000000 // detached
                0xffff000001ee6670|+0x0040|+008: 0xffff000005f831a1 // shared.rb.__rb_parent_color
                0xffff000001ee6678|+0x0048|+009: 0x0000000000000000 // shared.rb.rb_right
                0xffff000001ee6680|+0x0050|+010: 0x0000000000000000 // shared.rb.rb_left
                0xffff000001ee6688|+0x0058|+011: 0x00000000000000c6 // shared.rb_subtree_last
                0xffff000001ee6690|+0x0060|+012: 0xffff000001ee6690 // anon_vma_chain.next
                0xffff000001ee6698|+0x0068|+013: 0xffff000001ee6690 // anon_vma_chain.prev
                0xffff000001ee66a0|+0x0070|+014: 0x0000000000000000 // anon_vma
                0xffff000001ee66a8|+0x0078|+015: 0xffffa4277c4d80c8 // vm_ops
                0xffff000001ee66b0|+0x0080|+016: 0x0000000000000000 // vm_pgoff
                0xffff000001ee66b8|+0x0088|+017: 0xffff00000025d400 // vm_file
                """
                vm_area_struct, _ = self.get_vm_area_struct(mm)
                ptr_anon_vma_chain = vm_area_struct + offset_vm_flags + runtime.current_arch.ptrsize * i
                if not is_double_link_list(ptr_anon_vma_chain):
                    found = False
                    break
                ptr_anon_vma = vm_area_struct + offset_vm_flags + runtime.current_arch.ptrsize * (i + 2)
                anon_vma = read_int_from_memory(ptr_anon_vma)
                if anon_vma != 0 and not is_valid_addr(anon_vma): # allow NULL
                    found = False
                    break
                ptr_vm_ops = vm_area_struct + offset_vm_flags + runtime.current_arch.ptrsize * (i + 3)
                vm_ops = read_int_from_memory(ptr_vm_ops)
                if vm_ops != 0 and not is_valid_addr(vm_ops): # allow NULL
                    found = False
                    break
                ptr_vm_file = vm_area_struct + offset_vm_flags + runtime.current_arch.ptrsize * (i + 5)
                vm_file = read_int_from_memory(ptr_vm_file)
                if vm_file != 0 and not is_valid_addr(vm_file): # allow NULL
                    found = False
                    break
            if found:
                return offset_vm_flags + runtime.current_arch.ptrsize * (i + 5)
        return None

    def get_mm(self, task, offset_mm):
        mm = read_int_from_memory(task + offset_mm)
        if mm == 0:
            return []

        vm_areas = []
        VmArea = collections.namedtuple("VmArea", "start end flags file")
        current, get_next_vma_area_struct = self.get_vm_area_struct(mm)
        while current:
            vm_start = read_int_from_memory(current)
            vm_end = read_int_from_memory(current + runtime.current_arch.ptrsize)
            vm_flags = read_int_from_memory(current + self.offset_vm_flags)
            vm_file = read_int_from_memory(current + self.offset_vm_file)
            filepath = self.get_filepath(vm_file)
            perm = Permission(value=vm_flags)
            vm_areas.append(VmArea(vm_start, vm_end, str(perm), filepath))
            current = get_next_vma_area_struct(current)
        return vm_areas

    def get_offset_mnt(self, file):
        """
        [~v6.4]
        struct file {
            union {                           // ~v5.19
                struct llist_node fu_llist;   // ~v5.19
                struct rcu_head fu_rcuhead;   // ~v5.19
            } f_u;                            // ~v5.19
            union {                           // v6.0~
                struct llist_node f_llist;    // v6.0~
                struct rcu_head f_rcuhead;    // v6.0~
                unsigned int f_iocb_flags;    // v6.0~
            };                                // v6.0~
            struct path {
                struct vfsmount *mnt;
                struct dentry *dentry;
            } f_path;
            struct inode *f_inode;            // v3.9~
            ...
        };

        [v6.5~v6.11]
        struct file {
            union {
                struct callback_head {
                    struct callback_head *next;
                    void (*func)(struct callback_head *head);
                } f_task_work; // v6.8~;
                struct llist_node f_llist;
                struct rcu_head f_rcuhead; // ~v6.7 (=callback_head)
                unsigned int f_iocb_flags;
            };
            spinlock_t f_lock;
            fmode_t f_mode;
            atomic_long_t f_count;
            struct mutex f_pos_lock;
            loff_t f_pos;
            unsigned int f_flags;
            struct fown_struct {
                rwlock_t lock;
                struct pid *pid;
                enum pid_type pid_type;
                kuid_t uid, euid;
                int signum;
            } f_owner;
            const struct cred *f_cred;
            struct file_ra_state {
                pgoff_t start;
                unsigned int size;
                unsigned int async_size;
                unsigned int ra_pages;
                unsigned int mmap_miss;
                loff_t prev_pos;
            } f_ra;
            struct path {
                struct vfsmount *mnt;
                struct dentry *dentry;
            } f_path;
            struct inode *f_inode;
            ...
        };

        [v6.12~]
        struct file {
            atomic_long_t f_count; // v6.12
            file_ref_t f_ref; // v6.13~v6.14
            spinlock_t f_lock;
            fmode_t f_mode;
            const struct file_operations *f_op;
            struct address_space *f_mapping;
            void *private_data;
            struct inode *f_inode;
            unsigned int f_flags;
            unsigned int f_iocb_flags;
            const struct cred *f_cred;
            struct fown_struct *f_owner; // v6.15~
            /* --- cacheline 1 boundary (64 bytes) --- */
            struct path {
                struct vfsmount *mnt;
                struct dentry *dentry;
            } f_path;
            union {
                struct mutex f_pos_lock;
                u64 f_pipe;
            };
            loff_t f_pos;
            ...
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct file*)0).f_path")
            ) + to_unsigned_long(
                gdb.parse_and_eval("&((struct path*)0).mnt")
            )
        except gdb.error:
            pass

        # slow path
        if not is_valid_addr(file):
            return None

        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        if kversion < "6.5":
            offset_mnt = runtime.current_arch.ptrsize * 2
        elif "6.5" <= kversion < "6.12":
            # plan 1
            """
            gef> slab-contains 0xffff9f49811d33e0
            slab: 0xfffff93f800474c0
            kmem_cache: 0xffff9f4981048c00
            base: 0xffff9f49811d3000
            name: mnt_cache  size: 0x140  num_pages: 0x1
            remarks: unaligned
            """
            for i in range(0x40):
                cand_offset_mnt = runtime.current_arch.ptrsize * i
                mnt = read_int_from_memory(file + cand_offset_mnt)
                # f_path.mnt points in the middle of the chunk, so the "unaligned" warning is not a problem
                ret = Kernel.get_slab_contains(mnt, allow_unaligned=True)
                if not ret:
                    continue
                if "mnt_cache" in ret:
                    offset_mnt = cand_offset_mnt
                    break
            else:
                # plan 2
                """
                It has also been observed when mnt_cache is not used.
                In this case, the 2 previous elements from ext4_inode_cache or shmem_inode_cache
                seem to be the relevant pointer.

                0xffff8b864013a298|+0x0098|+019: 0xffff8b86436e4da0 (task_group) <-- here is mnt but various slab names
                0xffff8b864013a2a0|+0x00a0|+020: 0xffff8b86404079c0 (kmalloc-rcl-192)
                0xffff8b864013a2a8|+0x00a8|+021: 0xffff8b864041e0a8 (ext4_inode_cache) <- unique (`*_inode_cache`)

                0xffff8b864013a698|+0x0098|+019: 0xffff8b8640171020 (task_group) <-- here is mnt but various slab names
                0xffff8b864013a6a0|+0x00a0|+020: 0xffff8b86436159c0 (kmalloc-rcl-192)
                0xffff8b864013a6a8|+0x00a8|+021: 0xffff8b8643730640 (shmem_inode_cache) <- unique (`*_inode_cache`)
                """
                for i in range(0x40):
                    cand_offset_mnt = runtime.current_arch.ptrsize * i
                    mnt = read_int_from_memory(file + cand_offset_mnt)
                    ret = Kernel.get_slab_contains(mnt, allow_unaligned=True)
                    if not ret:
                        continue
                    if "inode_cache" in ret:
                        offset_mnt = cand_offset_mnt - runtime.current_arch.ptrsize * 2
                        break
                else:
                    raise
        elif "6.12" <= kversion:
            if is_64bit():
                offset_mnt = 64
            else:
                """
                0x811f3180|+0x0000|+000: f_count        : 0x00000004
                0x811f3184|+0x0004|+001: f_lock         : 0x00000000
                0x811f3188|+0x0008|+002: f_mode         : 0x004a801d
                0x811f318c|+0x000c|+003: f_op           : 0x80a0e040  ->  0x00000000
                0x811f3190|+0x0010|+004: f_mapping      : 0x813a2140  ->  0x813a2050  ->  0x000589ed
                0x811f3194|+0x0014|+005: private_data   : 0x00000000
                0x811f3198|+0x0018|+006: f_inode        : 0x813a2050  ->  0x000589ed
                0x811f319c|+0x001c|+007: f_flags        : 0x00020020
                0x811f31a0|+0x0020|+008: f_iocb_flags   : 0x00000000
                0x811f31a4|+0x0024|+009: f_cred         : 0x81378280  ->  0x00000005
                0x811f31a8|+0x0028|+010: f_path.mnt     : 0x810043d0  ->  0x81402088  ->  0x00210000
                0x811f31ac|+0x002c|+011: f_path.dentry  : 0x814fd990  ->  0x00400008
                0x811f31b0|+0x0030|+012: mutex.owner    : 0x00000000
                0x811f31b4|+0x0034|+013: mutex.wait_lock: 0x00000000
                0x811f31b8|+0x0038|+014:                : 0x00000000

                pattern of sizeof(lock) == 0:
                0xc33c7100|+0x0000|+000: f_lock,f_mode         : 0x0c4a801d
                0xc33c7104|+0x0004|+001: f_op                  : 0xc1f9bee0  ->  0x00000000
                0xc33c7108|+0x0008|+002: f_mapping             : 0xc3491150  ->  0xc3491068  ->  0x000d89ed
                0xc33c710c|+0x000c|+003: private_data          : 0x00000000
                0xc33c7110|+0x0010|+004: f_inode               : 0xc3491068  ->  0x000d89ed
                0xc33c7114|+0x0014|+005: f_flags               : 0x00008020
                0xc33c7118|+0x0018|+006: f_iocb_flags          : 0x00000000
                0xc33c711c|+0x001c|+007: f_cred                : 0xc30ba080  ->  0x00000004
                0xc33c7120|+0x0020|+008: f_owner               : 0x00000000
                0xc33c7124|+0x0024|+009: f_path.mnt            : 0xc38b4f10  ->  0xc3459300  ->  0x00100000
                0xc33c7128|+0x0028|+010: f_path.dentry         : 0xc3459580  ->  0x00200000
                0xc33c712c|+0x002c|+011: mutex.owner           : 0x00000000
                0xc33c7130|+0x0030|+012: mutex.wait_{lock,list}: 0xc33c7130  ->  [loop detected]
                0xc33c7134|+0x0034|+013:                       : 0xc33c7130  ->  [loop detected]
                """
                for i in range(16):
                    cand_offset_mnt = runtime.current_arch.ptrsize * (i + 9)
                    # f_path.mnt
                    if not is_valid_addr_addr(file + cand_offset_mnt):
                        continue
                    # f_path.mnt.mnt_root
                    x = read_int_from_memory(read_int_from_memory(file + cand_offset_mnt))
                    if not is_valid_addr(x):
                        continue
                    # f_path.dentry
                    if not is_valid_addr_addr(file + cand_offset_mnt + runtime.current_arch.ptrsize):
                        continue
                    offset_mnt = cand_offset_mnt
                    break
                else:
                    raise
        return offset_mnt

    def get_offset_dentry(self, offset_mnt):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct file*)0).f_path")
            ) + to_unsigned_long(
                gdb.parse_and_eval("&((struct path*)0).dentry")
            )
        except gdb.error:
            pass

        # slow path
        return offset_mnt + runtime.current_arch.ptrsize

    def get_offset_d_iname(self, dentry):
        """
        struct dentry {
            unsigned int d_flags;
            seqcount_spinlock_t d_seq;
            struct hlist_bl_node d_hash;
            struct dentry *d_parent;
                                           // Padding can be added here
            struct qstr {
                union {
                    struct {
                        HASH_LEN_DECLARE;
                    };
                    u64 hash_len;
                };
                const unsigned char *name; // this points d_iname
            } d_name;
            struct inode *d_inode;
            unsigned char d_iname[DNAME_INLINE_LEN];
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct dentry*)0).d_iname")
            )
        except gdb.error:
            pass

        # slow path
        current = dentry
        while True:
            name = read_int_from_memory(current)
            if 0 < name - current <= 0x20:
                offset_d_iname = name - dentry
                break
            current += runtime.current_arch.ptrsize
        return offset_d_iname

    def get_offset_d_inode(self, offset_d_iname):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct dentry*)0).d_inode")
            )
        except gdb.error:
            pass

        # slow path
        return offset_d_iname - runtime.current_arch.ptrsize

    def get_offset_d_parent(self, dentry, offset_d_iname):
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct dentry*)0).d_parent")
            )
        except gdb.error:
            pass

        # slow path
        offset_dname_name = offset_d_iname - runtime.current_arch.ptrsize * 2
        # skip if padding
        while read_int_from_memory(dentry + offset_dname_name) != dentry + offset_d_iname:
            offset_dname_name -= runtime.current_arch.ptrsize

        offset_d_parent = offset_dname_name - 8 - runtime.current_arch.ptrsize
        # skip if padding
        while True:
            if is_valid_addr_addr(dentry + offset_d_parent): # roughly check
                parent = read_int_from_memory(dentry + offset_d_parent)
                if (parent & 0b11) == 0: # align check
                    parent_parent = read_int_from_memory(parent + offset_d_parent)
                    if is_valid_addr(parent_parent):
                        break
            offset_d_parent -= runtime.current_arch.ptrsize
        return offset_d_parent

    def get_offset_i_ino(self, inode):
        """
        struct inode {
            umode_t i_mode;
            unsigned short i_opflags;
            kuid_t i_uid;
            kgid_t i_gid;
            unsigned int i_flags;
        #ifdef CONFIG_FS_POSIX_ACL
            struct posix_acl *i_acl;
            struct posix_acl *i_default_acl;
        #endif
            const struct inode_operations *i_op;
            struct super_block *i_sb;
            struct address_space *i_mapping;
        #ifdef CONFIG_SECURITY
            void *i_security;
        #endif
            unsigned long i_ino;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct inode*)0).i_no")
            )
        except gdb.error:
            pass

        # slow path
        current = inode + 2 + 2 + 4 + 4 + 4

        # now, `current` points i_acl or i_op
        while True:
            v = read_int_from_memory(current)
            if v == 0:
                current += runtime.current_arch.ptrsize
                continue
            if is_64bit() and v == 0xffff_ffff_ffff_ffff:
                current += runtime.current_arch.ptrsize
                continue
            elif is_32bit() and v == 0xffff_ffff:
                current += runtime.current_arch.ptrsize
                continue
            elif is_valid_addr(v):
                current += runtime.current_arch.ptrsize
                continue
            offset_i_ino = current - inode
            break
        return offset_i_ino

    def get_ino(self, file):
        dentry = read_int_from_memory(file + self.offset_dentry)
        inode = read_int_from_memory(dentry + self.offset_d_inode)
        i_ino = read_int_from_memory(inode + self.offset_i_ino)
        return i_ino

    def get_filepath(self, file):
        if not is_valid_addr(file):
            return ""

        if file in self.filepath_cache:
            return self.filepath_cache[file]

        """
        struct path {
            struct vfsmount *mnt;
            struct dentry *dentry;
        } f_path;

        struct mount {
            struct hlist_node mnt_hash;
            struct mount *mnt_parent;
            struct dentry *mnt_mountpoint;
            struct vfsmount {
                struct dentry *mnt_root;
                struct super_block *mnt_sb;
                int mnt_flags;
                struct mnt_idmap *mnt_idmap; // v6.2~
                struct user_namespace *mnt_userns; // v5.12~v6.1
            } mnt; <-- f_path.mnt points here
            ...
        };
        """

        def is_root(vfsmnt, dentry):
            mnt_root = read_int_from_memory(vfsmnt + offset_vfsmount_mnt_root)
            parent = read_int_from_memory(dentry + self.offset_d_parent)
            return dentry == mnt_root or parent == dentry

        def is_global_root(mnt):
            parent = read_int_from_memory(mnt + offset_mount_mnt_parent)
            return parent == mnt

        def read_dentry_str(dentry):
            # Try d_shortname (inline name) directly
            name = read_cstring_from_memory(dentry + self.offset_d_iname)
            if name:
                return name

            # Try d_name.name pointer (no padding case)
            # Validate pointer before dereferencing
            for back in [2, 3]:
                name_ptr = read_int_from_memory(
                    dentry + self.offset_d_iname - runtime.current_arch.ptrsize * back
                )
                if not is_valid_addr(name_ptr) or (name_ptr & 0b11) != 0:
                    continue
                name = read_cstring_from_memory(name_ptr)
                if name:
                    return name
            return ""

        offset_vfsmount_mnt_root = 0
        offset_mount_mnt_parent = runtime.current_arch.ptrsize * 2
        offset_mount_mnt_mountpoint = runtime.current_arch.ptrsize * 3
        offset_mount_mnt = runtime.current_arch.ptrsize * 4

        filepath = []

        dentry = read_int_from_memory(file + self.offset_dentry)
        vfsmnt = read_int_from_memory(file + self.offset_mnt)
        mnt = vfsmnt - offset_mount_mnt

        while True:
            if is_root(vfsmnt, dentry):
                if is_global_root(mnt):
                    name = read_dentry_str(dentry)
                    filepath.append(name)
                    break
                else:
                    dentry = read_int_from_memory(mnt + offset_mount_mnt_mountpoint)
                    mnt = read_int_from_memory(mnt + offset_mount_mnt_parent)
                    vfsmnt = mnt + offset_mount_mnt
                    continue
            else:
                name = read_dentry_str(dentry)
                filepath.append(name)
                dentry = read_int_from_memory(dentry + self.offset_d_parent)

        filepath = os.path.join(*filepath[::-1])
        if filepath in ["UNIX", "NETLINK", "TCP", "TCPv6", "UDP", "UDPv6", "PACKET"]:
            filepath = "socket:[{:d}]".format(self.get_ino(file))
        elif filepath and not filepath.startswith("/"):
            filepath = "anon_inode:{:s}".format(filepath)
        elif filepath == "":
            filepath = "pipe:[{:d}]".format(self.get_ino(file))

        self.filepath_cache[file] = filepath
        return filepath

    def add_lwp_task(self, task_addrs):
        lwp_task_addrs = []
        kversion = Kernel.kernel_version()

        for task in task_addrs:
            seen = []
            if kversion < "6.7":
                lwp = task
                while lwp not in seen:
                    seen.append(lwp)
                    try:
                        lwp = read_int_from_memory(lwp + self.offset_thread_group) - self.offset_thread_group
                    except gdb.MemoryError:
                        break
                lwp_task_addrs.extend(seen)

            else:
                signal = read_int_from_memory(task + self.offset_signal)
                head = signal + self.offset_thread_head
                seen = [head]
                curr = read_int_from_memory(head)
                while curr not in seen:
                    seen.append(curr)
                    lwp = curr - self.offset_thread_group
                    lwp_task_addrs.append(lwp)
                    try:
                        curr = read_int_from_memory(curr)
                    except gdb.MemoryError:
                        break
        return lwp_task_addrs

    def get_offset_nsproxy(self, task_addr, offset_files):
        """
        struct task_struct {
            ...
            struct files_struct *files;
        #ifdef CONFIG_IO_URING
            struct io_uring_task *io_uring;
            struct io_restriction *io_uring_restrict; // v7.0~
        #endif
            struct nsproxy *nsproxy;
            struct signal_struct *signal;
            struct sighand_struct __rcu *sighand;
            sigset_t blocked;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).nsproxy")
            )
        except gdb.error:
            pass

        # slow path
        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        offset_nsproxy = offset_files + runtime.current_arch.ptrsize # or io_uring
        v = read_int_from_memory(task_addr + offset_nsproxy + runtime.current_arch.ptrsize * 3) # blocked
        if not is_valid_addr(v):
            # CONFIG_IO_URING=n
            return offset_nsproxy
        # CONFIG_IO_URING=y
        if kversion < "7.0":
            offset_nsproxy += runtime.current_arch.ptrsize
        else:
            offset_nsproxy += runtime.current_arch.ptrsize * 2
        return offset_nsproxy

    def get_offset_sighand(self, task_addr, offset_files):
        """
        struct task_struct {
            ...
            struct files_struct *files;
        #ifdef CONFIG_IO_URING
            struct io_uring_task *io_uring;
            struct io_restriction *io_uring_restrict; // v7.0~
        #endif
            struct nsproxy *nsproxy;
            struct signal_struct *signal;
            struct sighand_struct __rcu *sighand;
            sigset_t blocked;
            ...
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct task_struct*)0).sighand")
            )
        except gdb.error:
            pass

        # slow path
        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        offset_sighand = offset_files + runtime.current_arch.ptrsize * 3 # or nsproxy
        v = read_int_from_memory(task_addr + offset_sighand + runtime.current_arch.ptrsize) # blocked
        if not is_valid_addr(v):
            # CONFIG_IO_URING=n
            return offset_sighand
        # CONFIG_IO_URING=y
        if kversion < "7.0":
            offset_sighand += runtime.current_arch.ptrsize
        else:
            offset_sighand += runtime.current_arch.ptrsize * 2
        return offset_sighand + runtime.current_arch.ptrsize

    def get_offset_action(self, sighand):
        """
        [v5.3~]
        struct sighand_struct {
            spinlock_t siglock;
            refcount_t count;
            struct wait_queue_head {
                spinlock_t lock;
                struct list_head head;
            } signalfd_wqh;
            struct k_sigaction {
                struct sigaction {
                    __sighandler_t sa_handler;
                    unsigned long sa_flags;
                #ifdef __ARCH_HAS_SA_RESTORER
                    __sigrestore_t sa_restorer;
                #endif
                    sigset_t sa_mask;
                } sa;
            #ifdef __ARCH_HAS_KA_RESTORER
                __sigrestore_t ka_restorer;
            #endif
            } action[_NSIG]; // 64
        };

        [~v5.2]
        struct sighand_struct {
            refcount_t count;
            struct k_sigaction {
                struct sigaction sa;
            #ifdef __ARCH_HAS_KA_RESTORER
                __sigrestore_t ka_restorer;
            #endif
            } action[_NSIG]; // 64
            spinlock_t siglock;
            wait_queue_head_t signalfd_wqh;
        };
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("&((struct sighand_struct*)0).action")
            )
        except gdb.error:
            pass

        # slow path
        kversion = Kernel.kernel_version()
        if kversion is None:
            return None
        if "5.3" <= kversion:
            # search for signalfd_wqh.list_head
            found = False
            for i in range(1, 30):
                offset_list_head = runtime.current_arch.ptrsize * i
                head = sighand + offset_list_head
                if not is_valid_addr(head):
                    continue

                current = read_int_from_memory(head)
                seen = []
                while True:
                    if current == head:
                        found = True
                        break
                    if not is_valid_addr(current):
                        break
                    if current in seen:
                        break
                    seen.append(current)
                    current = read_int_from_memory(current)
                if found:
                    break

            if not found:
                return None

            offset_action = offset_list_head + runtime.current_arch.ptrsize * 2

        else: # < 5.3
            offset_action = runtime.current_arch.ptrsize
        return offset_action

    def get_sizeof_action(self, task_addrs, offset_sighand, offset_action, offset_mm):
        """
        case 1 (x64)
        0xffff8f63011e4400|+0x0000|+000: 0x0000000100000000
        0xffff8f63011e4408|+0x0008|+001: 0x0000000000000000
        0xffff8f63011e4410|+0x0010|+002: 0xffff8f63593e11e0  ->  [loop detected]
        0xffff8f63011e4418|+0x0018|+003: 0xffff8f63593e11e0  ->  0xffff8f63011e4410  ->  [loop detected]
        0xffff8f63011e4420|+0x0020|+004: 0x0000000000000000 <- action[0]
        0xffff8f63011e4428|+0x0028|+005: 0x0000000014000000
        0xffff8f63011e4430|+0x0030|+006: 0x00007f3ec71d0d60
        0xffff8f63011e4438|+0x0038|+007: 0x0000000000000000
        0xffff8f63011e4440|+0x0040|+008: 0x0000000000000000 <- action[1]
        0xffff8f63011e4448|+0x0048|+009: 0x0000000014000000
        0xffff8f63011e4450|+0x0050|+010: 0x00007f3ec71d0d60
        0xffff8f63011e4458|+0x0058|+011: 0x0000000000000000
        0xffff8f63011e4460|+0x0060|+012: 0x0000562e3b34bdf0 <- action[2]
        0xffff8f63011e4468|+0x0068|+013: 0x0000000044000000
        0xffff8f63011e4470|+0x0070|+014: 0x00007f3ec71d0d60
        0xffff8f63011e4478|+0x0078|+015: 0x0000000000000000
        0xffff8f63011e4480|+0x0080|+016: 0x0000562e3b34bdf0 <- action[3]
        0xffff8f63011e4488|+0x0088|+017: 0x0000000044000000
        0xffff8f63011e4490|+0x0090|+018: 0x00007f3ec71d0d60
        0xffff8f63011e4498|+0x0098|+019: 0x0000000000000000
        ...

        case 2 (arm64)
        0xffff000003080000|+0x0000|+000: 0x0000000100000000
        0xffff000003080008|+0x0008|+001: 0x0000000000000000
        0xffff000003080010|+0x0010|+002: 0xffff000003080010  ->  [loop detected]
        0xffff000003080018|+0x0018|+003: 0xffff000003080010  ->  [loop detected]
        0xffff000003080020|+0x0020|+004: 0x0000000000000000 <- action[0]
        0xffff000003080028|+0x0028|+005: 0x0000000000000000
        0xffff000003080030|+0x0030|+006: 0x0000000000000000
        0xffff000003080038|+0x0038|+007: 0x0000000000000000
        0xffff000003080040|+0x0040|+008: 0x000000000051dc20 <- action[1]
        0xffff000003080048|+0x0048|+009: 0x0000000000000000
        0xffff000003080050|+0x0050|+010: 0x0000000000000002
        0xffff000003080058|+0x0058|+011: 0xfffffffe7ffbfeff
        0xffff000003080060|+0x0060|+012: 0x0000000000000001 <- action[2]
        0xffff000003080068|+0x0068|+013: 0x0000000000000000
        0xffff000003080070|+0x0070|+014: 0x0000000000000002
        0xffff000003080078|+0x0078|+015: 0xfffffffe7ffbfeff
        0xffff000003080080|+0x0080|+016: 0x0000000000000000 <- action[3]
        0xffff000003080088|+0x0088|+017: 0x0000000000000000
        0xffff000003080090|+0x0090|+018: 0x0000000000000000
        0xffff000003080098|+0x0098|+019: 0x0000000000000000
        ...
        """
        # fast path
        try:
            return to_unsigned_long(
                gdb.parse_and_eval("sizeof(struct k_sigaction)")
            )
        except gdb.error:
            pass

        # slow path
        if is_32bit():
            possible_sizes = [0x10, 0x14, 0x18]
        else:
            possible_sizes = [0x18, 0x20, 0x28]

        # calc sizeof(action[0])
        sizeof_action = 0xffff_ffff_ffff_ffff
        for task in task_addrs:
            mm = read_int_from_memory(task + offset_mm)
            if mm == 0:
                # for speed up; ignore if kernel thread
                continue

            sighand = read_int_from_memory(task + offset_sighand)
            current = sighand + offset_action
            found_offset_case1 = []
            found_offset_case2 = []

            for i in range(64 * 4):
                offset = runtime.current_arch.ptrsize * i

                # check case 1 (sa_flags)
                v = read_int_from_memory(current + offset)
                # SA_RESTORER, SA_RESTART, SA_NODEFER, SA_RESTART|SA_RESTORER, SA_NODEFER|SA_RESTORER
                if v in [0x0400_0000, 0x1000_0000, 0x4000_0000, 0x1400_0000, 0x4400_0000]:
                    found_offset_case1.append(offset)

                # check case 2 (sa_mask)
                v = read_int64_from_memory(current + offset)
                if bin(v)[2:].count("1") > 56: # heuristic threshold
                    found_offset_case2.append(offset)

            if len(found_offset_case1) >= 2:
                sizeof_action_tmp = min(y - x for x, y in zip(found_offset_case1[:-1], found_offset_case1[1:]))
                # it is minimum size, so fast return
                if sizeof_action_tmp in possible_sizes:
                    return sizeof_action_tmp
                # not minimum size, so check next task
                sizeof_action = min(sizeof_action, sizeof_action_tmp)

            if len(found_offset_case2) >= 2:
                sizeof_action_tmp = min(y - x for x, y in zip(found_offset_case2[:-1], found_offset_case2[1:]))
                # it is minimum size, so fast return
                if sizeof_action_tmp in possible_sizes:
                    return sizeof_action_tmp
                # not minimum size, so check next task
                sizeof_action = min(sizeof_action, sizeof_action_tmp)

        if sizeof_action != 0xffff_ffff_ffff_ffff:
            for ps in possible_sizes:
                if sizeof_action % ps == 0:
                    return sizeof_action
        return None

    def initialize(self):
        kversion = Kernel.kernel_version()
        if kversion is None:
            self.quiet_err("Could not find Linux kernel")
            return False

        # init_task
        if self.args.init_task is not None:
            init_task = self.args.init_task
        else:
            init_task = KernelAddressHeuristicFinder.get_init_task()
        if init_task is None:
            self.quiet_err("Could not find init_task")
            return False
        self.quiet_info("init_task: {:#x}".format(init_task))

        # task_struct->tasks
        if self.offset_tasks is None:
            self.offset_tasks = self.get_offset_tasks(init_task)
        if self.offset_tasks is None:
            self.quiet_err("Could not find task_struct->tasks")
            return False
        self.quiet_info("offsetof(task_struct, tasks): {:#x}".format(self.offset_tasks))

        # task addresses
        task_addrs = self.get_task_list(init_task, self.offset_tasks)
        if task_addrs is None:
            self.quiet_err("Failed to list each tasks")
            return False
        self.quiet_info("Number of tasks: {:d}".format(len(task_addrs)))

        # task_struct->mm
        if self.offset_mm is None:
            self.offset_mm = self.get_offset_mm(task_addrs[0], self.offset_tasks)
        if self.offset_mm is None:
            self.quiet_err("Could not find task_struct->mm")
            return False
        self.quiet_info("offsetof(task_struct, mm): {:#x}".format(self.offset_mm))

        # task_struct->stack
        if self.offset_stack is None:
            self.offset_stack = self.get_offset_stack(task_addrs)
        if self.offset_stack is None:
            self.quiet_err("Could not find task_struct->stack")
            return False
        self.quiet_info("offsetof(task_struct, stack): {:#x}".format(self.offset_stack))

        # task_struct->pid
        if self.offset_pid is None:
            self.offset_pid = self.get_offset_pid(task_addrs)
        if self.offset_pid is None:
            self.quiet_err("Could not find task_struct->pid")
            return False
        self.quiet_info("offsetof(task_struct, pid): {:#x}".format(self.offset_pid))

        # task_struct->stack_canary
        if self.offset_kcanary is None:
            self.offset_kcanary = self.get_offset_canary(task_addrs, self.offset_pid)
        if self.offset_kcanary is None:
            self.quiet_info("offsetof(task_struct, stack_canary): None")
        else:
            self.quiet_info("offsetof(task_struct, stack_canary): {:#x}".format(self.offset_kcanary))

        # task_struct->comm
        if self.offset_comm is None:
            self.offset_comm = self.get_offset_comm(task_addrs)
        if self.offset_comm is None:
            self.quiet_err("Could not find task_struct->comm[TASK_CMM_LEN]")
            return False
        self.quiet_info("offsetof(task_struct, comm): {:#x}".format(self.offset_comm))

        # task_struct->cred
        if self.offset_cred is None:
            self.offset_cred = self.get_offset_cred(task_addrs, self.offset_comm)
        if self.offset_cred is None:
            self.quiet_err("Could not find task_struct->cred")
            return False
        self.quiet_info("offsetof(task_struct, cred): {:#x}".format(self.offset_cred))

        # cred.uid
        if self.offset_uid is None:
            self.offset_uid = self.get_offset_uid(task_addrs[0] + self.offset_cred)
        if self.offset_uid is None:
            self.quiet_err("Could not find cred->uid")
            return False
        self.quiet_info("offsetof(cred, uid): {:#x}".format(self.offset_uid))

        # kstack_top->saved_ptregs
        if self.args.print_regs:
            if self.offset_ptregs is None:
                self.kstack_size, self.offset_ptregs = self.get_offset_ptregs(task_addrs, self.offset_stack)
            if self.offset_ptregs is None:
                self.quiet_err("Could not find saved ptregs")
                return False
            self.quiet_info("kstack size: {:#x}".format(self.kstack_size))
            self.quiet_info("offsetof(kstack_top, saved ptregs): {:#x}".format(self.offset_ptregs))

        # vm_area_struct->vm_mm
        # vm_area_struct->vm_flags
        # vm_area_struct->vm_file
        # file->f_path.mnt
        # file->f_path.dentry
        # dentry->d_iname
        # dentry->d_parent
        # dentry->d_inode
        # inode->i_ino
        if self.args.print_maps or self.args.print_fd:
            if self.offset_vm_mm is None:
                self.offset_vm_mm = self.get_offset_vm_mm(task_addrs, self.offset_mm)
            if self.offset_vm_mm is None:
                self.quiet_err("Could not find vm_area_struct->vm_mm")
                return False
            self.quiet_info("offsetof(vm_area_struct, vm_mm): {:#x}".format(self.offset_vm_mm))

            if self.offset_vm_flags is None:
                self.offset_vm_flags = self.get_offset_vm_flags(self.offset_vm_mm)
            if self.offset_vm_flags is None:
                self.quiet_err("Could not find vm_area_struct->vm_flags")
                return False
            self.quiet_info("offsetof(vm_area_struct, vm_flags): {:#x}".format(self.offset_vm_flags))

            if self.offset_vm_file is None:
                self.offset_vm_file = self.get_offset_vm_file(task_addrs, self.offset_mm, self.offset_vm_flags)
            if self.offset_vm_file is None:
                self.quiet_err("Could not find vm_area_struct->vm_file")
                return False
            self.quiet_info("offsetof(vm_area_struct, vm_file): {:#x}".format(self.offset_vm_file))

            if self.offset_mnt is None:
                mm = read_int_from_memory(task_addrs[1] + self.offset_mm)
                current, _ = self.get_vm_area_struct(mm)
                self.quiet_info("vm_area_struct (init process): {:#x}".format(current))
                vm_file = read_int_from_memory(current + self.offset_vm_file)
                self.quiet_info("vm_file (init process): {:#x}".format(vm_file))
                self.offset_mnt = self.get_offset_mnt(vm_file)
            if self.offset_mnt is None:
                self.quiet_err("Could not find file->f_path.mnt")
                return False
            self.quiet_info("offsetof(file, f_path.mnt): {:#x}".format(self.offset_mnt))

            if self.offset_dentry is None:
                self.offset_dentry = self.get_offset_dentry(self.offset_mnt)
            self.quiet_info("offsetof(file, f_path.dentry): {:#x}".format(self.offset_dentry))

            if self.offset_d_iname is None:
                mm = read_int_from_memory(task_addrs[1] + self.offset_mm)
                current, _ = self.get_vm_area_struct(mm)
                vm_file = read_int_from_memory(current + self.offset_vm_file)
                dentry = read_int_from_memory(vm_file + self.offset_dentry)
                self.offset_d_iname = self.get_offset_d_iname(dentry)
            self.quiet_info("offsetof(dentry, d_iname): {:#x}".format(self.offset_d_iname))

            if self.offset_d_inode is None:
                self.offset_d_inode = self.get_offset_d_inode(self.offset_d_iname)
            self.quiet_info("offsetof(dentry, d_inode): {:#x}".format(self.offset_d_inode))

            if self.offset_d_parent is None:
                dentry = read_int_from_memory(vm_file + self.offset_dentry)
                self.offset_d_parent = self.get_offset_d_parent(dentry, self.offset_d_iname)
            self.quiet_info("offsetof(dentry, d_parent): {:#x}".format(self.offset_d_parent))

            if self.offset_i_ino is None:
                dentry = read_int_from_memory(vm_file + self.offset_dentry)
                inode = read_int_from_memory(dentry + self.offset_d_inode)
                self.offset_i_ino = self.get_offset_i_ino(inode)
            self.quiet_info("offsetof(inode, i_ino): {:#x}".format(self.offset_i_ino))

        # task_struct->files
        if self.args.print_fd or self.args.print_sighand or self.args.print_namespace or \
            ("6.7" <= kversion and self.args.print_thread) or self.args.print_seccomp:
            if self.offset_files is None:
                self.offset_files = self.get_offset_files(task_addrs, self.offset_comm)
            if self.offset_files is None:
                self.quiet_err("Could not find task_struct->files")
                return False
            self.quiet_info("offsetof(task_struct, files): {:#x}".format(self.offset_files))

        # files_struct->fdt
        if self.args.print_fd:
            if self.offset_fdt is None:
                self.offset_fdt = self.get_offset_fdt(task_addrs, self.offset_files)
            if self.offset_fdt is None:
                self.quiet_err("Could not find files_struct->fdt")
                return False
            self.quiet_info("offsetof(files_struct, fdt): {:#x}".format(self.offset_fdt))

        # cred->user_ns
        # task_struct->nsproxy
        if self.args.print_namespace or ("6.7" <= kversion and self.args.print_thread) or self.args.print_seccomp:
            if self.offset_user_ns is None:
                init_cred = read_int_from_memory(task_addrs[0] + self.offset_cred)
                self.offset_user_ns = self.get_offset_user_ns(init_cred, self.offset_uid)
            if self.offset_user_ns is None:
                self.quiet_err("Could not find cred->user_ns")
                return False
            self.quiet_info("offsetof(cred, user_ns): {:#x}".format(self.offset_user_ns))

            if self.offset_nsproxy is None:
                self.offset_nsproxy = self.get_offset_nsproxy(task_addrs[0], self.offset_files)
            if self.offset_nsproxy is None:
                self.quiet_err("Could not find task_struct->nsproxy")
                return False
            self.quiet_info("offsetof(task_struct, nsproxy): {:#x}".format(self.offset_nsproxy))

        # task_struct->group_leader
        # task_struct->thread_group
        # task_struct->signal (6.7~)
        # signal->thread_head (6.7~)
        if self.args.print_thread:
            if self.offset_group_leader is None:
                self.offset_group_leader = self.get_offset_group_leader(self.offset_pid, self.offset_kcanary)
            self.quiet_info("offsetof(task_struct, group_leader): {:#x}".format(self.offset_group_leader))

            if self.offset_thread_group is None:
                self.offset_thread_group = self.get_offset_thread_group(self.offset_group_leader)
            if self.offset_thread_group is None:
                self.quiet_err("Could not find task_struct->thread_group")
                return False
            if "6.7" <= kversion:
                self.quiet_info("offsetof(task_struct, thread_node): {:#x}".format(self.offset_thread_group))
            else:
                self.quiet_info("offsetof(task_struct, thread_group): {:#x}".format(self.offset_thread_group))

            if "6.7" <= kversion:
                if self.offset_signal is None:
                    self.offset_signal = self.get_offset_signal(self.offset_nsproxy)
                self.quiet_info("offsetof(task_struct, signal): {:#x}".format(self.offset_signal))

                if self.offset_thread_head is None:
                    self.offset_thread_head = self.get_offset_thread_head(task_addrs[0], self.offset_signal)
                self.quiet_info("offsetof(signal, thread_head): {:#x}".format(self.offset_thread_head))

        # task_struct->sighand
        if self.args.print_sighand:
            if self.offset_sighand is None:
                self.offset_sighand = self.get_offset_sighand(task_addrs[0], self.offset_files)
            if self.offset_sighand is None:
                self.quiet_err("Could not find task_struct->sighand")
                return False
            self.quiet_info("offsetof(task_struct, sighand): {:#x}".format(self.offset_sighand))

            if self.offset_action is None:
                sighand = read_int_from_memory(task_addrs[1] + self.offset_sighand)
                self.offset_action = self.get_offset_action(sighand)
            if self.offset_action is None:
                self.quiet_err("Could not find sighand_struct->action")
                return False
            self.quiet_info("offsetof(sighand_struct, action): {:#x}".format(self.offset_action))

            if self.sizeof_action is None:
                self.sizeof_action = self.get_sizeof_action(
                    task_addrs, self.offset_sighand, self.offset_action, self.offset_mm,
                )
            if self.sizeof_action is None:
                self.quiet_err("Could not find sizeof(action[0])")
                return False
            self.quiet_info("sizeof(action[0]): {:#x}".format(self.sizeof_action))

            self.signame_list = {
                1: "SIGHUP",
                2: "SIGINT",
                3: "SIGQUIT",
                4: "SIGILL",
                5: "SIGTRAP",
                6: "SIGABRT",
                7: "SIGBUS",
                8: "SIGFPE",
                9: "SIGKILL",
                10: "SIGUSR1",
                11: "SIGSEGV",
                12: "SIGUSR2",
                13: "SIGPIPE",
                14: "SIGALRM",
                15: "SIGTERM",
                16: "SIGSTKFLT",
                17: "SIGCHLD",
                18: "SIGCONT",
                19: "SIGSTOP",
                20: "SIGTSTP",
                21: "SIGTTIN",
                22: "SIGTTOU",
                23: "SIGURG",
                24: "SIGXCPU",
                25: "SIGXFSZ",
                26: "SIGVTALRM",
                27: "SIGPROF",
                28: "SIGWINCH",
                29: "SIGIO",
                30: "SIGPWR",
                31: "SIGSYS",
                32: "SIGCANCEL", # from glibc source code
                33: "SIGSETXID", # from glibc source code
                34: "SIGRTMIN",
                # 35 ... 49: SIGRTMIN+i
                # 50 ... 63: SIGRTMAX-i
                64: "SIGRTMAX",
            }
            for i in range(35, 50):
                self.signame_list[i] = "SIGRTMIN+{:d}".format(i - 34)
            for i in range(63, 49, -1):
                self.signame_list[i] = "SIGRTMAX-{:d}".format(64 - i)

        # task_struct->seccomp
        if self.args.print_seccomp:
            if self.offset_signal is None:
                self.offset_signal = self.get_offset_signal(self.offset_nsproxy)
            self.quiet_info("offsetof(task_struct, signal): {:#x}".format(self.offset_signal))

            if self.offset_seccomp is None:
                self.offset_seccomp = self.get_offset_seccomp(task_addrs, self.offset_signal)
            if self.offset_seccomp is None:
                self.quiet_err("Could not find task_struct->seccomp")
                return False
            self.quiet_info("offsetof(task_struct, seccomp): {:#x}".format(self.offset_seccomp))

            if self.offset_prev is None:
                self.offset_prev = self.get_offset_prev(task_addrs, self.offset_seccomp)
            if self.offset_prev is None:
                self.quiet_err("Could not find seccomp_filter->prev")
                return False
            self.quiet_info("offsetof(seccomp_filter, prev): {:#x}".format(self.offset_prev))

            if self.offset_prog is None:
                self.offset_prog = self.get_offset_prog(self.offset_prev)
            if self.offset_prog is None:
                self.quiet_err("Could not find seccomp_filter->prog")
                return False
            self.quiet_info("offsetof(seccomp_filter, prog): {:#x}".format(self.offset_prog))

            if self.offset_bpf_func is None:
                self.offset_bpf_func = self.get_offset_bpf_func(task_addrs, self.offset_seccomp, self.offset_prog)
            if self.offset_bpf_func is None:
                self.quiet_err("Could not find bpf_prog->bpf_func")
                return False
            self.quiet_info("offsetof(bpf_prog, bpf_func): {:#x}".format(self.offset_bpf_func))

            if self.offset_orig_prog is None:
                self.offset_orig_prog = self.get_offset_orig_prog(self.offset_bpf_func)
            if self.offset_orig_prog is None:
                self.quiet_err("Could not find bpf_prog->orig_prog")
                return False
            self.quiet_info("offsetof(bpf_prog, orig_prog): {:#x}".format(self.offset_orig_prog))

            self.offset_jited_len = 16

            try:
                self.seccomp_tools_command = [GefUtil.which("ceccomp"), "disasm", "-c", "always"]
                self.quiet_info("ceccomp is found")
            except FileNotFoundError:
                try:
                    self.seccomp_tools_command = [GefUtil.which("seccomp-tools"), "disasm"]
                    self.quiet_info("seccomp-tools is found")
                    if is_arm32():
                        self.quiet_warn("`seccomp-tools` is not supported on ARM32. "
                                        "Consider using `ceccomp` instead, as it supports ARM32.")
                        self.quiet_info("GEF uses `capstone-disassemble bpf_func`")
                        self.seccomp_tools_command = None
                except FileNotFoundError:
                    self.quiet_info("Could not find ceccomp or seccomp-tools, GEF uses `capstone-disassemble bpf_func`")
                    self.seccomp_tools_command = None

        return task_addrs

    def get_current_task_list(self):
        args = self.args # backup
        try:
            res = gdb.execute("kcurrent --quiet", to_string=True)
        except gdb.error:
            return {}
        # kcurrent calls ktask itself, so self.args will be overwritten. this is workaround.
        self.args = args # revert

        tmp_current_tasks = {}
        for line in res.splitlines():
            r = re.search(r"current \(cpu(\d+)\): (0x\S+) .+", line.strip())
            if r:
                cpu = int(r.group(1))
                task = int(r.group(2), 16)
                new_list = tmp_current_tasks.get(task, []) + [cpu]
                tmp_current_tasks[task] = new_list
                continue
            r = re.search(r"current: (0x\S+) .+", line.strip())
            if r:
                cpu = 0
                task = int(r.group(1), 16)
                new_list = tmp_current_tasks.get(task, []) + [cpu]
                tmp_current_tasks[task] = new_list
                continue

        current_tasks = {}
        for k, v in tmp_current_tasks.items():
            if len(v) > 1:
                # It is unclear whether this case can occur.
                current_tasks[k] = "cpu{:d},..".format(min(v))
            else:
                current_tasks[k] = "cpu{:d}".format(v[0])
        return current_tasks

    def dump(self, task_addrs):
        # add current tasks (cpuN > 0)
        current_tasks = self.get_current_task_list()
        to_add_tasks = [task for task in current_tasks.keys() if task not in task_addrs]
        task_addrs = task_addrs[:1] + to_add_tasks + task_addrs[1:]

        # LWP
        if self.args.print_thread:
            task_addrs = self.add_lwp_task(task_addrs)

        # print legend
        if not self.args.quiet:
            fmt = "{:<18s} {:7s} {:3s} {:<7s} {:<16s} {:<18s} [{:s}] {:<8s} {:<18s} {:<18s}"
            if self.args.print_all_id:
                ids_str = ["uid", "gid", "suid", "sgid", "euid", "egid", "fsuid", "fsgid"]
                uids_fmt = "{:>5s} {:>5s} {:>5s} {:>5s} {:>5s} {:>5s} {:>5s} {:>5s}"
            else:
                ids_str = ["uid", "gid"]
                uids_fmt = "{:>5s} {:>5s}"
            uids_str = uids_fmt.format(*ids_str)
            legend = [
                "task", "current", "K/U", "lwpid", "task->comm", "task->cred",
                uids_str, "seccomp", "kstack", "kcanary",
            ]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        if self.args.print_namespace:
            kversion = Kernel.kernel_version()
            nsproxy_members = ["count", "uts_ns", "ipc_ns", "mnt_ns", "pid_ns_for_children", "net_ns"]
            if "5.6" <= kversion:
                nsproxy_members += ["time_ns", "time_ns_for_children"]
            if "4.6" <= kversion:
                nsproxy_members += ["cgroup_ns"]
            if task_addrs:
                init_cred = read_int_from_memory(task_addrs[0] + self.offset_cred)
                init_user_ns = read_int_from_memory(init_cred + self.offset_user_ns)
                init_nsproxy = read_int_from_memory(task_addrs[0] + self.offset_nsproxy)

        # task parse
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for task in tqdm(task_addrs, leave=False, desc="task"):
            comm_string = read_cstring_from_memory(task + self.offset_comm)
            if self.args.filter:
                if not any(re_pattern.search(comm_string) for re_pattern in self.args.filter):
                    continue

            if self.args.task_filter:
                if task not in self.args.task_filter:
                    continue

            kstack = read_int_from_memory(task + self.offset_stack)
            pid = read_int32_from_memory(task + self.offset_pid)
            cred = read_int_from_memory(task + self.offset_cred)

            # current
            currentN = current_tasks.get(task, "-")

            # get process type (kernel or user-land)
            mm = read_int_from_memory(task + self.offset_mm)
            if mm == 0 or pid == 0:
                proctype = "K"
            else:
                proctype = "U"

            if self.args.user_process_only:
                if proctype == "K":
                    continue

            # get process type (main process or not)
            if self.args.print_thread:
                leader = read_int_from_memory(task + self.offset_group_leader)
                if leader != task:
                    proctype += "T"

            # uid
            if self.args.print_all_id:
                uids = [read_int32_from_memory(cred + self.offset_uid + j * 4) for j in range(8)]
                uids_fmt = "{:>5d},{:>5d},{:>5d},{:>5d},{:>5d},{:>5d},{:>5d},{:>5d}"
            else:
                uids = [read_int32_from_memory(cred + self.offset_uid + j * 4) for j in range(2)]
                uids_fmt = "{:>5d},{:>5d}"
            uids_str = uids_fmt.format(*uids)

            # kcanary
            if self.offset_kcanary:
                kcanary = read_int_from_memory(task + self.offset_kcanary)
                kcanary = "{:#018x}".format(kcanary)
            else:
                kcanary = "None"

            # seccomp
            if self.has_seccomp(task):
                seccomp = "Enabled"
            else:
                seccomp = "Disabled"

            # make output
            self.out.append("{:#018x} {:<7s} {:<3s} {:<7d} {:<16s} {:#018x} [{:s}] {:<8s} {:#018x} {:<18s}".format(
                task, currentN, proctype, pid, comm_string, cred, uids_str, seccomp, kstack, kcanary,
            ).rstrip())

            # skip additional information when swapper/N
            if pid == 0:
                continue

            additional = False

            # additional information (maps)
            if self.args.print_maps:
                additional = True
                mms = self.get_mm(task, self.offset_mm)
                if mms:
                    self.out.append(titlify("memory map of `{:s}`".format(comm_string)))
                    for mm in mms:
                        self.out.append("{:#018x}-{:#018x} {:s} {:s}".format(
                            mm.start, mm.end, mm.flags, mm.file,
                        ).rstrip())

            # additional information (regs)
            if proctype == "U" and self.args.print_regs:
                additional = True
                regs = self.get_regs(kstack, self.offset_ptregs)
                nr_table = Syscall.get_syscall_table().nr_table
                syscall_nr_regs = ["orig_rax", "orig_eax", "r7", "x8"]
                if regs:
                    self.out.append(titlify("registers of `{:s}`".format(comm_string)))
                    for k, v in regs.items():
                        if k in syscall_nr_regs and v in nr_table:
                            syscall_name = nr_table[v].name
                            self.out.append("{:16s}: {:s} ({:s})".format(
                                k, AddressUtil.format_address(v, long_fmt=True), syscall_name,
                            ))
                        else:
                            self.out.append("{:16s}: {:s}".format(
                                k, AddressUtil.format_address(v, long_fmt=True,
                            )))

            # additional information (files)
            if proctype == "U" and self.args.print_fd:
                additional = True
                self.out.append(titlify("file descriptors of `{:s}`".format(comm_string)))

                fmt = "{:3s} {:18s} {:18s} {:18s} {:s}"
                legend = ["fd", "struct file", "struct dentry", "struct inode", "path"]
                self.out.append(GefUtil.make_legend(fmt.format(*legend)))

                files = read_int_from_memory(task + self.offset_files)
                fdt = read_int_from_memory(files + self.offset_fdt)
                if is_valid_addr(fdt):
                    max_fds = read_int32_from_memory(fdt)
                    array = read_int_from_memory(fdt + runtime.current_arch.ptrsize)
                    for i in range(max_fds):
                        file = read_int_from_memory(array + runtime.current_arch.ptrsize * i)
                        if file == 0:
                            continue
                        dentry = read_int_from_memory(file + self.offset_dentry)
                        inode = read_int_from_memory(dentry + self.offset_d_inode)
                        filepath = self.get_filepath(file)
                        self.out.append("{:<3d} {:#018x} {:#018x} {:#018x} {:s}".format(
                            i, file, dentry, inode, filepath,
                        ))

            # additional information (sighands)
            if proctype == "U" and self.args.print_sighand:
                additional = True
                self.out.append(titlify("sighandlers of `{:s}`".format(comm_string)))

                fmt = "{:14s} {:18s} {:18s} {:18s}"
                legend = ["sig", "sigaction", "handler", "flags"]
                self.out.append(GefUtil.make_legend(fmt.format(*legend)))

                sighand = read_int_from_memory(task + self.offset_sighand)
                for i in range(64):
                    sigaction = sighand + self.offset_action + self.sizeof_action * i
                    signame = self.signame_list.get(i + 1, "???")
                    handler = read_int_from_memory(sigaction + runtime.current_arch.ptrsize * 0)
                    if handler == 0:
                        handler = "SIG_DFL"
                    elif handler == 1:
                        handler = "SIG_IGN"
                    elif handler == -1:
                        handler = "SIG_ERR"
                    else:
                        handler = "{:#018x}".format(handler)
                    flags = read_int_from_memory(sigaction + runtime.current_arch.ptrsize * 1)
                    self.out.append("{:<2d} {:11s} {:#018x} {:18s} {:#018x}".format(
                        i + 1, signame, sigaction, handler, flags,
                    ))

            # additional information (namespace)
            if proctype == "U" and self.args.print_namespace:
                additional = True
                self.out.append(titlify("namespace of `{:s}`".format(comm_string)))

                fmt = "{:30s} {:18s} {:8s}"
                legend = ["name", "value", "init_ns?"]
                self.out.append(GefUtil.make_legend(fmt.format(*legend)))

                # user_ns (via real_cred)
                real_cred = read_int_from_memory(task + self.offset_cred - runtime.current_arch.ptrsize)
                user_ns = read_int_from_memory(real_cred + self.offset_user_ns)
                is_init_ns = str(user_ns == init_user_ns)
                self.out.append("{:30s} {:#018x} {:8s}".format("real_cred->user_ns", user_ns, is_init_ns).rstrip())

                # other ns (via nsproxy)
                nsproxy = read_int_from_memory(task + self.offset_nsproxy)
                for i, name in enumerate(nsproxy_members):
                    value = read_int_from_memory(nsproxy + runtime.current_arch.ptrsize * i)
                    if i == 0:
                        is_init_ns = "-"
                    else:
                        init_value = read_int_from_memory(init_nsproxy + runtime.current_arch.ptrsize * i)
                        is_init_ns = str(value == init_value)
                    self.out.append("{:30s} {:#018x} {:8s}".format("nsproxy->" + name, value, is_init_ns).rstrip())

            # additional information (seccomp)
            if proctype == "U" and self.args.print_seccomp:
                if self.has_seccomp(task):
                    additional = True
                    self.out.append(titlify("seccomp of `{:s}`".format(comm_string)))

                    fmt = "{:18s} {:25s} {:12s} {:18s}"
                    legend = ["&task.seccomp", "mode", "filter_count", "filter"]
                    self.out.append(GefUtil.make_legend(fmt.format(*legend)))

                    seccomp = task + self.offset_seccomp
                    mode = read_int32_from_memory(seccomp)
                    mode_define = {
                        0: "SECCOMP_MODE_DISABLED",
                        1: "SECCOMP_MODE_STRICT",
                        2: "SECCOMP_MODE_FILTER",
                    }.get(mode, "UNKNOWN")
                    mode_str = "{:d} ({:s})".format(mode, mode_define)
                    filter_count = read_int32_from_memory(seccomp + 4)
                    filter_current = read_int_from_memory(seccomp + 4 * 2)
                    self.out.append("{:#018x} {:25s} {:<12d} {:#018x}".format(
                        seccomp, mode_str, filter_count, filter_current,
                    ))

                    for i in tqdm(range(filter_count), leave=False, desc="filter"):
                        if not filter_current:
                            break
                        prog = read_int_from_memory(filter_current + self.offset_prog)
                        filter_prev = read_int_from_memory(filter_current + self.offset_prev)
                        bpf_func = read_int_from_memory(prog + self.offset_bpf_func)
                        orig_prog = read_int_from_memory(prog + self.offset_orig_prog)
                        jited_len = read_int32_from_memory(prog + self.offset_jited_len)

                        self.out.append("")
                        self.out.append(
                            "[{:d}/{:d}] filter:{:#x} prev:{:#x} prog:{:#x} bpf_func:{:#x} jited_len:{:#x} orig_prog:{:#x}".format(
                                i + 1, filter_count, filter_current, filter_prev, prog, bpf_func, jited_len, orig_prog,
                            )
                        )

                        if self.seccomp_tools_command and is_valid_addr(orig_prog):
                            # use seccomp-tools or ceccomp
                            cnt = read_int16_from_memory(orig_prog)
                            prog = read_int_from_memory(orig_prog + runtime.current_arch.ptrsize)
                            data = read_memory(prog, cnt * 8)
                            tmp_fd, tmp_path = GefUtil.mkstemp(prefix="ktask")
                            os.fdopen(tmp_fd, "wb").write(data)
                            ret = GefUtil.gef_execute_external(
                                self.seccomp_tools_command + [tmp_path], as_list=True,
                            )
                            self.out.extend(ret)
                            os.unlink(tmp_path)
                        elif is_valid_addr(bpf_func):
                            try:
                                __import__("capstone")
                                # use capstone
                                data = read_memory(bpf_func, jited_len)
                                dump_count = 0
                                for insn in Disasm.capstone_disassemble(bpf_func, jited_len, code=data.hex()):
                                    msg = insn.colored_text(10)
                                    self.out.append(msg)
                                    dump_count += insn.size
                                    if dump_count >= jited_len:
                                        break
                            except ImportError:
                                ret = gdb.execute("x/40i {:#x}".format(bpf_func), to_string=True).rstrip()
                                self.out.append(ret)
                                self.out.append("...")
                        else:
                            self.err_add_out("Memory read error")

                        filter_current = filter_prev

            # print separator
            if additional:
                self.out.append(titlify(""))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        if self.args.all:
            self.args.print_maps = True
            self.args.print_regs = True
            self.args.print_all_id = True
            self.args.print_thread = True
            self.args.print_fd = True
            self.args.print_sighand = True
            self.args.print_seccomp = True
            self.args.print_namespace = True

        # initialize
        self.filepath_cache = {}
        ret = self.initialize()
        if ret is False:
            return
        task_addrs = ret

        # skip real parse if specified --meta option
        if args.meta:
            return

        # parse
        self.out = []
        self.dump(task_addrs)
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

