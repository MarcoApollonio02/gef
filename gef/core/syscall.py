"""GEF syscall tables (Layer 0 core).

Extracted verbatim from gef.py (Syscall base class + 29 architecture
subclasses). Only data tables plus parsing helpers; no gdb imports.

Note: method bodies reference symbols (arch classes like X86_64, helpers like
is_x86_64, and the syscall_defs / *_syscall_tbl data blobs) that still live in
gef.py at this stage of the modularization work. Those references are deferred
to call time, so importing this module does not require them. They will be
wired up when the data blobs and arch classes are extracted.
"""
import re

from gef.core import runtime
from gef.core.cache import Cache


class Syscall:
    """A collection of utility functions that are related to syscall tables."""

    @staticmethod
    @Cache.cache_this_session
    def parse_common_syscall_defs():
        """Parse and return a common definition of a syscall, common to all architectures."""
        sc_defs = [
            syscall_defs,
            syscall_defs_compat,
        ]
        dic = {}
        for defs in sc_defs:
            for line in defs.splitlines():
                if line == "":
                    continue
                if line.startswith("#"):
                    continue
                # ignore `!`
                m = re.search(r"asmlinkage\s+(?:long|ssize_t)\s+(\S+)\((.+?)\);", line)
                if not m:
                    continue
                name, args = m.group(1), m.group(2)
                args = [x.strip() for x in args.split(",")]
                if name in dic:
                    err("Duplicate: {:s}".format(name))
                    raise
                if len(args) == 1 and args[0] == "void":
                    dic[name] = []
                else:
                    dic[name] = args
        return dic

    @staticmethod
    def parse_syscall_table_defs(table_defs):
        """Parse and return syscall table defines for a specified architecture."""
        table = []
        for line in table_defs.splitlines():
            if line == "":
                continue
            if line.startswith("#"):
                continue
            entry = line.split()
            if len(entry) == 3: # it is unimplemented
                continue
            entry[0] = int(entry[0])
            table.append(entry)
        return table

    @staticmethod
    @Cache.cache_this_session
    def make_syscall_table(arch, mode):
        if arch == "X86" and mode == "64":
            return_register = X86_64.return_register
            args_register = X86_64.syscall_parameters
            syscall_list = SyscallX86_64.make_syscall_list()

        elif arch == "X86" and mode == "Emulated-32":
            return_register = X86.return_register
            args_register = X86.syscall_parameters
            syscall_list = SyscallX86_32Emulated.make_syscall_list()

        elif arch == "X86" and mode == "Native-32":
            return_register = X86.return_register
            args_register = X86.syscall_parameters
            syscall_list = SyscallX86_32Native.make_syscall_list()

        elif arch == "X86" and mode == "16":
            syscall_list = []
            return_register = {}
            args_register = {}
            for nr, name, ret_regs, args, arg_regs in x86_16_dos_syscall_list:
                syscall_list.append([nr, name, args])
                return_register[nr] = ret_regs
                args_register[nr] = arg_regs

        elif arch == "ARM64" and mode == "ARM":
            return_register = AARCH64.return_register
            args_register = AARCH64.syscall_parameters
            syscall_list = SyscallARM64.make_syscall_list()

        elif arch == "ARM" and mode == "Emulated-32":
            return_register = ARM.return_register
            args_register = ARM.syscall_parameters
            syscall_list = SyscallARM32Emulated.make_syscall_list() # only support EABI

        elif arch == "ARM" and mode == "Native-32":
            return_register = ARM.return_register
            args_register = ARM.syscall_parameters
            syscall_list = SyscallARM32Native.make_syscall_list() # only support EABI

        elif arch == "ARM64" and mode == "Secure-World":
            return_register = AARCH64.return_register
            args_register = AARCH64.syscall_parameters + ["$x6"] # OPTEE uses 7 args
            syscall_list = arm_OPTEE_syscall_list.copy()

        elif arch == "ARM" and mode == "Secure-World":
            return_register = ARM.return_register
            args_register = ARM.syscall_parameters
            syscall_list = arm_OPTEE_syscall_list.copy()

        elif arch == "MIPS" and mode == "32":
            return_register = MIPS.return_register
            args_register = MIPS.syscall_parameters
            syscall_list = SyscallMIPS32.make_syscall_list()

        elif arch == "MIPS" and mode == "n32":
            return_register = MIPSN32.return_register
            args_register = MIPSN32.syscall_parameters
            syscall_list = SyscallMIPSN32.make_syscall_list()

        elif arch == "MIPS" and mode == "64":
            return_register = MIPS64.return_register
            args_register = MIPS64.syscall_parameters
            syscall_list = SyscallMIPS64.make_syscall_list()

        elif arch == "PPC" and mode == "32":
            return_register = PPC.return_register
            args_register = PPC.syscall_parameters
            syscall_list = SyscallPPC32.make_syscall_list()

        elif arch == "PPC" and mode == "64":
            return_register = PPC64.return_register
            args_register = PPC64.syscall_parameters
            syscall_list = SyscallPPC64.make_syscall_list()

        elif arch == "SPARC" and mode == "32":
            return_register = SPARC.return_register
            args_register = SPARC.syscall_parameters
            syscall_list = SyscallSPARC32.make_syscall_list()

        elif arch == "SPARC" and mode == "32PLUS":
            return_register = SPARC32PLUS.return_register
            args_register = SPARC32PLUS.syscall_parameters
            syscall_list = SyscallSPARC32.make_syscall_list() # same sparc32

        elif arch == "SPARC" and mode == "64":
            return_register = SPARC64.return_register
            args_register = SPARC64.syscall_parameters
            syscall_list = SyscallSPARC64.make_syscall_list()

        elif arch == "RISCV" and mode == "32":
            return_register = RISCV.return_register
            args_register = RISCV.syscall_parameters
            syscall_list = SyscallRISCV32.make_syscall_list()

        elif arch == "RISCV" and mode == "64":
            return_register = RISCV64.return_register
            args_register = RISCV64.syscall_parameters
            syscall_list = SyscallRISCV64.make_syscall_list()

        elif arch == "S390X" and mode == "64":
            return_register = S390X.return_register
            args_register = S390X.syscall_parameters
            syscall_list = SyscallS390X.make_syscall_list()

        elif arch == "SH4" and mode == "SH4":
            return_register = SH4.return_register
            args_register = SH4.syscall_parameters
            syscall_list = SyscallSH4.make_syscall_list()

        elif arch == "M68K" and mode == "32":
            return_register = M68K.return_register
            args_register = M68K.syscall_parameters
            syscall_list = SyscallM68K.make_syscall_list()

        elif arch == "ALPHA" and mode == "ALPHA":
            return_register = ALPHA.return_register
            args_register = ALPHA.syscall_parameters
            syscall_list = SyscallALPHA.make_syscall_list()

        elif arch == "HPPA" and mode == "32":
            return_register = HPPA.return_register
            args_register = HPPA.syscall_parameters
            syscall_list = SyscallHPPA32.make_syscall_list()

        elif arch == "HPPA" and mode == "64":
            return_register = HPPA64.return_register
            args_register = HPPA64.syscall_parameters
            syscall_list = SyscallHPPA64.make_syscall_list()

        elif arch == "OR1K" and mode == "OR1K":
            return_register = OR1K.return_register
            args_register = OR1K.syscall_parameters
            syscall_list = SyscallOR1K.make_syscall_list()

        elif arch == "NIOS2" and mode == "NIOS2":
            return_register = NIOS2.return_register
            args_register = NIOS2.syscall_parameters
            syscall_list = SyscallNIOS2.make_syscall_list()

        elif arch == "MICROBLAZE" and mode == "MICROBLAZE":
            return_register = MICROBLAZE.return_register
            args_register = MICROBLAZE.syscall_parameters
            syscall_list = SyscallMICROBLAZE.make_syscall_list()

        elif arch == "XTENSA" and mode == "XTENSA":
            return_register = XTENSA.return_register
            args_register = XTENSA.syscall_parameters
            syscall_list = SyscallXTENSA.make_syscall_list()

        elif arch == "CRIS" and mode == "CRIS":
            return_register = CRIS.return_register
            args_register = CRIS.syscall_parameters
            syscall_list = SyscallCRIS.make_syscall_list()

        elif arch == "LOONGARCH" and mode == "64":
            return_register = LOONGARCH64.return_register
            args_register = LOONGARCH64.syscall_parameters
            syscall_list = SyscallLOONGARCH64.make_syscall_list()

        elif arch == "ARC" and mode in ["32v2", "32"]:
            return_register = ARC.return_register
            args_register = ARC.syscall_parameters
            syscall_list = SyscallARC.make_syscall_list("32")

        elif arch == "ARC" and mode in ["32v3"]:
            return_register = ARCv3.return_register
            args_register = ARCv3.syscall_parameters
            syscall_list = SyscallARC.make_syscall_list("32")

        elif arch == "ARC" and mode in ["64v3", "64"]:
            return_register = ARC64.return_register
            args_register = ARC64.syscall_parameters
            syscall_list = SyscallARC.make_syscall_list("64")

        elif arch == "CSKY" and mode == "CSKY":
            return_register = CSKY.return_register
            args_register = CSKY.syscall_parameters
            syscall_list = SyscallCSKY.make_syscall_list()

        else:
            return None

        Table = collections.namedtuple("Table", "arch mode nr_table name_table")
        syscall_table = Table(arch, mode, {}, {})

        # example:
        #   syscall_table.arch: 'X86'
        #   syscall_table.mode: '64'
        #   syscall_table.nr_table[0].nr: 0
        #   syscall_table.nr_table[0].name: 'read'
        #   syscall_table.nr_table[0].ret_regs: ['$rax']
        #   syscall_table.nr_table[0].arg_regs: ['$rdi', '$rsi', ...]
        #   syscall_table.nr_table[0].args_full: ['unsigned int fd', ...]
        #   syscall_table.nr_table[0].args: ['fd', ...]
        #   syscall_table.nr_table[1] ...
        #   syscall_table.name_table["read"].nr: 0
        #   syscall_table.name_table["read"].name: 'read'
        #   syscall_table.name_table["read"].ret_regs: ['$rax']
        #   syscall_table.name_table["read"].arg_regs: ['$rdi', '$rsi', ...]
        #   syscall_table.name_table["read"].args_full: ['unsigned int fd', ...]
        #   syscall_table.name_table["read"].args: ['fd', ...]
        #   syscall_table.name_table["write"] ...
        Entry = collections.namedtuple("Entry", "nr name ret_regs arg_regs args_full args")
        for nr, name, args_full in sorted(syscall_list, key=lambda x: x[0]):
            # make entry
            args = [re.split(r" |\*", p)[-1] for p in args_full]
            if (arch, mode) == ("X86", "16"):
                entry = Entry(nr, name, return_register[nr], args_register[nr], args_full, args)
            else:
                entry = Entry(nr, name, [return_register], args_register[:len(args)], args_full, args)
            # nr_table
            syscall_table.nr_table[nr] = entry
            # name_table
            if name not in syscall_table.name_table:
                syscall_table.name_table[name] = entry
        return syscall_table

    @classmethod
    def get_syscall_table(cls, arch=None, mode=None):

        if arch is None and mode is None :
            if is_x86_64():
                arch, mode = "X86", "64"
            elif is_x86_32():
                if is_emulated32():
                    arch, mode = "X86", "Emulated-32"
                else:
                    arch, mode = "X86", "Native-32"
            elif is_arm64():
                if is_in_secure():
                    arch, mode = "ARM64", "Secure-World"
                else:
                    arch, mode = "ARM64", "ARM"
            elif is_arm32():
                if is_in_secure():
                    arch, mode = "ARM", "Secure-World"
                elif is_emulated32():
                    arch, mode = "ARM", "Emulated-32"
                else:
                    arch, mode = "ARM", "Native-32"
            elif runtime.current_arch:
                arch = runtime.current_arch.arch
                mode = runtime.current_arch.mode
            else:
                arch, mode = None, None

        if arch in ["ARM", "ARM64"] and mode == "S":
            mode = "Secure-World"
        if arch in ["X86", "ARM"] and mode == "32":
            mode = "Emulated-32"
        elif arch in ["X86", "ARM"] and mode == "N32":
            mode = "Native-32"

        return cls.make_syscall_table(arch, mode)


class SyscallX86_64(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_modify_ldt": [
            "int func", "void __user *ptr", "unsigned long bytecount",
        ], # arch/x86/kernel/ldt.c
        "sys_arch_prctl": [
            "int option", "unsigned long arg2",
        ], # arch/x86/kernel/process_64.c
        "sys_iopl": [
            "unsigned int level",
        ], # arch/x86/kernel/ioport.c
        "compat_sys_x32_rt_sigreturn": [], # arch/x86/kernel/signal.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off",
        ], # arch/x86/kernel/sys_x86_64.c
        "sys_rt_sigreturn": [], # arch/x86/kernel/signal.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # include/linux/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(x64_syscall_tbl)
        syscall_list = []
        __X32_SYSCALL_BIT = 0x4000_0000
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            if abi not in ["common", "64", "x32"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                if abi in ["common", "64"]:
                    syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                if abi in ["common", "x32"]:
                    syscall_list.append([nr + __X32_SYSCALL_BIT, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            if abi in ["common", "64"]:
                syscall_list.append([nr, name, sc_def[func]])
            if abi in ["common", "x32"]:
                syscall_list.append([nr + __X32_SYSCALL_BIT, name, sc_def[func]])
        return syscall_list


class SyscallX86_32Emulated(Syscall):
    arch_specific_dic = {
        "compat_sys_sigreturn": [], # arch/x86/ia32/ia32_signal.c
        "compat_sys_rt_sigreturn": [], # arch/x86/ia32/ia32_signal.c
        "compat_sys_old_getrlimit": [
            "unsigned int resource", "struct compat_rlimit *rlim",
        ], # kernel/sys.c
        "compat_sys_ia32_mmap": [
            "struct mmap_arg_struct32 __user *arg",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_iopl": [
            "unsigned int level",
        ], # arch/x86/kernel/ioport.c
        "compat_sys_ia32_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls_val", "int __user *child_tidptr",
        ], # arch/x86/kernel/sys_ia32.c (CONFIG_CLONE_BACKWARDS)
        "sys_modify_ldt": [
            "int func", "void __user *ptr", "unsigned long bytecount",
        ], # arch/x86/kernel/ldt.c
        "sys_ia32_pread64": [
            "unsigned int fd", "char __user *ubuf", "u32 count", "u32 poslo", "u32 poshi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_pwrite64": [
            "unsigned int fd", "const char __user *ubuf", "u32 count", "u32 poslo", "u32 poshi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_truncate64": [
            "const char __user *filename", "unsigned long offset_low", "unsigned long offset_high",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_ftruncate64": [
            "unsigned int fd", "unsigned long offset_low", "unsigned long offset_high",
        ], # arch/x86/kernel/sys_ia32.c
        "compat_sys_ia32_stat64": [
            "const char __user *filename", "struct stat64 __user *statbuf",
        ], # arch/x86/kernel/sys_ia32.c
        "compat_sys_ia32_lstat64": [
            "const char __user *filename", "struct stat64 __user *statbuf",
        ], # arch/x86/kernel/sys_ia32.c
        "compat_sys_ia32_fstat64": [
            "unsigned long fd", "struct stat64 __user *statbuf",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_readahead": [
            "int fd", "unsigned int off_lo", "unsigned int off_high", "size_t count",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_set_thread_area": [
            "struct user_desc __user *u_info",
        ], # arch/x86/kernel/tls.c
        "sys_get_thread_area": [
            "struct user_desc __user *u_info",
        ], # arch/x86/kernel/tls.c
        "sys_ia32_fadvise64": [
            "int fd", "unsigned int offset_lo", "unsigned int offset_hi", "size_t len", "int advice",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_fadvise64_64": [
            "int fd", "__u32 offset_low", "__u32 offset_high", "__u32 len_low", "__u32 len_high", "int advice",
        ], # arch/x86/kernel/sys_ia32.c
        "compat_sys_ia32_fstatat64": [
            "unsigned int dfd", "const char __user *filename", "struct stat64 __user *statbuf", "int flag",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_sync_file_range": [
            "int fd", "unsigned int off_low", "unsigned int off_hi", "unsigned int n_low",
            "unsigned int n_hi", "unsigned int flags",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_fallocate": [
            "int fd", "int mode", "unsigned int offset_lo", "unsigned int offset_hi",
            "unsigned int len_lo", "unsigned int len_hi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_arch_prctl": [
            "int option", "unsigned long arg2",
        ], # arch/x86/kernel/process_64.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(x86_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            if len(entry) == 5:
                nr, abi, name, _, func = entry # use compat
            else:
                nr, abi, name, func = entry[:4]
            if abi != "i386":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallX86_32Native(Syscall):
    arch_specific_dic = {
        "sys_iopl": [
            "unsigned int level",
        ], # arch/x86/kernel/ioport.c
        "sys_vm86old": [
            "struct vm86_struct __user *user_vm86",
        ], # arch/x86/kernel/vm86_32.c
        "sys_sigreturn": [], # arch/x86/kernel/signal.c
        "sys_rt_sigreturn": [], # arch/x86/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_modify_ldt": [
            "int func", "void __user *ptr", "unsigned long bytecount",
        ], # arch/x86/kernel/ldt.c
        "sys_vm86": [
            "unsigned long cmd", "unsigned long arg",
        ], # arch/x86/kernel/vm86_32.c
        "sys_ia32_pread64": [
            "unsigned int fd", "char __user *ubuf", "u32 count", "u32 poslo", "u32 poshi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_pwrite64": [
            "unsigned int fd", "const char __user *ubuf", "u32 count", "u32 poslo", "u32 poshi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_truncate64": [
            "const char __user *filename", "unsigned long offset_low", "unsigned long offset_high",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_ftruncate64": [
            "unsigned int fd", "unsigned long offset_low", "unsigned long offset_high",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_readahead": [
            "int fd", "unsigned int off_lo", "unsigned int off_high", "size_t count",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_set_thread_area": [
            "struct user_desc __user *u_info",
        ], # arch/x86/kernel/tls.c
        "sys_get_thread_area": [
            "struct user_desc __user *u_info",
        ], # arch/x86/kernel/tls.c
        "sys_ia32_fadvise64": [
            "int fd", "unsigned int offset_lo", "unsigned int offset_hi", "size_t len", "int advice",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_fadvise64_64": [
            "int fd", "__u32 offset_low", "__u32 offset_high", "__u32 len_low", "__u32 len_high", "int advice",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_sync_file_range": [
            "int fd", "unsigned int off_low", "unsigned int off_hi", "unsigned int n_low",
            "unsigned int n_hi", "unsigned int flags",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_ia32_fallocate": [
            "int fd", "int mode", "unsigned int offset_lo", "unsigned int offset_hi",
            "unsigned int len_lo", "unsigned int len_hi",
        ], # arch/x86/kernel/sys_ia32.c
        "sys_arch_prctl": [
            "int option", "unsigned long arg2",
        ], # arch/x86/kernel/process_32.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "unsigned int mask_1",
            "unsigned int mask_2", "int dfd", "const char __user *pathname",
        ], # include/linux/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(x86_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi != "i386":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallARM64(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_rt_sigreturn": [], # arch/arm64/kernel/signal.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off",
        ], # arch/arm64/kernel/sys.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # include/linux/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(arm64_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/arm64/kernel/Makefile.syscalls
            if abi not in ["common", "64", "renameat", "rlimit", "memfd_secret"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallARM32Emulated(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "compat_sys_aarch32_pread64": [
            "unsigned int fd", "char *buf", "size_t count", "u32 __pad", "arg_u32p(pos)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_pwrite64": [
            "unsigned int fd", "const char *buf", "size_t count", "u32 __pad", "arg_u32p(pos)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off_4k",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_truncate64": [
            "const char *path", "u32 __pad", "arg_u32p(length)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_ftruncate64": [
            "unsigned int fd", "u32 __pad", "arg_u32p(length)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_readahead": [
            "int fd", "u32 __pad", "arg_u32(offset)", "size_t count",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_statfs64": [
            "const char *pathname", "compat_size_t sz", "struct compat_statfs64 *buf",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_fstatfs64": [
            "unsigned int fd", "compat_size_t sz", "struct compat_statfs64 *buf",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_fadvise64_64": [
            "int fd", "int advice", "arg_u32p(offset)", "arg_u32p(len)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_sync_file_range2": [
            "int fd", "unsigned int flags", "arg_u32p(offset)", "arg_u32p(nbytes)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_aarch32_fallocate": [
            "int fd", "int mode", "arg_u32p(offset)", "arg_u32p(len)",
        ], # arch/arm64/kernel/sys32.c
        "compat_sys_old_semctl": [
            "int semid", "int semnum", "int cmd", "int arg",
        ], # ipc/sem.c
        "compat_sys_old_msgctl": [
            "int msqid", "int cmd", "void *uptr",
        ], # ipc/msg.c
        "compat_sys_old_shmctl": [
            "int shmid", "int cmd", "void *uptr",
        ], # ipc/shm.c
        "compat_sys_sigreturn": [], # arch/arm64/kernel/signal32.c
        "compat_sys_rt_sigreturn": [], # arch/arm64/kernel/signal32.c
    }

    arch_specific_extra = [
        [0xf0002, "cacheflush", [
            "unsigned long start", "unsigned long end", "int flags",
        ]], # arch/arm64/kernel/sys_compat.c
        [0xf0005, "set_tls", [
            "unsigned long val",
        ]], # arch/arm64/kernel/sys_compat.c
    ]

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(arm_compat_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            if len(entry) == 5:
                nr, abi, name, _, func = entry # use compat
            else:
                nr, abi, name, func = entry[:4]
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])

        syscall_list += cls.arch_specific_extra
        return syscall_list


class SyscallARM32Native(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # include/asm-generic/syscalls.h
        "sys_sigreturn_wrapper": [], # arch/arm/kernel/entry-common.S
        "sys_rt_sigreturn_wrapper": [], # arch/arm/kernel/entry-common.S
        "sys_statfs64_wrapper": [
            "const char __user *path", "size_t sz", "struct statfs64 __user *buf",
        ], # arch/arm/kernel/entry-common.S
        "sys_fstatfs64_wrapper": [
            "unsigned int fd", "size_t sz", "struct statfs64 __user *buf",
        ], # arch/arm/kernel/entry-common.S
        "sys_arm_fadvise64_64": [
            "int fd", "int advice", "loff_t offset", "loff_t len",
        ], # arch/arm/kernel/sys_arm.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    arch_specific_extra = [
        [0xf0001, "breakpoint", []], # arch/arm/kernel/traps.c
        [0xf0002, "cacheflush", [
            "unsigned long start", "unsigned long end", "int flags",
        ]], # arch/arm/kernel/traps.c
        [0xf0003, "usr26", []], # arch/arm/kernel/traps.c
        [0xf0004, "usr32", []], # arch/arm/kernel/traps.c
        [0xf0005, "set_tls", [
            "unsigned long val",
        ]], # arch/arm/kernel/traps.c
        [0xf0006, "get_tls", []], # arch/arm/kernel/traps.c
    ]

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(arm_native_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use OABI
            if abi not in ["common", "eabi"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])

        syscall_list += cls.arch_specific_extra
        return syscall_list


class SyscallMIPS32(Syscall):
    arch_specific_dic = {
        "sys_syscall": ["..."], #
        "__sys_fork": [], #
        "sys_rt_sigreturn": [], # arch/mips/kernel/signal.c
        "sysm_pipe": [], # arch/mips/kernel/syscall.c
        "sys_mips_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/mips/kernel/syscall.c
        "sys_sigreturn": [], #
        "__sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long bytes", "unsigned int cache",
        ], # arch/mips/mm/cache.c
        "sys_cachectl": [
            "char *addr", "int nbytes", "int op",
        ], # arch/mips/kernel/syscall.c
        "__sys_sysmips": [
            "long cmd", "long arg1", "long arg2",
        ], # arch/mips/kernel/syscall.c
        "sys_mips_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/mips/kernel/syscall.c
        "sys_set_thread_area": [
            "unsigned long addr",
        ], # arch/mips/kernel/syscall.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
        "sys_sigsuspend": [
            "sigset_t __user *uset",
        ], # arch/mips/kernel/signal.c
        "sys_sigaction": [
            "int sig2", "const struct sigaction __user *act", "struct sigaction __user *oact",
        ], # arch/mips/kernel/signal.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(mips_o32_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi != "o32":
                continue
            nr += 4000 # arch/mips/include/asm/unistd.h
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallMIPSN32(Syscall):
    arch_specific_dic = {
        "__sys_fork": [], #
        "sysm_pipe": [], # arch/mips/kernel/syscall.c
        "sys_mips_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/mips/kernel/syscall.c
        "__sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long bytes", "unsigned int cache",
        ], # arch/mips/mm/cache.c
        "sys_cachectl": [
            "char *addr", "int nbytes", "int op",
        ], # arch/mips/kernel/syscall.c
        "__sys_sysmips": [
            "long cmd", "long arg1", "long arg2",
        ], # arch/mips/kernel/syscall.c
        "sys_set_thread_area": [
            "unsigned long addr",
        ], # arch/mips/kernel/syscall.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
        "compat_sys_old_shmctl": [
            "int shmid", "int cmd", "void *uptr",
        ], # ipc/shm.c
        "compat_sys_old_semctl": [
            "int semid", "int semnum", "int cmd", "int arg",
        ], # ipc/sem.c
        "compat_sys_old_msgctl": [
            "int msqid", "int cmd", "void *uptr",
        ], # ipc/msg.c
        "sys_32_personality": [
            "unsigned long personality",
        ], # arch/mips/kernel/linux32.c
        "sysn32_rt_sigreturn": [], # arch/mips/kernel/signal_n32.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(mips_n32_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi != "n32":
                continue
            nr += 6000 # arch/mips/include/asm/unistd.h
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallMIPS64(Syscall):
    arch_specific_dic = {
        "sys_mips_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/mips/kernel/syscall.c
        "sysm_pipe": [], # arch/mips/kernel/syscall.c
        "__sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "__sys_fork": [], #
        "sys_rt_sigreturn": [], # arch/mips/kernel/signal.c
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long bytes", "unsigned int cache",
        ], # arch/mips/mm/cache.c
        "sys_cachectl": [
            "char *addr", "int nbytes", "int op",
        ], # arch/mips/kernel/syscall.c
        "__sys_sysmips": [
            "long cmd", "long arg1", "long arg2",
        ], # arch/mips/kernel/syscall.c
        "sys_set_thread_area": [
            "unsigned long addr",
        ], # arch/mips/kernel/syscall.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(mips_n64_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi != "n64":
                continue
            nr += 5000 # arch/mips/include/asm/unistd.h
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallPPC32(Syscall):
    arch_specific_dic = {
        "sys_sigreturn": [], # arch/powerpc/kernel/signal_32.c
        "sys_rt_sigreturn": [], # arch/powerpc/kernel/signal_32.c
        "sys_mmap": [
            "unsigned long addr", "size_t len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_mmap2": [
            "unsigned long addr", "size_t len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_swapcontext": [
            "struct ucontext __user *old_ctx", "struct ucontext __user *new_ctx", "long ctx_size",
        ], # arch/powerpc/kernel/signal_32.c
        "ppc_fadvise64_64": [
            "int fd", "int advice", "u32 offset_high", "u32 offset_low", "u32 len_high", "u32 len_low",
        ], # arch/poerpc/kernel/syscalls.c
        "sys_rtas": [
            "struct rtas_args __user *uargs",
        ], # arch/powerpc/include/asm/syscalls.h
        "sys_debug_setcontext": [
            "struct ucontext __user *ctx", "int ndbg", "struct sig_dbg_op __user *dbg",
        ], # arch/powerpc/kernel/signal_32.c
        "sys_subpage_prot": [
            "unsigned long addr", "unsigned long len", "u32 __user *map",
        ], # arch/powerpc/mm/book3s64/subpage_prot.c
        "sys_ppc_pread64": [
            "unsigned int fd", "char __user *ubuf", "compat_size_t count", "u32 reg6", "u32 pos1", "u32 pos2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_pwrite64": [
            "unsigned int fd", "const char __user *ubuf", "compat_size_t count", "u32 reg6", "u32 pos1", "u32 pos2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_readahead": [
            "int fd", "u32 r4", "u32 offset1", "u32 offset2", "u32 count",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_truncate64": [
            "const char __user *path", "u32 reg4", "unsigned long len1", "unsigned long len2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_ftruncate64": [
            "unsigned int fd", "u32 reg4", "unsigned long len1", "unsigned long len2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc32_fadvise64": [
            "int fd", "u32 unused", "u32 offset1", "u32 offset2", "size_t len", "int advice",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_fadvise64_64": [
            "int fd", "int advice", "u32 offset_high", "u32 offset_low", "u32 len_high", "u32 len_low",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_ppc_sync_file_range2": [
            "int fd", "unsigned int flags", "unsigned int offset1", "unsigned int offset2",
            "unsigned int nbytes1", "unsigned int nbytes2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_ppc_fallocate": [
            "int fd", "int mode", "u32 offset1", "u32 offset2", "u32 len1", "u32 len2",
        ], # arch/powerpc/kernel/sys_ppc32.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "unsigned int mask_1",
            "unsigned int mask_2", "int dfd", "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(ppc_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "32", "nospu"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallPPC64(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int __user *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_rt_sigreturn": [], # arch/powerpc/kernel/signal_64.c
        "sys_mmap": [
            "unsigned long addr", "size_t len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_mmap2": [
            "unsigned long addr", "size_t len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_ppc64_personality": [
            "unsigned long personality",
        ], # arch/powerpc/kernel/syscalls.c
        "sys_swapcontext": [
            "struct ucontext __user *old_ctx", "struct ucontext __user *new_ctx", "long ctx_size",
        ], # arch/powerpc/kernel/signal_64.c
        "sys_rtas": [
            "struct rtas_args __user *uargs",
        ], # arch/powerpc/include/asm/syscalls.h
        "sys_subpage_prot": [
            "unsigned long addr", "unsigned long len", "u32 __user *map",
        ], # arch/powerpc/mm/book3s64/subpage_prot.c
        "sys_switch_endian": [], # arch/powerpc/kernel/syscalls.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(ppc_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "64", "nospu"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallSPARC32(Syscall):
    arch_specific_dic = {
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off"
        ], # arch/sparc/kernel/sys_sparc_32.c
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff"
        ], # arch/sparc/kernel/sys_sparc_32.c
        "sunos_execv": [
            "const char __user *filename", "const char __user *const __user *argv",
            "const char __user *const __user *envp",
        ], # arch/sparc/kernel/entry.S
        "sys_sparc_pipe": [], # arch/sparc/kernel/sys_sparc_32.c
        "sys_getpagesize": [], # arch/sparc/kernel/sys_sparc_32.c
        "sys_getdomainname": [
            "char __user *name", "int len"
        ], # arch/sparc/kernel/sys_sparc_32.c
        "sys_sparc_remap_file_pages": [
            "unsigned long start", "unsigned long size", "unsigned long prot",
            "unsigned long pgoff", "unsigned long flags",
        ], # kernel/sys_sparc_32.c
        "sys_sparc_sigaction": [
            "int, sig", "struct old_sigaction __user *act", "struct old_sigaction __user *oact",
        ], # arch/sparc/kernel/sys_sparc_32.c
        "sys_sigreturn": [], # arch/sparc/kernel/syscalls.S
        "sys_rt_sigreturn": [], # arch/sparc/kernel/syscalls.S
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(sparc_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "32"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func in ["sys_ni_syscall", "sys_nis_syscall"]:
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallSPARC64(Syscall):
    arch_specific_dic = {
        "sparc_exit": [
            "int error_code",
        ], # arch/sparc/kernel/syscalls.S
        "sys_sparc_pipe": [], # arch/sparc/kernel/sys_sparc_64.c
        "sys_memory_ordering": [
            "unsigned long model",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys64_execve": [
            "const char __user *filename", "const char __user *const __user *argv",
            "const char __user *const __user *envp",
        ], # arch/sparc/kernel/syscalls.S
        "sys_getpagesize": [], # arch/sparc/kernel/sys_sparc_64.c
        "sys_64_munmap": [
            "unsigned long addr", "size_t len",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_getdomainname": [
            "char __user *name", "int len"
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_utrap_install": [
            "utrap_entry_t type", "utrap_handler_t new_p", "utrap_handler_t new_d",
            "utrap_handler_t __user * old_p", "utrap_handler_t __user *old_d",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sparc_exit_group": [
            "int error_code",
        ], # arch/sparc/kernel/syscalls.S
        "sys_sparc64_personality": [
            "unsigned long personality",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_sparc_ipc": [
            "unsigned int call", "int first", "unsigned long second",
            "unsigned long third", "void __user *ptr", "long fifth",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_sparc_adjtimex": [
            "struct __kernel_timex __user *txc_p",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off"
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_64_mremap": [
            "unsigned long addr", "unsigned long old_len", "unsigned long new_len",
            "unsigned long flags", "unsigned long new_addr",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_sparc_clock_adjtime": [
            "const clockid_t which_clock", "struct __kernel_timex __user *txc_p",
        ], # arch/sparc/kernel/sys_sparc_64.c
        "sys_kern_features": [], # arch/sparc/kernel/sys_sparc_64.c
        "sys64_execveat": [
            "int dfd", "const char __user *filename", "const char __user *const __user *argv",
            "const char __user *const __user *envp", "int flags",
        ] ,# arch/sparc/kernel/syscalls.S
        "sys_rt_sigreturn": [
            "struct pt_regs *regs",
        ], # arch/sparc/kernel/signal_64.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(sparc_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "64"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func in ["sys_ni_syscall", "sys_nis_syscall"]:
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallRISCV32(Syscall):
    arch_specific_dic = {
        "sys_rt_sigreturn": [], # arch/riscv/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/riscv/kernel/sys_riscv.c"
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_riscv_flush_icache": [
            "uintptr_t start", "uintptr_t end", "uintptr_t flags",
        ], # arch/riscv/kernel/sys_riscv.c
        "sys_riscv_hwprobe": [
            "struct riscv_hwprobe __user *pairs", "size_t pair_count", "size_t cpusetsize",
            "unsigned long __user *cpus", "unsigned int flags",
        ], # arch/riscv/kernel/sys_hwprobe.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(riscv32_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/riscv/kernel/Makefile.syscalls
            if abi not in ["common", "32", "riscv", "memfd_secret"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallRISCV64(Syscall):
    arch_specific_dic = {
        "sys_rt_sigreturn": [], # arch/riscv/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "off_t offset",
        ], # arch/riscv/kernel/sys_riscv.c"
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_riscv_flush_icache": [
            "uintptr_t start", "uintptr_t end", "uintptr_t flags",
        ], # arch/riscv/kernel/sys_riscv.c
        "sys_riscv_hwprobe": [
            "struct riscv_hwprobe __user *pairs", "size_t pair_count", "size_t cpusetsize",
            "unsigned long __user *cpus", "unsigned int flags",
        ], # arch/riscv/kernel/sys_hwprobe.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(riscv64_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/riscv/kernel/Makefile.syscalls
            if abi not in ["common", "64", "riscv", "rlimit", "memfd_secret"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallS390X(Syscall):
    arch_specific_dic = {
        "sys_s390_ipc": [
            "uint, call", "int first", "unsigned long second",
            "unsigned long third", "void __user *ptr",
        ], # arch/s390/kernel/syscall.c
        "sys_sigreturn": [], # arch/s390/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int stack_size",
            "int __user *parent_tidptr", "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS2)
        "sys_s390_personality": [
            "unsigned int personality",
        ], # arch/s390/kernel/syscall.c
        "sys_rt_sigreturn": [], # arch/s390/kernel/signal.c
        "sys_s390_runtime_instr": [
            "int, command", "int signum",
        ], # arch/s390/kernel/runtime_instr.c
        "sys_s390_pci_mmio_write": [
            "unsigned long mmio_addr", "const void __user *user_buffer", "size_t length",
        ], # arch/s390/pci/pci_mmio.c
        "sys_s390_pci_mmio_read": [
            "unsigned long mmio_addr", "void __user *user_buffer", "size_t length",
        ], # arch/s390/pci/pci_mmio.c
        "sys_s390_guarded_storage": [
            "int command", "struct gs_cb __user *gs_cb",
        ], # arch/s390/kernel/guarded_storage.c
        "sys_s390_sthyi": [
            "unsigned long function_code", "void __user *buffer", "u64 __user *return_code",
            "unsigned long flags",
        ], # arch/s390/kernel/sthyi.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(s390x_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "64"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func in ["sys_ni_syscall", "-"]:
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallSH4(Syscall):
    arch_specific_dic = {
        "sys_sh_pipe": [], # arch/sh/kernel/sys_sh32.c
        "old_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "int fd", "unsigned long off",
        ], # arch/sh/kernel/sys_sh.c
        "sys_sigreturn": [], # arch/sh/kernel/signal_32.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long len", "int op",
        ], # arch/sh/kernel/sys_sh.c
        "sys_rt_sigreturn": [], # arch/sh/kernel/signal_32.c
        "sys_pread_wrapper": [
            "unsigned int fd", "char __user *buf", "size_t count", "long dummy", "loff_t pos",
        ], # arch/sh/kernel/sys_sh32.c
        "sys_pwrite_wrapper": [
            "unsigned int fd", "const char __user *buf", "size_t count", "long dummy", "loff_t pos",
        ], # arch/sh/kernel/sys_sh32.c
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/sh/kernel/sys_sh.c
        "sys_fadvise64_64_wrapper": [
            "int fd", "u32 offset0", "u32 offset1", "u32 len0", "u32 len1", "int advice",
        ], # arch/sh/kernel/sys_sh32.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_sh_sync_file_range6": [
            "int fd", "u64 offset", "u64 nbytes", "unsigned int flags",
        ], # sh/kernel/sys_sh32.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(sh4_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallM68K(Syscall):
    arch_specific_dic = {
        "__sys_fork": [], # kernel/fork.c
        "sys_sigreturn": [], # arch/m68k/kernel/entry.S
        "__sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_cacheflush": [
            "unsigned long addr", "int scope", "int cache", "unsigned long len",
        ], #
        "sys_getpagesize": [], # arch/m68k/kernel/sys_m68k.c
        "sys_rt_sigreturn": [], # arch/m68k/kernel/entry.S
        "__sys_vfork": [], # kernel/fork.c
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/m68k/kernel/sys_m68k.c
        "sys_get_thread_area": [], # arch/m68k/kernel/sys_m68k.c
        "sys_set_thread_area": [
            "unsigned long tp",
        ], # arch/m68k/kernel/sys_m68k.c
        "sys_atomic_cmpxchg_32": [
            "unsigned long newval", "int oldval", "int d3", "int d4", "int d5",
            "unsigned long __user *mem",
        ], # arch/m68k/kernel/sys_m68k.c
        "sys_atomic_barrier": [], # arch/m68k/kernel/sys_m68k.c
        "__sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], #
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(m68k_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallALPHA(Syscall):
    arch_specific_dic = {
        "alpha_syscall_zero": [], # arch/alpha/kernel/entry.S
        "alpha_fork": [], # arch/alpha/kernel/entry.S (fork_like macro)
        "sys_osf_wait4": [
            "pid_t pid", "int __user *ustatus", "int options", "struct rusage32 __user *ur",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_brk": [
            "unsigned long brk",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_getxpid": [], # arch/alpha/kernel/osf_sys.c
        "sys_osf_mount": [
            "unsigned long typenr", "const char __user *path", "int flag", "void __user *data"
        ], # arch/alpha/kernel/osf_sys.c
        "sys_getxuid": [], # arch/alpha/kernel/osf_sys.c
        "sys_alpha_pipe": [], # arch/alpha/kernel/osf_sys.c
        "sys_osf_set_program_attributes": [
            "unsigned long text_start", "unsigned long text_len",
            "unsigned long bss_start", "unsigned long bss_len",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_getxgid": [], # arch/alpha/kernel/osf_sys.c
        "sys_osf_sigprocmask": [
            "int how", "unsigned long newmask",
        ], # arch/alpha/kernel/signal.c
        "sys_getpagesize": [], # arch/alpha/kernel/osf_sys.c
        "alpha_vfork": [], # arch/alpha/kernel/entry.S (fork_like macro)
        "sys_osf_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_getdtablesize": [], # arch/alpha/kernel/osf_sys.c
        "sys_osf_select": [
            "int, n, fd_set __user *inp", "fd_set __user *outp",
            "fd_set __user *exp", "struct timeval32 __user *tvp",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_getpriority": [
            "int which", "int who",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_sigreturn": [], # arch/alpha/kernel/entry.S (sigreturn_like macro)
        "sys_osf_sigstack": [
            "struct sigstack __user *uss", "struct sigstack __user *uoss",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_gettimeofday": [
            "struct timeval32 __user *tv", "struct timezone __user *tz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_getrusage": [
            "int who", "struct rusage32 __user *ru",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_settimeofday": [
            "struct timeval32 __user *tv", "struct timezone __user *tz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_utimes": [
            "const char __user *filename", "struct timeval32 __user *tvs",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_sigaction": [
            "int, sig", "const struct osf_sigaction __user *act", "struct osf_sigaction __user *oact",
        ], # arch/alpha/kernel/signal.c
        "sys_osf_getdirentries": [
            "unsigned int fd", "struct osf_dirent __user *dirent",
            "unsigned int count", "long __user *basep",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_statfs": [
            "const char __user *pathname", "struct osf_statfs __user *buffer", "unsigned long bufsiz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_fstatfs": [
            "unsigned long fd", "struct osf_statfs __user *buffer", "unsigned long bufsiz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_getdomainname": [
            "char __user *name", "int namelen",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_utsname": [
            "char __user *name",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_stat": [
            "char __user *name", "struct osf_stat __user *buf",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_lstat": [
            "char __user *name", "struct osf_stat __user *buf",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_fstat": [
            "int fd", "struct osf_stat __user *buf",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_statfs64": [
            "char __user *pathname", "struct osf_statfs64 __user *buffer", "unsigned long bufsiz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_fstatfs64": [
            "unsigned long fd", "struct osf_statfs64 __user *buffer", "unsigned long bufsiz",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_sysinfo": [
            "int command", "char __user *buf", "long count",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_proplist_syscall": [
            "enum pl_code code", "union pl_args __user *args",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_usleep_thread": [
            "struct timeval32 __user *sleep", "struct timeval32 __user *remain",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_getsysinfo": [
            "unsigned long op", "void __user *buffer", "unsigned long nbytes",
            "int __user *start", "void __user *arg",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_osf_setsysinfo": [
            "unsigned long op", "void __user *buffer", "unsigned long nbytes",
            "int __user *start", "void __user *arg",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_sethae": [
            "unsigned long val",
        ], # arch/alpha/kernel/osf_sys.c
        "sys_old_adjtimex": [
            "struct timex32 __user *txc_p",
        ], # arch/alpha/kernel/osf_sys.c
        "alpha_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # arch/alpha/kernel/entry.S (fork_like macro)
        "alpha_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], # arch/alpha/kernel/entry.S (fork_like macro)
        "sys_rt_sigreturn": [], # arch/alpha/kernel/entry.S (sigreturn_like macro)
        "sys_rt_sigaction": [
            "int sig", "const struct sigaction __user *act", "struct sigaction __user *oact",
            "size_t sigsetsize", "void __user *restorer",
        ], # arch/alpha/kernel/signal.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(alpha_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallHPPA32(Syscall):
    arch_specific_dic = {
        "sys_fork_wrapper": [], # arch/parisc/kernel/entry.S (fork_like macro)
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long offset",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_pread64": [
            "unsigned int fd", "char __user *buf", "size_t count",
            "unsigned int high", "unsigned int low",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_pwrite64": [
            "unsigned int fd", "const char __user *buf", "size_t count",
            "unsigned int high", "unsigned int low",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_vfork_wrapper": [], # arch/parisc/kernel/entry.S (fork_like macro)
        "sys_clone_wrapper": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # arch/parisc/kernel/entry.S (fork_like macro, CONFIG_CLONE_BACKWARDS)
        "parisc_personality": [
            "unsigned long personality",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_rt_sigreturn_wrapper": [], # arch/parisc/kernel/entry.S
        "parisc_truncate64": [
            "const char __user * path", "unsigned int high", "unsigned int low",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_ftruncate64": [
            "unsigned int fd", "unsigned int high", "unsigned int low",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_readahead": [
            "int fd", "unsigned int high", "unsigned int low", "size_t count",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_fadvise64_64": [
            "int fd", "unsigned int high_off", "unsigned int low_off",
            "unsigned int high_len", "unsigned int low_len", "int advice",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_sync_file_range": [
            "int fd", "u32 hi_off", "u32 lo_off", "u32 hi_nbytes", "u32 lo_nbytes",
            "unsigned int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_fallocate": [
            "int fd", "int mode", "u32 offhi", "u32 offlo", "u32 lenhi", "u32 lenlo",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_timerfd_create": [
            "int clockid", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_signalfd4": [
            "int ufd", "sigset_t __user *user_mask", "size_t sizemask", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_eventfd2": [
            "unsigned int count", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_pipe2": [
            "int __user *fildes", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_inotify_init1": [
            "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_userfaultfd": [
            "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_clone3_wrapper": [
            "struct clone_args __user *uargs", "size_t size",
        ], # arch/parisc/kernel/entry.S (fork_like macro)
        "parisc_madvise": [
            "unsigned long start", "size_t len_in", "int behavior",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long bytes", "unsigned int cache",
        ], # arch/parisc/kernel/cache.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "unsigned int mask_1",
            "unsigned int mask_2", "int dfd", "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(hppa_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "32"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallHPPA64(Syscall):
    arch_specific_dic = {
        "sys_fork_wrapper": [], # arch/parisc/kernel/entry.S (fork_like macro)
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long offset",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_vfork_wrapper": [], # arch/parisc/kernel/entry.S (fork_like macro)
        "sys_clone_wrapper": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # arch/parisc/kernel/entry.S (fork_like macro, CONFIG_CLONE_BACKWARDS)
        "sys_rt_sigreturn_wrapper": [], # arch/parisc/kernel/entry.S
        "parisc_timerfd_create": [
            "int clockid", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_signalfd4": [
            "int ufd", "sigset_t __user *user_mask", "size_t sizemask", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_eventfd2": [
            "unsigned int count", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_pipe2": [
            "int __user *fildes", "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_inotify_init1": [
            "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "parisc_userfaultfd": [
            "int flags",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_clone3_wrapper": [
            "struct clone_args __user *uargs", "size_t size",
        ], # arch/parisc/kernel/entry.S (fork_like macro)
        "parisc_madvise": [
            "unsigned long start", "size_t len_in", "int behavior",
        ], # arch/parisc/kernel/sys_parisc.c
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long bytes", "unsigned int cache",
        ], # arch/parisc/kernel/cache.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c

    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(hppa_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4] # don't use compat
            if abi not in ["common", "64"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallOR1K(Syscall):
    arch_specific_dic = {
        "sys_rt_sigreturn": [], # arch/openrisc/kernel/entry.S
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp",
            "void __user *parent_tid", "void __user *child_tid", "int tls",
        ], # arch/openrisc/include/syscalls.h
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # include/asm-generic/syscalls.h
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_or1k_atomic": [
            "unsigned long type", "unsigned long *v1", "unsigned long *v2",
        ], # arch/openrisc/include/asm/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(or1k_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/openrisc/kernel/Makefile.syscalls
            if abi not in ["common", "32", "or1k", "time32", "stat64", "rlimit", "renameat"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallNIOS2(Syscall):
    arch_specific_dic = {
        "sys_rt_sigreturn": [], # arch/nios2/kernel/entry.S
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp",
            "int __user *parent_tidptr", "int __user *child_tidptr", "int tls_val",
        ], # arch/nios2/kernel/entry.S
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # include/asm-generic/syscalls.h
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_cacheflush": [
            "unsigned long addr", "unsigned long len", "unsigned int op",
        ], # arch/nios2/include/asm/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(nios2_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/nios2/kernel/Makefile.syscalls
            if abi not in ["common", "32", "nios2", "time32", "stat64", "renameat", "rlimit"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func in ["sys_clone3"]: # __ARCH_BROKEN_SYS_CLONE3
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallMICROBLAZE(Syscall):
    arch_specific_dic = {
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/microblaze/kernel/sys_microblaze.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int stack_size",
            "int __user *parent_tidptr", "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS3)
        "sys_rt_sigreturn_wrapper": [], # arch/microblaze/kernel/entry.S
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/microblaze/kernel/sys_microblaze.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(microblaze_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallXTENSA(Syscall):
    arch_specific_dic = {
        "xtensa_fadvise64_64": [
            "int fd", "int advice", "unsigned long long offset", "unsigned long long len",
        ], # arch/xtensa/kernel/syscall.c
        "xtensa_shmat": [
            "int shmid", "char __user *shmaddr", "int shmflg",
        ], # arch/xtensa/kernel/syscall.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS)
        "xtensa_rt_sigreturn": [], # arch/xtensa/kernel/signal.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(xtensa_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "common":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallCRIS(Syscall):
    arch_specific_dic = {
        "sys_sigreturn": [], # arch/cris/arch-v10/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int stack_size",
            "int __user *parent_tidptr", "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c (CONFIG_CLONE_BACKWARDS2)
        "sys_bdflush": [
            "int func", "long data",
        ], # include/linux/syscalls.h
        "sys_sysctl": [
            "struct __sysctl_args __user *args",
        ], # include/linux/syscalls.h
        "sys_rt_sigreturn": [], # arch/cris/arch-v10/kernel/signal.c
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/cris/kernel/sys_cris.c
        "sys_lookup_dcookie": [
            "u64 cookie64", "char __user *buf", "size_t, len",
        ], # fs/dcookies.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(cris_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "cris":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallLOONGARCH64(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_rt_sigreturn": [], # arch/loongarch/kernel/signal.c
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long offset",
        ], # arch/loongarch/kernel/syscall.c
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(loongarch_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry
            if abi != "loongarch":
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallARC(Syscall):
    arch_specific_dic = {
        "sys_rt_sigreturn": [], # arch/arc/kernel/signal.c
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "unsigned long tls", "int *child_tidptr",
        ], # arch/arc/kernel/entry.S (sys_clone_wrapper, CONFIG_CLONE_BACKWARDS)
        "sys_clone3": [
            "struct clone_args __user *uargs", "size_t size",
        ], # arch/arc/kernel/entry.S (sys_clone3_wrapper)
        "sys_mmap": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long off",
        ], # include/uapi/asm/unistd.h
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long pgoff",
        ], # arch/arc/kernel/sys.c (sys_mmap_pgoff)
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_cacheflush": [
            "uint32_t start", "uint32_t sz", "uint32_t flags",
        ], # arch/arc/mm/cache.c
        "sys_arc_settls": [
            "void* user_tls_data_ptr",
        ], # arch/arc/kernel/process.c
        "sys_arc_gettls": [], # arch/arc/kernel/process.c
        "sys_sysfs": [
            "int option", "unsigned long arg1", "unsigned long arg2",
        ], # fs/filesystems.c
        "sys_arc_usr_cmpxchg": [
            "int __user *uaddr", "int expected", "int new",
        ], # arch/arc/kernel/process.c
    }

    @classmethod
    def make_syscall_list(cls, bit_str):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(arc_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/arc/kernel/Makefile.syscalls
            if abi not in ["common", bit_str, "arc", "time32", "renameat", "stat64", "rlimit"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list


class SyscallCSKY(Syscall):
    arch_specific_dic = {
        "sys_clone": [
            "unsigned long clone_flags", "unsigned long newsp", "int __user *parent_tidptr",
            "int __user *child_tidptr", "unsigned long tls",
        ], # kernel/fork.c
        "sys_rt_sigreturn": [], # arch/csky/kernel/signal.c
        "sys_mmap2": [
            "unsigned long addr", "unsigned long len", "unsigned long prot",
            "unsigned long flags", "unsigned long fd", "unsigned long offset",
        ], # arch/csky/kernel/syscall.c
        "sys_fadvise64_64": [
            "int fd", "int advice", "loff_t offset", "loff_t len",
        ], # arch/csky/include/asm/syscalls.h
        "sys_fanotify_mark": [
            "int fanotify_fd", "unsigned int flags", "u64 mask", "int fd",
            "const char __user *pathname",
        ], # fs/notify/fanotify/fanotify_user.c
        "sys_set_thread_area": [
            "unsigned long addr",
        ], # arch/csky/kernel/signal.c
        "sys_cacheflush": [
            "void __user *addr", "unsigned long len", "int op",
        ], # arch/csky/include/asm/syscalls.h
    }

    @classmethod
    def make_syscall_list(cls):
        sc_def = cls.parse_common_syscall_defs()
        tbl = cls.parse_syscall_table_defs(csky_syscall_tbl)
        syscall_list = []
        for entry in tbl:
            nr, abi, name, func = entry[:4]
            # arch/csky/kernel/Makefile.syscalls
            if abi not in ["common", "32", "csky", "time32", "stat64", "rlimit"]:
                continue
            # special case
            if func in cls.arch_specific_dic:
                syscall_list.append([nr, name, cls.arch_specific_dic[func]])
                continue
            # common case
            if func == "sys_ni_syscall":
                continue
            if func not in sc_def:
                err("Not found: {:s}".format(func))
                raise
            syscall_list.append([nr, name, sc_def[func]])
        return syscall_list
