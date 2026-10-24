"""GEF kernel commands (category 06-i) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Linux Dynamic Inspection: the tracer commands
(usermodehelper-tracer, thunk-tracer, kmalloc-tracer, kmalloc-allocated-by,
ktrace) together with the gdb.Breakpoint / gdb.FinishBreakpoint helper classes
they install. The helpers are co-located here because they carry no
`_category_` and are used only by these commands. Auto-discovered by
gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import collections
import itertools
import re
import struct

import gdb

from gef.commands.base import (
    GenericCommand,
    only_if_gdb_running,
    only_if_in_kernel,
    only_if_kvm_disabled,
    only_if_smp_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.config import Config
from gef.core.instruction import Disasm
from gef.core.kernel import Kernel, KernelPerCpu, Ksym
from gef.core.memory import (
    is_valid_addr,
    p16,
    p32,
    p64,
    p8,
    read_cstring_from_memory,
    read_int32_from_memory,
    read_int8_from_memory,
    read_int_from_memory,
    read_memory,
    write_memory,
)
from gef.core.pagewalk import KernelAddressHeuristicFinder
from gef.core.process import get_pagesize, get_pagesize_mask_low, is_arm32, is_arm64
from gef.core.registers import get_register
from gef.core.strings import String
from gef.core.symbols import Symbol
from gef.core.syscall import Syscall
from gef.core.utils import GefUtil, align, slice_unpack, slicer, u2i


class CallUsermodehelperSetupBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to print argv information at call_usermodehelper_setup."""

    def __init__(self, loc):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        return

    def stop(self):
        ptr1, addr1 = runtime.current_arch.get_ith_parameter(0)
        ptr2, addr2 = runtime.current_arch.get_ith_parameter(1)
        path = read_cstring_from_memory(addr1)
        argv = []
        while True:
            string_addr = read_int_from_memory(addr2)
            if string_addr == 0:
                break
            string = read_cstring_from_memory(string_addr)
            argv.append("'{:s}'".format(string))
            addr2 += runtime.current_arch.ptrsize
        gef_print("{:s}: {:#x} -> '{:s}'".format(ptr1, addr1, path))
        gef_print("{:s}: {:#x} -> [{:s}]".format(ptr2, addr2, ",".join(argv)))
        return False # continue


@register_command
class UsermodehelperTracerCommand(GenericCommand):
    """Collect and display information that is executed by call_usermodehelper_setup."""

    _cmdline_ = "usermodehelper-tracer"
    _category_ = "06-i. Qemu-system/KGDB Cooperation - Linux Dynamic Inspection"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel
    def do_invoke(self, args):
        info("Resolving the function addresses")
        addr = Symbol.get_ksymaddr("call_usermodehelper_setup")
        if addr is None:
            err("Could not find call_usermodehelper_setup")
            return
        CallUsermodehelperSetupBreakpoint(addr)
        info("Setup is complete. Try `continue`")
        return


class ThunkBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to print caller address for thunk function."""

    def __init__(self, loc, sym, reg, maps):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.loc = loc
        self.sym = sym
        self.reg = reg
        self.maps = maps
        self.seen = []
        return

    def search_perm(self, target):
        for m in self.maps:
            addr, size, perm = m
            if addr <= target < addr + size:
                return perm.lower()
        return "?"

    def stop(self):
        try:
            return_address = gdb.selected_frame().older().pc()
            caller_address = Disasm.gdb_get_nth_previous_instruction_address(return_address, 1)
            target_address = get_register(self.reg)
        except gdb.error:
            return False # continue

        # duplicate, check
        if (caller_address, target_address) in self.seen:
            return False # continue
        else:
            self.seen.append((caller_address, target_address))

        # get caller address, symbol
        caller_symbol = Symbol.get_symbol_string(caller_address, nosymbol_string=" <NO_SYMBOL>")

        # get callee address, symbol
        target_symbol = Symbol.get_symbol_string(target_address, nosymbol_string=" <NO_SYMBOL>")

        # print information
        if caller_address is None:
            info("{:s}{:s} -> {:#x} <{:s}> -> {:#x}{:s}".format(
                "???(unknown)", caller_symbol, self.loc, self.sym, target_address, target_symbol,
            ))
        else:
            info("{:#x}{:s} -> {:#x} <{:s}> -> {:#x}{:s}".format(
                caller_address, caller_symbol, self.loc, self.sym, target_address, target_symbol,
            ))

        # print preferred register condition
        pattern = [0] + [(x + 1) * y for x, y in itertools.product(range(0x100), [1, -1])] # [0, 1, -1, 2, -2, ...]
        for reg in runtime.current_arch.general_registers:
            reg_value = get_register(reg)
            for i in pattern:
                slide = runtime.current_arch.ptrsize * i
                reg_value_slided = reg_value + slide
                try:
                    mem_value = read_int_from_memory(reg_value_slided)
                except (gdb.MemoryError, OverflowError):
                    continue
                if mem_value != target_address:
                    continue
                perm = self.search_perm(reg_value_slided)
                reg_value_slided_symbol = Symbol.get_symbol_string(reg_value_slided, nosymbol_string=" <NO_SYMBOL>")
                mem_value_symbol = Symbol.get_symbol_string(mem_value, nosymbol_string=" <NO_SYMBOL>")
                info("    {:s}{:+#x}: {:#x}{:s} [{:s}]  ->  {:#x}{:s}".format(
                    reg, slide, reg_value_slided, reg_value_slided_symbol, perm, mem_value, mem_value_symbol,
                ))
                break
        return False # continue


@register_command
class ThunkTracerCommand(GenericCommand):
    """Collect and display the thunk addresses that are called automatically (x64/x86 only)."""

    _cmdline_ = "thunk-tracer"
    _category_ = "06-i. Qemu-system/KGDB Cooperation - Linux Dynamic Inspection"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64"))
    @only_if_in_kernel
    def do_invoke(self, args):
        info("Wait for memory scan")
        maps = Kernel.get_maps() # [vaddr, size, perm]
        info("Resolving thunk function addresses")
        for reg in runtime.current_arch.general_registers:
            if reg in ["$esp", "$rsp", "$eip", "$rip"]:
                continue
            sym = "__x86_indirect_thunk_{}".format(reg.replace("$", ""))
            addr = Symbol.get_ksymaddr(sym)
            if addr is None:
                continue
            gef_print(sym + ": ", end="")
            ThunkBreakpoint(addr, sym, reg, maps)
        info("Setup is complete, try `continue`")
        return


class KmallocBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to print information of kmalloc."""

    def __init__(self, loc, sym, index_of_size_arg, option, extra):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.index_of_size_arg = index_of_size_arg
        self.option = option
        self.extra = extra
        self.enabled = False
        return

    def check_nested(self, task_addr):
        for bp in gdb.breakpoints():
            try:
                if bp.__class__.__name__ in ["KmallocRetBreakpoint"]:
                    if bp.enabled and bp.task_addr == task_addr:
                        return True
            except Exception:
                pass
        return False

    def stop(self):
        Cache.reset_gef_caches()

        # fast return if nested break
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.check_nested(task_addr):
            return False

        # filtering by task addr
        if self.option.target_task and task_addr != self.option.target_task:
            return False

        # filtering by task name
        if self.option.task_name and task_name not in self.option.task_name:
            return False

        # get size from arguments
        if self.index_of_size_arg >= 0:
            # e.g., kmalloc(size, ...)
            _, size = runtime.current_arch.get_ith_parameter(self.index_of_size_arg)
        else:
            # e.g., kmem_cache_alloc_node has no `size` argument
            _, kmem_cache = runtime.current_arch.get_ith_parameter(0)
            slab_cache_name_ptr = read_int_from_memory(kmem_cache + self.extra.kmem_cache_offset_name)
            slab_cache_name = read_cstring_from_memory(slab_cache_name_ptr)
            if not slab_cache_name.startswith("kmalloc-"):
                return False
            size = read_int32_from_memory(kmem_cache + self.extra.kmem_cache_offset_size)

        # Use gdb.Breakpoint instead of gdb.FinishBreakpoint because gdb.FinishBreakpoint is buggy
        ret_addr = gdb.newest_frame().older().pc()
        KmallocRetBreakpoint(ret_addr, self.sym, size, task_addr, self.option, self.extra)
        return False


class KmallocRetBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to print information of kmalloc."""

    def __init__(self, loc, sym, size, task_addr, option, extra):
        # Note that specifying temporary=True does not remove the breakpoint if stop() returns False.
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=True)
        self.size = size
        self.sym = sym
        self.task_addr = task_addr
        self.option = option
        self.extra = extra
        KmallocTracerCommand.clear_disabled_breakpoints("KmallocRetBreakpoint")
        return

    def stop(self):
        Cache.reset_gef_caches()

        # check if another thread is detected
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.task_addr != task_addr:
            return False

        task_prefix = Color.boldify("[task:{:#018x} {:16s}]".format(task_addr, task_name))
        allocated = AddressUtil.parse_address(runtime.current_arch.return_register)
        allocated_s = Color.colorify_hex(allocated, Config.get_gef_setting("theme.heap_chunk_address_used"))

        if self.extra:
            ret = KmallocTracerCommand.virt2name_and_size(allocated)
            if ret:
                # print more info
                name, chunk_size = ret
                if not name.startswith("kmalloc-"):
                    self.enabled = False
                    return False
                if self.option.filter and name not in self.option.filter:
                    self.enabled = False
                    return False
                name_s = Color.colorify(name, Config.get_gef_setting("theme.heap_chunk_label"))
                chunk_size_s = Color.colorify("{:<#6x}".format(chunk_size), Config.get_gef_setting("theme.heap_chunk_size"))
                gef_print("{:s} {:40s}: {:s} (size: {:s} name: {:s})".format(
                    task_prefix, self.sym, allocated_s, chunk_size_s, name_s,
                ))
                KmallocTracerCommand.print_backtrace(self.option.backtrace)
                KmallocTracerCommand.dump_chunk(self.option.dump_chunk, allocated)
                self.enabled = False
                return False
            # fall through

        # print less info
        gef_print("{:s} {:40s}: {:s} (size: {:<#6x})".format(task_prefix, self.sym, allocated_s, self.size))
        KmallocTracerCommand.print_backtrace(self.option.backtrace)
        KmallocTracerCommand.dump_chunk(self.option.dump_chunk, allocated)
        self.enabled = False
        return False


class KfreeBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to print information of kfree."""

    def __init__(self, loc, sym, index_of_addr_arg, option, extra):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.index_of_addr_arg = index_of_addr_arg
        self.option = option
        self.extra = extra
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()

        # check if NULL
        _, to_free = runtime.current_arch.get_ith_parameter(self.index_of_addr_arg)
        if not self.option.print_null and to_free == 0:
            return False

        # filtering by task addr
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.option.target_task and task_addr != self.option.target_task:
            return False

        # filtering by task name
        if self.option.task_name and task_name not in self.option.task_name:
            return False

        task_prefix = Color.boldify("[task:{:#018x} {:16s}]".format(task_addr, task_name))
        to_free_s = Color.colorify_hex(to_free, Config.get_gef_setting("theme.heap_chunk_address_freed"))

        if self.extra:
            ret = KmallocTracerCommand.virt2name_and_size(to_free)
            if ret:
                # print more info
                name, chunk_size = ret
                if not name.startswith("kmalloc-"):
                    return False
                if self.option.filter and name not in self.option.filter:
                    return False
                name_s = Color.colorify(name, Config.get_gef_setting("theme.heap_chunk_label"))
                chunk_size_s = Color.colorify("{:<#6x}".format(chunk_size), Config.get_gef_setting("theme.heap_chunk_size"))
                gef_print("{:s} {:40s}: {:s} (size: {:s} name: {:s})".format(
                    task_prefix, self.sym, to_free_s, chunk_size_s, name_s,
                ))
                KmallocTracerCommand.print_backtrace(self.option.backtrace)
                KmallocTracerCommand.dump_chunk(self.option.dump_chunk, to_free)
                return False
            # fall through

        # print less info
        gef_print("{:s} {:40s}: {:s}".format(task_prefix, self.sym, to_free_s))
        KmallocTracerCommand.print_backtrace(self.option.backtrace)
        KmallocTracerCommand.dump_chunk(self.option.dump_chunk, to_free)
        return False


class AllocPagesBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to print information of __alloc_pages."""

    def __init__(self, loc, sym, index_of_order_arg, option, extra):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.index_of_order_arg = index_of_order_arg
        self.option = option
        self.extra = extra
        self.enabled = False
        return

    def check_nested(self, task_addr):
        for bp in gdb.breakpoints():
            try:
                if bp.__class__.__name__ in ["AllocPagesRetBreakpoint"]:
                    if bp.enabled and bp.task_addr == task_addr:
                        return True
            except Exception:
                pass
        return False

    def stop(self):
        Cache.reset_gef_caches()

        # fast return if nested break
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.check_nested(task_addr):
            return False

        # filtering by task addr
        if self.option.target_task and task_addr != self.option.target_task:
            return False

        # filtering by task name
        if self.option.task_name and task_name not in self.option.task_name:
            return False

        # get order from arguments
        _, order = runtime.current_arch.get_ith_parameter(self.index_of_order_arg)

        # Use gdb.Breakpoint instead of gdb.FinishBreakpoint because gdb.FinishBreakpoint is buggy
        ret_addr = gdb.newest_frame().older().pc()
        AllocPagesRetBreakpoint(ret_addr, self.sym, order, task_addr, self.option, self.extra)
        return False


class AllocPagesRetBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to print information of __alloc_pages."""

    def __init__(self, loc, sym, order, task_addr, option, extra):
        # Note that specifying temporary=True does not remove the breakpoint if stop() returns False.
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=True)
        self.order = order
        self.sym = sym
        self.task_addr = task_addr
        self.option = option
        self.extra = extra
        KmallocTracerCommand.clear_disabled_breakpoints("AllocPagesRetBreakpoint")
        return

    def stop(self):
        Cache.reset_gef_caches()

        # check if another thread is detected
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.task_addr != task_addr:
            return False

        task_prefix = Color.boldify("[task:{:#018x} {:16s}]".format(task_addr, task_name))
        allocated_page = AddressUtil.parse_address(runtime.current_arch.return_register)
        if not is_valid_addr(allocated_page):
            allocated_virt = 0
        else:
            allocated_virt = Kernel.page2virt(allocated_page)
        if allocated_virt is None:
            allocated_virt = 0
        allocated_virt_s = Color.colorify_hex(
            allocated_virt, Config.get_gef_setting("theme.heap_page_address"),
        )
        size = KernelAddressHeuristicFinder.consts().PAGE_SIZE * (2 ** self.order)

        # print less info
        gef_print("{:s} {:40s}: {:s} (page: {:#x}, order: {:d}, size: {:#x})".format(
            task_prefix, self.sym, allocated_virt_s, allocated_page, self.order, size,
        ))
        KmallocTracerCommand.print_backtrace(self.option.backtrace)
        KmallocTracerCommand.dump_chunk(self.option.dump_chunk, allocated_virt)
        self.enabled = False
        return False


class FreePagesBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to print information of __free_pages."""

    def __init__(self, loc, sym, index_of_addr_arg, index_of_order_arg, option, extra):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.index_of_addr_arg = index_of_addr_arg
        self.index_of_order_arg = index_of_order_arg
        self.option = option
        self.extra = extra
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()

        _, to_free_page = runtime.current_arch.get_ith_parameter(self.index_of_addr_arg)
        _, order = runtime.current_arch.get_ith_parameter(self.index_of_order_arg)

        # filtering by task addr
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.option.target_task and task_addr != self.option.target_task:
            return False

        # filtering by task name
        if self.option.task_name and task_name not in self.option.task_name:
            return False

        task_prefix = Color.boldify("[task:{:#018x} {:16s}]".format(task_addr, task_name))
        if not is_valid_addr(to_free_page):
            to_free_virt = 0
        else:
            to_free_virt = Kernel.page2virt(to_free_page)
        if to_free_virt is None:
            to_free_virt = 0
        to_free_virt_s = Color.colorify_hex(
            to_free_virt, Config.get_gef_setting("theme.heap_page_address")
        )
        size = KernelAddressHeuristicFinder.consts().PAGE_SIZE * (2 ** order)

        # print less info
        gef_print("{:s} {:40s}: {:s} (page: {:#x}, order: {:d}, size: {:#x})".format(
            task_prefix, self.sym, to_free_virt_s, to_free_page, order, size,
        ))
        KmallocTracerCommand.print_backtrace(self.option.backtrace)
        KmallocTracerCommand.dump_chunk(self.option.dump_chunk, to_free_virt)
        return False


@register_command
class KmallocTracerCommand(GenericCommand):
    """Collect and display information when kmalloc/kfree."""

    _cmdline_ = "kmalloc-tracer"
    _category_ = "06-i. Qemu-system/KGDB Cooperation - Linux Dynamic Inspection"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--filter", action="append", default=[], help="filter specified slab name (e.g., kmalloc-XX)")
    parser.add_argument("-T", "--task-name", action="append", default=[], help="filter specified task name (e.g., sh)")
    parser.add_argument("-N", "--print-null", action="store_true", help="display free(NULL).")
    parser.add_argument("-t", "--backtrace", action="store_true", help="display backtrace.")
    parser.add_argument("-d", "--dump-chunk", action="store_true", help="dump the first 0x40 bytes of each chunk.")
    parser.add_argument("-p", "--enable-page-allocator-trace", action="store_true",
                        help="in addition to kmalloc and kfree, it also monitors __alloc_pages and __free_pages.")
    parser.add_argument("-v", "--verbose", action="store_true", help="print meta information.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}       # simple output",
        "{0:s} -dtv  # useful output",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Disable `-enable-kvm` option for qemu-system (#PF may occur).",
        "Append `tsc=unstable` option for kernel cmdline.",
        "Tracing `kmem_cache_alloc` type is not supported.",
        "This command requires CONFIG_RANDSTRUCT=n.",
    ]
    _note_ = "\n".join(_note_)

    @staticmethod
    def create_option_info(args, target_task=None):
        dic = {
            "print_null": args.print_null,
            "backtrace": args.backtrace,
            "filter": args.filter,
            "dump_chunk": args.dump_chunk,
            "task_name": getattr(args, "task_name", []),
            "target_task": target_task,
        }
        OptionInfo = collections.namedtuple("OptionInfo", dic.keys())
        option_info = OptionInfo(*dic.values())
        return option_info

    @staticmethod
    def clear_disabled_breakpoints(name, force=False):
        for bp in gdb.breakpoints():
            try:
                if bp.__class__.__name__ != name:
                    continue
                if force is False and bp.enabled:
                    continue
                bp.delete()
            except Exception:
                pass
        return

    @staticmethod
    def initialize(allocator, verbose):
        if allocator != "SLUB":
            # Do nothing other than SLUB.
            return None

        res = gdb.execute("slub-dump --meta", to_string=True)

        r = re.search(r"offsetof\((?:page|slab), slab_cache\): (0x\S+)", res)
        if not r:
            return False
        page_offset_slab_cache = int(r.group(1), 16)
        if verbose:
            info("offsetof({:s}, slab_cache): {:#x}".format(Kernel.slab_page_str(), page_offset_slab_cache))

        r = re.search(r"offsetof\(kmem_cache, name\): (0x\S+)", res)
        if not r:
            return False
        kmem_cache_offset_name = int(r.group(1), 16)
        if verbose:
            info("offsetof(kmem_cache, name): {:#x}".format(kmem_cache_offset_name))

        r = re.search(r"offsetof\(kmem_cache, size\): (0x\S+)", res)
        if not r:
            return False
        kmem_cache_offset_size = int(r.group(1), 16)
        if verbose:
            info("offsetof(kmem_cache, size): {:#x}".format(kmem_cache_offset_size))

        # create extra_info
        dic = {
            "kmem_cache_offset_name": kmem_cache_offset_name,
            "kmem_cache_offset_size": kmem_cache_offset_size,
            "page_offset_slab_cache": page_offset_slab_cache,
        }
        ExtraInfo = collections.namedtuple("ExtraInfo", dic.keys())
        extra_info = ExtraInfo(*dic.values())
        return extra_info

    @staticmethod
    def get_task():
        th_num = gdb.selected_thread().num
        res = gdb.execute("kcurrent --quiet", to_string=True)
        r = re.search(r"current \(cpu{:d}\): (0x\S+) (.*)".format(th_num - 1), res)
        if r:
            task = int(r.group(1), 16)
            name = r.group(2)
            return task, name
        return 0, ""

    @staticmethod
    def virt2name_and_size(vaddr):
        ret = Kernel.get_slab_contains(vaddr)
        if not ret:
            return None
        r = re.search(r"name: (\S+)  object_size: (\S+)", ret)
        if not r:
            return None
        slab_cache_name = r.group(1)
        slab_cache_size = int(r.group(2), 16)
        return slab_cache_name, slab_cache_size

    @staticmethod
    def print_backtrace(backtrace):
        if not backtrace:
            return

        try:
            frame = gdb.newest_frame()
            while frame and frame.is_valid():
                addr = frame.pc()
                if not is_valid_addr(addr):
                    break
                sym = Symbol.get_symbol_string(addr, nosymbol_string=" <NO_SYMBOL>")
                gef_print("  {:#018x}{:s}".format(addr, sym))
                frame = frame.older()
        except gdb.error:
            return

    @staticmethod
    def dump_chunk(dump, loc):
        if not dump:
            return
        if not is_valid_addr(loc):
            err("Invalid address")
            return
        gdb.execute("dereference -n {:#x} 8".format(loc))
        return

    @staticmethod
    def set_bp_to_kmalloc_kfree(option_info, extra_info):
        # `kmalloc` is always inlined and not exported, so its symbol cannot be identified.
        # Therefore, you must set a breakpoint in a function that is exported instead of kmalloc.
        # This can be done by checking EXPORT_SYMBOL, and a tool to automate this is dev/update-kmalloc-tracer.
        # The same symbol may be found multiple times from different *.c files, and they can be treated as the same.
        """
        [3.0~3.15]
        EXPORT_SYMBOL(__kmalloc);
        EXPORT_SYMBOL(__kmalloc_node);
        EXPORT_SYMBOL(__kmalloc_node_track_caller);
        EXPORT_SYMBOL(__kmalloc_track_caller);
        EXPORT_SYMBOL(__krealloc);
        EXPORT_SYMBOL(kfree);
        EXPORT_SYMBOL(kmalloc_order_trace);
        EXPORT_SYMBOL(kmem_cache_alloc);
        EXPORT_SYMBOL(kmem_cache_alloc_node);
        EXPORT_SYMBOL(kmem_cache_alloc_node_trace);
        EXPORT_SYMBOL(kmem_cache_alloc_trace);
        EXPORT_SYMBOL(krealloc);
        [3.16~5.5]
        EXPORT_SYMBOL(__kmalloc);
        EXPORT_SYMBOL(__kmalloc_node);
        EXPORT_SYMBOL(__kmalloc_node_track_caller);
        EXPORT_SYMBOL(__kmalloc_track_caller);
        EXPORT_SYMBOL(__krealloc);
        EXPORT_SYMBOL(kfree);
        EXPORT_SYMBOL(kmalloc_order);
        EXPORT_SYMBOL(kmalloc_order_trace);
        EXPORT_SYMBOL(kmem_cache_alloc);
        EXPORT_SYMBOL(kmem_cache_alloc_node);
        EXPORT_SYMBOL(kmem_cache_alloc_node_trace);
        EXPORT_SYMBOL(kmem_cache_alloc_trace);
        EXPORT_SYMBOL(krealloc);
        [5.6~5.17]
        EXPORT_SYMBOL(__kmalloc);
        EXPORT_SYMBOL(__kmalloc_node);
        EXPORT_SYMBOL(__kmalloc_node_track_caller);
        EXPORT_SYMBOL(__kmalloc_track_caller);
        EXPORT_SYMBOL(kfree);
        EXPORT_SYMBOL(kmalloc_order);
        EXPORT_SYMBOL(kmalloc_order_trace);
        EXPORT_SYMBOL(kmem_cache_alloc);
        EXPORT_SYMBOL(kmem_cache_alloc_node);
        EXPORT_SYMBOL(kmem_cache_alloc_node_trace);
        EXPORT_SYMBOL(kmem_cache_alloc_trace);
        EXPORT_SYMBOL(krealloc);
        [5.18~6.0]
        EXPORT_SYMBOL(__kmalloc);
        EXPORT_SYMBOL(__kmalloc_node);
        EXPORT_SYMBOL(__kmalloc_node_track_caller);
        EXPORT_SYMBOL(__kmalloc_track_caller);
        EXPORT_SYMBOL(kfree);
        EXPORT_SYMBOL(kmalloc_order);
        EXPORT_SYMBOL(kmalloc_order_trace);
        EXPORT_SYMBOL(kmem_cache_alloc);
        EXPORT_SYMBOL(kmem_cache_alloc_lru);
        EXPORT_SYMBOL(kmem_cache_alloc_node);
        EXPORT_SYMBOL(kmem_cache_alloc_node_trace);
        EXPORT_SYMBOL(kmem_cache_alloc_trace);
        EXPORT_SYMBOL(krealloc);
        [6.1~6.9]
        EXPORT_SYMBOL(__kmalloc);
        EXPORT_SYMBOL(__kmalloc_node);
        EXPORT_SYMBOL(__kmalloc_node_track_caller);
        EXPORT_SYMBOL(kfree);
        EXPORT_SYMBOL(kmalloc_large);
        EXPORT_SYMBOL(kmalloc_large_node);
        EXPORT_SYMBOL(kmalloc_node_trace);
        EXPORT_SYMBOL(kmalloc_trace);
        EXPORT_SYMBOL(kmem_cache_alloc);
        EXPORT_SYMBOL(kmem_cache_alloc_lru);
        EXPORT_SYMBOL(kmem_cache_alloc_node);
        EXPORT_SYMBOL(krealloc);
        [6.10]
        EXPORT_SYMBOL(__kmalloc_node_noprof);
        EXPORT_SYMBOL(__kmalloc_noprof);
        EXPORT_SYMBOL(kfree);
        EXPORT_SYMBOL(kmalloc_large_node_noprof);
        EXPORT_SYMBOL(kmalloc_large_noprof);
        EXPORT_SYMBOL(kmalloc_node_trace_noprof);
        EXPORT_SYMBOL(kmalloc_node_track_caller_noprof);
        EXPORT_SYMBOL(kmalloc_trace_noprof);
        EXPORT_SYMBOL(kmem_cache_alloc_lru_noprof);
        EXPORT_SYMBOL(kmem_cache_alloc_node_noprof);
        EXPORT_SYMBOL(kmem_cache_alloc_noprof);
        EXPORT_SYMBOL(krealloc_noprof);
        [6.11~6.17]
        EXPORT_SYMBOL(__kmalloc_cache_node_noprof);
        EXPORT_SYMBOL(__kmalloc_cache_noprof);
        EXPORT_SYMBOL(__kmalloc_large_node_noprof);
        EXPORT_SYMBOL(__kmalloc_large_noprof);
        EXPORT_SYMBOL(__kmalloc_node_noprof);
        EXPORT_SYMBOL(__kmalloc_node_track_caller_noprof);
        EXPORT_SYMBOL(__kmalloc_noprof);
        EXPORT_SYMBOL(kfree);
        EXPORT_SYMBOL(kmem_cache_alloc_lru_noprof);
        EXPORT_SYMBOL(kmem_cache_alloc_node_noprof);
        EXPORT_SYMBOL(kmem_cache_alloc_noprof);
        EXPORT_SYMBOL(krealloc_noprof);
        [6.18~]
        EXPORT_SYMBOL(__kmalloc_cache_node_noprof);
        EXPORT_SYMBOL(__kmalloc_cache_noprof);
        EXPORT_SYMBOL(__kmalloc_large_node_noprof);
        EXPORT_SYMBOL(__kmalloc_large_noprof);
        EXPORT_SYMBOL(__kmalloc_node_noprof);
        EXPORT_SYMBOL(__kmalloc_node_track_caller_noprof);
        EXPORT_SYMBOL(__kmalloc_noprof);
        EXPORT_SYMBOL(kfree);
        EXPORT_SYMBOL(kmem_cache_alloc_lru_noprof);
        EXPORT_SYMBOL(kmem_cache_alloc_node_noprof);
        EXPORT_SYMBOL(kmem_cache_alloc_noprof);
        EXPORT_SYMBOL(krealloc_node_align_noprof);
        EXPORT_SYMBOL_GPL(kfree_nolock);
        EXPORT_SYMBOL_GPL(kmalloc_nolock_noprof);
        """

        # This list may be incomplete.
        # If you know of any memory-allocating functions that may be freed with kfree, please let me know.
        # The number is the argument index of the size. -1 means index 0 is `struct kmem_cache*`.
        kversion = Kernel.kernel_version()
        if kversion < "3.16":
            kmalloc_syms = [
                ["__kmalloc", 0],
                ["__kmalloc_node", 0],
                ["__kmalloc_node_track_caller", 0],
                ["__kmalloc_track_caller", 0],
                ["__krealloc", 1],
                ["kmalloc_order_trace", 0],
                ["kmem_cache_alloc", -1],
                ["kmem_cache_alloc_node", -1],
                ["kmem_cache_alloc_node_trace", 3],
                ["kmem_cache_alloc_trace", 2],
                ["krealloc", 1],
            ]
        elif kversion < "5.6":
            kmalloc_syms = [
                ["__kmalloc", 0],
                ["__kmalloc_node", 0],
                ["__kmalloc_node_track_caller", 0],
                ["__kmalloc_track_caller", 0],
                ["__krealloc", 1],
                ["kmalloc_order", 0],
                ["kmalloc_order_trace", 0],
                ["kmem_cache_alloc", -1],
                ["kmem_cache_alloc_node", -1],
                ["kmem_cache_alloc_node_trace", 3],
                ["kmem_cache_alloc_trace", 2],
                ["krealloc", 1],
            ]
        elif kversion < "5.18":
            kmalloc_syms = [
                ["__kmalloc", 0],
                ["__kmalloc_node", 0],
                ["__kmalloc_node_track_caller", 0],
                ["__kmalloc_track_caller", 0],
                ["kmalloc_order", 0],
                ["kmalloc_order_trace", 0],
                ["kmem_cache_alloc", -1],
                ["kmem_cache_alloc_node", -1],
                ["kmem_cache_alloc_node_trace", 3],
                ["kmem_cache_alloc_trace", 2],
                ["krealloc", 1],
            ]
        elif kversion < "6.1":
            kmalloc_syms = [
                ["__kmalloc", 0],
                ["__kmalloc_node", 0],
                ["__kmalloc_node_track_caller", 0],
                ["__kmalloc_track_caller", 0],
                ["kmalloc_order", 0],
                ["kmalloc_order_trace", 0],
                ["kmem_cache_alloc", -1],
                ["kmem_cache_alloc_lru", -1],
                ["kmem_cache_alloc_node", -1],
                ["kmem_cache_alloc_node_trace", 3],
                ["kmem_cache_alloc_trace", 2],
                ["krealloc", 1],
            ]
        elif kversion < "6.10":
            kmalloc_syms = [
                ["__kmalloc", 0],
                ["__kmalloc_node", 0],
                ["__kmalloc_node_track_caller", 0],
                ["kmalloc_large", 0],
                ["kmalloc_large_node", 0],
                ["kmalloc_node_trace", 3],
                ["kmalloc_trace", 2],
                ["kmem_cache_alloc", -1],
                ["kmem_cache_alloc_lru", -1],
                ["kmem_cache_alloc_node", -1],
                ["krealloc", 1],
            ]
        elif kversion < "6.11":
            kmalloc_syms = [
                ["__kmalloc_node_noprof", 0],
                ["__kmalloc_noprof", 0],
                ["kmalloc_large_node_noprof", 0],
                ["kmalloc_large_noprof", 0],
                ["kmalloc_node_trace_noprof", 3],
                ["kmalloc_node_track_caller_noprof", 0],
                ["kmalloc_trace_noprof", 2],
                ["kmem_cache_alloc_lru_noprof", -1],
                ["kmem_cache_alloc_node_noprof", -1],
                ["kmem_cache_alloc_noprof", -1],
                ["krealloc_noprof", 1],
            ]
        elif kversion < "6.18":
            kmalloc_syms = [
                ["__kmalloc_cache_node_noprof", 3],
                ["__kmalloc_cache_noprof", 2],
                ["__kmalloc_large_node_noprof", 0],
                ["__kmalloc_large_noprof", 0],
                ["__kmalloc_node_noprof", 0],
                ["__kmalloc_node_track_caller_noprof", 0],
                ["__kmalloc_noprof", 0],
                ["kmem_cache_alloc_lru_noprof", -1],
                ["kmem_cache_alloc_node_noprof", -1],
                ["kmem_cache_alloc_noprof", -1],
                ["krealloc_noprof", 1],
            ]
        else:
            kmalloc_syms = [
                ["__kmalloc_cache_node_noprof", 3],
                ["__kmalloc_cache_noprof", 2],
                ["__kmalloc_large_node_noprof", 0],
                ["__kmalloc_large_noprof", 0],
                ["__kmalloc_node_noprof", 0],
                ["__kmalloc_node_track_caller_noprof", 0],
                ["__kmalloc_noprof", 0],
                ["kmem_cache_alloc_lru_noprof", -1],
                ["kmem_cache_alloc_node_noprof", -1],
                ["kmem_cache_alloc_noprof", -1],
                ["krealloc_node_align_noprof", 1],
                ["kmalloc_nolock_noprof", 0],
            ]

        if kversion < "6.18":
            kfree_syms = [
                ["kfree", 0],
            ]
        else:
            kfree_syms = [
                ["kfree", 0],
                ["kfree_nolock", 0],
            ]

        breakpoints = []
        for sym, index_of_size_arg in kmalloc_syms:
            func_addr = Symbol.get_ksymaddr(sym)
            if func_addr:
                gef_print(sym + ": ", end="")
                bp = KmallocBreakpoint(func_addr, sym, index_of_size_arg, option_info, extra_info)
                breakpoints.append(bp)
        for sym, index_of_addr_arg in kfree_syms:
            func_addr = Symbol.get_ksymaddr(sym)
            if func_addr:
                gef_print(sym + ": ", end="")
                bp = KfreeBreakpoint(func_addr, sym, index_of_addr_arg, option_info, extra_info)
                breakpoints.append(bp)
        return breakpoints

    @staticmethod
    def set_bp_to_alloc_free_pages(option_info, extra_info):
        """
        [3.0~5.12]
        EXPORT_SYMBOL(__alloc_pages_nodemask);
        EXPORT_SYMBOL(__free_pages);
        [5.13~6.9]
        EXPORT_SYMBOL(__alloc_pages);
        EXPORT_SYMBOL(__free_pages);
        [6.10~6.13]
        EXPORT_SYMBOL(__alloc_pages_noprof);
        EXPORT_SYMBOL(__free_pages);
        [6.14~]
        EXPORT_SYMBOL(__alloc_frozen_pages_noprof);
        EXPORT_SYMBOL(__free_pages);
        """

        # This list may be incomplete.
        # If you know of any memory-allocating functions that may be freed with kfree, please let me know.
        # The number is the argument index of the order.
        kversion = Kernel.kernel_version()
        if kversion < "5.13":
            alloc_pages_sym = [
                ["__alloc_pages_nodemask", 1],
            ]
        elif kversion < "6.10":
            alloc_pages_sym = [
                ["__alloc_pages", 1],
            ]
        elif kversion < "6.14":
            alloc_pages_sym = [
                ["__alloc_pages_noprof", 1],
            ]
        else:
            alloc_pages_sym = [
                ["__alloc_frozen_pages_noprof", 1],
            ]

        free_pages_sym = [
            ["__free_pages", 0, 1],
        ]

        breakpoints = []
        for sym, index_of_order_arg in alloc_pages_sym:
            func_addr = Symbol.get_ksymaddr(sym)
            if func_addr:
                gef_print(sym + ": ", end="")
                bp = AllocPagesBreakpoint(func_addr, sym, index_of_order_arg, option_info, extra_info)
                breakpoints.append(bp)
        for sym, index_of_addr_arg, index_of_order_arg in free_pages_sym:
            func_addr = Symbol.get_ksymaddr(sym)
            if func_addr:
                gef_print(sym + ": ", end="")
                bp = FreePagesBreakpoint(func_addr, sym, index_of_addr_arg, index_of_order_arg, option_info, extra_info)
                breakpoints.append(bp)
        return breakpoints

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel
    @only_if_kvm_disabled
    def do_invoke(self, args):
        info("Wait for memory scan")

        kversion = Kernel.kernel_version()
        if kversion < "3.0":
            err("Unsupported before v3.0")
            return

        allocator = Kernel.get_slab_type()
        if allocator == "Unknown":
            err("Unsupported: Unknown allocator")
            return
        if allocator != "SLUB":
            warn("Unsupported viewing detailed information for SLAB, SLOB, SLUB_TINY")
            # fall through

        # initialize
        if not hasattr(self, "initialized"):
            ret = KmallocTracerCommand.initialize(allocator, args.verbose)
            if ret is False:
                err("Failed to initialize")
                return
            self.initialized = True
            self.extra_info = ret # allow None
        else:
            if args.verbose and self.extra_info:
                info("offsetof({:s}, slab_cache): {:#x}".format(Kernel.slab_page_str(), self.extra_info.page_offset_slab_cache))
                info("offsetof(kmem_cache, name): {:#x}".format(self.extra_info.kmem_cache_offset_name))
                info("offsetof(kmem_cache, size): {:#x}".format(self.extra_info.kmem_cache_offset_size))

        # create option_info
        option_info = KmallocTracerCommand.create_option_info(args)

        # set breakpoints
        breakpoints = KmallocTracerCommand.set_bp_to_kmalloc_kfree(option_info, self.extra_info)
        if args.enable_page_allocator_trace:
            breakpoints += KmallocTracerCommand.set_bp_to_alloc_free_pages(option_info, self.extra_info)
        for bp in breakpoints:
            bp.enabled = True

        # doit
        info("Setup is complete. continuing...")
        gdb.execute("continue")

        # clean up
        info("kmalloc-tracer is complete, cleaning up...")
        for bp in breakpoints:
            bp.delete()
        KmallocTracerCommand.clear_disabled_breakpoints("KmallocRetBreakpoint", force=True)
        if args.enable_page_allocator_trace:
            KmallocTracerCommand.clear_disabled_breakpoints("AllocPagesRetBreakpoint", force=True)
        return


class KmallocAllocatedBy_UserlandHardwareBreakpoint(gdb.Breakpoint):
    """Breakpoint to userland `sleep` process for KmallocAllocatedByCommand."""

    def __init__(self, loc):
        super().__init__("*{:#x}".format(loc), gdb.BP_HARDWARE_BREAKPOINT, internal=False)
        self.silent = True
        return

    def stop(self):
        return True # stop


@register_command
class KmallocAllocatedByCommand(GenericCommand):
    """Call predefined system-calls and print kmalloc-N chunks allocated and freed (x64 only)."""

    _cmdline_ = "kmalloc-allocated-by"
    _category_ = "06-i. Qemu-system/KGDB Cooperation - Linux Dynamic Inspection"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-f", "--filter", action="append", default=[], help="filter specified name (e.g., kmalloc-XX)")
    parser.add_argument("-N", "--print-null", action="store_true", help="display free(NULL).")
    parser.add_argument("-t", "--backtrace", action="store_true", help="display backtrace.")
    parser.add_argument("-d", "--dump-chunk", action="store_true", help="dump the first 0x40 bytes of each chunk.")
    parser.add_argument("-v", "--verbose", action="store_true", help="print meta information.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}       # simple output",
        "{0:s} -dtv  # useful output",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Disable `-enable-kvm` option for qemu-system (#PF may occur).",
        "Disable `-smp N` option for qemu-system (write memory error may occur).",
        "Append `tsc=unstable` option for kernel cmdline.",
        "This command requires CONFIG_RANDSTRUCT=n.",
    ]
    _note_ = "\n".join(_note_)

    def setup_syscall(self, syscall_name, args):
        gdb.execute("set $pc-={:#x}".format(len(runtime.current_arch.syscall_insn)), to_string=True)
        nr = self.syscall_table[syscall_name]
        gdb.execute("set $rax={:#x}".format(nr), to_string=True)
        sp = runtime.current_arch.sp
        for reg, arg in zip(runtime.current_arch.syscall_parameters, args):
            if arg is None:
                break
            if isinstance(arg, str):
                arg = String.str2bytes(arg)
            if isinstance(arg, bytes):
                write_memory(sp, arg)
                gdb.execute("set {:s}={:#x}".format(reg, sp), to_string=True)
                sp = align(sp + len(arg), runtime.current_arch.ptrsize * 2)
            else:
                gdb.execute("set {:s}={:#x}".format(reg, arg), to_string=True)
        self.tested_syscall.add(syscall_name)
        return

    def dump_untested_syscall(self):
        valid_syscall = []
        for line in self.syscall_table_view_ret.splitlines():
            tag, _, valid, name, *__ = Color.remove_color(line).split()
            if tag != "x86_64":
                continue
            if valid != "valid":
                continue
            valid_syscall.append(name)

        invalid_syscall = []
        tested_syscall = []
        untested_syscall = []
        skipped_syscall = []
        # sort by index and translate from set to list
        for name, _nr in self.syscall_table.items():
            if name not in valid_syscall:
                invalid_syscall.append(name)
            elif name in self.tested_syscall:
                tested_syscall.append(name)
            elif name in self.scheduled_syscall:
                skipped_syscall.append(name)
            elif name in self.skipped_syscall:
                skipped_syscall.append(name)
            else:
                untested_syscall.append(name)

        gef_print(titlify("Tested syscall"))
        gef_print(", ".join(tested_syscall))

        gef_print(titlify("Untested syscall"))
        gef_print(", ".join(untested_syscall))

        gef_print(titlify("Skipped syscall"))
        gef_print(", ".join(skipped_syscall))

        gef_print(titlify("Invalid (Unsupported) syscall"))
        gef_print(", ".join(invalid_syscall))
        return

    def test_syscall(self, breakpoints):

        def u2i(x):
            x = struct.pack("<Q", x & 0xffff_ffff_ffff_ffff)
            return struct.unpack("<q", x)[0]

        def gen_testcase():
            # It is implemented with a generator because
            # it requires delayed execution in order to use the previous result.

            nonlocal ret_history

            yield "msgget -> msgsnd -> msgrcv -> msgctl"
            yield ("msqid = msgget(IPC_PRIVATE, IPC_CREAT|0666)", "msgget", [0, 0o1000 | 0o666])
            msgsize = 0x100
            msg = p64(1) + b"A" * msgsize
            if u2i(ret_history[-1]) >= 0:
                msqid = ret_history[-1]
                yield ("msgsnd(msqid, &msg, msgsize, 0)", "msgsnd", [msqid, msg, msgsize, 0])
                yield ("msgrcv(msqid, &msg, msgsize, 0, 0)", "msgrcv", [msqid, msg, msgsize, 0, 0])
                yield ("msgctl(msqid, IPC_RMID, 0)", "msgctl", [msqid, 0, 0])

            yield "shmget -> shmat -> shmdt -> shmctl"
            yield ("shmid = shmget(IPC_PRIVATE, 1024, IPC_CREAT|0666)", "shmget", [0, 0x400, 0o1000 | 0o666])
            if u2i(ret_history[-1]) >= 0:
                shmid = ret_history[-1]
                yield ("addr = shmat(shmid, NULL, 0)", "shmat", [shmid, 0, 0])
                addr = ret_history[-1]
                yield ("shmdt(addr)", "shmdt", [addr])
                yield ("shmctl(shmid, IPC_RMID, 0)", "shmctl", [shmid, 0, 0])

            yield "semget -> semop -> semctl"
            yield ("semid = semget(IPC_PRIVATE, 1, IPC_CREAT|0666)", "semget", [0, 1, 0o1000 | 0o666])
            if u2i(ret_history[-1]) >= 0:
                semid = ret_history[-1]
                sembuf = p16(0)  # sem_num
                sembuf += p16(2) # sem_op
                sembuf += p16(0) # sem_flg
                yield ("semop(semid, &sembuf, 1)", "semop", [semid, sembuf, 1])
                self.skipped_syscall.add("semtimedop")
                yield ("semctl(semid, 0, IPC_RMID)", "semctl", [semid, 0, 0])

            yield "mq_open -> mq_timedsend -> mq_timedreceive -> mq_notify -> mq_getsetattr -> mq_unlink -> close"
            MQ_NAME = "mq_test\0"
            attr = p64(0o4000) # mq_flags: O_NONBLOCK
            attr += p64(10)    # mq_maxmsg
            attr += p64(0x100) # mq_msgsize
            attr += p64(0)     # mq_curmsgs
            attr += p64(0) * 4 # __reserved[4]
            yield (
                'fd = mq_open("mq_test", O_RDWR|O_CREAT, 0700, &attr)',
                "mq_open", [MQ_NAME, 0o2 | 0o100, 0o700, attr],
            )
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                msg = "A" * 0x100
                yield ("mq_timedsend(fd, &msg, sizeof(msg), 0, NULL)", "mq_timedsend", [fd, msg, len(msg), 0, 0])
                buf = "\0" * 0x100
                prio = p32(0)
                timeout = p64(0)  # tv_sec
                timeout += p64(0) # tv_nsec
                yield (
                    "mq_timedreceive(fd, &buf, sizeof(buf), &prio, &timeout)",
                    "mq_timedreceive", [fd, buf, len(buf), prio, timeout],
                )
                sigevent = p32(0)   # sigev_notify: SIGEV_SIGNAL
                sigevent += p32(10) # sigev_signo: SIGUSR1
                sigevent += p64(0)  # sigev_value
                sigevent += p64(0)  # sigev_notify_function
                sigevent += p64(0)  # sigev_notify_attributes
                sigevent += p64(0)  # sigev_notify_thread_id
                yield ("mq_notify(fd, &sigevent)", "mq_notify", [fd, sigevent])
                attr = p64(0)      # mq_flags
                attr += p64(0)     # mq_maxmsg
                attr += p64(0)     # mq_msgsize
                attr += p64(0)     # mq_curmsgs
                attr += p64(0) * 4 # __reserved[4]
                yield ("mq_getsetattr(fd, NULL, &attr)", "mq_getsetattr", [fd, 0, attr])
                yield ('mq_unlink("mq_test")', "mq_unlink", [MQ_NAME])
                yield ("close(fd)", "close", [fd])

            yield "signalfd4 -> close"
            mask = "\0" * 8
            yield ("fd = signalfd4(-1, &mask, sizeof(mask), 0)", "signalfd4", [-1, mask, len(mask), 0])
            self.skipped_syscall.add("signalfd")
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                yield ("close(fd)", "close", [fd])

            yield "setitimer -> getitimer"
            new_value = p64(0)  # it_interval.tv_sec
            new_value += p64(0) # it_interval.tv_nsec
            new_value += p64(0) # it_value.tv_sec
            new_value += p64(0) # it_value.tv_nsec
            old_value = p64(0)  # it_interval.tv_sec
            old_value += p64(0) # it_interval.tv_nsec
            old_value += p64(0) # it_value.tv_sec
            old_value += p64(0) # it_value.tv_nsec
            yield ("setitimer(ITIMER_REAL, &new_value, &old_value)", "setitimer", [0, new_value, old_value])
            curr_value = p64(0)  # it_interval.tv_sec
            curr_value += p64(0) # it_interval.tv_nsec
            curr_value += p64(0) # it_value.tv_sec
            curr_value += p64(0) # it_value.tv_nsec
            yield ("getitimer(ITIMER_REAL, &curr_value)", "getitimer", [0, curr_value])

            yield "timerfd_create -> timerfd_settime -> timerfd_gettime -> close"
            yield ("fd = timerfd_create(CLOCK_MONOTONIC, 0)", "timerfd_create", [1, 0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                new_value = p64(0)  # it_interval.tv_sec
                new_value += p64(0) # it_interval.tv_nsec
                new_value += p64(0) # it_value.tv_sec
                new_value += p64(0) # it_value.tv_nsec
                old_value = p64(0)  # it_interval.tv_sec
                old_value += p64(0) # it_interval.tv_nsec
                old_value += p64(0) # it_value.tv_sec
                old_value += p64(0) # it_value.tv_nsec
                yield (
                    "timerfd_settime(fd, 0, &new_value, &old_value)",
                    "timerfd_settime", [fd, 0, new_value, old_value],
                )
                curr_value = p64(0)  # it_interval.tv_sec
                curr_value += p64(0) # it_interval.tv_nsec
                curr_value += p64(0) # it_value.tv_sec
                curr_value += p64(0) # it_value.tv_nsec
                yield ("timerfd_gettime(fd, &curr_value)", "timerfd_gettime", [fd, curr_value])
                yield ("close(fd)", "close", [fd])

            yield "timer_create -> timer_settime -> timier_gettime -> timer_getoverrun -> timer_delete"
            timerid = p64(0)
            yield ("timer_create(CLOCK_MONOTONIC, NULL, &timerid)", "timer_create", [1, 0, timerid])
            if u2i(ret_history[-1]) == 0:
                timerid = read_int_from_memory(runtime.current_arch.sp)
                new_value = p64(0)  # it_interval.tv_sec
                new_value += p64(0) # it_interval.tv_nsec
                new_value += p64(0) # it_value.tv_sec
                new_value += p64(0) # it_value.tv_nsec
                old_value = p64(0)  # it_interval.tv_sec
                old_value += p64(0) # it_interval.tv_nsec
                old_value += p64(0) # it_value.tv_sec
                old_value += p64(0) # it_value.tv_nsec
                yield (
                    "timer_settime(timerid, 0, &new_value, &old_value)",
                    "timer_settime", [timerid, 0, new_value, old_value],
                )
                curr_value = p64(0)  # it_interval.tv_sec
                curr_value += p64(0) # it_interval.tv_nsec
                curr_value += p64(0) # it_value.tv_sec
                curr_value += p64(0) # it_value.tv_nsec
                yield ("timer_gettime(timerid, &curr_value)", "timer_gettime", [timerid, curr_value])
                yield ("timer_getoverrun(timerid)", "timer_getoverrun", [timerid])
                yield ("timer_delete(timerid)", "timer_delete", [timerid])

            yield "epoll_create1 -> epoll_ctl -> epoll_wait -> close"
            yield ("epfd = epoll_create1(0)", "epoll_create1", [0])
            self.skipped_syscall.add("epoll_create")
            if u2i(ret_history[-1]) >= 0:
                epfd = ret_history[-1]
                event = p32(1)  # events: EPOLLIN
                event += p64(0) # data
                yield ("epoll_ctl(epfd, EPOLL_CTL_ADD, STDIN_FILENO, &event)", "epoll_ctl", [epfd, 1, 0, event])
                yield ("epoll_wait(epfd, &events, 1, 0)", "epoll_wait", [epfd, event, 1, 0])
                self.skipped_syscall.add("epoll_pwait")
                self.skipped_syscall.add("epoll_pwait2")
                yield ("close(epfd)", "close", [epfd])

            yield "eventfd2 -> close"
            yield ("fd = eventfd2(0, 0)", "eventfd2", [0, 0])
            self.skipped_syscall.add("eventfd")
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                yield ("close(fd)", "close", [fd])

            yield "perf_event_open (need kernel.perf_event_paranoid <= 2) -> close"
            attr = p32(1)      # type: PERF_TYPE_SOFTWARE
            attr += p32(0x80)  # size: sizeof(attr)
            attr += p64(9)     # config: PERF_COUNT_SW_DUMMY
            attr += p64(0)     # sample_period or sample_freq
            attr += p64(0)     # sample_type
            attr += p64(0)     # read_format
            flags = 1 << 5     # execlude_kernel=1
            flags |= 1 << 6    # execlude_hv=1
            flags |= 1 << 8    # mmap=1
            flags |= 1 << 17   # mmap_data=1
            attr += p64(flags) # flags
            attr += p32(0)     # wakeup_events or wakeup_watermalk
            attr += p32(0)     # bp_type
            attr += p64(0)     # bp_addr or kprobe_func or uprobe_path or config1
            attr += p64(0)     # bp_len or kprobe_addr or probe_offset or config2
            attr += p64(0)     # branch_sample_type
            attr += p64(0)     # sample_regs_user
            attr += p32(0)     # sample_stack_user
            attr += p32(0)     # clockid
            attr += p64(0)     # sample_regs_intr
            attr += p32(0)     # aux_watermark
            attr += p16(0)     # sample_max_stack
            attr += p16(0)     # __reserved_2
            attr += p32(0)     # aux_sample_size
            attr += p32(0)     # __reserved_3
            attr += p64(0)     # sig_data
            attr += p64(0)     # config3
            yield ("fd = perf_event_open(&attr, 0, -1, -1, 0)", "perf_event_open", [attr, 0, -1, -1, 0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                yield ("close(fd)", "close", [fd])

            yield "bpf (need kernel.unprivileged_bpf_disabled == 0) -> close"
            attr = p32(2)     # map_type: BPF_MAP_TYPE_ARRAY
            attr += p32(4)    # key_size
            attr += p32(0x10) # value_size
            attr += p32(0x10) # max_entries
            yield ("bpf(BPF_MAP_CREATE, &attr, sizeof(attr))", "bpf", [0, attr, len(attr)])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                yield ("close(fd)", "close", [fd])

            yield "mmap -> mprotect -> mremap -> msync -> madvise -> munmap"
            size = get_pagesize()
            yield (
                "addr = mmap(NULL, 0x1000, RWX, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)",
                "mmap", [0, size, 7, 0x20 | 0x2, -1, 0],
            )
            if u2i(ret_history[-1]) >= 0:
                addr = ret_history[-1]
                yield ("mprotect(addr, 0x1000, R--)", "mprotect", [addr, size, 1])
                size2 = size * 2
                yield ("addr2 = mremap(addr, 0x1000, 0x2000, MREMAP_MAYMOVE)", "mremap", [addr, size, size2, 1])
                if u2i(ret_history[-1]) >= 0:
                    addr2 = ret_history[-1]
                    yield ("msync(addr2, 0x2000, MS_SYNC)", "msync", [addr2, size2, 4])
                    yield ("madvise(addr2, 0x2000, MADV_DONTNEED)", "madvise", [addr2, size2, 4])
                    self.skipped_syscall.add("process_madvise")
                    yield ("munmap(addr2, 0x2000)", "munmap", [addr2, size2])

            yield "mmap -> mincore -> mbind -> move_pages -> migrate_pages -> munmap"
            size = get_pagesize()
            yield (
                "addr = mmap(NULL, 0x1000, RWX, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0)",
                "mmap", [0, size, 7, 0x20 | 0x2, -1, 0],
            )
            if u2i(ret_history[-1]) >= 0:
                addr = ret_history[-1]
                vec = "\0" * 0x100
                yield ("mincore(addr, 0x1000, &vec)", "mincore", [addr, size, vec])
                yield ("mbind(addr, 0x1000, MPOL_DEFAULT, NULL, 0, 0)", "mbind", [addr, size, 0, 0, 0, 0])
                pages = p64(addr)
                status = p64(0)
                yield ("move_pages(0, 1, &pages, NULL, &status, 0)", "move_pages", [0, 1, pages, 0, status, 0])
                maxnode = 8
                old_nodes = "\x02"
                new_nodes = "\x01"
                yield (
                    "migrate_pages(0, 8, old_nodes, new_nodes)",
                    "migrate_pages", [0, maxnode, old_nodes, new_nodes],
                )
                yield ("munmap(addr, 0x1000)", "munmap", [addr, size])

            yield "brk -> userfaultfd -> ioctl -> close"
            yield ("addr = brk(0)", "brk", [0])
            last_page = ret_history[-1] - get_pagesize()
            yield ("fd = userfaultfd(O_CLOEXEC|O_NONBLOCK)", "userfaultfd", [0o2000000 | 0o4000])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                uffdio_api = p64(0xaa) # api: UFFD_API
                uffdio_api += p64(0)   # features
                uffdio_api += p64(0)   # ioctls
                yield ("ioctl(fd, UFFDIO_API, &uffdio_api)", "ioctl", [fd, 0xc018aa3f, uffdio_api])
                uffdio_register = p64(last_page)          # range.start
                uffdio_register += p64(get_pagesize()) # range.len
                uffdio_register += p64(1)                 # mode: UFFDIO_REGISTER_MODE_MISSING
                uffdio_register += p64(0)                 # ioctls
                yield ("ioctl(fd, UFFDIO_REGISTER, &uffdio_register)", "ioctl", [fd, 0xc020aa00, uffdio_register])
                yield ("ioctl(fd, UFFDIO_UNREGISTER, &uffdio_register)", "ioctl", [fd, 0x8010aa01, uffdio_register])
                yield ("close(fd)", "close", [fd])

            yield "mlockall -> munlockall"
            yield ("mlockall(MCL_CURRENT)", "mlockall", [1])
            self.skipped_syscall.add("mlock")
            self.skipped_syscall.add("mlock2")
            yield ("munlockall()", "munlockall", [])
            self.skipped_syscall.add("munlock")

            yield "get_robust_list -> set_robust_list"
            head_ptr = p64(0)
            len_ptr = p64(0)
            yield ("get_robust_list(0, &head_ptr, &len_ptr)", "get_robust_list", [0, head_ptr, len_ptr])
            if u2i(ret_history[-1]) >= 0:
                head = read_int_from_memory(runtime.current_arch.sp)
                len_ = read_int_from_memory(runtime.current_arch.sp + 0x10)
                yield ("set_robust_list(head, len)", "set_robust_list", [head, len_])

            yield "prctl -> arch_prctl -> set_tid_address"
            buf = p32(0)
            yield ("prctl(PR_GET_PDEATHSIG, &buf)", "prctl", [2, buf])
            yield ("prctl(PR_GET_DUMPABLE)", "prctl", [3])
            yield ("prctl(PR_GET_KEEPCAPS)", "prctl", [7])
            yield ("prctl(PR_GET_TIMING)", "prctl", [13])
            buf = "\0" * 16
            yield ("prctl(PR_GET_NAME, &buf)", "prctl", [16, buf])
            yield ("prctl(PR_GET_SECCOMP)", "prctl", [21])
            yield ("prctl(PR_CAPBSET_READ, CAP_CHOWN)", "prctl", [23, 0])
            buf = p32(0)
            yield ("prctl(PR_GET_TSC, &buf)", "prctl", [25, buf])
            yield ("prctl(PR_GET_SECUREBITS)", "prctl", [27])
            yield ("prctl(PR_GET_TIMERSLACK)", "prctl", [30])
            yield ("prctl(PR_TASK_PERF_EVENTS_DISABLE)", "prctl", [31])
            yield ("prctl(PR_MCE_KILL_GET, 0, 0, 0, 0)", "prctl", [34, 0, 0, 0, 0])
            buf = p32(0)
            yield ("prctl(PR_GET_CHILD_SUBREAPER, &buf)", "prctl", [37, buf])
            yield ("prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)", "prctl", [39, 0, 0, 0, 0])
            yield ("prctl(PR_GET_TID_ADDRESS)", "prctl", [40, buf])
            yield ("prctl(PR_GET_THP_DISABLE, 0, 0, 0, 0)", "prctl", [42, 0, 0, 0, 0])
            yield ("arch_prctl(ARCH_GET_CPUID)", "arch_prctl", [0x1011])
            buf = p64(0)
            yield ("arch_prctl(ARCH_GET_GS, &buf)", "arch_prctl", [0x1001, buf])
            buf = p64(0)
            yield ("arch_prctl(ARCH_GET_FS, &buf)", "arch_prctl", [0x1003, buf])
            fsbase = ret_history[-1]
            yield ("set_tid_address(fsbase)", "set_tid_address", [fsbase])

            yield "futex"
            uaddr = p64(0)
            yield ("futex(&uaddr, FUTEX_WAKE, 1, &timeout, 0, 0)", "futex", [uaddr, 1, 1, 0, 0, 0])

            yield "time"
            yield ("time(NULL)", "time", [0])

            yield "times"
            buf = p64(0)  # tms_utime
            buf += p64(0) # tms_stime
            buf += p64(0) # tms_cutime
            buf += p64(0) # tms_cstime
            yield ("times(&buf)", "times", [buf])

            yield "gettimeofday"
            tv = p64(0)  # tv_sec
            tv += p64(0) # tv_usec
            tz = p32(0)  # tz_minuteswest
            tz += p32(0) # tz_dsttime
            yield ("gettimeofday(&tv, &tz)", "gettimeofday", [tv, tz])

            yield "nanosleep"
            req = p64(0)     # tv_sec
            req += p64(1000) # tv_nsec
            rem = p64(0)     # tv_sec
            rem += p64(0)    # tv_nsec
            yield ("nanosleep(&req, &rem)", "nanosleep", [req, rem])
            self.skipped_syscall.add("clock_nanosleep")

            yield "clock_getres -> clock_gettime"
            res = p64(0)  # tv_sec
            res += p64(0) # tv_nsec
            yield ("clock_getres(CLOCK_PROCESS_CPUTIME_ID, &res)", "clock_getres", [2, res])
            tp = p64(0)  # tv_sec
            tp += p64(0) # tv_nsec
            yield ("clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &tp)", "clock_gettime", [2, tp])

            yield "adjtimex"
            buf = p64(0)  # modes
            buf += p64(0) # offset
            buf += p64(0) # freq
            buf += p64(0) # maxerror
            buf += p64(0) # esterror
            buf += p64(0) # status
            buf += p64(0) # constant
            buf += p64(0) # precision
            buf += p64(0) # tolerance
            buf += p64(0) # time.tv_sec
            buf += p64(0) # time.tv_usec
            buf += p64(0) # tick
            buf += p64(0) # ppsfreq
            buf += p64(0) # jitter
            buf += p64(0) # shift
            buf += p64(0) # stabil
            buf += p64(0) # jitcnt
            buf += p64(0) # calcnt
            buf += p64(0) # errcnt
            buf += p64(0) # stbcnt
            buf += p64(0) # tai
            yield ("adjtimex(&buf)", "adjtimex", [buf])
            self.skipped_syscall.add("clock_adjtime")

            yield "membarrier"
            yield ("membarrier(MEMBARRIER_CMD_QUERY, 0, 0)", "membarrier", [0, 0, 0])

            yield "getcwd"
            buf = "\0" * 0x100
            yield ("getcwd(&buf, sizeof(buf))", "getcwd", [buf, len(buf)])

            yield "uname"
            buf = "\0" * 0x400
            yield ("uname(&buf)", "uname", [buf])

            yield "getrandom"
            buf = "\0" * 0x100
            yield ("getrandom(&buf, sizeof(buf), 0)", "getrandom", [buf, len(buf), 0])

            yield "getrlimit -> setrlimit"
            rlim = p64(0)  # rlim_cur
            rlim += p64(0) # rlim_max
            yield ("getrlimit(RLIMIT_STACK, &rlim, sizeof(rlim))", "getrlimit", [3, rlim, len(rlim)])
            rlim = read_memory(runtime.current_arch.sp, 16)
            yield ("setrlimit(RLIMIT_STACK, &rlim, sizeof(rlim))", "setrlimit", [3, rlim, len(rlim)])
            self.skipped_syscall.add("prlimit64")

            yield "sched_yield"
            yield ("sched_yield()", "sched_yield", [])

            yield "sched_getscheduler -> sched_setscheduler"
            yield ("sched_getscheduler(0)", "sched_getscheduler", [0])
            param = p32(0)
            yield ("sched_setscheduler(0, SCHED_OTHER, &param)", "sched_setscheduler", [0, 0, param])

            yield "sched_getparam -> sched_setparam"
            param = p32(0)
            yield ("sched_getparam(0, &param)", "sched_getparam", [0, param])
            yield ("sched_setparam(0, &param)", "sched_setparam", [0, param])

            yield "sched_getaffinity -> sched_setaffinity"
            mask = "\0" * 0x80
            yield ("sched_getaffinity(0, sizeof(mask), &mask)", "sched_getaffinity", [0, len(mask), mask])
            mask = read_memory(runtime.current_arch.sp, 0x80)
            yield ("sched_setaffinity(0, sizeof(mask), &mask)", "sched_setaffinity", [0, len(mask), mask])

            yield "sched_get_priority_max -> sched_get_priority_min"
            yield ("sched_get_priority_max(SCHED_OTHER)", "sched_get_priority_max", [0])
            yield ("sched_get_priority_min(SCHED_OTHER)", "sched_get_priority_min", [0])

            yield "sched_rr_get_interval"
            tp = p64(0)  # tv_sec
            tp += p64(0) # tv_nsec
            yield ("sched_rr_get_interval(0, &tp)", "sched_rr_get_interval", [0, tp])

            yield "sched_getattr -> sched_setattr"
            attr = p32(8 * 6) # size
            attr += p32(0) # sched_policy: SCHED_OTHER
            attr += p64(0) # sched_flags
            attr += p32(0) # sched_nice
            attr += p32(0) # sched_priority
            attr += p64(0) # sched_runtime
            attr += p64(0) # sched_deadline
            attr += p64(0) # sched_period
            yield ("sched_getattr(0, &attr, sizeof(attr), 0)", "sched_getattr", [0, attr, len(attr), 0])
            # sched_setattr must be called before setpriority, or failed.
            yield ("sched_setattr(0, &attr, 0)", "sched_setattr", [0, attr, 0])

            yield "getpriority -> setpriority"
            yield ("getpriority(PRIO_PROCESS, 0)", "getpriority", [0, 0])
            yield ("setpriority(PRIO_PROCESS, 0, 1)", "setpriority", [0, 0, 1])

            yield "ioprio_get -> ioprio_set"
            yield ("ioprio_get(IOPRIO_WHO_PROCESS, 0)", "ioprio_get", [1, 0])
            yield ("ioprio_set(IOPRIO_WHO_PROCESS, 0, IOPRIO_PRIO_VALUE(2, 0))", "ioprio_set", [1, 0, 0x4000])

            yield "getrusage"
            buf = p64(0)  # ru_utime.tv_sec
            buf += p64(0) # ru_utime.tv_usec
            buf += p64(0) # ru_stime.tv_sec
            buf += p64(0) # ru_stime.tv_usec
            buf += p64(0) # ru_maxrss
            buf += p64(0) # ru_ixrss
            buf += p64(0) # ru_idrss
            buf += p64(0) # ru_isrss
            buf += p64(0) # ru_minflt
            buf += p64(0) # ru_majflt
            buf += p64(0) # ru_nswap
            buf += p64(0) # ru_inblock
            buf += p64(0) # ru_oublock
            buf += p64(0) # ru_msgsnd
            buf += p64(0) # ru_msgrcv
            buf += p64(0) # ru_nsignals
            buf += p64(0) # ru_nvcsw
            buf += p64(0) # ru_nivcsw
            yield ("getrusage(RUSAGE_SELF, &buf)", "getrusage", [0, buf])

            yield "personality"
            yield ("personality(0xffffffff)", "personality", [0xffff_ffff])

            yield "get_mempolicy -> set_mempolicy"
            nodemask = p64(0)
            yield ("get_mempolicy(0, &nodemask, 8, 0, MPOL_F_MEMS_ALLOWED)", "get_mempolicy", [0, nodemask, 8, 0, 4])
            yield ("set_mempolicy(MPOL_DEFAULT, NULL, 8)", "set_mempolicy", [0, 0, 8])

            yield "getcpu"
            cpu = p32(0)
            node = p32(0)
            yield ("getcpu(&cpu, &node, NULL)", "getcpu", [cpu, node, 0])

            yield "sysinfo"
            buf = p64(0)      # uptime
            buf += p64(0) * 3 # loads[3]
            buf += p64(0)     # totalram
            buf += p64(0)     # freeram
            buf += p64(0)     # sharedram
            buf += p64(0)     # bufferram
            buf += p64(0)     # totalswap
            buf += p64(0)     # freeswap
            buf += p16(0)     # procs
            buf += p8(0) * 22 # padding
            yield ("sysinfo(&buf)", "sysinfo", [buf])

            yield "sysfs"
            buf = "\0" * 0x100
            yield ("sysfs(2, 0, &buf)", "sysfs", [2, 0, buf])

            yield "sigaltstack"
            oss = p64(0)  # ss_sp
            oss += p32(0) # ss_flags
            oss += p32(0) # padding
            oss += p64(0) # ss_size
            yield ("sigaltstack(NULL, &oss)", "sigaltstack", [0, oss])

            yield "rt_sigprocmask -> rt_sigpending"
            oldset = "\0" * 0x100
            sigsetsize = 8
            yield ("rt_sigprocmask(0, NULL, &oldset, sigsetsize)", "rt_sigprocmask", [0, 0, oldset, sigsetsize])
            set_ = "\0" * 0x100
            yield ("rt_sigpending(&set)", "rt_sigpending", [set_])

            yield "getpid -> getppid -> getsid -> gettid -> getpgid -> setpgid -> getpgrp -> kcmp"
            yield ("pid = getpid()", "getpid", [])
            pid = ret_history[-1]
            yield ("getppid()", "getppid", [])
            yield ("getsid(pid)", "getsid", [pid])
            yield ("gettid()", "gettid", [])
            tid = ret_history[-1]
            yield ("pgid = getpgid(pid)", "getpgid", [pid])
            pgid = ret_history[-1]
            yield ("setpgid(pid, pgid)", "setpgid", [pid, pgid])
            yield ("getpgrp()", "getpgrp", [])
            yield ("kcmp(pid, pid, KCMP_FS, 0, 0)", "kcmp", [pid, pid, 3, 0, 0])

            yield "getuid -> setuid -> setreuid -> setfsuid -> geteuid -> getresuid -> setresuid"
            yield ("uid = getuid()", "getuid", [])
            uid = ret_history[-1]
            yield ("setuid(uid)", "setuid", [uid])
            yield ("setreuid(uid, uid)", "setreuid", [uid, uid])
            yield ("setfsuid(uid)", "setfsuid", [uid])
            yield ("geteuid()", "geteuid", [])
            ruid = euid = suid = p32(0)
            yield ("getresuid(&ruid, &euid, &suid)", "getresuid", [ruid, euid, suid])
            yield ("setresuid(uid, uid, uid)", "setresuid", [uid, uid, uid])

            yield "getgid -> setgid -> setregid -> setfsgid -> getegid -> getresgid -> setresgid -> getgroups"
            yield ("gid = getgid()", "getgid", [])
            gid = ret_history[-1]
            yield ("setgid(gid)", "setgid", [gid])
            yield ("setregid(gid, gid)", "setregid", [gid, gid])
            yield ("setfsgid(uid)", "setfsgid", [gid])
            yield ("getegid()", "getegid", [])
            rgid = egid = sgid = p32(0)
            yield ("getresgid(&rgid, &egid, &sgid)", "getresgid", [rgid, egid, sgid])
            yield ("setresgid(gid, gid, gid)", "setresgid", [gid, gid, gid])
            yield ("getgroups(0, NULL)", "getgroups", [0, 0])

            yield "rt_sigaction -> alarm -> kill -> tkill -> rt_sigtimedwait"
            act = p64(1)    # sa_handler: SIG_IGN
            act += p64(0)   # sa_flags
            act += p64(0)   # sa_restorer
            act += p64(0xe) # sa_mask: SIGALRM
            oldact = p64(0)  # sa_handler
            oldact += p64(0) # sa_flags
            oldact += p64(0) # sa_restorer
            oldact += p64(0) # sa_mask: SIGALRM
            sigsetsize = 8
            yield ("rt_sigaction(SIGALRM, &act, &oldact, sigsetsize)", "rt_sigaction", [14, act, oldact, sigsetsize])
            yield ("alarm(1000)", "alarm", [1000])
            yield ("kill(pid, SIGALRM)", "kill", [pid, 14])
            yield ("tkill(tid, SIGALRM)", "kill", [tid, 14])
            self.skipped_syscall.add("tgkill")
            self.skipped_syscall.add("rt_sigqueueinfo")
            self.skipped_syscall.add("rt_tgsigqueueinfo")
            set_ = "\0" * 0x100
            info = p32(0)  # si_signo
            info += p32(0) # si_code
            info += p64(0) # si_value
            info += p32(0) # si_errno
            info += p32(0) # si_pid
            info += p32(0) # si_uid
            info += p32(0) # padding
            info += p64(0) # si_addr
            info += p32(0) # si_status
            info += p32(0) # si_band
            timeout = p64(0)  # tv_sec
            timeout += p64(0) # tv_nsec
            sigsetsize = 8
            yield (
                "rt_sigtimedwait(&set, &info, &timeout, sigsetsize)",
                "rt_sigtimedwait", [set_, info, timeout, sigsetsize],
            )

            yield "pidfd_open -> pidfd_getfd -> pidfd_send_signal -> close"
            yield ("pfdfd = pidfd_open(pid, 0)", "pidfd_open", [pid, 0])
            if u2i(ret_history[-1]) >= 0:
                pidfd = ret_history[-1]
                yield ("fd = pidfd_getfd(pidfd, STDIN_FILENO, 0)", "pidfd_getfd", [pidfd, 0, 0])
                if u2i(ret_history[-1]) >= 0:
                    fd = ret_history[-1]
                    yield ("close(fd)", "close", [fd])
                yield ("pidfd_send_signal(pidfd, SIGALRM, NULL, 0)", "pidfd_send_signal", [pidfd, 14, 0, 0])
                yield ("close(pidfd)", "close", [pidfd])

            yield "capget -> capset"
            hdrp = p32(0x20080522) # version
            hdrp += p32(pid)       # pid
            datap = p32(0)  # effective
            datap += p32(0) # permitted
            datap += p32(0) # inheritable
            yield ("capget(&hdrp, &datap)", "capget", [hdrp, datap])
            datap = read_memory(runtime.current_arch.sp + 0x10, 4 * 3)
            yield ("capset(&hdrp, &datap)", "capset", [hdrp, datap])

            yield "umask"
            yield ("umask(022)", "umask", [0o022])

            yield "open -> fallocate -> write -> fdatasync -> fsync -> syncfs -> fadvise64 -> close"
            TMP_XXX = "/tmp/xxx\0"
            yield ('fd = open("/tmp/xxx", 0_WRONLY|O_CREAT, 0666)', "open", [TMP_XXX, 0o1 | 0o100, 0o666])
            self.skipped_syscall.add("creat")
            self.skipped_syscall.add("openat")
            self.skipped_syscall.add("openat2")
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                yield ("fallocate(fd, 0, 0, 0x100)", "fallocate", [fd, 0, 0, 0x100])
                buf = "A" * 4
                yield ('write(fd, "AAAA", 4)', "write", [fd, buf, len(buf)])
                self.skipped_syscall.add("writev")
                self.skipped_syscall.add("pwrite64")
                self.skipped_syscall.add("pwritev")
                self.skipped_syscall.add("pwritev2")
                self.skipped_syscall.add("process_vm_writev")
                yield ("fdatasync(fd)", "fdatasync", [fd])
                yield ("fsync(fd)", "fsync", [fd])
                yield ("syncfs(fd)", "syncfs", [fd])
                self.skipped_syscall.add("sync")
                yield ("fadvise64(fd, 0, 0x100, POSIX_FADV_DONTNEED)", "fadvise64", [fd, 0, 0x100, 4])
                yield ("close(fd)", "close", [fd])

            yield "open -> flock -> lseek -> readahead -> poll -> read -> dup -> close_range"
            yield ('fd = open("/tmp/xxx", 0_RDONLY)', "open", [TMP_XXX, 0o0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                yield ("flock(fd, LOCK_SH|LOCK_NB)", "flock", [fd, 1 | 4])
                yield ("lseek(fd, SEEK_SET, 0)", "lseek", [fd, 0, 0])
                yield ("readahead(fd, 0, 0x1000)", "readahead", [fd, 0, 0x1000])
                fds = p32(fd) # fd
                fds += p16(0) # events
                fds += p16(0) # revents
                yield ("poll(&fds, 1, 0)", "poll", [fds, 1, 0])
                self.skipped_syscall.add("ppoll")
                buf = "\0" * 4
                yield ("read(fd, &buf, 4)", "read", [fd, buf, len(buf)])
                self.skipped_syscall.add("readv")
                self.skipped_syscall.add("pread64")
                self.skipped_syscall.add("preadv")
                self.skipped_syscall.add("preadv2")
                self.skipped_syscall.add("process_vm_readv")
                yield ("fd2 = dup(fd)", "dup", [fd])
                self.skipped_syscall.add("dup2")
                self.skipped_syscall.add("dup3")
                fd2 = ret_history[-1]
                yield ("close_range(fd, fd2, 0)", "close_range", [fd, fd2, 0])

            yield "open -> mmap -> remap_file_pages -> munmap -> close"
            yield ('fd = open("/tmp/xxx", 0_RDONLY)', "open", [TMP_XXX, 0o0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                size = get_pagesize()
                yield (
                    "addr = mmap(NULL, 0x1000, R--, MAP_ANONYMOUS|MAP_SHARED, -1, 0)",
                    "mmap", [0, size, 1, 0x20 | 0x1, fd, 0],
                )
                if u2i(ret_history[-1]) >= 0:
                    addr = ret_history[-1]
                    yield ("remap_file_pages(addr, 0x1000, 0, 0, 0)", "remap_file_pages", [addr, size, 0, 0, 0])
                    yield ("munmap(addr, 0x1000)", "munmap", [addr, size])
                yield ("close(fd)", "close", [fd])

            yield "chmod -> chown"
            yield ('chmod("/tmp/xxx", 0o664)', "chmod", [TMP_XXX, 0o664])
            self.skipped_syscall.add("fchmod")
            self.skipped_syscall.add("fchmodat")
            yield ('chown("/tmp/xxx", -1, -1)', "chown", [TMP_XXX, -1, -1])
            self.skipped_syscall.add("fchown")
            self.skipped_syscall.add("lchown")
            self.skipped_syscall.add("fchownat")

            yield "open -> pipe -> sendfile -> splice -> select -> vmsplice -> close_range -> close"
            yield ('fd = open("/tmp/xxx", 0_RDONLY)', "open", [TMP_XXX, 0o0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                pipefd_array = p32(0) * 2 # pipefd[2]
                yield ("pipe(&pipefd[])", "pipe", [pipefd_array])
                self.skipped_syscall.add("pipe2")
                if u2i(ret_history[-1]) >= 0:
                    pipefd0 = read_int32_from_memory(runtime.current_arch.sp)
                    pipefd1 = read_int32_from_memory(runtime.current_arch.sp + 4)
                    offset = p64(0)
                    yield ("sendfile(pipefd[1], fd, &offset, 4)", "sendfile", [pipefd1, fd, offset, 4])
                    off_in = p64(0)
                    yield ("splice(fd, &off_in, pipefd[1], NULL, 4, 0)", "splice", [fd, off_in, pipefd1, 0, 4, 0])
                    readfds = [0] * 1024
                    readfds[pipefd0] = 1
                    readfds = slicer("".join([str(x) for x in readfds]), 64)
                    readfds = b"".join([p64(int(x[::-1], 2)) for x in readfds])
                    nfds = pipefd0 + 1
                    yield ("select(nfds, readfds, NULL, NULL, NULL)", "select", [nfds, readfds, 0, 0, 0])
                    self.skipped_syscall.add("pselect6")
                    iov = p64(runtime.current_arch.sp + 0x10) # iov_base
                    iov += p64(0x100)                 # iov_len
                    yield ("vmsplice(pipefd[0], &iov, 1, 0)", "vmsplice", [pipefd0, iov, 1, 0])
                    yield ("close_range(pipefd[0], pipefd[1], 0)", "close_range", [pipefd0, pipefd1, 0])
                yield ("close(fd)", "close", [fd])

            yield "pipe -> pipe -> tee -> close_range"
            pipefd_array = p32(0) * 2 # pipefd[2]
            yield ("pipe(&pipefd[])", "pipe", [pipefd_array])
            pipefd0 = read_int32_from_memory(runtime.current_arch.sp)
            _pipefd1 = read_int32_from_memory(runtime.current_arch.sp + 4)
            yield ("pipe(&pipefd[])", "pipe", [pipefd_array])
            _pipefd2 = read_int32_from_memory(runtime.current_arch.sp)
            pipefd3 = read_int32_from_memory(runtime.current_arch.sp + 4)
            yield ("tee(pipefd[0], pipefd[3], 0", "tee", [pipefd0, pipefd3])
            yield ("close_range(pipefd[0], pipefd[3], 0)", "close_range", [pipefd0, pipefd3, 0])

            yield "mknod -> unlink"
            TMP_PIPE = "/tmp/pipe\0"
            yield ('mknod("/tmp/pipe", S_IFIFO|0644, 0)', "mknod", [TMP_PIPE, 0o10000 | 0o644, 0])
            self.skipped_syscall.add("mknodat")
            if u2i(ret_history[-1]) >= 0:
                yield ('unlink("/tmp/pipe")', "unlink", [TMP_PIPE])

            yield "open -> sync_file_range -> copy_file_range -> close -> unlink -> close"
            TMP_XXX2 = "/tmp/xxx2\0"
            yield ('fd_in = open("/tmp/xxx", 0_RDONLY)', "open", [TMP_XXX, 0o0])
            if u2i(ret_history[-1]) >= 0:
                fd_in = ret_history[-1]
                yield ('fd_out = open("/tmp/xxx2", 0_WRONLY|O_CREAT, 0666)', "open", [TMP_XXX2, 0o1 | 0o100, 0o666])
                if u2i(ret_history[-1]) >= 0:
                    fd_out = ret_history[-1]
                    yield (
                        "sync_file_range(fd_out, 0, 4, SYNC_FILE_RANGE_WAIT_AFTER)",
                        "sync_file_range", [fd_out, 0, 4, 4],
                    )
                    yield (
                        "copy_file_range(fd_in, 0, fd_out, 0, 4, 0)",
                        "copy_file_range", [fd_in, 0, fd_out, 0, 4, 0],
                    )
                    yield ("close(fd_out)", "close", [fd_out])
                    yield ('unlink("/tmp/xxx2")', "unlink", [TMP_XXX2])
                yield ("close(fd_in)", "close", [fd_in])

            yield "access -> utime -> stat -> statx -> truncate"
            yield ('access("/tmp/xxx", F_OK)', "access", [TMP_XXX, 0])
            self.skipped_syscall.add("faccessat")
            self.skipped_syscall.add("faccessat2")
            if u2i(ret_history[-1]) >= 0:
                yield ('utime("/tmp/xxx", NULL)', "utime", [TMP_XXX, 0])
                self.skipped_syscall.add("utimes")
                self.skipped_syscall.add("futimesat")
                self.skipped_syscall.add("utimensat")
                buf = p64(0)      # st_dev
                buf += p64(0)     # st_ino
                buf += p64(0)     # st_nlink
                buf += p32(0)     # st_mode
                buf += p32(0)     # st_uid
                buf += p32(0)     # st_gid
                buf += p32(0)     # __pad0
                buf += p64(0)     # st_rdev
                buf += p64(0)     # st_size
                buf += p64(0)     # st_blksize
                buf += p64(0)     # st_blocks
                buf += p64(0)     # st_atim.tv_sec
                buf += p64(0)     # st_atim.tv_nsec
                buf += p64(0)     # st_mtim.tv_sec
                buf += p64(0)     # st_mtim.tv_nsec
                buf += p64(0)     # st_ctim.tv_sec
                buf += p64(0)     # st_ctim.tv_nsec
                buf += p64(0) * 3 # __glibc_reserved[3]
                yield ('stat("/tmp/xxx", &buf)', "stat", [TMP_XXX, buf])
                self.skipped_syscall.add("fstat")
                self.skipped_syscall.add("lstat")
                self.skipped_syscall.add("newfstatat")
                statxbuf = p32(0)  # stx_mask
                statxbuf += p32(0) # stx_blksize
                statxbuf += p64(0) # stx_attributes
                statxbuf += p32(0) # stx_nlink
                statxbuf += p32(0) # stx_uid
                statxbuf += p32(0) # stx_gid
                statxbuf += p16(0) # stx_mode
                statxbuf += p16(0) # padding
                statxbuf += p64(0) # stx_ino
                statxbuf += p64(0) # stx_size
                statxbuf += p64(0) # stx_blocks
                statxbuf += p64(0) # stx_attributes_mask
                statxbuf += p64(0) # stx_atime.tv_sec
                statxbuf += p32(0) # stx_atime.tv_nsec
                statxbuf += p32(0) # stx_atime.padding
                statxbuf += p64(0) # stx_btime.tv_sec
                statxbuf += p32(0) # stx_btime.tv_nsec
                statxbuf += p32(0) # stx_btime.padding
                statxbuf += p64(0) # stx_ctime.tv_sec
                statxbuf += p32(0) # stx_ctime.tv_nsec
                statxbuf += p32(0) # stx_ctime.padding
                statxbuf += p64(0) # stx_mtime.tv_sec
                statxbuf += p32(0) # stx_mtime.tv_nsec
                statxbuf += p32(0) # stx_mtime.padding
                statxbuf += p32(0) # stx_rdev_major
                statxbuf += p32(0) # stx_rdev_minor
                statxbuf += p32(0) # stx_dev_major
                statxbuf += p32(0) # stx_dev_minor
                statxbuf += p64(0) # stx_mnt_id
                statxbuf += p32(0) # stx_dio_mem_align
                statxbuf += p32(0) # stx_dio_offset_align
                yield ('statx(0, "/tmp/xxx", 0, 0, &statxbuf)', "statx", [0, TMP_XXX, 0, 0, statxbuf])
                yield ('truncate("/tmp/xxx", 10)', "truncate", [TMP_XXX, 10])
                self.skipped_syscall.add("ftruncate")

            yield "access -> setxattr -> getxattr -> listxattr -> removexattr"
            yield ('access("/tmp/xxx", F_OK)', "access", [TMP_XXX, 0])
            if u2i(ret_history[-1]) >= 0:
                buf = "A" * 0xff + "\0"
                userx = "user.x\0"
                yield (
                    'setxattr("/tmp/xxx", "user.x", &buf, sizeof(buf), 0)',
                    "setxattr", [TMP_XXX, userx, buf, len(buf), 0],
                )
                self.skipped_syscall.add("lsetxattr")
                self.skipped_syscall.add("fsetxattr")
                if u2i(ret_history[-1]) >= 0:
                    buf= "\0" * 0x100
                    yield (
                        'getxattr("/tmp/xxx", "user.x", &buf, sizeof(buf))',
                        "getxattr", [TMP_XXX, userx, buf, len(buf)],
                    )
                    self.skipped_syscall.add("lgetxattr")
                    self.skipped_syscall.add("fgetxattr")
                    buf = "\0" * 0x100
                    yield ('listxattr("/tmp/xxx", &buf, sizeof(buf))', "listxattr", [TMP_XXX, buf, len(buf)])
                    self.skipped_syscall.add("llistxattr")
                    self.skipped_syscall.add("flistxattr")
                    yield ('removexattr("/tmp/xxx", "user.x")', "removexattr", [TMP_XXX, userx])
                    self.skipped_syscall.add("lremovexattr")
                    self.skipped_syscall.add("fremovexattr")

            yield "link -> unlink"
            TMP_XXX3 = "/tmp/xxx3\0"
            yield ('link("/tmp/xxx", "/tmp/xxx3")', "link", [TMP_XXX, TMP_XXX3])
            self.skipped_syscall.add("linkat")
            if u2i(ret_history[-1]) >= 0:
                yield ('unlink("/tmp/xxx3")', "unlink", [TMP_XXX3])
                self.skipped_syscall.add("unlinkat")

            yield "symlink -> readlink -> rename -> unlink"
            TMP_XXX4 = "/tmp/xxx4\0"
            yield ('symlink("/tmp/xxx", "/tmp/xxx4")', "symlink", [TMP_XXX, TMP_XXX4])
            self.skipped_syscall.add("symlinkat")
            if u2i(ret_history[-1]) >= 0:
                buf = "\0" * 0x100
                yield ('readlink("/tmp/xxx4", &buf, sizeof(buf))', "readlink", [TMP_XXX4, buf, len(buf)])
                self.skipped_syscall.add("readlinkat")
                TMP_XXX5 = "/tmp/xxx5\0"
                yield ('rename("/tmp/xxx4", "/tmp/xxx5")', "rename", [TMP_XXX4, TMP_XXX5])
                self.skipped_syscall.add("renameat")
                self.skipped_syscall.add("renameat2")
                if u2i(ret_history[-1]) >= 0:
                    yield ('unlink("/tmp/xxx5")', "unlink", [TMP_XXX5])
                    self.skipped_syscall.add("unlinkat")

            yield "inotify_init1 -> inotify_add_watch -> inotify_rm_watch -> close"
            yield ("fd = inotify_init1(0)", "inotify_init1", [0])
            self.skipped_syscall.add("inotify_init")
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                yield (
                    'wd = inotify_add_watch(fd, "/tmp/xxx", IN_MOVE_SELF)',
                    "inotify_add_watch", [fd, TMP_XXX, 0x800],
                )
                if u2i(ret_history[-1]) >= 0:
                    wd = ret_history[-1]
                    yield ("inotify_rm_watch(fd, wd)", "inotify_rm_watch", [fd, wd])
                yield ("close(fd)", "close", [fd])

            yield "open -> io_setup -> io_submit -> io_getevents -> close -> io_destroy"
            yield ('fd = open("/tmp/xxx", 0_RDONLY)', "open", [TMP_XXX, 0o0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                ctx_idp = p64(0)
                yield ("io_setup(1, &ctx_idp)", "io_setup", [1, ctx_idp])
                ctx_id = read_int_from_memory(runtime.current_arch.sp)
                iocb = p64(0)                       # aio_data
                iocb += p32(0)                      # aio_key
                iocb += p32(0)                      # aio_rw_flags
                iocb += p16(0)                      # aio_lio_opcode: IOCB_CMD_PREAD
                iocb += p16(0)                      # aio_reqprio
                iocb += p32(fd)                     # aio_fildes
                iocb += p64(runtime.current_arch.sp + 0x70) # aio_buf
                iocb += p64(0x100)                  # aio_nbytes
                iocb += p64(0)                      # aio_offset
                iocb += p64(0)                      # aio_reserved2
                iocb += p32(0)                      # aio_flags
                iocb += p32(0)                      # aio_resfd
                iocb += b"\0" * 0x100               # data buffer <-- aio_buf
                iocbp = p64(runtime.current_arch.sp + 0x30) # iocb
                iocbp += p64(0) * 5                 # padding
                iocbp += iocb
                yield ("io_submit(ctx_id, 1, &iocbp)", "io_submit", [ctx_id, 1, iocbp])
                events = p64(0)  # data
                events += p64(0) # obj
                events += p64(0) # res
                events += p64(0) # res2
                timeout = p64(0)  # tv_sec
                timeout += p64(0) # tv_nsec
                yield (
                    "io_getevents(ctx_id, 1, 1, &events, &timeout)",
                    "io_getevents", [ctx_id, 1, 1, events, timeout],
                )
                self.tested_syscall.add("io_pgetevents")
                yield ("clode(fd)", "close", [fd])
                yield ("io_destroy(ctx_id)", "io_destroy", [ctx_id])

            yield "io_uring_setup -> mmap -> io_uring_enter -> io_uring_register -> munmap"
            params = p32(0)      # sq_entries
            params += p32(0)     # cq_entries
            params += p32(0)     # flags
            params += p32(0)     # sq_thread_cpu
            params += p32(0)     # sq_thread_idle
            params += p32(0)     # features
            params += p32(0)     # wq_fd
            params += p32(0) * 3 # resv[3]
            params += p32(0)     # sq_off.head
            params += p32(0)     # sq_off.tail
            params += p32(0)     # sq_off.ring_mask
            params += p32(0)     # sq_off.ring_entries
            params += p32(0)     # sq_off.flags
            params += p32(0)     # sq_off.dropped
            params += p32(0)     # sq_off.array
            params += p32(0) * 3 # sq_off.resv[3]
            params += p32(0)     # cq_off.head
            params += p32(0)     # cq_off.tail
            params += p32(0)     # cq_off.ring_mask
            params += p32(0)     # cq_off.ring_entries
            params += p32(0)     # cq_off.overflow
            params += p32(0)     # cq_off.cqes
            params += p32(0)     # cq_off.flags
            params += p32(0) * 3 # cq_off.resv[3]
            yield ("ring_fd = io_uring_setup(1, &params)", "io_uring_setup", [1, params])
            params = slice_unpack(read_memory(runtime.current_arch.sp, len(params)), 4)
            if u2i(ret_history[-1]) >= 0 and params[5] & 1: # IORING_FEAT_SINGLE_MMAP (available linux v5.4~)
                ring_fd = ret_history[-1]
                sring_sz = params[16] + params[0] * 4    # sq_off.array + sq_entries * sizeof(uint)
                cring_sz = params[25] + params[1] * 0x10 # cq_off.cqes + cq_entries * sizeof(struct io_uring_cqe)
                sring_sz = max(sring_sz, cring_sz)
                yield (
                    "mmap(0, sring_sz, RW-, MAP_SHARED|MAP_POPULATE, ring_fd, IORING_OFF_SQ_RING)",
                    "mmap", [0, sring_sz, 3, 0x1 | 0x8000, ring_fd, 0],
                )
                if u2i(ret_history[-1]) >= 0:
                    sq_ptr = ret_history[-1]
                    yield (
                        "io_uring_enter(ring_fd, 0, 0, 0, NULL, 8)",
                        "io_uring_enter", [ring_fd, 0, 0, 0, 0, 8],
                    )
                    arg = p32(0)
                    yield (
                        "io_uring_register(ring_fd, IORING_REGISTER_FILES, &arg, 1)",
                        "io_uring_register", [ring_fd, 2, arg, 1],
                    )
                    yield (
                        "io_uring_register(ring_fd, IORING_UNREGISTER_FILES, NULL, 0)",
                        "io_uring_register", [ring_fd, 3, 0, 0],
                    )
                    yield ("munmap(sq_ptr, sring_sz)", "munmap", [sq_ptr, sring_sz])
                yield ("close(ring_fd)", "close", [ring_fd])

            yield "unshare"
            yield ("unshare(CLONE_FS|CLONE_FILES)", "unshare", [0x200 | 0x400])

            yield "name_to_handle_at -> unlink"
            handle = p32(0x80)     # handle_bytes: MAX_HANDLE_SZ
            handle += p32(0)       # handle_type
            handle += b"\0" * 0x80 # f_handle
            mntid = p32(0)
            yield (
                'name_to_handle_at(0, "/tmp/xxx", &handle, &mntid, 0)',
                "name_to_handle_at", [0, TMP_XXX, handle, mntid, 0],
            )
            yield ('unlink("/tmp/xxx")', "unlink", [TMP_XXX])

            yield "mkdir -> open_tree -> close -> chdir -> rmdir"
            TMP_YYY = "/tmp/yyy\0"
            yield ('mkdir("/tmp/yyy", 0777)', "mkdir", [TMP_YYY, 0o777])
            self.tested_syscall.add("mkdirat")
            if u2i(ret_history[-1]) >= 0:
                yield ('fd = open_tree(-1, "/tmp/yyy", 0)', "open_tree", [-1, TMP_YYY, 0])
                if u2i(ret_history[-1]) >= 0:
                    fd = ret_history[-1]
                    yield ("close(fd)", "close", [fd])
                yield ('chdir("/tmp/yyy")', "chdir", [TMP_YYY])
                self.skipped_syscall.add("fchdir")
                yield ('chdir("..")', "chdir", ["..\0"])
                yield ('rmdir("/tmp/yyy")', "rmdir", [TMP_YYY])

            yield "statfs"
            buf = p64(0)      # f_type
            buf += p64(0)     # f_bsize
            buf += p64(0)     # f_blocks
            buf += p64(0)     # f_bfree
            buf += p64(0)     # f_bavail
            buf += p64(0)     # f_files
            buf += p64(0)     # f_ffree
            buf += p64(0)     # f_fsid
            buf += p64(0)     # f_namelen
            buf += p64(0)     # f_frsize
            buf += p64(0)     # f_flags
            buf += p64(0) * 4 # f_spare[4]
            yield ('statfs("/", &buf)', "statfs", ["/\0", buf])
            self.skipped_syscall.add("fstatfs")
            self.skipped_syscall.add("ustat")

            yield "open -> getdents -> fcntl -> close"
            yield ('fd = open("/", 0_RDONLY)', "open", ["/\0", 0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                buf = "\0" * 0x200
                yield ("getdents(fd, &buf, sizeof(buf))", "getdents", [fd, buf, len(buf)])
                self.skipped_syscall.add("getdents64")
                yield ("fcntl(fd, F_GETFD)", "fcntl", [fd, 1])
                yield ("fcntl(fd, F_GETFL)", "fcntl", [fd, 3])
                flock = "\0" * 0x200
                yield ("fcntl(fd, F_GETLK, &flock)", "fcntl", [fd, 5, flock])
                yield ("fcntl(fd, F_OFD_GETLK, &flock)", "fcntl", [fd, 36, flock])
                yield ("close(fd)", "close", [fd])

            yield "invalid socket -> close"
            yield ("socket(22, SOCK_STREAM, 0)", "socket", [22, 1, 0])

            yield "socket AF_INET/TCP -> bind -> listen -> setsockopt -> getsockopt -> close"
            yield ("fd = socket(AF_INET, SOCK_STREAM, 0)", "socket", [2, 1, 0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                import socket
                sockaddr = p16(socket.AF_INET)          # sin_len, sin_family
                sockaddr += p16(socket.htons(13337))    # sin_port
                sockaddr += socket.inet_aton("0.0.0.0") # sin_addr.s_addr
                sockaddr += b"\0" * 8                   # sin_zero[8]
                yield ("bind(fd, &sockaddr, sizeof(sockaddr))", "bind", [fd, sockaddr, len(sockaddr)])
                yield ("listen(fd, 16)", "listen", [fd, 16])
                opt = p32(0)
                yield (
                    "setsockopt(fd, SOL_SOCKET, SO_DEBUG, &opt, sizeof(opt))",
                    "setsockopt", [fd, 1, 1, opt, len(opt)],
                )
                optlen = p32(len(opt))
                yield ("getsockopt(fd, SOL_SOCKET, SO_DEBUG, &opt, &optlen)", "getsockopt", [fd, 1, 1, opt, optlen])
                yield ("close(fd)", "close", [fd])

            yield "socket AF_INET/UDP -> connect -> getsockname -> getpeername -> close"
            yield ("fd = socket(AF_INET, SOCK_DGRAM , 0)", "socket", [2, 2, 0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                import socket
                sockaddr = p16(socket.AF_INET)          # sin_len, sin_family
                sockaddr += p16(socket.htons(13337))    # sin_port
                sockaddr += socket.inet_aton("0.0.0.0") # sin_addr.s_addr
                sockaddr += b"\0" * 8                   # sin_zero[8]
                yield ("connect(fd, &sockaddr, sizeof(sockaddr))", "connect", [fd, sockaddr, len(sockaddr)])
                sockaddr = p16(0)     # sin_len, sin_family
                sockaddr += p16(0)    # sin_port
                sockaddr += p32(0)    # sin_addr.s_addr
                sockaddr += b"\0" * 8 # sin_zero[8]
                addr_len = p64(len(sockaddr))
                yield ("getsockname(fd, &sockaddr, &addrlen)", "getsockname", [fd, sockaddr, addr_len])
                yield ("getpeername(fd, &sockaddr, &addrlen)", "getpeername", [fd, sockaddr, addr_len])
                yield ("close(fd)", "close", [fd])

            yield "socketpair AF_UNIX -> sendto -> recvfrom -> sendmsg -> recvmsg -> shutdown -> close"
            sv_array = p32(0) * 2 # sv[2]
            yield ("socketpair(AF_UNIX, SOCK_STREAM, 0, &sv[])", "socketpair", [1, 1, 0, sv_array])
            if u2i(ret_history[-1]) >= 0:
                sv0 = read_int32_from_memory(runtime.current_arch.sp)
                sv1 = read_int32_from_memory(runtime.current_arch.sp + 4)
                buf = "A" * 4
                yield ('sendto(sv[0], "AAAA", 4, 0, NULL, 0)', "sendto", [sv0, buf, len(buf), 0, 0, 0])
                buf = "\0" * 4
                yield ("recvfrom(sv[1], buf, 4, 0, NULL, NULL)", "recvfrom", [sv1, buf, len(buf), 0, 0, 0])
                msg = p64(0)                       # msg_name
                msg += p64(0)                      # msg_melen
                msg += p64(runtime.current_arch.sp + 0x40) # msg_iov
                msg += p64(1)                      # msg_iov_len
                msg += p64(0)                      # msg_control
                msg += p64(0)                      # msg_controllen
                msg += p64(0)                      # msg_flags
                msg += p64(0)                      # padding
                msg += p64(runtime.current_arch.sp + 0x50) # iov_base
                msg += p64(4)                      # iov_len
                msg += b"AAAA"                     # data
                yield ("sendmsg(sv[0], &msg, 0)", "sendmsg", [sv0, msg, 0])
                self.skipped_syscall.add("sendmmsg")
                yield ("recvmsg(sv[1], &msg, 0)", "sendmsg", [sv1, msg, 0])
                self.skipped_syscall.add("recvmmsg")
                yield ("shutdown(sv[0], SHUT_RDWR)", "shutdown", [sv0, 2])
                yield ("close(sv[0])", "close", [sv0])
                yield ("close(sv[1])", "close", [sv1])

            yield "memfd_create -> close"
            yield ('fd = memfd_create("test", 0)', "memfd_create", ["test\0", 0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                yield ("close(fd)", "close", [fd])

            yield "add_key -> request_key -> keyctl"
            user = "user\0"
            tkey = "test:testkey\0"
            payload = "payload\0"
            yield ('add_key("user", "test:testkey", "payload", plen, KEY_SPEC_PROCESS_KEYRING)',
                   "add_key", [user, tkey, payload, len(payload) - 1, 0xffff_fffe])
            callout_info = "\0" * 0x100
            yield ('request_key("user", "test:testkey", &callout_info, KEY_SPEC_PROCESS_KEYRING)',
                   "request_key", [user, tkey, callout_info, 0xffff_fffe])
            if u2i(ret_history[-1]) >= 0:
                key_serial = ret_history[-1]
                yield ("keyctl(KEYCTL_REVOKE, key_serial)", "keyctl", [3, key_serial])

            yield "invalid add_key"
            tkey = "A" * 0x100
            yield ('add_key("user", "AAAAAAAA...", NULL, 0, KEY_SPEC_PROCESS_KEYRING)',
                   "add_key", [user, tkey, 0, 0, 0xffff_fffe])

            yield "open /dev/ptmx -> close"
            yield ('fd = open("/dev/ptmx", O_RDWR|O_NOCTTY)', "open", ["/dev/ptmx\0", 0o2 | 0o400])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                yield ("close(fd)", "close", [fd])

            yield "open /proc/self/stat -> close"
            yield ('fd = open("/proc/self/stat", O_RDONLY)', "open", ["/proc/self/stat\0", 0])
            if u2i(ret_history[-1]) >= 0:
                fd = ret_history[-1]
                yield ("close(fd)", "close", [fd])

            self.skipped_syscall.add("restart_syscall")   # difficult to implement generically
            self.skipped_syscall.add("pause")             # difficult to implement generically
            self.skipped_syscall.add("rt_sigreturn")      # difficult to implement generically
            self.skipped_syscall.add("rt_sigsuspend")     # difficult to implement generically
            self.skipped_syscall.add("clone")             # difficult to implement generically
            self.skipped_syscall.add("clone3")            # difficult to implement generically
            self.skipped_syscall.add("execve")            # difficult to implement generically
            self.skipped_syscall.add("execveat")          # difficult to implement generically
            self.skipped_syscall.add("fork")              # difficult to implement generically
            self.skipped_syscall.add("vfork")             # difficult to implement generically
            self.skipped_syscall.add("exit")              # difficult to implement generically
            self.skipped_syscall.add("exit_group")        # difficult to implement generically
            self.skipped_syscall.add("wait4")             # difficult to implement generically
            self.skipped_syscall.add("waitid")            # difficult to implement generically
            self.skipped_syscall.add("accept")            # difficult to implement generically
            self.skipped_syscall.add("accept4")           # difficult to implement generically
            self.skipped_syscall.add("setsid")            # difficult to implement generically
            self.skipped_syscall.add("io_cancel")         # difficult to implement generically
            self.skipped_syscall.add("seccomp")           # affect subsequent system calls
            self.skipped_syscall.add("rseq")              # affect subsequent system calls
            self.skipped_syscall.add("pkey_alloc")        # maybe unsupported by qemu HW
            self.skipped_syscall.add("pkey_mprotect")     # maybe unsupported by qemu HW
            self.skipped_syscall.add("pkey_free")         # maybe unsupported by qemu HW
            self.skipped_syscall.add("modify_ldt")        # supported i386 only
            self.skipped_syscall.add("lookup_dcookie")    # deprecated
            self.skipped_syscall.add("quotactl")          # supported ufs only
            self.skipped_syscall.add("setgroups")         # need CAP_SETGID
            self.skipped_syscall.add("chroot")            # need CAP_SYS_CHROOT
            self.skipped_syscall.add("acct")              # need CAP_SYS_PACCT
            self.skipped_syscall.add("ptrace")            # need CAP_SYS_PTRACE
            self.skipped_syscall.add("iopl")              # need CAP_SYS_RAWIO
            self.skipped_syscall.add("ioperm")            # need CAP_SYS_RAWIO
            self.skipped_syscall.add("vhangup")           # need CAP_SYS_TTY_CONFIG
            self.skipped_syscall.add("reboot")            # need CAP_SYS_BOOT
            self.skipped_syscall.add("kexec_load")        # need CAP_SYS_BOOT
            self.skipped_syscall.add("kexec_file_load")   # need CAP_SYS_BOOT
            self.skipped_syscall.add("init_module")       # need CAP_SYS_MODULE
            self.skipped_syscall.add("finit_module")      # need CAP_SYS_MODULE
            self.skipped_syscall.add("delete_module")     # need CAP_SYS_MODULE
            self.skipped_syscall.add("syslog")            # need CAP_SYS_ADMIN
            self.skipped_syscall.add("pivot_root")        # need CAP_SYS_ADMIN
            self.skipped_syscall.add("mount")             # need CAP_SYS_ADMIN
            self.skipped_syscall.add("umount2")           # need CAP_SYS_ADMIN
            self.skipped_syscall.add("swapon")            # need CAP_SYS_ADMIN
            self.skipped_syscall.add("swapoff")           # need CAP_SYS_ADMIN
            self.skipped_syscall.add("sethostname")       # need CAP_SYS_ADMIN
            self.skipped_syscall.add("setdomainname")     # need CAP_SYS_ADMIN
            self.skipped_syscall.add("setns")             # need CAP_SYS_ADMIN
            self.skipped_syscall.add("move_mount")        # need CAP_SYS_ADMIN
            self.skipped_syscall.add("fsopen")            # need CAP_SYS_ADMIN
            self.skipped_syscall.add("fspick")            # need CAP_SYS_ADMIN
            self.skipped_syscall.add("fsconfig")          # need CAP_SYS_ADMIN
            self.skipped_syscall.add("fsmount")           # need CAP_SYS_ADMIN
            self.skipped_syscall.add("fanotify_init")     # need CAP_SYS_ADMIN
            self.skipped_syscall.add("fanotify_mark")     # need CAP_SYS_ADMIN
            self.skipped_syscall.add("clock_settime")     # need CAP_SYS_TIME
            self.skipped_syscall.add("settimeofday")      # need CAP_SYS_TIME
            self.skipped_syscall.add("open_by_handle_at") # need CAP_DAC_READ_SEARCH
            return None

        self.scheduled_syscall = set()
        self.tested_syscall = set()
        self.skipped_syscall = set()

        ret_history = []
        for testcase in gen_testcase():
            if isinstance(testcase, str):
                gef_print(titlify(testcase, msg_color="bold"))
                self.scheduled_syscall |= set(testcase.split(" -> "))
                continue

            desc, syscall_name, args = testcase
            gef_print(titlify("{:s};".format(desc)))
            self.setup_syscall(syscall_name, args)
            for bp in breakpoints:
                bp.enabled = True
            gdb.execute("continue")

            # here, stop at hw breakpoint
            ret = get_register(runtime.current_arch.return_register)
            gef_print("ret: {:#x}".format(ret))
            if u2i(ret) < 0:
                gef_print(Color.colorify("WARNING: r < 0", "bold red underline"))
                gdb.execute("errno {:#x}".format(ret))
            ret_history.append(ret)

            for bp in breakpoints:
                bp.enabled = False

        self.dump_untested_syscall()

        self.setup_syscall("exit", [0])
        return

    def cleanup(self, hwbp, breakpoints):
        # clean up
        from gef.commands.debugging.context import ContextCommand
        hwbp.delete()
        for bp in breakpoints:
            bp.delete()
        KmallocTracerCommand.clear_disabled_breakpoints("KmallocRetBreakpoint", force=True)
        ContextCommand.unhide_context()
        info("Exiting `sleep` process... (Please issue Ctrl+C)")
        gdb.execute("continue")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_64",))
    @only_if_in_kernel
    @only_if_kvm_disabled
    @only_if_smp_disabled
    def do_invoke(self, args):
        from gef.commands.debugging.context import ContextCommand
        info("Wait for memory scan")

        kversion = Kernel.kernel_version()
        if kversion < "3.0":
            err("Unsupported before v3.0")
            return

        allocator = Kernel.get_slab_type()
        if allocator == "Unknown":
            err("Unsupported: Unknown allocator")
            return
        if allocator != "SLUB":
            warn("Unsupported viewing detailed information for SLAB, SLOB, SLUB_TINY")
            # fall through

        # initialize
        if not hasattr(self, "initialized"):
            ret = KmallocTracerCommand.initialize(allocator, args.verbose)
            if ret is False:
                err("Failed to initialize")
                return
            self.initialized = True
            self.extra_info = ret # allow None
        else:
            if args.verbose and self.extra_info:
                info("offsetof({:s}, slab_cache): {:#x}".format(Kernel.slab_page_str(), self.extra_info.page_offset_slab_cache))
                info("offsetof(kmem_cache, name): {:#x}".format(self.extra_info.kmem_cache_offset_name))
                info("offsetof(kmem_cache, size): {:#x}".format(self.extra_info.kmem_cache_offset_size))

        # get syscall table
        syscall_table = Syscall.get_syscall_table()
        if syscall_table is None:
            err("Could not find the syscall table")
            return
        self.syscall_table = {e.name: n for n, e in syscall_table.nr_table.items() if n < 0x1000}
        self.syscall_table_view_ret = gdb.execute("syscall-table-view --no-pager --quiet", to_string=True)

        # get task
        res = gdb.execute("ktask --print-regs --no-pager --quiet --filter sleep", to_string=True)
        r = re.findall(r"(?:^|\n)(0x\S+)", res)
        if not r:
            err("Could not find `sleep` process, unable to continue")
            info("Do `/bin/sleep 5` in the guest (use full path), then `{:s}` again".format(
                self._cmdline_,
            ))
            return
        if len(r) != 1:
            err("Multiple sleep processes are found, unable to continue")
            return
        target_task = int(r[0], 16)
        info("The task of `sleep`: {:#x}".format(target_task))

        # create option_info
        option_info = KmallocTracerCommand.create_option_info(args, target_task)

        # get rip for breakpoint
        # get rsp for checking process
        r1 = re.search(r"rip\s*: (0x\S+)", res)
        r2 = re.search(r"rsp\s*: (0x\S+)", res)
        if not r1 or not r2:
            err("Failed to get rip and rsp")
            return
        rip_of_sleep = int(r1.group(1), 16)
        rsp_of_sleep = int(r2.group(1), 16)
        info("The sleep's $rip: {:#x}, rsp: {:#x} (after return from nanosleep syscall)".format(
            rip_of_sleep, rsp_of_sleep,
        ))

        # set a hw breakpoints
        hwbp = KmallocAllocatedBy_UserlandHardwareBreakpoint(rip_of_sleep)

        # set kmalloc breakpoints (but disabled)
        breakpoints = KmallocTracerCommand.set_bp_to_kmalloc_kfree(option_info, self.extra_info)

        # wait to stop at userland `sleep` process
        ContextCommand.hide_context()
        info("Setup is complete. continuing...")
        gdb.execute("continue")

        # here, stop in userland `sleep` process
        if runtime.current_arch.sp != rsp_of_sleep:
            err("Stack pointer is different from expected. Unable to continue")
            self.cleanup(hwbp, breakpoints)
            return
        # rsp align
        gdb.execute("set $rsp = {:#x}".format(rsp_of_sleep & ~0xf))
        # For some reason, setting rsp can break rip. Here's a workaround for that.
        gdb.execute("set $rip = {:#x}".format(rip_of_sleep))

        # do test
        self.test_syscall(breakpoints)
        info("Syscall test is complete, cleaning up...")
        self.cleanup(hwbp, breakpoints)
        return


class KtraceBreakpoint(gdb.Breakpoint):
    """Create a breakpoint to print information for kernel functions."""

    def __init__(self, loc, sym, task_name_filter, task_addr_filter):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=True)
        self.loc = loc
        self.sym = sym
        self.task_name_filter = task_name_filter
        self.task_addr_filter = task_addr_filter
        return

    def stop(self):
        Cache.reset_gef_caches()

        # check task
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.task_name_filter and task_name not in self.task_name_filter:
            return False
        if self.task_addr_filter and task_addr not in self.task_addr_filter:
            return False

        # get args
        arg_key_color = Config.get_gef_setting("theme.registers_register_name")
        args = []
        nb_argument = 6 # guessed
        for i in range(nb_argument):
            try:
                key, value = runtime.current_arch.get_ith_parameter(i, in_func=True)
                value = AddressUtil.recursive_dereference_to_string(value)
            except Exception:
                break
            args.append("    {} = {}".format(Color.colorify(key, arg_key_color), value))

        # random id to distinguish between nested functions
        import random
        random_id = random.randint(1, 0xffff_ffff)

        # print
        task_prefix = Color.boldify("[task:{:#018x} {:16s}]".format(task_addr, task_name))
        gef_print("{:s} {:#x} <{:s}> ( // enter // random_id:{:#x}".format(
            task_prefix, self.loc, self.sym, random_id,
        ))
        for arg in args:
            gef_print(arg)
        gef_print(")")

        # set bp for return value
        try:
            KtraceRetBreakpoint(self.loc, self.sym, self.task_name_filter, self.task_addr_filter, random_id)
        except gdb.error:
            # The case is following (why?):
            #   Warning:
            #   Cannot insert breakpoint -440.
            #   Cannot access memory at address 0x0
            pass
        return False


class KtraceRetBreakpoint(gdb.FinishBreakpoint):
    """Create a breakpoint to print information for kernel functions."""

    def __init__(self, loc, sym, task_name_filter, task_addr_filter, random_id):
        super().__init__(gdb.newest_frame(), internal=True)
        self.loc = loc
        self.sym = sym
        self.task_name_filter = task_name_filter
        self.task_addr_filter = task_addr_filter
        self.random_id = random_id
        KernelTraceCommand.finish_breakpoints.append(self)
        return

    def stop(self):
        Cache.reset_gef_caches()

        # check task
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.task_name_filter and task_name not in self.task_name_filter:
            return False
        if self.task_addr_filter and task_addr not in self.task_addr_filter:
            return False

        # get return value
        arg_key_color = Config.get_gef_setting("theme.registers_register_name")
        # self.return_value unavailable since no type information. use current_arch.return register
        reg = runtime.current_arch.return_register
        value = AddressUtil.recursive_dereference_to_string(get_register(reg))
        msg = "    {} = {}".format(Color.colorify(reg, arg_key_color), value)

        # print
        task_prefix = Color.boldify("[task:{:#018x} {:16s}]".format(task_addr, task_name))
        gef_print("{:s} {:#x} <{:s}> ( // return // random_id:{:#x}".format(
            task_prefix, self.loc, self.sym, self.random_id,
        ))
        gef_print(msg)
        gef_print(")")
        return False

    def out_of_scope(self): # noqa
        if self.enabled:
            self.enabled = False

        # print
        task_addr, task_name = KmallocTracerCommand.get_task()
        task_prefix = Color.boldify("[task:{:#018x} {:16s}]".format(task_addr, task_name))
        warn("{:s} {:#x} <{:s}> (random_id{:#x}) has been disabled due to out of scope".format(
            task_prefix, self.loc, self.sym, self.random_id,
        ))
        return


@register_command
class KernelTraceCommand(GenericCommand):
    """Trace kernel functions and arguments."""

    _cmdline_ = "ktrace"
    _category_ = "06-i. Qemu-system/KGDB Cooperation - Linux Dynamic Inspection"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--task-name", action="append", default=[],
                        help="task name (from `ktask`) for filtering.")
    parser.add_argument("--task-addr", action="append", type=AddressUtil.parse_address, default=[],
                        help="task address for filtering.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[],
                        help="function include filter (REGEXP).")
    parser.add_argument("-e", "--exclude", action="append", type=re.compile, default=[],
                        help="function exclude filter (REGEXP).")
    parser.add_argument("-c", "--commit", action="store_true", help="actually perform ktrace.")
    parser.add_argument("-q", "--quiet", action="store_true", help="skip tqdm and displaying function name.")
    _syntax_ = parser.format_help()

    _note_ = [
        "If you set breakpoints in some commonly called functions, it became too slow to be useful.",
        "Use filtering options to reduce the number of functions targeted by breakpoints as much as possible.",
    ]
    _note_ = "\n".join(_note_)

    finish_breakpoints = []

    def is_valid_addr(self, addr):
        page_start = addr & get_pagesize_mask_low()

        if page_start in self.addr_range_ok_cache:
            return True
        if page_start in self.addr_range_ng_cache:
            return False

        if is_valid_addr(addr):
            self.addr_range_ok_cache.append(page_start)
            return True
        else:
            self.addr_range_ng_cache.append(page_start)
            return False

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel
    @only_if_kvm_disabled
    def do_invoke(self, args):
        info("Wait for memory scan")

        # check if text base is available
        text_base = Symbol.get_ksymaddr("_stext")
        if text_base is None:
            err("Failed to get kernel base (_stext)")
            return

        self.addr_range_ok_cache = []
        self.addr_range_ng_cache = []

        # list target functions
        res = gdb.execute("ksymaddr-remote --quiet --no-pager --type t", to_string=True)
        target_functions = []
        tqdm = GefUtil.get_tqdm(not args.quiet)
        for line in tqdm(res.splitlines(), leave=False):
            func_addr, _, func_name = line.split()
            func_addr = int(func_addr, 16)

            # user specified filtering
            if args.filter and not any(filt.search(func_name) for filt in args.filter):
                continue
            if args.exclude and any(filt.search(func_name) for filt in args.exclude):
                continue

            # lower address is percpu-relative.
            if func_addr < text_base:
                continue

            # The function with `init` attribute may no longer exist.
            if not self.is_valid_addr(func_addr):
                continue

            target_functions.append([func_addr, func_name])

        # check num of breakpoints
        info("Num of breakpoint targets: {:d}".format(len(target_functions)))
        if len(target_functions) > 1000:
            err("Too many breakpoints cause this to not work properly (>1000)")
            return

        if len(target_functions) > 100:
            warn("Too many breakpoints may cause this to not work properly (>100)")

        # debug print
        if not args.quiet:
            for func_addr, func_name in target_functions:
                info("{:#x} {:s}".format(func_addr, func_name))

        # not commit
        if not args.commit:
            warn('This dry run mode skips executing; add "--commit" to proceed')
            return

        # set break points
        info("Set breakpoints in all functions that match the specified criteria")
        breakpoints = []
        for func_addr, func_name in target_functions:
            bp = KtraceBreakpoint(func_addr, func_name, args.task_name, args.task_addr)
            breakpoints.append(bp)

        # Locking a thread can have disadvantages: such as making it impossible to enter commands
        # from the guest's terminal. Therefore, we decided not to disable it.

        # doit
        info("Setup is complete (set {:d} braekpoints). continuing...".format(len(breakpoints)))
        gdb.execute("continue")

        # clean up
        info("ktrace is complete, cleaning up...")
        for bp in breakpoints:
            bp.delete()
        while KernelTraceCommand.finish_breakpoints:
            bp = KernelTraceCommand.finish_breakpoints.pop()
            if bp.is_valid():
                bp.delete()
        return


class KuafWatchAllocBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at an allocator entry for kuaf-watch."""

    def __init__(self, loc, sym, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.watcher = watcher
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()
        # Capture the caller and execution context before the function can schedule.
        try:
            ret_addr = KmallocTracerCommand.get_return_address()
        except gdb.error:
            return False
        KuafWatchAllocRetBreakpoint(ret_addr, self.sym, ret_addr, self.watcher)
        return False



class KuafWatchAllocRetBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at an allocator return for kuaf-watch."""

    def __init__(self, loc, sym, caller_pc, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=True)
        self.sym = sym
        self.caller_pc = caller_pc
        self.watcher = watcher
        task_addr, task_name = KmallocTracerCommand.get_task()
        self.call_context = Kernel.get_call_context(task_addr)
        KmallocTracerCommand.clear_disabled_breakpoints("KuafWatchAllocRetBreakpoint", owner=self.watcher)
        return

    def stop(self):
        Cache.reset_gef_caches()
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.call_context != Kernel.get_call_context(task_addr, at_return=True):
            return False
        allocated = AddressUtil.parse_address(runtime.current_arch.return_register)
        self.enabled = False
        return self.watcher.handle_alloc(allocated, self.sym, self.caller_pc)



class KuafWatchFreeBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at kfree for kuaf-watch."""

    def __init__(self, loc, sym, index_of_addr_arg, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.index_of_addr_arg = index_of_addr_arg
        self.watcher = watcher
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()
        to_free = KmallocTracerCommand.get_ith_parameter(self.index_of_addr_arg)
        if to_free == 0:
            return False
        caller_pc = KmallocTracerCommand.get_return_address()
        return self.watcher.handle_free(to_free, self.sym, caller_pc)



class KuafWatchBulkFreeBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at kmem_cache_free_bulk for kuaf-watch."""

    def __init__(self, loc, sym, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.watcher = watcher
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()
        size = KmallocTracerCommand.get_ith_parameter(1)
        objects = KmallocTracerCommand.get_ith_parameter(2)
        if size == 0 or objects == 0:
            return False

        caller_pc = KmallocTracerCommand.get_return_address()
        stop = False
        ptrsize = runtime.current_arch.ptrsize
        try:
            # Keep remote reads bounded while still handling every object in the batch.
            for index in range(0, size, 256):
                count = min(size - index, 256)
                data = read_memory(objects + index * ptrsize, count * ptrsize)
                for to_free in slice_unpack(data, ptrsize):
                    if to_free == 0:
                        continue
                    # In object mode avoid the comparatively expensive slab lookup for
                    # unrelated entries. Cache mode intentionally resolves every entry.
                    if self.watcher.cache_name is None and to_free not in self.watcher.watched:
                        continue
                    stop |= self.watcher.handle_free(to_free, self.sym, caller_pc)
        except (gdb.error, OverflowError, ValueError):
            pass
        return stop



@register_command
class KuafWatchCommand(GenericCommand):
    """Track the alloc/free/reuse lifecycle of a slab object (or an entire cache) for UAF analysis."""

    _cmdline_ = "kuaf-watch"
    _category_ = "06-i. Qemu-system/KGDB Cooperation - Linux Dynamic Inspection"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", nargs="*", type=AddressUtil.parse_address,
                        help="the slab object address(es) (or interior pointer) to watch.")
    parser.add_argument("-c", "--cache", help="follow an entire slab cache by name instead of specific objects.")
    parser.add_argument("-s", "--stop-on-reuse", action="store_true", help="stop at the first reuse (re-allocation) event.")
    parser.add_argument("-t", "--backtrace", action="store_true", help="display a backtrace for each event.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffff888012345600                     # watch one object's alloc/free/reuse",
        "{0:s} 0xffff888012345600 0xffff888012345700  # watch several objects at once",
        "{0:s} --cache kmalloc-256                    # watch every object of a cache",
        "{0:s} 0xffff888012345600 -s                  # break at the first reuse",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Disable `-enable-kvm` option for qemu-system (#PF may occur).",
        "Append `tsc=unstable` option for kernel cmdline.",
        "This is a higher-level view built on the same allocator breakpoints as kmalloc-tracer.",
        "In --cache mode the slab cache of every alloc/free is resolved, which is slower than single-object mode.",
        "This command requires CONFIG_RANDSTRUCT=n.",
    ]
    _note_ = "\n".join(_note_)

    def resolve_offsets(self):
        self.offset_pid = None
        ret = gdb.execute("ktask --no-pager --meta", to_string=True)
        r = re.search(r"offsetof\(task_struct, pid\): (0x\S+)", ret)
        if r:
            self.offset_pid = int(r.group(1), 16)
        return

    def get_task_info(self):
        cpu = KernelPerCpu.get_cpu_index(gdb.selected_thread())
        task_addr, comm = KmallocTracerCommand.get_task()
        pid = None
        if task_addr and self.offset_pid is not None:
            pid = read_int32_from_memory(task_addr + self.offset_pid)
        return task_addr, comm, pid, cpu

    def lookup_cache(self, addr):
        ret = KmallocTracerCommand.virt2name_and_size(addr)
        if ret:
            return ret[0]
        return None

    def resolve_object(self, addr):
        """Resolve (object_base, cache_name, object_size, state) for a slab address, or None."""
        out = Color.remove_color(gdb.execute("slab-contains {:#x}".format(addr), to_string=True))
        m = re.search(r"^name: (\S+)\s+object_size: (\S+)", out, re.M)
        if not m:
            return None
        name, object_size = m.group(1), int(m.group(2), 0)
        m = re.search(r"^object_base: (0x\S+)", out, re.M)
        if not m:
            return None
        base = int(m.group(1), 16)
        m = re.search(r"^status: (freed|in-use)", out, re.M)
        state = None
        if m:
            if m.group(1) == "freed":
                state = "freed"
            else:
                state = "allocated"
        return base, name, object_size, state

    def emit_event(self, tag, addr, cache, caller_pc, api):
        _task_addr, _comm, pid, cpu = self.get_task_info()
        caller = Symbol.format(caller_pc, bracket="", missing="?" if caller_pc is None else "{:#x}".format(caller_pc))
        if tag == "FREE":
            theme = "theme.heap_chunk_address_freed"
        else:
            theme = "theme.heap_chunk_address_used"
        addr_s = Color.colorify_hex(addr, Config.get(theme))
        cache_s = Color.colorify(cache or "?", Config.get("theme.heap_chunk_label"))
        gef_print("[{:5s}] {:s}  cache={:s}".format(tag, addr_s, cache_s))
        if pid is None:
            pid_s = "?"
        else:
            pid_s = "{:d}".format(pid)
        gef_print("        caller={:s}  pid={:s} cpu={:s}  api={:s}".format(
            caller, pid_s, "?" if cpu is None else str(cpu), api,
        ))
        if self.backtrace:
            KmallocTracerCommand.print_backtrace(True)
        return

    def handle_alloc(self, allocated, sym, caller_pc):
        if self.cache_name is None:
            if allocated not in self.watched:
                return False
            cache = self.lookup_cache(allocated) or self.watched[allocated]
        else:
            cache = self.lookup_cache(allocated)
            if cache != self.cache_name:
                return False
        reuse = allocated in self.freed_slots
        self.freed_slots.discard(allocated)
        self.emit_event("ALLOC", allocated, cache, caller_pc, sym)
        return self.stop_on_reuse and reuse

    def handle_free(self, to_free, sym, caller_pc):
        if self.cache_name is None:
            if to_free not in self.watched:
                return False
            cache = self.watched[to_free]
        else:
            cache = self.lookup_cache(to_free)
            if cache != self.cache_name:
                return False
        self.freed_slots.add(to_free)
        self.emit_event("FREE", to_free, cache, caller_pc, sym)
        return False

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel
    @only_if_kvm_disabled
    def do_invoke(self, args):
        if args.cache is None and not args.address:
            err("Specify an ADDRESS or --cache CACHE")
            return

        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "3.0":
            err("Unsupported before v3.0")
            return

        allocator = Kernel.get_slab_type()
        if allocator not in ["SLUB", "SLUB_TINY", "SLAB"]:
            err("Unsupported: SLOB, Unknown allocator")
            return

        info("Wait for memory scan")
        self.resolve_offsets()
        self.stop_on_reuse = args.stop_on_reuse
        self.backtrace = args.backtrace
        self.watched = {}
        self.freed_slots = set()

        if args.cache is not None:
            self.cache_name = args.cache
            info("Watching cache: {:s}".format(Color.colorify(self.cache_name, Config.get("theme.heap_chunk_label"))))
        else:
            self.cache_name = None
            for address in args.address:
                resolved = self.resolve_object(address)
                if resolved is None:
                    err("{:#x} is not a slab object".format(address))
                    continue
                base, cache, object_size, state = resolved
                if base in self.watched:
                    # several interior pointers can designate the same object
                    continue
                self.watched[base] = cache
                if state == "freed":
                    self.freed_slots.add(base)
                gef_print("[{:5s}] {:s}  cache={:s}  object_size={:#x}  state={:s}".format(
                    "WATCH",
                    Color.colorify_hex(base, Config.get("theme.heap_chunk_address_used")),
                    Color.colorify(cache, Config.get("theme.heap_chunk_label")),
                    object_size, state or "unknown",
                ))
            if not self.watched:
                err("No slab object to watch")
                return

        try:
            # set breakpoints (reuse kmalloc-tracer's allocator symbol tables)
            kmalloc_syms, kfree_syms = KmallocTracerCommand.get_kmalloc_kfree_syms()
            # Dedicated caches (task_struct, cred, filp, ...) - the usual UAF targets - are
            # released with kmem_cache_free, not kfree, so track it as well (ptr is arg 1).
            kfree_syms = kfree_syms + [["kmem_cache_free", 1]]
            breakpoints = []
            for sym, _index_of_size_arg in kmalloc_syms:
                func_addr = Ksym.get_addr(sym)
                if func_addr:
                    gef_print(sym + ": ", end="")
                    breakpoints.append(KuafWatchAllocBreakpoint(func_addr, sym, self))
            for sym, index_of_addr_arg in kfree_syms:
                func_addr = Ksym.get_addr(sym)
                if func_addr:
                    gef_print(sym + ": ", end="")
                    breakpoints.append(KuafWatchFreeBreakpoint(func_addr, sym, index_of_addr_arg, self))
            bulk_free_sym = "kmem_cache_free_bulk"
            func_addr = Ksym.get_addr(bulk_free_sym)
            if func_addr:
                gef_print(bulk_free_sym + ": ", end="")
                breakpoints.append(KuafWatchBulkFreeBreakpoint(func_addr, bulk_free_sym, self))
            if not breakpoints:
                warn("No allocator hooks resolved; nothing will be observed")
                return
            for bp in breakpoints:
                bp.enabled = True

            info("Setup is complete. continuing...")
            gdb.execute("continue")

        finally:
            info("kuaf-watch is complete, cleaning up...")
            GefUtil.delete_breakpoints(self, report_pending=True)
        return



class KpageWatchAllocBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at the page allocator entry for kpage-watch."""

    def __init__(self, loc, sym, index_of_order_arg, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.index_of_order_arg = index_of_order_arg
        self.watcher = watcher
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()
        task_addr, task_name = KmallocTracerCommand.get_task()
        # the bulk allocator falls back to this one; its return records the page instead
        names = ["KpageWatchAllocRetBreakpoint", "KpageWatchAllocBulkRetBreakpoint"]
        if GefUtil.is_nested_call(self.watcher, names, task_addr):
            return False
        order = KmallocTracerCommand.get_ith_parameter(self.index_of_order_arg)
        caller_pc = KmallocTracerCommand.get_return_address()
        KpageWatchAllocRetBreakpoint(caller_pc, self.sym, order, caller_pc, task_addr, self.watcher)
        return False



class KpageWatchAllocRetBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at the page allocator return for kpage-watch."""

    def __init__(self, loc, sym, order, caller_pc, task_addr, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=True)
        self.sym = sym
        self.order = order
        self.caller_pc = caller_pc
        self.task_addr = task_addr
        self.watcher = watcher
        self.call_context = Kernel.get_call_context(task_addr)
        self.interrupt_context = Kernel.get_interrupt_context()
        KmallocTracerCommand.clear_disabled_breakpoints("KpageWatchAllocRetBreakpoint", owner=self.watcher)
        return

    def stop(self):
        Cache.reset_gef_caches()
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.call_context != Kernel.get_call_context(task_addr, at_return=True):
            return False
        self.enabled = False
        page = AddressUtil.parse_address(runtime.current_arch.return_register)
        return self.watcher.record("alloc", self.sym, page, order=self.order, caller_pc=self.caller_pc)



class KpageWatchAllocBulkBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at the bulk page allocator entry for kpage-watch."""

    def __init__(self, loc, sym, has_page_list, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.has_page_list = has_page_list
        self.watcher = watcher
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()
        task_addr, task_name = KmallocTracerCommand.get_task()
        # (gfp, preferred_nid, nodemask, int nr_pages, struct list_head *page_list (~v6.13), struct page **page_array)
        nr_pages = u2i(KmallocTracerCommand.get_ith_parameter(3), 32)
        if self.has_page_list:
            page_list = KmallocTracerCommand.get_ith_parameter(4)
        else:
            page_list = 0
        page_array = KmallocTracerCommand.get_ith_parameter(5 if self.has_page_list else 4)
        pages_at_entry = self.watcher.watched_pages_in_bulk(page_list, page_array, nr_pages)
        caller_pc = KmallocTracerCommand.get_return_address()
        KpageWatchAllocBulkRetBreakpoint(caller_pc, self.sym, page_list, page_array, nr_pages, pages_at_entry, caller_pc,
                                         task_addr, self.watcher)
        return False



class KpageWatchAllocBulkRetBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at the bulk page allocator return for kpage-watch."""

    def __init__(self, loc, sym, page_list, page_array, nr_pages, pages_at_entry, caller_pc, task_addr, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=True)
        self.sym = sym
        self.page_list = page_list
        self.page_array = page_array
        self.nr_pages = nr_pages
        self.pages_at_entry = pages_at_entry
        self.caller_pc = caller_pc
        self.task_addr = task_addr
        self.watcher = watcher
        self.call_context = Kernel.get_call_context(task_addr)
        self.interrupt_context = Kernel.get_interrupt_context()
        KmallocTracerCommand.clear_disabled_breakpoints("KpageWatchAllocBulkRetBreakpoint", owner=self.watcher)
        return

    def stop(self):
        Cache.reset_gef_caches()
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.call_context != Kernel.get_call_context(task_addr, at_return=True):
            return False
        self.enabled = False
        stop = False
        # the pages that were already there at the entry are not allocated by this call
        for page in self.watcher.watched_pages_in_bulk(self.page_list, self.page_array, self.nr_pages):
            if page not in self.pages_at_entry:
                stop |= self.watcher.record("alloc", self.sym, page, order=0, caller_pc=self.caller_pc)
        return stop



class KpageWatchFreeBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at the buddy free entry for kpage-watch."""

    def __init__(self, loc, sym, index_of_page_arg, index_of_order_arg, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.index_of_page_arg = index_of_page_arg
        self.index_of_order_arg = index_of_order_arg
        self.watcher = watcher
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()
        page = KmallocTracerCommand.get_ith_parameter(self.index_of_page_arg)
        order = 0
        if self.index_of_order_arg is not None:
            order = KmallocTracerCommand.get_ith_parameter(self.index_of_order_arg)
        caller_pc = KmallocTracerCommand.get_return_address()
        return self.watcher.record("free", self.sym, page, order=order, caller_pc=caller_pc)



class KpageWatchBatchFreeBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at the batched free path (folio_batch or page list) for kpage-watch.
    These paths return order-0 pages straight to the pcp lists without going through
    free_frozen_pages/__free_pages, so a page freed here would otherwise be missed."""

    def __init__(self, loc, sym, mode, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.mode = mode
        self.watcher = watcher
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()
        arg0 = KmallocTracerCommand.get_ith_parameter(0)
        caller_pc = KmallocTracerCommand.get_return_address()
        stop = False
        try:
            if self.mode == "folio_batch":
                # struct folio_batch { u8 nr; u8 i; bool drained; struct folio *folios[PAGEVEC_SIZE]; }
                nr = read_int8_from_memory(arg0)
                for i in range(min(nr, 31)):
                    folio = read_int_from_memory(arg0 + runtime.current_arch.ptrsize + runtime.current_arch.ptrsize * i)
                    # a large folio (e.g. THP) is freed here as well
                    order = self.watcher.folio_order(folio)
                    stop |= self.watcher.record("free", self.sym, folio, order=order, caller_pc=caller_pc)
            else:
                # a list_head of pages linked by page->lru; a watched page matches when a node
                # falls inside its struct page (no need to know offsetof(page, lru)).
                for page in self.watcher.watched_pages_in_list(arg0):
                    stop |= self.watcher.record("free", self.sym, page, order=0, caller_pc=caller_pc)
        except gdb.error:
            pass
        return stop



class KpageWatchSlabBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at allocate_slab entry for kpage-watch."""

    def __init__(self, loc, sym, page_kind, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.page_kind = page_kind
        self.watcher = watcher
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()
        task_addr, task_name = KmallocTracerCommand.get_task()
        if GefUtil.is_nested_call(self.watcher, ["KpageWatchSlabRetBreakpoint"], task_addr):
            return False
        kmem_cache = KmallocTracerCommand.get_ith_parameter(0)
        caller_pc = KmallocTracerCommand.get_return_address()
        KpageWatchSlabRetBreakpoint(caller_pc, self.sym, self.page_kind, kmem_cache, caller_pc, task_addr, self.watcher)
        return False



class KpageWatchSlabRetBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at allocate_slab return for kpage-watch."""

    def __init__(self, loc, sym, page_kind, kmem_cache, caller_pc, task_addr, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=True)
        self.sym = sym
        self.page_kind = page_kind
        self.kmem_cache = kmem_cache
        self.caller_pc = caller_pc
        self.task_addr = task_addr
        self.watcher = watcher
        self.call_context = Kernel.get_call_context(task_addr)
        self.interrupt_context = Kernel.get_interrupt_context()
        KmallocTracerCommand.clear_disabled_breakpoints("KpageWatchSlabRetBreakpoint", owner=self.watcher)
        return

    def stop(self):
        Cache.reset_gef_caches()
        task_addr, task_name = KmallocTracerCommand.get_task()
        if self.call_context != Kernel.get_call_context(task_addr, at_return=True):
            return False
        self.enabled = False
        page = self.watcher.slab_page(AddressUtil.parse_address(runtime.current_arch.return_register), self.page_kind)
        return self.watcher.record("slab_assign", self.sym, page, caller_pc=self.caller_pc, kmem_cache=self.kmem_cache)



class KpageWatchSlabFreeBreakpoint(gdb.Breakpoint):
    """Create a breakpoint at __free_slab entry for kpage-watch."""

    def __init__(self, loc, sym, page_kind, watcher):
        super().__init__("*{:#x}".format(loc), gdb.BP_BREAKPOINT, internal=False)
        self.sym = sym
        self.page_kind = page_kind
        self.watcher = watcher
        self.enabled = False
        return

    def stop(self):
        Cache.reset_gef_caches()
        kmem_cache = KmallocTracerCommand.get_ith_parameter(0)
        page = self.watcher.slab_page(KmallocTracerCommand.get_ith_parameter(1), self.page_kind)
        caller_pc = KmallocTracerCommand.get_return_address()
        return self.watcher.record("slab_free", self.sym, page, caller_pc=caller_pc, kmem_cache=kmem_cache)



@register_command
class KpageWatchCommand(GenericCommand):
    """Track the alloc/free/slab lifecycle of a physical page (PFN) for cross-cache analysis."""

    _cmdline_ = "kpage-watch"
    _category_ = "06-i. Qemu-system/KGDB Cooperation - Linux Dynamic Inspection"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", nargs="*", type=AddressUtil.parse_address,
                        help="the virtual address(es) whose backing page is watched.")
    parser.add_argument("-p", "--page", action="append", default=[], type=AddressUtil.parse_address,
                        help="watch by `struct page` address instead of a virtual address (can be repeated).")
    parser.add_argument("--pfn", action="append", default=[], type=AddressUtil.parse_address,
                        help="watch by page frame number (PFN) (can be repeated).")
    parser.add_argument("-s", "--stop-on-reuse", action="store_true",
                        help="stop at the first reuse (a re-allocation after a free).")
    parser.add_argument("-t", "--backtrace", action="store_true", help="display a backtrace for each event.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0xffff888012345600                           # watch the page backing this virtual address",
        "{0:s} 0xffff888012345600 0xffff888012346000        # watch several pages at once",
        "{0:s} -p 0xffffea000048d140 -p 0xffffea000048d180  # watch by struct page address",
        "{0:s} --pfn 0x12345 --pfn 0x12346                  # watch by PFN",
        "{0:s} 0xffff888012345600 -s                        # stop at the first reuse",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Disable `-enable-kvm` option for qemu-system (#PF may occur).",
        "Append `tsc=unstable` option for kernel cmdline.",
        "ADDRESS, --page and --pfn can be mixed; each resolves to one watched PFN.",
        "This records events touching the watched PFNs, so the page-allocator/SLUB/page-table boundary is visible.",
        "Only events reached while continuing are recorded; the history before the command started is not.",
        "On SLAB the slab-assign hook may be missing (its helpers are inlined); page alloc/free and slab-release are still shown.",
        "This command requires CONFIG_RANDSTRUCT=n.",
    ]
    _note_ = "\n".join(_note_)

    def resolve_offsets(self):
        self.name_offset = None
        allocator = Kernel.get_slab_type()
        command = {"SLUB": "slub-dump", "SLUB_TINY": "slub-tiny-dump", "SLAB": "slab-dump"}.get(allocator)
        if command is None:
            return
        ret = Color.remove_color(gdb.execute("{:s} --meta --no-pager".format(command), to_string=True))
        r = re.search(r"offsetof\(kmem_cache, name\): (0x\S+)", ret)
        if r:
            self.name_offset = int(r.group(1), 16)
        return

    def get_task_info(self):
        thread = gdb.selected_thread()
        cpu = KernelPerCpu.get_cpu_index(thread)
        task_addr, comm = KmallocTracerCommand.get_task()
        return task_addr, comm, cpu

    def pfn_of(self, page):
        if not is_valid_addr(page):
            return None
        phys = Kernel.page2phys(page)
        if phys is None:
            return None
        return phys >> self.page_shift

    def cache_name(self, kmem_cache):
        if self.name_offset is None or not kmem_cache:
            return None
        try:
            name_ptr = read_int_from_memory(kmem_cache + self.name_offset)
            return read_cstring_from_memory(name_ptr)
        except gdb.error:
            return None

    def slab_page(self, value, page_kind):
        # SLAB before v3.13 passes page_address(page), and its slab_destroy() takes the slab descriptor
        if page_kind == "virt":
            if value:
                return Kernel.virt2page(value)
            return None
        if page_kind == "slab_desc":
            # struct slab { struct list_head list; unsigned long colouroff; void *s_mem; ... }
            colouroff = read_int_from_memory(value + runtime.current_arch.ptrsize * 2)
            s_mem = read_int_from_memory(value + runtime.current_arch.ptrsize * 3)
            return Kernel.virt2page(s_mem - colouroff)
        return value

    def slab_matched_pfns(self, page):
        # sibling command module: lazy import per layering rule 1
        from gef.commands.kernel.page import PageInfoCommand
        base_pfn = self.pfn_of(page)
        if base_pfn is None:
            return []
        # a slab may be a compound page: compare the head PFN of both sides.
        head = PageInfoCommand.get_head_page(page)
        if head is None:
            head_pfn = base_pfn
        else:
            head_pfn = self.pfn_of(head)
        matched = []
        for pfn, (target_page, _virt) in self.watched.items():
            # a multi-page slab of SLAB before v3.13 is not compound: use the block seen when it was allocated
            if pfn == base_pfn or self.blocks.get(pfn) == page:
                matched.append(pfn)
                continue
            target_head = PageInfoCommand.get_head_page(target_page)
            if target_head is not None and self.pfn_of(target_head) == head_pfn:
                matched.append(pfn)
        return matched

    def watched_pages_in_list(self, list_head):
        # walk a list_head of page->lru nodes; a watched page matches when a node lands
        # inside its struct page, so offsetof(page, lru) never has to be known.
        if not is_valid_addr(list_head):
            return []
        found = []
        node = read_int_from_memory(list_head)
        for _ in range(4096):
            if node == list_head or not is_valid_addr(node):
                break
            for target_page, _virt in self.watched.values():
                if target_page <= node < target_page + self.sizeof_struct_page:
                    found.append(target_page)
            node = read_int_from_memory(node)
        return found

    def watched_pages_in_bulk(self, page_list, page_array, nr_pages):
        # the bulk allocator links order-0 pages to page_list, or fills the empty slots of page_array
        if page_list:
            return self.watched_pages_in_list(page_list)
        if not is_valid_addr(page_array) or nr_pages <= 0:
            return []
        targets = [target_page for target_page, _virt in self.watched.values()]
        pages = []
        for index in range(0, nr_pages, 4096):
            count = min(nr_pages - index, 4096)
            data = read_memory(page_array + index * runtime.current_arch.ptrsize, count * runtime.current_arch.ptrsize)
            pages.extend(page for page in slice_unpack(data, runtime.current_arch.ptrsize) if page in targets)
        return pages

    def folio_order(self, folio):
        # sibling command module: lazy import per layering rule 1
        from gef.commands.kernel.page import PageInfoCommand
        # folio_order(): a large folio keeps its order in the low byte of _flags_1 (the flags of page[1])
        if not PageInfoCommand.has_flag(read_int_from_memory(folio), "PG_head"):
            return 0
        return read_int_from_memory(folio + self.sizeof_struct_page) & 0xff

    def direct_map_virt(self, page, phys):
        # the same resolution as buddy-dump: physmap + phys, or page2virt when it falls outside the direct map
        consts = KernelAddressHeuristicFinder.consts()
        page_offset = KernelAddressHeuristicFinder.get_PAGE_OFFSET()
        if is_arm64():
            physmap = consts.physmap_base
        elif is_arm32():
            phys_offset = consts.PHYS_OFFSET
            if page_offset is None or phys_offset is None:
                physmap = None
            else:
                physmap = page_offset - phys_offset
        else:
            physmap = page_offset
        if physmap is not None:
            # check the range before normalizing, or a 32-bit PA of 4 GiB or more wraps into the direct map
            virt = physmap + phys
            page_offset_end = KernelAddressHeuristicFinder.get_PAGE_OFFSET_END()
            if page_offset is None or page_offset_end is None:
                return AddressUtil.normalize_address(virt)
            if page_offset <= virt < page_offset_end:
                return virt
        return Kernel.page2virt(page)

    def emit_event(self, tag, pfn, api, page, order, cache, caller_pc):
        task_addr, comm, cpu = self.get_task_info()
        caller = Symbol.format(caller_pc, bracket="", missing="?" if caller_pc is None else "{:#x}".format(caller_pc))
        if tag == "FREE":
            theme = "theme.heap_chunk_address_freed"
        else:
            theme = "theme.heap_chunk_address_used"
        target_page, virt = self.watched[pfn]
        if virt is None:
            virt_s = "-"
        else:
            virt_s = Color.colorify_hex(virt, Config.get("theme.heap_page_address"))
        page_s = Color.colorify_hex(target_page, Config.get(theme))
        detail = "pfn={:#x} page={:s} virt={:s}".format(pfn, page_s, virt_s)
        if page != target_page:
            # the event is about the block whose head is `page` (e.g. a higher order allocation)
            detail += " head={:#x}".format(page)
        if order is not None:
            detail += " order={:d}".format(order)
        if cache:
            detail += "  cache={:s}".format(Color.colorify(cache, Config.get("theme.heap_chunk_label")))
        gef_print("[{:6s}] {:s}".format(tag, detail))
        gef_print("         via {:s}  caller={:s}  comm={:s} cpu={:s}".format(
            api, caller, comm, "?" if cpu is None else str(cpu),
        ))
        if self.backtrace:
            KmallocTracerCommand.print_backtrace(True)
        return

    def record(self, kind, api, page, order=None, caller_pc=None, kmem_cache=None):
        if kind in ("alloc", "free"):
            base_pfn = self.pfn_of(page)
            if base_pfn is None:
                return False
            # order comes from a register; ignore an out-of-range read so span stays sane.
            if order is None or order < 0 or order > 20:
                order = 0
            span = 1 << order
            matched = [pfn for pfn in self.watched if base_pfn <= pfn < base_pfn + span]
            # another block at the same page ends the one remembered for a watched page
            self.blocks = {pfn: block for pfn, block in self.blocks.items() if block != page}
        else:
            order = None
            matched = self.slab_matched_pfns(page)
        if not matched:
            return False

        cache = self.cache_name(kmem_cache)
        tag = {"alloc": "ALLOC", "free": "FREE", "slab_assign": "SLAB", "slab_free": "UNSLAB"}[kind]
        reuse = False
        for pfn in matched:
            if kind in ("alloc", "slab_assign") and pfn in self.freed:
                reuse = True
            self.emit_event(tag, pfn, api, page, order, cache, caller_pc)
            if kind in ("free", "slab_free"):
                self.freed.add(pfn)
            else:
                self.freed.discard(pfn)
            if kind == "alloc":
                self.blocks[pfn] = page
            elif kind == "free":
                self.blocks.pop(pfn, None)
        return self.stop_on_reuse and reuse

    def build_alloc_syms(self, kversion):
        if kversion < "5.13":
            return [["__alloc_pages_nodemask", 1]]
        elif kversion < "6.10":
            return [["__alloc_pages", 1]]
        elif kversion < "6.14":
            return [["__alloc_pages_noprof", 1]]
        else:
            # v6.15+: the nolock allocator (e.g. for BPF) takes pages from the freelists by itself.
            # alloc_pages_nolock_noprof() of v6.18+ calls alloc_frozen_pages_nolock_noprof().
            syms = [["__alloc_frozen_pages_noprof", 1]]
            sym, func_addr = self.first_resolvable(["alloc_frozen_pages_nolock_noprof", "alloc_pages_nolock_noprof",
                                                    "try_alloc_pages_noprof"])
            if sym:
                # (gfp_flags, nid, order) or (nid, order)
                syms.append([sym, 2 if sym == "alloc_frozen_pages_nolock_noprof" else 1])
            return syms

    def build_bulk_alloc_syms(self, kversion):
        # order-0 pages allocated in bulk (e.g. vmalloc, page_pool) are taken from the pcp lists by itself.
        # [sym, whether page_list comes before page_array]
        if kversion >= "6.14":
            return ["alloc_pages_bulk_noprof", False]
        elif kversion >= "6.10":
            return ["alloc_pages_bulk_noprof", True]
        elif kversion >= "5.13":
            return ["__alloc_pages_bulk", True]
        else:
            return [None, None]

    def build_free_syms(self, kversion):
        # Hook the functions reached only after the refcount dropped to zero (not __free_pages,
        # which also runs for a put that does not free). [sym, index of page, index of order or None]
        if kversion >= "6.14":
            # v6.15+: __free_pages -> ___free_pages -> __free_frozen_pages, skipping free_frozen_pages.
            sym, func_addr = self.first_resolvable(["__free_frozen_pages", "free_frozen_pages"])
            if sym:
                return [[sym, 0, 1]]
            return []
        elif kversion >= "6.10":
            return [["free_unref_page", 0, 1]]
        elif kversion >= "5.14":
            return [["free_unref_page", 0, 1], ["__free_pages_ok", 0, 1]]
        elif kversion >= "4.15":
            return [["free_unref_page", 0, None], ["__free_pages_ok", 0, 1]]
        else:
            return [["free_hot_cold_page", 0, None], ["__free_pages_ok", 0, 1]]

    def build_batch_free_syms(self, kversion):
        # order-0 pages freed in bulk skip the functions above and go straight to the pcp lists.
        # Before v4.15 free_hot_cold_page_list calls free_hot_cold_page per page, so it needs no hook.
        if kversion >= "6.9":
            return ["free_unref_folios", "folio_batch"]
        elif kversion >= "4.15":
            return ["free_unref_page_list", "list"]
        else:
            return [None, None]

    def build_slab_syms(self, allocator, kversion):
        # The function that hands a fresh page to a cache, and the one that gives it back,
        # as ordered candidates (the caller hooks the first that resolves). SLAB uses different
        # symbols than SLUB, and its inner helpers are often inlined, so an outer one is tried too.
        # {sym: how the page is passed (see slab_page)}
        if allocator == "SLAB":
            if kversion < "3.13":
                return {"kmem_getpages": "virt"}, {"kmem_freepages": "virt", "slab_destroy": "slab_desc"}
            return {"kmem_getpages": "page", "cache_grow_begin": "page"}, {"kmem_freepages": "page", "slab_destroy": "page"}
        return {"allocate_slab": "page"}, {"__free_slab": "page"}

    @staticmethod
    def first_resolvable(syms):
        for sym in syms:
            func_addr = Ksym.get_addr(sym)
            if func_addr:
                return sym, func_addr
        return None, None

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system",))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel
    @only_if_kvm_disabled
    def do_invoke(self, args):
        if not args.pfn and not args.page and not args.address:
            err("Specify an ADDRESS, --page PAGE or --pfn PFN")
            return

        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "3.0":
            err("Unsupported before v3.0")
            return

        allocator = Kernel.get_slab_type()
        if allocator == "Unknown":
            err("Unsupported: Unknown allocator")
            return

        info("Wait for memory scan")

        consts = KernelAddressHeuristicFinder.consts()
        if consts is None or consts.PAGE_SHIFT is None:
            err("Failed to resolve kernel constants")
            return
        self.page_shift = consts.PAGE_SHIFT

        # resolve the watched PFNs and their struct pages
        pfns = list(args.pfn)
        for page in args.page:
            phys = Kernel.page2phys(page)
            if phys is None:
                err("{:#x} is not a valid struct page".format(page))
                continue
            pfns.append(phys >> self.page_shift)
        for address in args.address:
            page = Kernel.virt2page(address)
            if page is not None:
                phys = Kernel.page2phys(page)
            else:
                phys = None
            if phys is None:
                err("Could not resolve the page of {:#x}".format(address))
                continue
            pfns.append(phys >> self.page_shift)

        self.watched = {}
        for pfn in pfns:
            if pfn in self.watched:
                continue
            target_page = Kernel.phys2page(pfn << self.page_shift)
            if target_page is None:
                err("Could not resolve the struct page of pfn {:#x}".format(pfn))
                continue
            virt = self.direct_map_virt(target_page, pfn << self.page_shift)
            self.watched[pfn] = (target_page, virt)
            gef_print("[WATCH ] pfn={:#x} page={:#x} virt={:s} phys={:#x}".format(
                pfn,
                target_page,
                "-" if virt is None else Color.colorify_hex(virt, Config.get("theme.heap_page_address")),
                pfn << self.page_shift,
            ))
        if not self.watched:
            err("No page to watch")
            return

        self.resolve_offsets()
        self.sizeof_struct_page = consts.sizeof_struct_page or (runtime.current_arch.ptrsize * 8)
        self.stop_on_reuse = args.stop_on_reuse
        self.backtrace = args.backtrace
        self.freed = set()
        self.blocks = {}

        if self.name_offset is None:
            warn("Slab cache names are unavailable (offset not resolved); slab events show no cache")

        # set breakpoints
        breakpoints = []
        try:
            for sym, index_of_order_arg in self.build_alloc_syms(kversion):
                func_addr = Ksym.get_addr(sym)
                if func_addr:
                    gef_print(sym + ": ", end="")
                    breakpoints.append(KpageWatchAllocBreakpoint(func_addr, sym, index_of_order_arg, self))
            bulk_sym, has_page_list = self.build_bulk_alloc_syms(kversion)
            if bulk_sym:
                func_addr = Ksym.get_addr(bulk_sym)
            else:
                func_addr = None
            if func_addr:
                gef_print(bulk_sym + ": ", end="")
                breakpoints.append(KpageWatchAllocBulkBreakpoint(func_addr, bulk_sym, has_page_list, self))
            for sym, index_of_page_arg, index_of_order_arg in self.build_free_syms(kversion):
                func_addr = Ksym.get_addr(sym)
                if func_addr:
                    gef_print(sym + ": ", end="")
                    breakpoints.append(KpageWatchFreeBreakpoint(func_addr, sym, index_of_page_arg, index_of_order_arg, self))
            slab_assign_syms, slab_free_syms = self.build_slab_syms(allocator, kversion)
            sym, func_addr = self.first_resolvable(slab_assign_syms)
            if func_addr:
                gef_print(sym + ": ", end="")
                breakpoints.append(KpageWatchSlabBreakpoint(func_addr, sym, slab_assign_syms[sym], self))
            sym, func_addr = self.first_resolvable(slab_free_syms)
            if func_addr:
                gef_print(sym + ": ", end="")
                breakpoints.append(KpageWatchSlabFreeBreakpoint(func_addr, sym, slab_free_syms[sym], self))
            batch_sym, batch_mode = self.build_batch_free_syms(kversion)
            if batch_sym:
                func_addr = Ksym.get_addr(batch_sym)
            else:
                func_addr = None
            if func_addr:
                gef_print(batch_sym + ": ", end="")
                breakpoints.append(KpageWatchBatchFreeBreakpoint(func_addr, batch_sym, batch_mode, self))
            if not breakpoints:
                warn("No page hooks resolved; nothing will be observed")
                return
            for bp in breakpoints:
                bp.enabled = True

            info("Setup is complete. continuing...")
            gdb.execute("continue")
            info("kpage-watch is complete, cleaning up...")
        finally:
            GefUtil.delete_breakpoints(self, report_pending=True)
        return
