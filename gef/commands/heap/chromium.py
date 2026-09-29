"""GEF Chromium/V8 heap commands (category 05-b) extracted from the monolithic gef.py.

Chromium / V8 heap commands (cage, v8-*, partition-alloc-dump).

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import collections
import os
import re
import struct
import sys

import gdb

from gef.bootstrap import http_get
from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    only_if_specific_arch,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Permission
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, ok, titlify
from gef.core.config import Config
from gef.core.exec import ExecSyscall
from gef.core.memory import (
    is_valid_addr,
    read_int16_from_memory,
    read_int32_from_memory,
    read_int64_from_memory,
    read_int8_from_memory,
    read_int_from_memory,
    read_memory,
)
from gef.core.process import (
    Path,
    ProcessMap,
    get_pagesize,
    get_pagesize_mask_high,
    get_pagesize_mask_low,
    is_32bit,
    is_64bit,
)
from gef.core.syscall import Syscall
from gef.core.utils import GEF_TEMP_DIR, GefUtil, align, byteswap, slice_unpack

@register_command
class CageCommand(GenericCommand, BufferingOutput):
    """Display v8 (Chromium and d8) ubercage area."""

    _cmdline_ = "cage"
    _category_ = "05-b. Heap - Chromium/V8"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the address for filtering.")
    parser.add_argument("-f", "--force-heuristic", action="store_true", help="use heuristic detection.")
    parser.add_argument("-v", "--verbose", action="store_true", help="show with zero page.")
    parser.add_argument("-vv", "--vverbose", action="store_true", help="show with permission NONE.")
    parser.add_argument("-vvv", "--vvverbose", action="store_true", help="show all maps (=~ vmmap).")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def get_sym_addr(self, sym, force_heuristic=False):
        if force_heuristic:
            return None
        try:
            x = AddressUtil.parse_address(f"&{sym}")
            return read_int_from_memory(x)
        except Exception:
            pass
        return None

    def get_sym_value(self, sym, force_heuristic=False):
        if force_heuristic:
            return None
        try:
            return AddressUtil.parse_address(f"{sym}")
        except Exception:
            pass
        return None

    @Cache.cache_until_next
    def get_isolate(self, force_heuristic=False):
        sym = "&'v8::internal::g_current_isolate_'.isolate_data_"
        addr = self.get_sym_value(sym, force_heuristic)
        if addr:
            return addr

        tls = runtime.current_arch.get_tls()
        for i in range(256 * 4): # heuristic; d8: 256, chromium: 1024
            try:
                x = read_int_from_memory(tls - runtime.current_arch.ptrsize * i)
            except gdb.MemoryError:
                continue
            if x == 0:
                continue
            if x & 7:
                continue
            if not is_valid_addr(x):
                continue
            try:
                y = read_int_from_memory(x)
            except gdb.MemoryError:
                continue
            if y == 0:
                continue
            if y & 0xffff_ffff:
                continue
            if not is_valid_addr(y):
                continue
            return x
        return None

    @Cache.cache_until_next
    def get_cage_base(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.cage_base_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        addr = self.get_isolate(force_heuristic)
        if addr:
            return read_int_from_memory(addr)
        return None

    @Cache.cache_until_next
    def get_table_candidates(self):
        isolate = self.get_isolate(force_heuristic=True)
        if not isolate:
            return None

        """
        gef> dt 'v8::internal::IsolateData'
        struct v8::internal::IsolateData {
            /* offset | size   */
            /*        | 0x0008 */    const intptr_t kIsolateRootBias;
            /* 0x0000 | 0x0008 */    const v8::internal::Address cage_base_;
            /* 0x0008 | 0x0040 */    v8::internal::StackGuard stack_guard_;
            /* 0x0048 | 0x0001 */    uint8_t is_marking_flag_;
            /* 0x0049 | 0x0001 */    uint8_t is_minor_marking_flag_;
            /* 0x004a | 0x0001 */    uint8_t is_shared_space_isolate_flag_;
            /* 0x004b | 0x0001 */    uint8_t uses_shared_heap_flag_;
            /* 0x004c | 0x0001 */    v8::base::Flags<...> execution_mode_;
            /* 0x004d | 0x0001 */    uint8_t stack_is_iterable_;
            /* 0x004e | 0x0001 */    uint8_t error_message_param_;
            /* 0x004f | 0x0001 */    uint8_t [1] tables_alignment_padding_;
            /* 0x0050 | 0x0008 */    int32_t * regexp_static_result_offsets_vector_;
            /* 0x0058 | 0x0038 */    v8::internal::Address [7] builtin_tier0_entry_table_;
            /* 0x0090 | 0x0038 */    v8::internal::Address [7] builtin_tier0_table_;
            /* 0x00c8 | 0x0018 */    v8::internal::LinearAllocationArea new_allocation_info_;
            /* 0x00e0 | 0x0018 */    v8::internal::LinearAllocationArea old_allocation_info_;
            /* 0x00f8 | 0x0028 */    v8::internal::Address [5] fast_c_call_alignment_padding_;
            /* 0x0120 | 0x0010 */    struct {...} ;
            /* 0x0130 | 0x0008 */    v8::internal::Address fast_api_call_target_;
            /* 0x0138 | 0x0008 */    size_t long_task_stats_counter_;
            /* 0x0140 | 0x00f0 */    v8::internal::ThreadLocalTop thread_local_top_;
            /* 0x0230 | 0x0018 */    v8::internal::HandleScopeData handle_scope_data_;
            /* 0x0248 | 0x0020 */    void *[4] embedder_data_;
            /* 0x0268 | 0x0030 */    v8::internal::ExternalPointerTable external_pointer_table_;
            /* 0x0298 | 0x0008 */    v8::internal::ExternalPointerTable * shared_external_pointer_table_;
            /* 0x02a0 | 0x0030 */    v8::internal::CppHeapPointerTable cpp_heap_pointer_table_;
            /* 0x02d0 | 0x0008 */    const v8::internal::Address trusted_cage_base_;
            /* 0x02d8 | 0x0030 */    v8::internal::TrustedPointerTable trusted_pointer_table_;
            /* 0x0308 | 0x0008 */    v8::internal::TrustedPointerTable * shared_trusted_pointer_table_;
            /* 0x0310 | 0x0008 */    v8::internal::TrustedPointerPublishingScope * trusted_pointer_publishing_scope_;
            /* 0x0318 | 0x0008 */    const v8::internal::Address code_pointer_table_base_address_;
            /* 0x0320 | 0x0008 */    v8::internal::Address api_callback_thunk_argument_;
            /* 0x0328 | 0x0008 */    v8::internal::Address js_dispatch_table_base_;
            /* 0x0330 | 0x0008 */    v8::internal::Address regexp_exec_vector_argument_;
            /* 0x0338 | 0x0008 */    v8::internal::Tagged<...> continuation_preserved_embedder_data_;
            /* 0x0340 | 0x23b8 */    v8::internal::RootsTable roots_table_;
            /* 0x26f8 | 0x3320 */    v8::internal::ExternalReferenceTable external_reference_table_;
            /* 0x5a18 | 0x49b8 */    v8::internal::Address [2359] builtin_entry_table_;
            /* 0xa3d0 | 0x49b8 */    v8::internal::Address [2359] builtin_table_;
            /* 0xed88 | 0x0008 */    v8::internal::wasm::StackMemory * active_stack_;
            /* 0xed90 | 0x0008 */    v8::internal::Tagged<...> active_suspender_;
            /* 0xed98 | 0x0004 */    int32_t date_cache_stamp_;
            /* 0xed9c | 0x0001 */    uint8_t is_date_cache_used_;
            /* 0xed9d | 0x0003 */    uint8_t [3] raw_arguments_padding_;
            /* 0xeda0 | 0x0010 */    v8::internal::IsolateData::RawArgument [2] raw_arguments_;
            /* 0xedb0 | 0x0000 */    uint8_t [0] trailing_padding_;
        } // total: 0xedb0 bytes
        gef>

        [d8]
        gef> telescope 0x555555857000 256 -M 0xfff -P r__ -n \
                -t 0 cage_base_ \
                -t 77 external_pointer_table_.base \
                -t 84 cpp_heap_pointer_table_.base \
                -t 90 trusted_cage_base_ \
                -t 91 trusted_pointer_table_ \
                -t 99 code_pointer_table_base_address_ \
                -t 101 js_dispatch_table_base_
              0x555555857000|+0x0000|+000: cage_base_                      : 0x00001adc00000000  ->  0x0000000000081140
              0x5555558570d8|+0x00d8|+027:                                 : 0x00001adc001c0000  ->  0x0000000000081140
              0x5555558570f0|+0x00f0|+030:                                 : 0x00001adc00080000  ->  0x0000000000081140
              0x555555857268|+0x0268|+077: external_pointer_table_.base    : 0x00007fff4c000000  ->  0x0000000000000000
              0x5555558572a0|+0x02a0|+084: cpp_heap_pointer_table_.base    : 0x00007fff2c000000  ->  0x0000000000000000
              0x5555558572d8|+0x02d8|+091: trusted_pointer_table_          : 0x00007fff28000000  ->  0x0000000000000000
              0x555555857318|+0x0318|+099: code_pointer_table_base_address_: 0x00007fffa4000000  ->  0x0000000000000000
              0x555555857328|+0x0328|+101: js_dispatch_table_base_         : 0x00007fff94000000  ->  0x0000000000000000
        gef>

        [chromium]
        gef> telescope 0x3ea4004a4000 256 -M 0xfff -P r__ -n \
                -t 0 cage_base_ \
                -t 77 external_pointer_table_.base \
                -t 84 cpp_heap_pointer_table_.base \
                -t 90 trusted_cage_base_ \
                -t 91 trusted_pointer_table_ \
                -t 99 code_pointer_table_base_address_ \
                -t 100 js_dispatch_table_base_
              0x3ea4004a4000|+0x0000|+000: cage_base_                      : 0x0000321700000000  ->  0x0000000000000000
              0x3ea4004a4268|+0x0268|+077: external_pointer_table_.base    : 0x0000720dbb154000  ->  0x0000000000000000
              0x3ea4004a42a0|+0x02a0|+084: cpp_heap_pointer_table_.base    : 0x0000720d9b154000  ->  0x0000000000000000
              0x3ea4004a42d8|+0x02d8|+091: trusted_pointer_table_          : 0x0000720d97154000  ->  0x0000000000000000
              0x3ea4004a4318|+0x0318|+099: code_pointer_table_base_address_: 0x0000720de3154000  ->  0x0000000000000000
              0x3ea4004a4320|+0x0320|+100: js_dispatch_table_base_         : 0x0000720d87154000  ->  0x0000000000000000
        gef>
        """

        # In d8 it is aligned to 0x100_0000 bytes.
        candidates_z_ffffff = []
        # In chromium it is aligned to 0x1000 bytes.
        candidates_z_fff = []

        for i in range(256):
            addr = isolate + runtime.current_arch.ptrsize * i
            try:
                value = read_int_from_memory(addr)
            except gdb.MemoryError:
                return []
            if value & 0xfff:
                continue
            if not is_valid_addr(value):
                continue
            pm = ProcessMap.lookup_address(value)
            try:
                if pm.section.permission.value != Permission.READ:
                    continue
            except Exception:
                continue
            if value & 0xff_ffff == 0:
                candidates_z_ffffff.append(value)
            candidates_z_fff.append(value)

        if len(candidates_z_ffffff) >= 6:
            return candidates_z_ffffff
        return candidates_z_fff

    @Cache.cache_until_next
    def get_external_pointer_table_base(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.external_pointer_table_.base_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        candidates = self.get_table_candidates()
        if candidates and len(candidates) > 1:
            return candidates[1]
        return None

    @Cache.cache_until_next
    def get_external_pointer_table_size(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.external_pointer_table_.kReservationSize"
        value = self.get_sym_value(sym, force_heuristic)
        if value:
            return value
        return 0x400_0000 # hard-coded

    @Cache.cache_until_next
    def get_shared_external_pointer_table_base(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.shared_external_pointer_table_.base_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr
        return None

    @Cache.cache_until_next
    def get_shared_external_pointer_table_size(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.shared_external_pointer_table_.kReservationSize"
        value = self.get_sym_value(sym, force_heuristic)
        if value:
            return value
        return 0x400_0000 # hard-coded

    @Cache.cache_until_next
    def get_cpp_heap_pointer_table_base(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.cpp_heap_pointer_table_.base_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        candidates = self.get_table_candidates()
        if candidates and len(candidates) > 2:
            return candidates[2]
        return None

    @Cache.cache_until_next
    def get_cpp_heap_pointer_table_size(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.cpp_heap_pointer_table_.kReservationSize"
        value = self.get_sym_value(sym, force_heuristic)
        if value:
            return value
        return 0x400_0000 # hard-coded

    @Cache.cache_until_next
    def get_trusted_pointer_table_base(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.trusted_pointer_table_.base_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        candidates = self.get_table_candidates()
        if candidates and len(candidates) > 3:
            return candidates[3]
        return None

    @Cache.cache_until_next
    def get_trusted_pointer_table_size(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.trusted_pointer_table_.kReservationSize"
        value = self.get_sym_value(sym, force_heuristic)
        if value:
            return value
        return 0x400_0000 # hard-coded

    @Cache.cache_until_next
    def get_shared_trusted_pointer_table_base(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.shared_trusted_pointer_table_.base_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr
        return None

    @Cache.cache_until_next
    def get_shared_trusted_pointer_table_size(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.shared_trusted_pointer_table_.kReservationSize"
        value = self.get_sym_value(sym, force_heuristic)
        if value:
            return value
        return 0x400_0000 # hard-coded

    @Cache.cache_until_next
    def get_code_pointer_table_base(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.code_pointer_table_base_address_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        candidates = self.get_table_candidates()
        if candidates and len(candidates) > 4:
            return candidates[4]
        return None

    @Cache.cache_until_next
    def get_code_pointer_table_size(self, force_heuristic=False):
        return 0x400_0000 # hard-coded

    @Cache.cache_until_next
    def get_js_dispatch_table_base(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.js_dispatch_table_base_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        candidates = self.get_table_candidates()
        if candidates and len(candidates) > 5:
            return candidates[5]
        return None

    @Cache.cache_until_next
    def get_js_dispatch_table_size(self, force_heuristic=False):
        return 0x400_0000 # hard-coded

    @Cache.cache_until_next
    def get_code_range_base(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'->heap_.code_range_.base_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        maps = ProcessMap.get_process_maps()
        if not maps:
            return None
        for i, m in enumerate(maps):
            if m.permission.value != Permission.READ | Permission.WRITE | Permission.EXECUTE:
                continue
            if (m.page_start & 0xffff) != 0:
                continue
            if m.size > 0x2000_0000:
                continue
            if m.size == 0x2000_0000:
                return m.page_start
            if m.size < 0x2000_0000:
                if i == len(maps) - 1:
                    continue
                if maps[i + 1].permission.value & Permission.EXECUTE == 0:
                    continue
                return m.page_start
        return None

    @Cache.cache_until_next
    def get_code_range_size(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'->heap_.code_range_.size_"
        value = self.get_sym_value(sym, force_heuristic)
        if value:
            return value
        return 0x2000_0000 # hard-coded

    @Cache.cache_until_next
    def get_cage_rw_space_candidates(self):
        maps = ProcessMap.get_process_maps()
        if not maps:
            return None
        candidates = []
        for m in maps:
            if m.permission.value != Permission.READ | Permission.WRITE:
                continue
            if not self.is_cage(m):
                continue
            candidates.append(m)
        return candidates

    @Cache.cache_until_next
    def get_new_space_start(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.new_allocation_info_.start_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        candidates = self.get_cage_rw_space_candidates()
        if candidates and len(candidates) > 1:
            return candidates[1].page_start
        return None

    @Cache.cache_until_next
    def get_new_space_limit(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.new_allocation_info_.limit_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        candidates = self.get_cage_rw_space_candidates()
        if candidates and len(candidates) > 1:
            return candidates[1].page_end
        return None

    @Cache.cache_until_next
    def get_old_space_start(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.old_allocation_info_.start_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        candidates = self.get_cage_rw_space_candidates()
        if candidates and len(candidates) > 0:
            return candidates[0].page_start
        return None

    @Cache.cache_until_next
    def get_old_space_limit(self, force_heuristic=False):
        sym = "'v8::internal::g_current_isolate_'.isolate_data_.old_allocation_info_.limit_"
        addr = self.get_sym_addr(sym, force_heuristic)
        if addr:
            return addr

        candidates = self.get_cage_rw_space_candidates()
        if candidates and len(candidates) > 0:
            return candidates[0].page_end
        return None

    def dump_entry(self, entry, path):
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

        # make line
        lines = []
        lines.append(Color.colorify(
            AddressUtil.format_address(entry.page_start, runtime.current_arch.ptrsize, long_fmt=True), line_color,
        ))
        lines.append(Color.colorify(
            AddressUtil.format_address(entry.page_end, runtime.current_arch.ptrsize, long_fmt=True), line_color,
        ))
        lines.append(Color.colorify(
            AddressUtil.format_address(entry.size, runtime.current_arch.ptrsize, long_fmt=True), line_color,
        ))
        lines.append(Color.colorify(
            AddressUtil.format_address(entry.offset, runtime.current_arch.ptrsize, long_fmt=True), line_color,
        ))
        lines.append(Color.colorify(
            str(entry.permission), line_color,
        ))

        if entry.path and path:
            path = entry.path + "," + path
        elif entry.path:
            path = entry.path
        lines.append(Color.colorify(path, line_color))

        self.out.append(" ".join(lines))
        return

    def is_external_pointer_table(self, entry):
        area_start = self.get_external_pointer_table_base(self.args.force_heuristic)
        area_size = self.get_external_pointer_table_size(self.args.force_heuristic)
        if area_start is not None and area_size is not None:
            area_end = area_start + area_size
            return area_start <= entry.page_start < area_end
        return False

    def is_shared_external_pointer_table(self, entry):
        area_start = self.get_shared_external_pointer_table_base(self.args.force_heuristic)
        area_size = self.get_shared_external_pointer_table_size(self.args.force_heuristic)
        if area_start is not None and area_size is not None:
            area_end = area_start + area_size
            return area_start <= entry.page_start < area_end
        return False

    def is_cpp_heap_pointer_table(self, entry):
        area_start = self.get_cpp_heap_pointer_table_base(self.args.force_heuristic)
        area_size = self.get_cpp_heap_pointer_table_size(self.args.force_heuristic)
        if area_start is not None and area_size is not None:
            area_end = area_start + area_size
            return area_start <= entry.page_start < area_end
        return False

    def is_trusted_pointer_table(self, entry):
        area_start = self.get_trusted_pointer_table_base(self.args.force_heuristic)
        area_size = self.get_trusted_pointer_table_size(self.args.force_heuristic)
        if area_start is not None and area_size is not None:
            area_end = area_start + area_size
            if area_start <= entry.page_start < area_end:
                # keep trusted space address
                if entry.permission.value == Permission.READ | Permission.WRITE:
                    v = read_int_from_memory(entry.page_start)
                    self.trusted_space_high = v & 0x0000_ffff_0000_0000
                    return True
        return False

    def is_shared_trusted_pointer_table(self, entry):
        area_start = self.get_shared_trusted_pointer_table_base(self.args.force_heuristic)
        area_size = self.get_shared_trusted_pointer_table_size(self.args.force_heuristic)
        if area_start is not None and area_size is not None:
            area_end = area_start + area_size
            return area_start <= entry.page_start < area_end
        return False

    def is_code_pointer_table(self, entry):
        area_start = self.get_code_pointer_table_base(self.args.force_heuristic)
        area_size = self.get_code_pointer_table_size(self.args.force_heuristic)
        if area_start is not None and area_size is not None:
            area_end = area_start + area_size
            return area_start <= entry.page_start < area_end
        return False

    def is_js_dispatch_table_space(self, entry):
        area_start = self.get_js_dispatch_table_base(self.args.force_heuristic)
        area_size = self.get_js_dispatch_table_size(self.args.force_heuristic)
        if area_start is not None and area_size is not None:
            area_end = area_start + area_size
            return area_start <= entry.page_start < area_end
        return False

    def is_code_range(self, entry):
        area_start = self.get_code_range_base(self.args.force_heuristic)
        area_size = self.get_code_range_size(self.args.force_heuristic)
        if area_start is not None and area_size is not None:
            area_end = area_start + area_size
            return area_start <= entry.page_start < area_end
        return False

    def is_new_space(self, entry):
        area_start = self.get_new_space_start(self.args.force_heuristic)
        area_end = self.get_new_space_limit(self.args.force_heuristic)
        if area_start is None or area_end is None:
            return False
        return entry.page_start <= area_start < area_end <= entry.page_end

    def is_old_space(self, entry):
        area_start = self.get_old_space_start(self.args.force_heuristic)
        area_end = self.get_old_space_limit(self.args.force_heuristic)
        if area_start is None or area_end is None:
            return False
        return entry.page_start <= area_start < area_end <= entry.page_end

    def is_ro_space(self, entry):
        if self.is_cage(entry):
            return entry.permission.value == Permission.READ
        return False

    def is_array_buffer(self, entry):
        if self.is_cage(entry):
            if entry.permission.value == Permission.READ | Permission.WRITE:
                if (entry.page_start & 0xffff_ffff) == 0:
                    return True
        return False

    def is_cage(self, entry):
        area_start = self.get_cage_base(self.args.force_heuristic)
        if area_start is None:
            return False
        area_end = area_start + (1 * 1024 * 1024 * 1024 * 1024) # 1TB
        return area_start <= entry.page_start < area_end

    def is_trusted_space(self, entry):
        if not hasattr(self, "trusted_space_high"):
            return False
        if self.trusted_space_high == (entry.page_start & 0x0000_ffff_0000_0000):
            return True
        return False

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        maps = ProcessMap.get_process_maps()
        if not maps:
            err("Could not find any maps")
            return

        if args.vvverbose:
            args.vverbose = True
        if args.vverbose:
            args.verbose = True

        self.out = []
        # To find the trusted_space from the trusted_pointer_table, traverse it in reverse order
        for entry in maps[::-1]:
            # location filtering
            if args.location is not None:
                if args.location < entry.page_start or entry.page_end <= args.location:
                    continue

            if not args.vverbose:
                # None permission filtering
                if entry.permission.value == Permission.NONE:
                    continue

            if not args.verbose:
                # zero contents filtering
                try:
                    if entry.size <= 0x10_0000:
                        d = read_memory(entry.page_start, entry.size)
                        if set(d) == {0}:
                            continue
                except gdb.error:
                    pass

            # known already entry filtering
            if entry.path and not entry.path.startswith("[anon:v8"):
                if args.vvverbose:
                    self.dump_entry(entry, "")
                continue

            # display the cage regions
            if self.is_external_pointer_table(entry):
                self.dump_entry(entry, "[v8:external_pointer_table]")
            elif self.is_shared_external_pointer_table(entry):
                self.dump_entry(entry, "[v8:shared_external_pointer_table]")
            elif self.is_cpp_heap_pointer_table(entry):
                self.dump_entry(entry, "[v8:cpp_heap_pointer_table]")
            elif self.is_trusted_pointer_table(entry):
                self.dump_entry(entry, "[v8:trusted_pointer_table]")
            elif self.is_shared_trusted_pointer_table(entry):
                self.dump_entry(entry, "[v8:shared_trusted_pointer_table]")
            elif self.is_code_pointer_table(entry):
                self.dump_entry(entry, "[v8:code_pointer_table]")
            elif self.is_js_dispatch_table_space(entry):
                self.dump_entry(entry, "[v8:js_dispatch_table]")
            elif self.is_code_range(entry):
                self.dump_entry(entry, "[v8:code_range]")
            elif self.is_new_space(entry):
                self.dump_entry(entry, "[v8:new_space]")
            elif self.is_old_space(entry):
                self.dump_entry(entry, "[v8:old_space]")
            elif self.is_ro_space(entry):
                self.dump_entry(entry, "[v8:ro_space]")
            elif self.is_array_buffer(entry):
                self.dump_entry(entry, "[v8:ArrayBuffer]")
            elif self.is_cage(entry):
                self.dump_entry(entry, "[v8:cage]")
            elif self.is_trusted_space(entry):
                self.dump_entry(entry, "[v8:trusted_space]")
            else:
                if args.vvverbose:
                    self.dump_entry(entry, "")

        # Order the results in ascending order
        self.out = self.out[::-1]

        self.print_output(check_terminal_size=True)
        return


@register_command
class V8ListMapsCommand(GenericCommand, BufferingOutput):
    """List v8 (Chromium and d8) built-in maps."""

    _cmdline_ = "v8-list-maps"
    _category_ = "05-b. Heap - Chromium/V8"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use map cache.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified built-in maps structure:",
        "",
        "                             +-cage-------------+",
        "chromium: partition-alloc    | +-ro_space-----+ |",
        "+-d8: glibc-heap-+           | | ...          | |",
        "| ...            |           | | ...          | |",
        "| *map           |------------>| map          | |",
        "| *map           |------------>| map          | |",
        "| *map1          |------------>| map1         |<----+",
        "| *map           |------------>| map          | |   |",
        "| *map           |------------>| map          | |   |",
        "| ...            |           | | ...          | |   + cage_base",
        "+----------------+           | | ...          | |   |",
        "                             | +-old_space----+ |   |",
        "                             | | ...          | |   |",
        "                             | | +0x10: ofs   |-----+",
        "                             | | ...          | |",
        "                             | +--------------+ |",
        "                             | | ...          | |",
        "                             | +--------------+ |",
        "                             | | ...          | |",
        "                             | +--------------+ |",
        "                             | ...              |",
        "                             +------------------+",
        "",
        "For Chromium: this command needs `--no-sandbox` to bypass `seccomp`.",
        "Also, since it uses V8 commands internally, `_v8_internal_Print_Object` must be resolvable.",
    ]
    _note_ = "\n".join(_note_)

    @staticmethod
    def redirect_stdout(output_path):
        from gef.commands.memory.patch import PatchCommand
        syscall_table = Syscall.get_syscall_table()

        # dup
        ret = ExecSyscall(syscall_table.name_table["dup"].nr, [1]).exec_code()
        stdout_oldfd = ret["reg"][runtime.current_arch.return_register]

        # open
        p = PatchCommand.PatchInfo(runtime.current_arch.sp, output_path.encode() + b"\0")
        p.patch(silent=True)
        flags = 0o100 | 0o1 | 0o1000 # O_CREAT | O_WRONLY | O_TRUNC
        ret = ExecSyscall(syscall_table.name_table["open"].nr, [runtime.current_arch.sp, flags, 0o666]).exec_code()
        file_fd = ret["reg"][runtime.current_arch.return_register]
        PatchCommand.PatchInfo.revert_to_tag(p.tag, silent=True)

        def u2i(x):
            x = struct.pack("<Q", x & 0xffff_ffff_ffff_ffff)
            return struct.unpack("<q", x)[0]

        if u2i(file_fd) < 0:
            # fail, revert dup
            ExecSyscall(syscall_table.name_table["dup2"].nr, [stdout_oldfd, 1]).exec_code()
            return None

        # dup2
        ExecSyscall(syscall_table.name_table["dup2"].nr, [file_fd, 1]).exec_code()

        # close
        ExecSyscall(syscall_table.name_table["close"].nr, [file_fd]).exec_code()
        return stdout_oldfd

    @staticmethod
    def revert_stdout(stdout_oldfd):
        if stdout_oldfd is None:
            return

        syscall_table = Syscall.get_syscall_table()

        # dup2
        ExecSyscall(syscall_table.name_table["dup2"].nr, [stdout_oldfd, 1]).exec_code()

        # close
        ExecSyscall(syscall_table.name_table["close"].nr, [stdout_oldfd]).exec_code()
        return

    @staticmethod
    def get_cage_base():
        res = gdb.execute("cage --no-pager", to_string=True)
        if "Not found" in res:
            return None

        for line in res.splitlines():
            line = Color.remove_color(line)
            if "[v8:cage]" in line or "[v8:ro_space]" in line:
                cage_base, *_ = line.split(None, 1)
                cage_base = int(cage_base, 16)
                return cage_base & 0x0000_ffff_0000_0000
        return None

    def get_old_space(self):
        res = gdb.execute("cage --no-pager", to_string=True)
        if "Not found" in res:
            return None

        for line in res.splitlines():
            line = Color.remove_color(line)
            if "[v8:old_space]" not in line:
                continue
            start, *_ = line.split()
            return int(start, 16)
        return None

    def get_heap_contents(self, map1):
        from gef.commands.process.base_address import HeapBaseCommand
        maps = ProcessMap.get_process_maps()
        pa_maps = [m for m in maps if m.path == "[anon:partition_alloc]"]
        if pa_maps:
            # get partition-alloc (for chromium)
            for m in pa_maps:
                if m.permission.value != Permission.READ | Permission.WRITE:
                    continue
                heap_contents = read_memory(m.page_start, m.size)
                heap_contents = slice_unpack(heap_contents, runtime.current_arch.ptrsize)
                if map1 in heap_contents:
                    break
            else:
                err("Could not find the partition-alloc heap")
                return None
        else:
            # get glibc heap (for d8)
            heap_base = HeapBaseCommand.heap_base()
            if not heap_base:
                err("Could not find the glibc heap")
                return None
            heap_section = ProcessMap.lookup_address(heap_base).section
            heap_contents = read_memory(heap_base, heap_section.size)
            heap_contents = slice_unpack(heap_contents, runtime.current_arch.ptrsize)
        return heap_contents

    def do_list_maps(self, region, cage_base):
        # old_space+0x10 has heap_object
        ofs = read_int32_from_memory(region + 0x10)
        map1 = cage_base + ofs
        if not is_valid_addr(map1):
            err("Memory access error")
            return

        # get heap contents
        heap_contents = self.get_heap_contents(map1)
        if heap_contents is None:
            return

        # get reference index (from glibc heap)
        try:
            sidx = eidx = heap_contents.index(map1)
        except ValueError:
            err("Could not find wanted maps")
            return

        """
        0x555555859178|+0x0000|+000: 0x000011b7000013e5  ->  0xa54b000013000004  <- cage_base + 0x10
        0x555555859180|+0x0008|+001: 0x000011b70000140d  ->  0xa64b000003000004
        0x555555859188|+0x0010|+002: 0x000011b700001435  ->  0xa74b000008000004
        0x555555859190|+0x0018|+003: 0x000011b70000145d  ->  0xa84b000004000004
        0x555555859198|+0x0020|+004: 0x000011b700001485  ->  0xa94b000003000004
        0x5555558591a0|+0x0028|+005: 0x000011b7000014ad  ->  0xaa4b000003000004
        0x5555558591a8|+0x0030|+006: 0x000011b7000014d5  ->  0xab4b000003000004
        0x5555558591b0|+0x0038|+007: 0x000011b7000014fd  ->  0xac4b000002000004
        """

        # glibc heap contains a array of addresses of v8 heap objects
        # find the top of the array
        cage_mask = cage_base & 0xffff_ffff_0000_0000
        while sidx >= 0:
            v = heap_contents[sidx]
            if v & 1 == 0:
                break
            if cage_mask != (v & 0xffff_ffff_0000_0000):
                break
            sidx -= 1
        sidx += 1

        # find the tail of the array
        while eidx < len(heap_contents):
            v = heap_contents[eidx]
            if v & 1 == 0:
                break
            if cage_mask != (v & 0xffff_ffff_0000_0000):
                break
            eidx += 1

        # dump
        try:
            # The v8 command simply invokes V8's own dump functions via an inferior function call.
            # The output is printed to stdout, but since it is not a GDB command, GDB cannot capture that output directly.
            # Therefore, GEF temporarily redirect stdout to collect the results.
            stdout_oldfd = None
            stdout_oldfd = V8ListMapsCommand.redirect_stdout(self.output_path)
            if stdout_oldfd is None:
                raise RuntimeError("Failed to redirect: {:s}".format(self.output_path))
            tqdm = GefUtil.get_tqdm()
            for idx in tqdm(range(sidx, eidx), leave=False):
                v = heap_contents[idx]
                gdb.execute("v8 {:#x}".format(v), to_string=True)
        finally:
            V8ListMapsCommand.revert_stdout(stdout_oldfd)
        return

    def list_maps(self, region, cage_base):
        self.output_path = os.path.join(GEF_TEMP_DIR, "v8-list-maps-{:#x}.txt".format(cage_base))

        # not found a cache file
        if self.args.rescan or not os.path.exists(self.output_path):
            self.do_list_maps(region, cage_base)
        else:
            info("Use cache")

        res = open(self.output_path).read()
        for line in res.splitlines():
            line = re.sub(r"^(0x[0-9a-f]+)", lambda x:Color.blueify(x.group(1)), line)
            self.out.append(line)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        cage_base = V8ListMapsCommand.get_cage_base()
        if not cage_base:
            err("Could not find cage base")
            return

        old_space_region = self.get_old_space()
        if not old_space_region:
            err("Could not find old space")
            return

        self.out = []
        self.list_maps(old_space_region, cage_base)
        self.print_output(check_terminal_size=True)
        return


@register_command
class V8DumpSpaceCommand(GenericCommand, BufferingOutput):
    """Dump v8 (Chromium and d8) heap objects in each space."""

    _cmdline_ = "v8-dump-space"
    _category_ = "05-b. Heap - Chromium/V8"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    spaces = ["old_space", "new_space", "ro_space", "trusted_space", "all", "o", "n", "r", "t", "a"]
    parser.add_argument("target_space", metavar="TARGET_SPACE", choices=spaces, nargs="?", default="all",
                        help="the space name to dump.")
    parser.add_argument("-m", "--max-count", type=AddressUtil.parse_address, default=0,
                        help="max count for each space.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="display also object details for string like objects (slow!).")
    parser.add_argument("-vv", "--vverbose", action="store_true",
                        help="display also object details for all objects (very slow!).")
    _syntax_ = parser.format_help()

    _note_ = [
        "It only works with the debug build of d8 or Chromium.",
        "Since many parts are detected heuristically and testing is insufficient,",
        "it is highly likely that it will not work depending on the version of v8.",
    ]
    _note_ = "\n".join(_note_)

    def get_target_regions(self):
        res = gdb.execute("cage --no-pager", to_string=True)
        if "Not found" in res:
            return []

        regions = []
        for line in res.splitlines():
            line = Color.remove_color(line)
            if self.args.target_space in ["all", "a"]:
                if "_space]" not in line:
                    continue
            elif self.args.target_space in ["old_space", "o"]:
                if "[v8:old_space]" not in line:
                    continue
            elif self.args.target_space in ["new_space", "n"]:
                if "[v8:new_space]" not in line:
                    continue
            elif self.args.target_space in ["ro_space", "r"]:
                if "[v8:ro_space]" not in line:
                    continue
            elif self.args.target_space in ["trusted_space", "t"]:
                if "[v8:trusted_space]" not in line:
                    continue
            start, limit, _, _, perm, path = line.split()
            start = int(start, 16)
            limit = int(limit, 16)
            regions.append([start, limit, perm, path])
        return regions

    def is_map(self, value, cage_base):
        if value & 1 == 0:
            return False # not a tagged pointer

        map_addr = cage_base + (value - 1) # untag
        if not is_valid_addr(map_addr):
            return False

        value2 = read_int32_from_memory(map_addr)
        if value2 & 1 == 0:
            return False # not a metamap

        meta_map_addr = cage_base + (value2 - 1) # untag
        if not is_valid_addr(meta_map_addr):
            return False
        return True

    instance_type_dic = {}

    def load_instance_type_dict(self):
        lines = open(self.instace_type_cache_path).read().splitlines()
        for line in lines:
            instance_type, type_name = line.split("=")
            self.instance_type_dic[int(instance_type)] = type_name
        return

    def append_instance_type_dict(self, instance_type, type_name):
        self.instance_type_dic[instance_type] = type_name

        with open(self.instace_type_cache_path, "a") as f:
            f.write("{:d}={:s}\n".format(instance_type, type_name))
        return

    def get_instance_name(self, map_addr):
        # load from cache file
        if not self.instance_type_dic:
            if os.path.exists(self.instace_type_cache_path):
                self.load_instance_type_dict()

        # fast path: load from cache
        instance_type = read_int16_from_memory((map_addr & ~1) + 8)
        if instance_type in self.instance_type_dic:
            return self.instance_type_dic[instance_type]

        # slow path
        try:
            stdout_oldfd = None
            stdout_oldfd = V8ListMapsCommand.redirect_stdout(self.output_path)
            if stdout_oldfd is None:
                raise RuntimeError("Failed to redirect: {:s}".format(self.output_path))
            gdb.execute("v8 {:#x}".format(map_addr | 1), to_string=True)
        finally:
            V8ListMapsCommand.revert_stdout(stdout_oldfd)

        map_content = open(self.output_path).read()
        if V8Command.is_chromium():
            # 0x06c300000475 <MetaMap (0x06c30000002d <null>)>
            r = re.search(r"<MetaMap ", map_content)
            if r:
                type_name = "MAP_TYPE"
                self.append_instance_type_dict(instance_type, type_name)
                return type_name

            # 0x06c30000049d <Map[28](ODDBALL_TYPE)>
            r = re.search(r"\(([A-Z_]+?)\)>$", map_content)
            if r:
                type_name = r.group(1)
                self.append_instance_type_dict(instance_type, type_name)
                return type_name
        else:
            r = re.search(r"- type: (.+)", map_content) # for d8
            if r:
                type_name = r.group(1)
                self.append_instance_type_dict(instance_type, type_name)
                return type_name
        return "???"

    def get_object_size(self, addr, map_addr, cage_base, area_end):
        """get header size and variable size"""

        """
        https://github.com/v8/v8/blob/main/src/objects/map.h
        Map layout:
          TaggedPointer   map - Always a pointer to the MetaMap root
          Int             The first int field
            Byte          [instance_size]
            ...
          Int             The second int field
            Short         [instance_type]
            ...
          ...
        """
        # fixed length pattern (map has instance size)
        instance_size = read_int8_from_memory(map_addr + 4)
        if instance_size > 0:
            return instance_size * 4, None

        # instance_size == 0
        instance_name = self.get_instance_name(map_addr)

        # Object sizes are manually specified by referencing src/objects.h etc.
        # TODO: inline property <-> external property
        if instance_name == "ARRAY_LIST_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 12, length * 4
        elif instance_name == "BIG_INT_BASE_TYPE":
            length = read_int32_from_memory(addr + 4)
            return 8, length * 4
        elif instance_name == "BYTECODE_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 8)
            length >>= 1
            length = align(length, 4)
            return 0x28, length
        elif instance_name == "BYTE_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            length = align(length, 4)
            return 8, length
        elif instance_name == "CLOSURE_FEEDBACK_CELL_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "CODE_TYPE":
            return 0x44, 0
        elif instance_name == "COVERAGE_INFO_TYPE":
            length = read_int16_from_memory(addr + 4)
            return 8, length * 4 * 4
        elif instance_name == "DESCRIPTOR_ARRAY_TYPE":
            length = read_int16_from_memory(addr + 4)
            return 0x14, length * 4 * 3
        elif instance_name == "DOUBLE_STRING_CACHE_TYPE":
            length = read_int32_from_memory(addr + 4)
            return 8, length * 12
        elif instance_name == "EMBEDDER_DATA_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            return 8, length * 4
        elif instance_name == "EPHEMERON_HASH_TABLE_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "FEEDBACK_METADATA_TYPE":
            length1 = read_int32_from_memory(addr + 4)
            if length1 != 0:
                length1 = (length1 - 1) // 6 + 1 # 5-bit encode
            length2 = read_int32_from_memory(addr + 8)
            length = align(length1 * 4 + length2 * 2, 4)
            return 12, length
        elif instance_name == "FEEDBACK_VECTOR_TYPE":
            length = read_int32_from_memory(addr + 4)
            return 0x1c, length * 4
        elif instance_name == "FIXED_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "FIXED_DOUBLE_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 8
        elif instance_name == "FREE_SPACE_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            length -= 2 # size of the free space including the header
            return 8, length * 4
        elif instance_name == "GLOBAL_DICTIONARY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "HASH_TABLE_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "INSTRUCTION_STREAM_TYPE": # in code_range
            header = 0x10
            length = read_int32_from_memory(addr + 12)
            length = align(header + length, 0x40)
            return header, length - header
        elif instance_name == "INTERNALIZED_ONE_BYTE_STRING_TYPE":
            length = read_int32_from_memory(addr + 8)
            length = align(length, 4)
            return 12, length
        elif instance_name == "INTERNALIZED_TWO_BYTE_STRING_TYPE":
            length = read_int32_from_memory(addr + 8)
            length = align(length * 2, 4)
            return 12, length
        elif instance_name == "NAME_DICTIONARY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "NAME_TO_INDEX_HASH_TABLE_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "NATIVE_CONTEXT_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, (length * 4) + (2 * 4)
        elif instance_name == "NUMBER_DICTIONARY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "OBJECT_BOILERPLATE_DESCRIPTION_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 0x10, length * 4
        elif instance_name == "ORDERED_HASH_MAP_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "ORDERED_HASH_SET_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "ORDERED_NAME_DICTIONARY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "PREPARSE_DATA_TYPE":
            data_length = read_int32_from_memory(addr + 4)
            children_length = read_int32_from_memory(addr + 8)
            padding = align(data_length, 4)
            length = data_length + padding + children_length * 4
            return 12, length
        elif instance_name == "PROPERTY_ARRAY_TYPE":
            length_or_hash = read_int32_from_memory(addr + 4)
            length = length_or_hash & 0x3ff
            length >>= 1
            return 8, length * 4
        elif instance_name == "PROTECTED_FIXED_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "PROTECTED_WEAK_FIXED_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "REGISTERED_SYMBOL_TABLE_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "REG_EXP_MATCH_INFO_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 0x14, length * 4
        elif instance_name == "SCOPE_INFO_TYPE":
            # The logic is very complicated, so the v8 command is used instead.
            try:
                stdout_oldfd = None
                stdout_oldfd = V8ListMapsCommand.redirect_stdout(self.output_path)
                if stdout_oldfd is None:
                    raise RuntimeError("Failed to redirect: {:s}".format(self.output_path))
                gdb.execute("v8 {:#x}".format(addr | 1), to_string=True)
            finally:
                V8ListMapsCommand.revert_stdout(stdout_oldfd)
            content = open(self.output_path).read()
            r = re.search(r"- length: (\d+)", content)
            if r:
                return 4, int(r.group(1)) * 4
            else:
                return 4, 5 * 4
        elif instance_name == "SCRIPT_CONTEXT_TABLE_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 0x10, length * 4
        elif instance_name == "SCRIPT_CONTEXT_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "SEQ_ONE_BYTE_STRING_TYPE":
            length = read_int32_from_memory(addr + 8)
            length = align(length, 4)
            return 12, length
        elif instance_name == "SEQ_TWO_BYTE_STRING_TYPE":
            length = read_int32_from_memory(addr + 8)
            length = align(length * 2, 4)
            return 12, length
        elif instance_name == "SHARED_SEQ_ONE_BYTE_STRING_TYPE":
            pass # TODO
        elif instance_name == "SHARED_SEQ_TWO_BYTE_STRING_TYPE":
            pass # TODO
        elif instance_name == "SIMPLE_NAME_DICTIONARY_TYPE":
            pass # TODO
        elif instance_name == "SIMPLE_NUMBER_DICTIONARY_TYPE":
            pass # TODO
        elif instance_name == "SLOPPY_ARGUMENTS_ELEMENTS_TYPE":
            pass # TODO
        elif instance_name == "SMALL_ORDERED_HASH_MAP_TYPE":
            pass # TODO
        elif instance_name == "SMALL_ORDERED_HASH_SET_TYPE":
            pass # TODO
        elif instance_name == "SMALL_ORDERED_NAME_DICTIONARY_TYPE":
            pass # TODO
        elif instance_name == "STRONG_DESCRIPTOR_ARRAY_TYPE":
            pass # TODO
        elif instance_name == "SWISS_NAME_DICTIONARY_TYPE":
            length = read_int32_from_memory(addr + 8)
            data_table_len = length * 2 * 4
            ctrl_table_len = align(length + 0x10, 4)
            property_details_table_len = align(length, 4)
            return 0x10, data_table_len + ctrl_table_len + property_details_table_len
        elif instance_name == "TRANSITION_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "TRUSTED_BYTE_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            length = align(length, 4)
            return 8, length
        elif instance_name == "TRUSTED_FIXED_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "TRUSTED_WEAK_FIXED_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4
        elif instance_name == "TURBOSHAFT_FLOAT64_SET_TYPE_TYPE":
            pass # TODO
        elif instance_name == "TURBOSHAFT_WORD32_SET_TYPE_TYPE":
            pass # TODO
        elif instance_name == "TURBOSHAFT_WORD64_SET_TYPE_TYPE":
            pass # TODO
        elif instance_name == "WASM_DISPATCH_TABLE_TYPE": # ???
            return 0x1c, 0
        elif instance_name == "WASM_NULL_TYPE":
            pass # TODO
        elif instance_name == "WASM_TYPE_INFO_TYPE":
            pass # TODO
        elif instance_name == "WEAK_ARRAY_LIST_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 12, length * 4
        elif instance_name == "WEAK_FIXED_ARRAY_TYPE":
            length = read_int32_from_memory(addr + 4)
            length >>= 1
            return 8, length * 4

        instance_type = read_int16_from_memory((map_addr & ~1) + 8)
        self.warn_add_out("Unknown instance_type: {:#x}".format(instance_type))
        return 0, 0

    def walk_space(self, start, limit, cage_base):
        v = read_int32_from_memory(start)
        if v & 1:
            addr = start
        else:
            addr = start + 0x10

        try:
            from tqdm import tqdm
        except ImportError:
            tqdm = None
        if tqdm:
            pbar = tqdm(total=limit - start, leave=False)

        count = 0
        while addr < limit:
            # check max_count
            if self.args.max_count:
                if count >= self.args.max_count:
                    return

            # get compressed pointer
            try:
                map_raw = read_int32_from_memory(addr)
            except gdb.MemoryError:
                self.warn_add_out("Cannot read memory at {:#x}".format(addr))
                return

            # check if magic number
            if map_raw == 0xbeadbeef:
                self.info_add_out("End of objects")
                return

            # check if it is a map
            if not self.is_map(map_raw, cage_base):
                self.warn_add_out("Could not find map")
                return
            map_addr = cage_base + map_raw - 1 # untag

            # get size, type, name
            header_size, variable_size = self.get_object_size(addr, map_addr, cage_base, limit)
            instance_type = read_int16_from_memory(map_addr + 8)
            instance_name = self.get_instance_name(map_addr + 1)

            # dump
            if variable_size is not None:
                size_str = "{:#x}+{:#x},".format(header_size, variable_size)
            else:
                size_str = "{:#x},".format(header_size)

            line = "{:s}: map:{:#x}, sz={:12s} type={:#05x}(={:s})".format(
                Color.colorify_hex(addr + 1, 'blue'),
                map_addr + 1, size_str, instance_type, instance_name,
            )
            self.out.append(line)

            # dump details
            if (self.args.verbose and "STRING" in instance_name) or self.args.vverbose:
                try:
                    stdout_oldfd = None
                    stdout_oldfd = V8ListMapsCommand.redirect_stdout(self.output_path)
                    if stdout_oldfd is None:
                        raise RuntimeError("Failed to redirect: {:s}".format(self.output_path))
                    gdb.execute("v8 {:#x}".format(addr | 1), to_string=True)
                finally:
                    V8ListMapsCommand.revert_stdout(stdout_oldfd)
                content = open(self.output_path).read()
                if not content:
                    self.warn_add_out("No content; Something is wrong")
                    return
                self.out.extend(content.splitlines()[:20])

            # check if last
            if instance_name == "FREE_SPACE_TYPE":
                self.info_add_out("End of objects")
                return

            # goto next
            if header_size == 0:
                return
            if variable_size is None:
                total_size = header_size
            else:
                total_size = header_size + variable_size
            addr += total_size

            if tqdm:
                pbar.update(total_size)

            count += 1
        return

    def walk_spaces(self, target_regions, cage_base):
        tqdm = GefUtil.get_tqdm()
        for start, limit, perm, path in tqdm(target_regions, leave=False):
            self.out.append(titlify("{:#x}-{:#x} {:s} {:s}".format(start, limit, perm, path)))
            self.walk_space(start, limit, cage_base)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_64",))
    def do_invoke(self, args):
        cage_base = V8ListMapsCommand.get_cage_base()
        if not cage_base:
            err("Cannot determine cage base")
            return
        info("The cage base: {:#x}".format(cage_base))

        self.output_path = os.path.join(GEF_TEMP_DIR, "v8-dump-space-{:#x}.txt".format(cage_base))
        self.instace_type_cache_path = os.path.join(GEF_TEMP_DIR, "v8-dump-space-instance-type.txt")

        target_regions = self.get_target_regions()
        if not target_regions:
            err("Cannot determine target space address range")
            return

        self.out = []
        self.walk_spaces(target_regions, cage_base)
        self.print_output(check_terminal_size=True)
        return


@register_command
class V8Command(GenericCommand):
    """Print v8 tagged object, or load more commands from internet."""

    _cmdline_ = "v8"
    _category_ = "05-b. Heap - Chromium/V8"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address, nargs="?",
                       help="target map address.")
    group.add_argument("-l", "--load-v8-gdbinit", action="store_true",
                       help="load gdbinit for v8 from internet.")
    group.add_argument("-L", "--list-command", action="store_true",
                       help="show newly added commands from v8 gdbinit.")
    _syntax_ = parser.format_help()

    def get_gdbinit(self):
        gdbinit_filename = os.path.join(GEF_TEMP_DIR, "gdbinit-v8")
        if not os.path.exists(gdbinit_filename):
            # https://chromium.googlesource.com/v8/v8/+/refs/heads/main/tools/gdbinit
            url = "https://chromium.googlesource.com/v8/v8/+/refs/heads/main/tools/gdbinit?format=TEXT"
            gdbinit_data = http_get(url)
            import base64
            gdbinit_data = base64.b64decode(gdbinit_data)
            open(gdbinit_filename, "wb").write(gdbinit_data)
            info("Download gdbinit from internet")
        else:
            info("Reuse gdbinit cached previously")
        return gdbinit_filename

    @staticmethod
    @Cache.cache_this_session
    def is_chromium():
        maps = ProcessMap.get_process_maps()
        for m in maps:
            if m.path.startswith("[anon:partition_alloc]"):
                return True
        return False

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    def do_invoke(self, args):
        if args.load_v8_gdbinit:
            gdbinit_filename = self.get_gdbinit()
            try:
                gdb.execute("source {:s}".format(gdbinit_filename))
                info("Successfully loaded")
            except gdb.error:
                err("Failed to load")
            return

        if args.list_command:
            gdb.execute("v8 -l", to_string=True)
            gdbinit_filename = self.get_gdbinit()
            data = open(gdbinit_filename).read()
            for line in data.splitlines():
                line = line.strip()
                if line.startswith(("alias ", "define ")):
                    comm = line.split()[1]
                    gef_print(titlify(comm))
                    gdb.execute("help {:s}".format(comm))
                elif line.startswith(("super(", "super (")) and '"' in line:
                    comm = line.split('"')[-2]
                    gef_print(titlify(comm))
                    gdb.execute("help {:s}".format(comm))
            return

        if args.address:
            try:
                # Since this command is used so often, it can be implemented without loading from internet.
                cmd = "call (void) _v8_internal_Print_Object((void*)({:#x}))".format(args.address)
                gdb.execute(cmd)
                # When attached to chromium and run, the newline is not generated,
                # so it is not displayed immediately due to buffering. As a workaround, run putchar('\n') and fflush(0).
                if V8Command.is_chromium():
                    cmd = "call (void) putchar(0x0a)"
                    gdb.execute(cmd)
                    cmd = "call (void) fflush(0)"
                    gdb.execute(cmd)
            except gdb.error:
                pass
        return


@register_command
class PartitionAllocDumpCommand(GenericCommand, BufferingOutput):
    """PartitionAlloc free-list viewer for chromium stable."""

    _cmdline_ = "partition-alloc-dump"
    _category_ = "05-b. Heap - Chromium/V8"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    modes = ["fast_malloc", "array_buffer", "buffer", "fm", "ab", "b"]
    parser.add_argument("target_buffer_root", choices=modes,
                        help="the target buffer_root. The last three are abbreviated forms.")
    parser.add_argument("-f", "--force-heuristic", action="store_true",
                        help="use heuristic roots detection.")
    parser.add_argument("-r", "--root", type=AddressUtil.parse_address,
                        help="the memory address of target {buffer,array_buffer,fast_malloc}_root_.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="display also empty slots.")
    parser.add_argument("--debug", action="store_true", help="[FOR DEVELOPER] enable debug print.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} array_buffer  # walk from array_buffer_root_",
        "{0:s} ab            # same above",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Chromium mainline is too fast to develop. So if parse is failed, you need fix this gef.py.",
        "",
        "Simplified partition alloc structure:",
        "",
        "+-root-----------------+",
        "| ...                  |    +---->+-extent------------+  +-->+-extent------------+  +-> ...",
        "| next_super_page_     |    |     | next              |--+   | next              |--+",
        "| next_partition_page_ |    |     +-------------------+      +-------------------+",
        "| ...                  |    |",
        "| first_extent_        |----+",
        "| direct_map_list_     |--------->+-direct_map_extent-+  +-->+-direct_map_extent-+  +-> ...",
        "| ...                  |          | bucket            |  |   | bucket            |  |",
        "|                      |          | next_extent       |--+   | next_extent       |--+",
        "|                      |          +-------------------+      +-------------------+",
        "|                      |",
        "+-bucket[0](0x20)------+",
        "| head                 |--------->+-slot_span---------+  +-->+-slot_span---------+  +-> ...",
        "| slot_size            |<---------| bucket            |  |   | bucket            |  |",
        "| ...                  |    +-----| freelist_head     |  |   | freelist_head     |  |",
        "+-bucket[1](0x20)------+    |     | next_slot_span    |--+   | next_slot_span    |--+",
        "| head                 |    |     +-------------------+      +-------------------+",
        "| slot_size            |    |",
        "| ...                  |    |",
        "+----------------------+    +---->+-slot--------------+",
        "| ...                  |          | next              |---+",
        "|                      |          | (freed)           |   |",
        "+----------------------+          +-slot--------------+   |",
        "                                  |                   |   |",
        "                                  | (used)            |   |",
        "                                  +-slot--------------+<--+",
        "                              +---| next              |",
        "                              |   | (freed)           |",
        "                              |   +-slot--------------+",
        "                              |   |                   |",
        "                              |   | (used)            |",
        "                              +-->+-slot--------------+",
        "                                  | next              |---> NULL",
        "                                  | (freed)           |",
        "                                  +-slot--------------+",
        "                                  |                   |",
        "                                  |                   |",
        "                                  +-------------------+",
        "",
        "`extent`, `slot_span` and `slot` are in super_page.",
        "",
        "     [~v144.x]                    [v145.x~; PA_CONFIG(MOVE_METADATA_OUT_OF_GIGACAGE)=y]",
        "     +-super_page-(2MB)-----+      +-super_page(for meta)-+ +-super_page(for chunk)+",
        "4KB  | Guard Page           |      | Guard Page           | | Guard Page           |",
        "     +----------------------+      +----------------------+ +----------------------+",
        "4KB  | extent * 1           |      | extend * 1           | | Unused               |",
        "     | slot_span * 126      |      | slot_span * 126      | |                      |",
        "     | unused * 1           |      | unused * 1           | |                      |",
        "     +----------------------+      +----------------------+ +----------------------+",
        "8KB  | Guard Page           |      | Guard Page           | | Guard Page           |",
        "     +----------------------+      +----------------------+ +----------------------+",
        "16KB | Partition Page #1    |      | ...                  | | Partition Page #1    |",
        "     |   slot               |      |                      | |   slot               |",
        "     |   slot               |      |                      | |   slot               |",
        "     |   ...                |      |                      | |   ...                |",
        "     +----------------------+      |                      | +----------------------+",
        "     | ...                  |      |                      | | ...                  |",
        "     +----------------------+      |                      | +----------------------|",
        "16KB | Partition Page #126  |      |                      | | Partition Page #126  |",
        "     |   slot               |      |                      | |   slot               |",
        "     |   slot               |      |                      | |   slot               |",
        "     |   ...                |      |                      | |   ...                |",
        "     +----------------------+      +----------------------+ +----------------------+",
        "12KB | Unused               |      | Unused               | | Unused               |",
        "     +----------------------+      +----------------------+ +----------------------+",
        " 4KB | Guard Page           |      | Guard Page           | | Guard Page           |",
        "     +----------------------+      +----------------------+ +----------------------+",
        "",
        "                                   * super_page_for_meta - metadata_offset_ == super_page_for_chunk",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete="use_user_complete")
        return

    def complete(self, text, word): # noqa
        if text.strip() in self.modes:
            # already matched
            return []

        if text == "":
            # no prefix
            return [s for s in self.modes if ((word is None) or (s and word in s))]

        # finally, look for possible values for given prefix
        return [s for s in self.modes if s and s.startswith(text.strip())]

    @Cache.cache_this_session
    def get_roots_heuristic(self):
        """Search for fast_malloc_root, array_buffer_root_ and buffer_root_"""
        from gef.commands.process.base_address import HeapBaseCommand

        # the pointers to each root are in the RW area.
        # first, we list the RW area.
        filepath = Path.get_filepath(append_proc_root_prefix=False)
        maps = ProcessMap.get_process_maps()
        if is_64bit():
            codebase = ProcessMap.get_section_base_address(filepath)
            mask = 0x0000_ffff_0000_0000
            chromium_rw_maps = [p for p in maps if p.permission.value == Permission.READ | Permission.WRITE]
            chromium_rw_maps = [p for p in chromium_rw_maps if (p.page_start & mask) == (codebase & mask) and p.path != filepath]
        elif is_32bit():
            mask = 0xff00_0000
            heapbase = HeapBaseCommand.heap_base()
            chromium_rw_maps = [p for p in maps if p.permission.value == Permission.READ | Permission.WRITE]
            chromium_rw_maps = [p for p in chromium_rw_maps if p.page_start < heapbase and p.path != filepath]

        # n_gram([1,2,3,4,5], 3) -> [[1, 2, 3], [2, 3, 4], [3, 4, 5]]
        def n_gram(target, n):
            for idx in range(len(target) - n + 1):
                yield target[idx:idx + n]

        # Check the RW area
        roots = []
        for maps in chromium_rw_maps:
            # explode to each qword (if 64 bit arch) or dword (if 32 bit arch)
            data_list = slice_unpack(read_memory(maps.page_start, maps.size), runtime.current_arch.ptrsize)
            addr_list = list(range(maps.page_start, maps.page_end, runtime.current_arch.ptrsize))

            """
            https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/renderer/  \
            platform/wtf/allocator/partitions.cc

            partition_alloc::PartitionRoot* Partitions::fast_malloc_root_ = nullptr;
            partition_alloc::PartitionRoot* Partitions::array_buffer_root_ = nullptr;
            partition_alloc::PartitionRoot* Partitions::buffer_root_ = nullptr;

            0x5a849775d5a8 <WTF::Partitions::fast_malloc_root_>:                                         0x0000000000000000
            0x5a849775d5b0 <WTF::Partitions::array_buffer_root_>:                                        0x00005a8497761040
            0x5a849775d5b8 <WTF::Partitions::buffer_root_>:                                              0x00005a849775d600
            0x5a849775d5c0 <guard variable for WTF::Partitions::Initialize()::initialized>:              0x0000000100000101
            ...
            0x5a8497759bc0 <WTF::Partitions::InitializeOnce()::fast_malloc_allocator>:                   0x0000000000000000
            ...
            0x5a849775d600 <WTF::Partitions::InitializeOnce()::buffer_allocator>:                        0x0000000000010000
            ...
            0x5a8497761040 <WTF::Partitions::InitializeArrayBufferPartition()::array_buffer_allocator>:  0x0000000000000000
            """
            # check consecutive quadruples
            for addr, data in zip(n_gram(addr_list, 4), n_gram(data_list, 4)):
                # root pointer address and root address are close (see above example)
                if data[0] != 0 and (addr[0] & mask) != (data[0] & mask):
                    # fast_malloc_root_ may be zero. but if non-zero, it holds address close to itself
                    continue
                if (addr[1] & mask) != (data[1] & mask):
                    # array_buffer_root_ is must be non-zero. it holds address close to itself
                    continue
                if (addr[2] & mask) != (data[2] & mask):
                    # buffer_root_ is must be non-zero. it holds address close to itself
                    continue
                # they should be aligned
                if data[0] & 0x7:
                    continue
                if data[1] & 0x7:
                    continue
                if data[2] & 0x7:
                    continue
                # initialized must be bool 0x01
                if (data[3] & 0xff) != 0x01:
                    continue
                # check root size
                buffer_root_size = data[1] - data[2]
                if buffer_root_size < 0x300: # 0x300 is heuristic value
                    continue
                if buffer_root_size > 0x4000: # 0x4000 is heuristic value
                    continue
                # check root struct.
                """
                The first 64 bytes of root are mostly 0 due to padding considering the cache line.
                This is same both at 64-bit and 32bit arch.

                [WTF::Partitions::InitializeOnce()::buffer_allocator]
                0x5a849775d600: 0x0000000000010000      0x0000000000000004
                0x5a849775d610: 0x0000000000000000      0x00000000ffffffff
                0x5a849775d620: 0x0000000400000001      0xfffffe7fec785000
                0x5a849775d630: 0x0000000000000000      0x0000000000000000

                [WTF::Partitions::InitializeArrayBufferPartition()::array_buffer_allocator]
                0x5a8497761040: 0x0000000000000000      0x0000000000000000
                0x5a8497761050: 0x0000000000000001      0x00000000ffffffff
                0x5a8497761060: 0x0000000000000000      0xffffcefbec787000
                0x5a8497761070: 0x0000000000000000      0x0000000000000000
                """
                if b"\0" * 8 not in read_memory(data[1], 64):
                    continue
                if b"\0" * 8 not in read_memory(data[2], 64):
                    continue
                if self.args.debug:
                    info(f"buffer_root_size: {buffer_root_size:#x}")
                    gdb.execute(f"ml x/8xg {data[1]:#x}; x/8xg {data[2]:#x}")
                # add candidate
                Root = collections.namedtuple("Root", ["name", "address"])
                root_candidate = [
                    Root("fast_malloc_root_", addr[0]),
                    Root("array_buffer_root_", addr[1]),
                    Root("buffer_root_", addr[2]),
                ]
                roots.append(root_candidate)

        # debug print
        if len(roots) == 0:
            err("Could not find any roots, try check code")
            return []

        if len(roots) == 1:
            for r in roots[0]:
                info("Found: {:s}: {:#x}".format(r.name, r.address))
            return roots[0]

        err("Candidates for root are found in multiple locates, try check code")
        for root in roots:
            for r in root:
                gef_print("  candidate: {:20s} {:#x}".format(r.name, r.address))
            gef_print()
        return []

    def get_roots(self, force_heuristic):

        def get_root(root_string):
            # newer version
            try:
                root_addr = AddressUtil.parse_address("&'blink::Partitions::{:s}'".format(root_string))
                Root = collections.namedtuple("Root", ["name", "address"])
                return [Root(root_string, root_addr)]
            except gdb.error:
                pass
            # older version
            try:
                root_addr = AddressUtil.parse_address("&'WTF::Partitions::{:s}'".format(root_string))
                Root = collections.namedtuple("Root", ["name", "address"])
                return [Root(root_string, root_addr)]
            except gdb.error:
                pass
            return []

        roots = []
        # user specific
        if self.args.root:
            Root = collections.namedtuple("Root", ["name", "address"])
            roots += [Root(self.args.target_buffer_root + "_root_", self.args.root)]
            return roots
        # try from symbols
        if not force_heuristic:
            for root_string in ["fast_malloc_root_", "array_buffer_root_", "buffer_root_"]:
                roots += get_root(root_string)
        # maybe no symbols, try heuristic
        if len(roots) == 0:
            info("Use heuristic search")
            roots = self.get_roots_heuristic()
        # retry checking
        if len(roots) == 0:
            info("Could not find the symbol")
        return roots

    @Cache.cache_until_next
    def get_sentinel_slot_spans(self):
        """sentinel_slot_span is default slot_span, so search for it."""
        sentinel = []

        # new version
        try:
            ns = "partition_alloc::internal::SlotSpanMetadata<(partition_alloc::internal::MetadataKind)1>"
            t = AddressUtil.parse_address("&'{:s}::sentinel_slot_span_'".format(ns))
            sentinel.append(t)
            return sentinel
        except gdb.error:
            pass

        # old version
        try:
            t = AddressUtil.parse_address("&'base::internal::SlotSpanMetadata<true>::sentinel_slot_span_'")
            sentinel.append(t)
        except gdb.error:
            pass
        try:
            f = AddressUtil.parse_address("&'base::internal::SlotSpanMetadata<false>::sentinel_slot_span_'")
            sentinel.append(f)
        except gdb.error:
            pass
        return sentinel

    def read_root(self, addr, name):
        ptrsize = runtime.current_arch.ptrsize
        root = {}
        root["name"] = name
        root["addr"] = current = read_int_from_memory(addr)
        """
        https://source.chromium.org/chromium/chromium/src/+/main:base/allocator/partition_allocator/  \
        src/partition_alloc/partition_root.h

        struct base::PartitionRoot {
            struct alignas(internal::kPartitionCachelineSize) Settings {
                BucketDistribution bucket_distribution = BucketDistribution::kNeutral; // uint8_t
                size_t thread_cache_index = internal::kInvalidThreadCacheIndex;
                bool with_thread_cache = false;
                bool use_cookie = false;
                bool brp_enabled_ = false;
                size_t in_slot_metadata_size = 0;
                internal::pool_handle pool_handle = internal::pool_handle::kNullPoolHandle;
                internal::PoolOffsetLookup offset_lookup;
                internal::ReservationOffsetTable reservation_offset_table;
                bool eventually_zero_freed_memory = false;
                internal::SchedulerLoopQuarantineConfig scheduler_loop_quarantine;
                bool memory_tagging_enabled_ = false;
                bool use_random_memory_tagging_enabled_ = false;
                TagViolationReportingMode memory_tagging_reporting_mode_ = TagViolationReportingMode::kUndefined;
                ThreadIsolationOption thread_isolation;
                uint32_t extras_size = 0;
                std::ptrdiff_t metadata_offset_ = 0;
                bool enable_free_with_size = false;
                bool enable_strict_free_size_check = true;
            } settings_; // 0x40 bytes or 0x80 bytes or 0xc0 bytes
            internal::Lock lock_;  // 8 bytes
            Bucket buckets_[BucketIndexLookup::kNumBuckets] = {};
            Bucket sentinel_bucket_{};
            bool initialized_ = false;
            std::atomic<size_t> total_size_of_committed_pages_{0};
            std::atomic<size_t> max_size_of_committed_pages_{0};
            std::atomic<size_t> total_size_of_super_pages_{0};
            std::atomic<size_t> total_size_of_direct_mapped_pages_{0};
            std::atomic<size_t> total_size_of_allocated_bytes_{0};
            std::atomic<size_t> max_size_of_allocated_bytes_{0};
            std::atomic<uint64_t> syscall_count_;
            std::atomic<uint64_t> syscall_total_time_ns_;
            std::atomic<size_t> total_size_of_brp_quarantined_bytes{0};
            std::atomic<size_t> total_count_of_brp_quarantined_slots_{0};
            std::atomic<size_t> cumulative_size_of_brp_quarantined_bytes_{0};
            std::atomic<size_t> cumulative_count_of_brp_quarantined_slots_{0};
            size_t empty_slot_spans_dirty_bytes_ PA_GUARDED_BY(internal::PartitionRootLock(this)) = 0;
            int max_empty_slot_spans_dirty_bytes_shift_ = 3;
            uintptr_t next_super_page_ = 0;
            uintptr_t next_partition_page_ = 0;
            uintptr_t next_partition_page_end_ = 0;
            SuperPageExtentEntry* current_extent_ = nullptr;
            SuperPageExtentEntry* first_extent_ = nullptr;
            DirectMapExtent* direct_map_list_ PA_GUARDED_BY(internal::PartitionRootLock(this)) = nullptr;
            SlotSpanMetadata* global_empty_slot_span_ring_[internal::kMaxEmptySlotSpanRingSize] \
                PA_GUARDED_BY(internal::PartitionRootLock(this)) = {};
            int16_t global_empty_slot_span_ring_index_ PA_GUARDED_BY(internal::PartitionRootLock(this)) = 0;
            int16_t global_empty_slot_span_ring_size_ PA_GUARDED_BY(internal::PartitionRootLock(this)) = \
                internal::kDefaultEmptySlotSpanRingSize;
            uintptr_t inverted_self_ = 0;
            internal::Lock thread_cache_construction_lock_; // 8 bytes
            size_t scheduler_loop_quarantine_branch_capacity_in_bytes_ = 0;
            internal::SchedulerLoopQuarantineRoot scheduler_loop_quarantine_root_;
            internal::GlobalSchedulerLoopQuarantineBranch scheduler_loop_quarantine_;
            internal::GlobalSchedulerLoopQuarantineBranch scheduler_loop_quarantine_for_advanced_memory_safety_checks_;
        };
        """
        x = read_int_from_memory(current + 0x40 + 8) # sizeof(struct Settings) + sizeof(lock_)
        if is_valid_addr(x): # buckets[0]->active_slot_spans_head
            current += 0x40 # sizeof(struct Settings) is 1 cache line
        else:
            x = read_int_from_memory(current + 0x80 + 8) # sizeof(struct Settings) + sizeof(lock_)
            if is_valid_addr(x): # buckets[0]->active_slot_spans_head
                current += 0x80 # sizeof(struct Settings) is 2 cache lines
            else:
                current += 0xc0 # sizeof(struct Settings) is 3 cache lines

        def get_metadata_offset(root_addr, current_addr):
            """
            # v145.x~ has PA_CONFIG(MOVE_METADATA_OUT_OF_GIGACAGE)
            0x599a3e48af40|+0x0000|+000: settings (=&root)        : 0x0000000000010000
            0x599a3e48af48|+0x0008|+001:                          : 0x0000000000000004
            0x599a3e48af50|+0x0010|+002:                          : 0x0000000000000002
            0x599a3e48af58|+0x0018|+003:                          : 0x000009f400000000
            0x599a3e48af60|+0x0020|+004:                          : 0xfffffffc00000000
            0x599a3e48af68|+0x0028|+005:                          : 0x0000599a3e1dc018
            0x599a3e48af70|+0x0030|+006:                          : 0x000009f400000000
            0x599a3e48af78|+0x0038|+007:                          : 0xfffffffc00000000
            0x599a3e48af80|+0x0040|+008:                          : 0x0000000000000000
            0x599a3e48af88|+0x0048|+009:                          : 0x0000000000000000
            0x599a3e48af90|+0x0050|+010:                          : 0xaaaaaaaaaa000000
            0x599a3e48af98|+0x0058|+011:                          : 0x00000000000f0000
            0x599a3e48afa0|+0x0060|+012:                          : 0x0000000000000000
            0x599a3e48afa8|+0x0068|+013:                          : 0x0000000000000000
            0x599a3e48afb0|+0x0070|+014:                          : 0x0000000000000000
            0x599a3e48afb8|+0x0078|+015:                          : 0x0000000000000000
            0x599a3e48afc0|+0x0080|+016:                          : 0x00000000ffffffff
            0x599a3e48afc8|+0x0088|+017:                          : 0x0000000000000004
            0x599a3e48afd0|+0x0090|+018: settings.metadata_offset_: 0x00002e37f278b000 <-- here
            0x599a3e48afd8|+0x0098|+019:                          : 0x0000000000000100
            0x599a3e48afe0|+0x00a0|+020:                          : 0x0000000000000000
            0x599a3e48afe8|+0x00a8|+021:                          : 0x0000000000000000
            0x599a3e48aff0|+0x00b0|+022:                          : 0x0000000000000000
            0x599a3e48aff8|+0x00b8|+023:                          : 0x0000000000000000
            0x599a3e48b000|+0x00c0|+024: lock_                    : 0x0000000000000000
            0x599a3e48b008|+0x00c8|+025: buckets[0]               : 0x0000382bf298b920
            0x599a3e48b010|+0x00d0|+026: buckets[0]               : 0x0000000000000000
            0x599a3e48b018|+0x00d8|+027: buckets[0]               : 0x0000000000000000
            0x599a3e48b020|+0x00e0|+028: buckets[0]               : 0x0000000400000010
            0x599a3e48b028|+0x00e8|+029: buckets[0]               : 0x0000004000000000
            0x599a3e48b030|+0x00f0|+030: buckets[0]               : 0x0000000000000000
            """
            if current_addr - root_addr != 0xc0:
                return get_pagesize()
            data = read_memory(root_addr + 0x80, 0x40)
            for x in slice_unpack(data, runtime.current_arch.ptrsize):
                if x & 0xfff:
                    continue
                if x == 0:
                    continue
                if (root_addr & 0x0000_ffff_ff00_0000) == (x & 0x0000_ffff_ff00_0000):
                    continue
                if (x & 0xffff_ffff) == 0:
                    continue
                return x
            return get_pagesize()

        root["metadata_offset_"] = get_metadata_offset(root["addr"], current)

        root["lock_"] = read_int64_from_memory(current)
        current += 8

        # for 32bit, there is 2 patterns because aligned or packed
        if is_32bit():
            if self.align_pad is None:
                x = read_int_from_memory(current)
                if x == 0:
                    self.align_pad = True
                else:
                    self.align_pad = False
            if self.align_pad:
                current += ptrsize

        root["buckets_"] = []
        while True:
            if read_int_from_memory(current) == 1: # search for `bool initialized`
                break
            bucket, current = self.read_bucket(current)
            root["buckets_"].append(bucket)

        root["sentinel_bucket_"] = root["buckets_"].pop()

        root["initialized_"] = read_int_from_memory(current) & 0xff
        current += ptrsize # with pad
        root["total_size_of_committed_pages_"] = read_int_from_memory(current)
        current += ptrsize
        root["max_size_of_committed_pages_"] = read_int_from_memory(current)
        current += ptrsize
        root["total_size_of_super_pages_"] = read_int_from_memory(current)
        current += ptrsize
        root["total_size_of_direct_mapped_pages_"] = read_int_from_memory(current)
        current += ptrsize
        root["total_size_of_allocated_bytes_"] = read_int_from_memory(current)
        current += ptrsize
        root["max_size_of_allocated_bytes_"] = read_int_from_memory(current)
        current += ptrsize
        root["syscall_count_"] = read_int_from_memory(current)
        current += ptrsize
        root["syscall_total_time_ns_"] = read_int_from_memory(current)
        current += ptrsize
        root["total_size_of_brp_quarantined_bytes"] = read_int_from_memory(current)
        current += ptrsize
        root["total_count_of_brp_quarantined_slots_"] = read_int_from_memory(current)
        current += ptrsize
        root["cumulative_size_of_brp_quarantined_bytes_"] = read_int_from_memory(current)
        current += ptrsize
        root["cumulative_count_of_brp_quarantined_slots_"] = read_int_from_memory(current)
        current += ptrsize
        root["empty_slot_spans_dirty_bytes_"] = read_int32_from_memory(current)
        current += ptrsize # with pad
        root["max_empty_slot_spans_dirty_bytes_shift_"] = read_int32_from_memory(current)
        current += ptrsize # with pad
        root["next_super_page_"] = read_int_from_memory(current)
        current += ptrsize
        root["next_partition_page_"] = read_int_from_memory(current)
        current += ptrsize
        root["next_partition_page_end_"] = read_int_from_memory(current)
        current += ptrsize
        root["current_extent_"] = read_int_from_memory(current)
        current += ptrsize
        root["first_extent_"] = read_int_from_memory(current)
        current += ptrsize
        root["direct_map_list_"] = read_int_from_memory(current)
        current += ptrsize

        root["global_empty_slot_span_ring_"] = []
        inv = root["addr"] ^ AddressUtil.get_vmem_end_mask()
        while True:
            if read_int_from_memory(current + ptrsize) == inv: # search for `inverted_self_`
                break
            x = read_int_from_memory(current)
            current += ptrsize
            root["global_empty_slot_span_ring_"].append(x)
        root["global_empty_slot_span_ring_index_"] = read_int16_from_memory(current)
        current += 2
        root["global_empty_slot_span_ring_size_"] = read_int16_from_memory(current)
        current += 2
        if is_64bit():
            current += 4 # pad
        root["inverted_self_"] = read_int_from_memory(current)
        current += ptrsize
        root["thread_cache_construction_lock_"] = read_int64_from_memory(current)
        current += 8
        root["scheduler_loop_quarantine_branch_capacity_in_bytes_"] = read_int32_from_memory(current)
        current += ptrsize # with pad
        root["scheduler_loop_quarantine_root_"] = read_int_from_memory(current)
        current += ptrsize
        root["scheduler_loop_quarantine_"] = read_int_from_memory(current)
        current += ptrsize
        root["scheduler_loop_quarantine_for_advanced_memory_safety_checks_"] = read_int_from_memory(current)
        current += ptrsize

        Root = collections.namedtuple("Root", root.keys())
        root = Root(*root.values())
        return root, current

    @Cache.cache_until_next
    def read_bucket(self, addr):
        ptrsize = runtime.current_arch.ptrsize
        bucket = {}
        bucket["addr"] = current = addr
        """
        https://source.chromium.org/chromium/chromium/src/+/main:base/allocator/partition_allocator/  \
        src/partition_alloc/partition_bucket.h

        struct base::internal::PartitionBucket {
            SlotSpanMetadata* active_slot_spans_head;
            SlotSpanMetadata* empty_slot_spans_head;
            SlotSpanMetadata* decommitted_slot_spans_head;
            uint32_t slot_size;
            uint32_t num_system_pages_per_slot_span : 8;
            uint32_t num_full_slot_spans : 24;
            uint64_t slot_size_reciprocal;
            bool can_store_raw_size;
        };
        """
        bucket["active_slot_spans_head"] = read_int_from_memory(current)
        current += ptrsize
        bucket["empty_slot_spans_head"] = read_int_from_memory(current)
        current += ptrsize
        bucket["decommitted_slot_spans_head"] = read_int_from_memory(current)
        current += ptrsize
        bucket["slot_size"] = read_int32_from_memory(current)
        current += 4
        x = read_int32_from_memory(current)
        bucket["num_system_pages_per_slot_span"] = x & 0xff
        bucket["num_full_slot_spans"] = (x >> 8) & 0xff_ffff
        current += 4

        # for 32bit, there is 2 patterns because aligned or packed
        if is_32bit() and self.align_pad:
            current += 4
        bucket["slot_size_reciprocal"] = read_int64_from_memory(current)
        current += 8

        x = read_int32_from_memory(current)
        bucket["can_store_raw_size"] = x & 0xff
        current += ptrsize # with pad

        Bucket = collections.namedtuple("Bucket", bucket.keys())
        bucket = Bucket(*bucket.values())
        return bucket, current

    @Cache.cache_until_next
    def read_extent(self, addr):
        ptrsize = runtime.current_arch.ptrsize
        extent = {}
        extent["addr"] = current = addr
        extent["super_page_base"] = current - 0x1000
        """
        https://source.chromium.org/chromium/chromium/src/+/main:base/allocator/partition_allocator/  \
        src/partition_alloc/partition_superpage_extent_entry.h

        struct PartitionSuperPageExtentEntry {
          PartitionRootBase* root;
          PartitionSuperPageExtentEntry* next;
          uint16_t number_of_consecutive_super_pages;
          uint16_t number_of_nonempty_slot_spans;
        };
        """
        extent["root"] = read_int_from_memory(current)
        current += ptrsize
        extent["next"] = read_int_from_memory(current)
        current += ptrsize
        extent["number_of_consecutive_super_pages"] = read_int16_from_memory(current)
        current += 2
        extent["number_of_nonempty_slot_spans"] = read_int16_from_memory(current)
        current += 2
        extent["super_page_end"] = extent["super_page_base"] + extent["number_of_consecutive_super_pages"] * 0x20_0000

        Extent = collections.namedtuple("Extent", extent.keys())
        extent = Extent(*extent.values())
        return extent, current

    @Cache.cache_until_next
    def read_direct_map(self, addr):
        ptrsize = runtime.current_arch.ptrsize
        direct_map = {}
        direct_map["addr"] = current = addr
        """
        https://source.chromium.org/chromium/chromium/src/+/main:base/allocator/partition_allocator/  \
        src/partition_alloc/partition_direct_map_extent.h

        struct PartitionDirectMapExtent {
          PartitionDirectMapExtent* next_extent;
          PartitionDirectMapExtent* prev_extent;
          const PartitionBucket* bucket;
          size_t reservation_size;
          size_t padding_for_alignment;
        };
        """
        direct_map["next_extent"] = read_int_from_memory(current)
        current += ptrsize
        direct_map["prev_extent"] = read_int_from_memory(current)
        current += ptrsize
        direct_map["bucket"] = read_int_from_memory(current)
        current += ptrsize
        direct_map["reservation_size"] = read_int_from_memory(current)
        current += ptrsize
        direct_map["padding_for_alignment"] = read_int_from_memory(current)
        current += ptrsize

        DirectMap = collections.namedtuple("DirectMap", direct_map.keys())
        direct_map = DirectMap(*direct_map.values())
        return direct_map, current

    @Cache.cache_until_next
    def read_slot_span(self, addr):
        ptrsize = runtime.current_arch.ptrsize
        slot_span = {}
        slot_span["addr"] = current = addr
        slot_span["super_page_addr"] = AddressUtil.normalize_address(
            (slot_span["addr"] & get_pagesize_mask_high()) - self.root.metadata_offset_,
        )
        slot_span["partition_page_index"] = (slot_span["addr"] & get_pagesize_mask_low()) // 0x20
        super_page_addr_offset = slot_span["partition_page_index"] * get_pagesize() * 4
        slot_span["partition_page_start"] = slot_span["super_page_addr"] + super_page_addr_offset
        """
        https://source.chromium.org/chromium/chromium/src/+/main:base/allocator/partition_allocator/  \
        src/partition_alloc/partition_page.h

        struct SlotSpanMetadata {
          FreelistEntry* freelist_head = nullptr;
          SlotSpanMetadata* next_slot_span = nullptr;
          PartitionBucket* const bucket = nullptr;
          uint32_t num_allocated_slots : kMaxSlotsPerSlotSpanBits; // 15 bits
          uint32_t num_unprovisioned_slots : kMaxSlotsPerSlotSpanBits; // 15 bits
          uint32_t marked_full : 1;
          const uint32_t can_store_raw_size_ : 1;
          uint16_t freelist_is_sorted_ : 1;
          uint16_t in_empty_cache_ : 1;
          uint16_t empty_cache_index_ : internal::base::bits::BitWidth(kMaxEmptySlotSpanRingSize - 1); // 7 or 10 bits
        };
        """
        slot_span["freelist_head"] = read_int_from_memory(current)
        current += ptrsize
        slot_span["next_slot_span"] = read_int_from_memory(current)
        current += ptrsize
        slot_span["bucket"] = read_int_from_memory(current)
        current += ptrsize
        x = read_int32_from_memory(current)
        current += 4
        slot_span["num_allocated_slots"] = (x >> 0) & 0x7fff
        slot_span["num_unprovisioned_slots"] = (x >> 15) & 0x7fff
        slot_span["marked_full"] = (x >> 30) & 1
        slot_span["can_store_raw_size_"] = (x >> 31) & 1

        x = read_int16_from_memory(current)
        current += 2
        slot_span["freelist_is_sorted_"] = (x >> 0) & 1
        slot_span["in_empty_cache_"] = (x >> 1) & 1
        slot_span["empty_cache_index_"] = (x >> 2) & 0x3ff

        SlotSpan = collections.namedtuple("SlotSpan", slot_span.keys())
        slot_span = SlotSpan(*slot_span.values())
        return slot_span, current

    def C(self, address):
        # coloring function for heap address
        management_color = Config.get_gef_setting("theme.heap_management_address")

        # in extent
        current = self.root.current_extent_
        while current:
            extent, _ = self.read_extent(current)
            if extent.super_page_base <= address < extent.super_page_end:
                return Color.colorify_hex(address, management_color)
            current = extent.next

        # not in extent, but valid
        if is_valid_addr(address):
            return str(ProcessMap.lookup_address(address))

        # not valid
        return "{:#x}".format(address)

    def P(self, address):
        # coloring function for heap page address
        page_address_color = Config.get_gef_setting("theme.heap_page_address")
        return Color.colorify_hex(address, page_address_color)

    def dump_root(self, root):
        self.out.append(titlify("*{} @ {:#x}".format(root.name, root.addr)))
        self.out.append("struct Settings settings_:                                      ...")
        self.out.append("std::ptrdiff_t settings.metadata_offset_:                       {:#x}".format(
            root.metadata_offset_,
        ))
        self.out.append("::partition_alloc::Lock lock_:                                  {:#x}".format(
            root.lock_,
        ))
        self.out.append("Bucket buckets_[{:3d}]:".format(len(root.buckets_)))
        for idx, bucket in enumerate(root.buckets_):
            self.dump_bucket(bucket, root, idx)
        if self.args.verbose:
            self.out.append("Bucket sentinel_bucket_:")
            self.dump_bucket(root.sentinel_bucket_, root)
        else:
            self.out.append("Bucket sentinel_bucket_:                                        ...")
        self.out.append("bool initialized_:                                              {:#x}".format(
            root.initialized_,
        ))
        self.out.append("std::atomic<size_t> total_size_of_committed_pages_:             {:#x}".format(
            root.total_size_of_committed_pages_,
        ))
        self.out.append("std::atomic<size_t> max_size_of_committed_pages_:               {:#x}".format(
            root.max_size_of_committed_pages_,
        ))
        self.out.append("std::atomic<size_t> total_size_of_super_pages_:                 {:#x}".format(
            root.total_size_of_super_pages_,
        ))
        self.out.append("std::atomic<size_t> total_size_of_direct_mapped_pages_:         {:#x}".format(
            root.total_size_of_direct_mapped_pages_,
        ))
        self.out.append("std::atomic<size_t> total_size_of_allocated_bytes_:             {:#x}".format(
            root.total_size_of_allocated_bytes_,
        ))
        self.out.append("std::atomic<size_t> max_size_of_allocated_bytes_:               {:#x}".format(
            root.max_size_of_allocated_bytes_,
        ))
        self.out.append("std::atomic<uint64_t> syscall_count_:                           {:#x}".format(
            root.syscall_count_,
        ))
        self.out.append("std::atomic<uint64_t> syscall_total_time_ns_:                   {:#x}".format(
            root.syscall_total_time_ns_,
        ))
        self.out.append("std::atomic<size_t> total_size_of_brp_quarantined_bytes:        {:#x}".format(
            root.total_size_of_brp_quarantined_bytes,
        ))
        self.out.append("std::atomic<size_t> total_count_of_brp_quarantined_slots_:      {:#x}".format(
            root.total_count_of_brp_quarantined_slots_,
        ))
        self.out.append("std::atomic<size_t> cumulative_size_of_brp_quarantined_bytes_:  {:#x}".format(
            root.cumulative_size_of_brp_quarantined_bytes_,
        ))
        self.out.append("std::atomic<size_t> cumulative_count_of_brp_quarantined_slots_: {:#x}".format(
            root.cumulative_count_of_brp_quarantined_slots_,
        ))
        self.out.append("size_t empty_slot_spans_dirty_bytes_:                           {:#x}".format(
            root.empty_slot_spans_dirty_bytes_,
        ))
        self.out.append("int max_empty_slot_spans_dirty_bytes_shift_:                    {:#x}".format(
            root.max_empty_slot_spans_dirty_bytes_shift_,
        ))
        self.out.append("uintptr_t next_super_page_:                                     {:s}".format(
            self.P(root.next_super_page_),
        ))
        self.out.append("uintptr_t next_partition_page_:                                 {:s}".format(
            self.P(root.next_partition_page_),
        ))
        self.out.append("uintptr_t next_partition_page_end_:                             {:s}".format(
            self.P(root.next_partition_page_end_),
        ))
        self.out.append("SuperPageExtentEntry* current_extent_:                          {:s}".format(
            self.C(root.current_extent_),
        ))
        self.dump_extent_list(root.current_extent_)
        self.out.append("SuperPageExtentEntry* first_extent_:                            {:s}".format(
            self.C(root.first_extent_),
        ))
        self.dump_extent_list(root.first_extent_)
        self.out.append("DirectMapExtent* direct_map_list_:                              {:s}".format(
            self.C(root.direct_map_list_),
        ))
        self.dump_direct_map_list(root.direct_map_list_, root)
        ring_len = len(root.global_empty_slot_span_ring_)
        if self.args.verbose:
            self.out.append("SlotSpanMetadata* global_empty_slot_span_ring_[{:4d}]:".format(
                ring_len,
            ))
            for i in range(len(root.global_empty_slot_span_ring_)):
                colored_slot_span = self.C(root.global_empty_slot_span_ring_[i])
                self.out.append("    global_empty_slot_span_ring_[{:4d}]:                         {:s}".format(
                    i, colored_slot_span,
                ))
        else:
            self.out.append("SlotSpanMetadata* global_empty_slot_span_ring_[{:4d}]:           ...".format(
                ring_len,
            ))
        self.out.append("int16_t global_empty_slot_span_ring_index_:                     {:#x}".format(
            root.global_empty_slot_span_ring_index_,
        ))
        self.out.append("int16_t global_empty_slot_span_ring_size_:                      {:#x}".format(
            root.global_empty_slot_span_ring_size_,
        ))
        inv_inv = root.inverted_self_ ^ AddressUtil.get_vmem_end_mask()
        self.out.append("uintptr_t inverted_self_:                                       {:#x} (=~{!s})".format(
            root.inverted_self_, ProcessMap.lookup_address(inv_inv),
        ))
        self.out.append("internal::Lock thread_cache_construction_lock_:                 {:#x}".format(
            root.thread_cache_construction_lock_,
        ))
        self.out.append("size_t scheduler_loop_quarantine_branch_capacity_in_bytes_:     {:#x}".format(
            root.scheduler_loop_quarantine_branch_capacity_in_bytes_,
        ))
        self.out.append("internal::SchedulerLoopQuarantineRoot scheduler_loop_quarantine_root_: {:#x}".format(
            root.scheduler_loop_quarantine_root_,
        ))
        self.out.append("internal::GlobalSchedulerLoopQuarantineBranch scheduler_loop_quarantine_: {:#x}".format(
            root.scheduler_loop_quarantine_,
        ))
        self.out.append("internal::GlobalSchedulerLoopQuarantineBranch "
                        "scheduler_loop_quarantine_for_advanced_memory_safety_checks_: {:#x}".format(
            root.scheduler_loop_quarantine_for_advanced_memory_safety_checks_,
        ))
        return

    def dump_extent_list(self, head):
        try:
            current = head
            while current:
                extent, _ = self.read_extent(current)
                self.out.append("    -> extent @{:s}".format(
                    self.C(extent.addr),
                ))
                self.out.append("           root:{!s} ".format(
                    ProcessMap.lookup_address(extent.root),
                ))
                super_page_info = "{:s} - {:s}".format(
                    self.P(extent.super_page_base), self.P(extent.super_page_end),
                )
                page_info = "(total 0x200000(2MB) * {:d} pages)".format(
                    extent.number_of_consecutive_super_pages,
                )
                self.out.append("           super_page:{:s} {:s}".format(
                    super_page_info, page_info,
                ))
                self.out.append("           non_empty_slot_spans:{:d} ".format(
                    extent.number_of_nonempty_slot_spans,
                ))
                self.out.append("           next:{:s}".format(
                    self.C(extent.next),
                ))
                current = extent.next
        except Exception:
            self.err_add_out("Corrupted?")
        return

    def dump_direct_map_list(self, head, root):
        try:
            current = head
            while current:
                direct_map, _ = self.read_direct_map(current)
                self.out.append("    -> direct_map @{:s}: ".format(
                    self.C(direct_map.addr),
                ))
                self.out.append("           next_extent:{:s} ".format(
                    self.C(direct_map.next_extent),
                ))
                self.out.append("           prev_extent:{:s} ".format(
                    self.C(direct_map.prev_extent),
                ))
                self.out.append("           bucket:{:s} ".format(
                    self.C(direct_map.bucket),
                ))
                self.out.append("           reservation_size:{:#x}".format(
                    direct_map.reservation_size,
                ))
                self.out.append("           padding_for_alignment:{:#x}".format(
                    direct_map.padding_for_alignment,
                ))
                bucket, _ = self.read_bucket(direct_map.bucket)
                self.dump_bucket(bucket, root)
                current = direct_map.next_extent
        except Exception:
            self.err_add_out("Corrupted?")
        return

    def dump_bucket(self, bucket, root, idx=None):
        sentinel1 = self.get_sentinel_slot_spans() # from symbol
        sentinel2 = [root.sentinel_bucket_.active_slot_spans_head] # from heuristic search
        sentinel_or_0 = list(set(sentinel1 + sentinel2 + [0x0])) # uniq

        if not self.args.verbose:
            if bucket.active_slot_spans_head in sentinel_or_0:
                return # skip printing

        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")
        label_active_color = Config.get_gef_setting("theme.heap_label_active")
        label_inactive_color = Config.get_gef_setting("theme.heap_label_inactive")

        slot_size = Color.colorify("{:#7x}".format(bucket.slot_size), chunk_size_color)
        if idx is not None:
            self.out.append("    buckets_[{:3d}](slot_size:{:s}) @{!s}".format(
                idx, slot_size, ProcessMap.lookup_address(bucket.addr),
            ))
        else:
            self.out.append("    bucket(slot_size:{:s}) @{!s}".format(
                slot_size, ProcessMap.lookup_address(bucket.addr),
            ))
        self.out.append("        num_system_pages_per_slot_span:{:#x} ".format(
            bucket.num_system_pages_per_slot_span,
        ))
        self.out.append("        num_full_slot_spans:{:#x} ".format(bucket.num_full_slot_spans))
        self.out.append("        slot_size_reciprocal:{:#x}".format(bucket.slot_size_reciprocal))
        self.out.append("        can_store_raw_size:{:#x}".format(bucket.can_store_raw_size))

        if self.args.verbose:
            target_list = ["active_slot_spans_head", "empty_slot_spans_head", "decommitted_slot_spans_head"]
        else:
            target_list = ["active_slot_spans_head"]

        for key in target_list:
            head = getattr(bucket, key)
            # sentinel can be ignored, so skip
            if not self.args.verbose and head in sentinel_or_0:
                continue
            if head in sentinel_or_0:
                # print sentinel (verbose)
                colored_key = Color.colorify(key, label_inactive_color)
                self.out.append("        {:s}:{:s} (=sentinel_pages)".format(colored_key, self.C(head)))
            else:
                # default
                colored_key = Color.colorify(key, label_active_color)
                self.out.append("        {:s}:{:s}".format(colored_key, self.C(head)))
            self.dump_slot_span(head, bucket)
        return

    def dump_slot_span(self, head, bucket):
        current = head
        while current:
            try:
                slot_span, _ = self.read_slot_span(current)
            except Exception:
                self.err_add_out("Corrupted?")
                break
            self.out.append("            -> slot_span @{:s} (#{:3d} of super_page @{:s})".format(
                self.C(slot_span.addr), slot_span.partition_page_index, self.P(slot_span.super_page_addr),
            ))
            self.out.append("                   next_slot_span:{:s} ".format(
                self.C(slot_span.next_slot_span),
            ))
            self.out.append("                   slot_span_area:{:s}-{:s} ".format(
                self.P(slot_span.partition_page_start),
                self.P(slot_span.partition_page_start + bucket.num_system_pages_per_slot_span * get_pagesize()),
            ))
            self.out.append("                   num_allocated_slots:{:#x}".format(
                slot_span.num_allocated_slots),
            )
            self.dump_freelist(slot_span.freelist_head, bucket, slot_span)
            current = slot_span.next_slot_span
        return

    def dump_freelist(self, head, bucket, slot_span):
        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

        self.out.append("                   freelist_head:{:s} ".format(self.C(head)))

        slot_size = bucket.slot_size
        page_start = slot_span.partition_page_start
        page_end = page_start + bucket.num_system_pages_per_slot_span * get_pagesize()

        text = ""
        cnt = 0
        chunk = head
        seen = []
        while chunk:
            if cnt % 6 == 0:
                if cnt > 0:
                    text += "\n"
                text += " " * 23

            if chunk in seen:
                text += Color.colorify("-> {:#x} (loop) ".format(chunk), corrupted_msg_color)
                break

            if chunk < page_start or page_end <= chunk:
                text += Color.colorify("-> {:#x} (corrupted: out of range {:#x}-{:#x}) ".format(
                    chunk, page_start, page_end,
                ), corrupted_msg_color)
                break

            if (chunk - page_start) % slot_size != 0:
                text += Color.colorify("-> {:#x} (corrupted: not aligned) ".format(chunk), corrupted_msg_color)
                break

            try:
                next_chunk = byteswap(read_int_from_memory(chunk))
                if is_64bit() and next_chunk:
                    next_chunk |= chunk & 0xffff_ffff_0000_0000
            except gdb.MemoryError:
                text += Color.colorify("-> {:#x} (corrupted: invalid address) ".format(chunk), corrupted_msg_color)
                break

            text += "-> " + Color.colorify_hex(chunk, freed_address_color) + " "
            cnt += 1
            seen.append(chunk)
            chunk = next_chunk

        if cnt > 0:
            text += "(num: {:#x})".format(cnt)

        if text:
            self.out.append(text)
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware", "wine"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        if is_32bit():
            self.align_pad = None

        if self.args.target_buffer_root == "fm":
            self.args.target_buffer_root = "fast_malloc"
        elif self.args.target_buffer_root == "b":
            self.args.target_buffer_root = "buffer"
        elif self.args.target_buffer_root == "ab":
            self.args.target_buffer_root = "array_buffer"

        self.out = []
        for r in self.get_roots(args.force_heuristic):

            ok = False
            if args.target_buffer_root == "fast_malloc":
                if r.name == "fast_malloc_root_":
                    ok = True
            if args.target_buffer_root == "array_buffer":
                if r.name == "array_buffer_root_":
                    ok = True
            if args.target_buffer_root == "buffer":
                if r.name == "buffer_root_":
                    ok = True

            if not ok:
                continue

            try:
                root, _ = self.read_root(r.address, r.name)
            except Exception:
                mem_value = read_int_from_memory(r.address)
                err("Parse error {:s}: @ {:#x} -> {:#x}".format(r.name, r.address, mem_value))
                exc_type, exc_value, exc_traceback = sys.exc_info()
                gef_print(exc_value)
                continue

            self.root = root # for coloring
            self.dump_root(root)

        self.print_output()
        return


