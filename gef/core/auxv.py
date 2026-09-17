"""GEF ELF Auxiliary Vector helpers (Layer 1).

Contains `Auxv`, a collection of utility functions related to ELF Auxiliary
Vectors (retrieved from gdb's `info auxv` with a stack-walking fallback).

Reads of the mutable global `current_arch` go through `runtime.current_arch`
(never a by-name import) to avoid the stale-binding pitfall documented in
runtime.py. References to modules that are not yet extracted (process,
gef.commands.auxv) are imported lazily inside the method that needs them.
"""
import gdb
import re

from gef.core import runtime
from gef.core.cache import Cache
from gef.core.config import Config
from gef.core.memory import is_valid_addr, read_int_from_memory, read_memory


class Auxv:
    """A collection of utility functions that are related to ELF Auxiliary Vectors."""

    @staticmethod
    def get_auxiliary_walk(offset=0):
        """Find AUXV by walking stack."""

        if Config.get_gef_setting("context.disable_auxv"):
            return None

        if runtime.current_arch.sp is None:
            return None

        from gef.core.process import is_in_kernel

        if is_in_kernel():
            return None

        # do not use get_pagesize(), get_pagesize_mask_high(), etc.
        # because get_pagesize() -> Auxv.get_auxiliary_values() -> Auxv.get_auxiliary_walk()
        page_size = 0x1000
        addr = runtime.current_arch.sp & ~(page_size - 1)

        # check readable or not
        if not is_valid_addr(addr):
            return None

        # find stack bottom
        try:
            while True:
                if b"\x7fELF" == read_memory(addr, 4):
                    break
                addr += page_size
        except gdb.MemoryError: # if read error, that is stack bottom
            pass
        current = addr - runtime.current_arch.ptrsize * 2 - offset

        # check readable or not again
        if not is_valid_addr(current):
            # something is wrong, maybe stack is pivoted
            return None

        # find auxv end
        while True:
            a = read_int_from_memory(current)
            b = read_int_from_memory(current + runtime.current_arch.ptrsize)
            if a == b == 0:
                break
            current -= runtime.current_arch.ptrsize * 2

        # skip dummy null if exist
        for _ in range(1024):
            a = read_int_from_memory(current)
            if a == 7: # AT_BASE
                break
            current -= runtime.current_arch.ptrsize * 2
        else:
            return None

        from gef.commands.auxv import AuxvCommand

        # find auxv start
        auxv_keys = AuxvCommand.AT_CONSTANTS.keys()
        while read_int_from_memory(current) in auxv_keys:
            current -= runtime.current_arch.ptrsize * 2
        current += runtime.current_arch.ptrsize * 2

        # parse auxv
        res = {}
        while True:
            key = read_int_from_memory(current)
            val = read_int_from_memory(current + runtime.current_arch.ptrsize)
            if key not in AuxvCommand.AT_CONSTANTS:
                break
            res[AuxvCommand.AT_CONSTANTS[key]] = val
            if key == 0:
                break
            current += runtime.current_arch.ptrsize * 2

        # test
        if "AT_ENTRY" not in res:
            return None
        if "AT_PHDR" not in res:
            return None
        if "AT_RANDOM" not in res:
            return None
        if "AT_BASE" not in res:
            return None
        if "AT_NULL" not in res:
            return None

        return res

    # Auxv.get_auxiliary_values (under qemu-user mode) is very slow,
    # Because it may call Auxv.get_auxiliary_walk that repeats read_memory many times to find the auxv value.
    # Cache.cache_until_next is ineffective due to frequent resets (each time the `stepi` runs).
    # Fortunately, auxv rarely changes.
    # The cache is retained until explicitly cleared.
    @staticmethod
    @Cache.cache_this_session
    def get_auxiliary_values(force_heuristic=False):
        """Retrieve the auxiliary values of the current execution.
        Return None if not running, or a dict() of values."""

        if Config.get_gef_setting("context.disable_auxv"):
            return None

        from gef.core.process import is_alive, is_in_kernel, is_kgdb, is_qemu_system, is_vmware, is_wine

        if not is_alive():
            return None

        if is_in_kernel():
            return None

        if is_qemu_system() or is_kgdb() or is_vmware() or is_wine():
            return None

        def fast_path():
            try:
                result = gdb.execute("info auxv", to_string=True)
            except gdb.error:
                return None
            res = {}
            for line in result.splitlines():
                tmp = line.split()
                auxv_type = tmp[1]
                if auxv_type in ("AT_PLATFORM", "AT_EXECFN", "AT_BASE_PLATFORM"):
                    m = re.match("^.+?(0x[0-9a-f]+)", line)
                    res[auxv_type] = int(m.group(1), 0)
                else:
                    res[auxv_type] = int(tmp[-1], 0)
            return res

        def slow_path():
            if runtime.current_arch is None:
                return None
            for offset in [0, runtime.current_arch.ptrsize]:
                res = Auxv.get_auxiliary_walk(offset)
                if res:
                    return res
            return None

        # ----

        if force_heuristic:
            return slow_path()

        return fast_path() or slow_path()

