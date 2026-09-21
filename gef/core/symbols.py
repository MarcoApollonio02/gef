"""Symbol resolution helpers and optional-dependency loaders (Layer 1).

`Symbol` is a `@staticmethod` collection of symbol name/address resolution
helpers (gdb `info symbol`, KGDB `ksymaddr-remote`, monitor fallback).
`ModuleLoader` holds the `load_*` decorator wrappers that lazily import
optional third-party packages (capstone, unicorn, keystone, ropper, binwalk,
crccheck, codext, angr) and raise the standard GEF `ImportWarning` when the
package is missing.

References to not-yet-extracted modules (gef.arch.* arch classes in
`load_capstone`) are late-imported inside the referencing wrapper.
"""
import functools
import re
import sys

import gdb

from gef.core.cache import Cache
from gef.core.color import Color
from gef.core.instruction import Instruction
from gef.core.memory import is_valid_addr

class Symbol:
    """A collection of utility functions that are related to symbols."""

    # `info symbol` called from gdb_get_location is heavy processing.
    # Moreover, AddressUtil.recursive_dereference causes each address to be resolved every time.
    # Cache.cache_until_next is ineffective due to frequent resets (each time the `stepi` runs).
    # Fortunately, symbol information rarely changes.
    # The cache is retained until explicitly cleared.
    @staticmethod
    @Cache.cache_this_session
    def gdb_get_location(address):
        """e.g., 0xffffffff9f6bd2a0 -> ('commit_creds', 0)"""
        if address is None:
            return None

        # Do not use gdb.format_address available from gdb 13.x,
        # because symbols added with add-symbol-temporary may not be recognized.

        # slow path uses `info symbol` command
        name = None
        sym = gdb.execute("info symbol {:#x}".format(address), to_string=True)
        if sym.startswith("No symbol matches"):
            return None

        i = sym.find(" in section ")
        sym = sym[:i].split()
        if len(sym) >= 3 and sym[-1].isdigit():
            # e.g., ptmalloc_init.part + 1 in section .text of /lib/x86_64-linux-gnu/libc.so.6
            name = " ".join(sym[:-2])
            offset = int(sym[-1])
        else:
            # e.g., ptmalloc_init.part in section .text of /lib/x86_64-linux-gnu/libc.so.6
            name = " ".join(sym)
            offset = 0
        return name, offset

    @staticmethod
    @Cache.cache_this_session
    def get_symbol_string(addr, nosymbol_string=""):
        """e.g., 0xffffffff9f6bd2a1 -> ' <commit_creds+0x1>'. Be careful to include leading spaces."""
        try:
            if isinstance(addr, str):
                addr = Color.remove_color(addr)
                addr = int(addr, 16)
            ret = Symbol.gdb_get_location(addr)
            if ret is None:
                return nosymbol_string
        except (ValueError, gdb.error):
            return nosymbol_string

        sym_name, sym_offset = ret[0], ret[1]
        if addr - sym_offset == 0:
            return nosymbol_string

        sym_name = Instruction.smartify_text(sym_name)
        if sym_offset == 0:
            return " <{}>".format(sym_name)
        else:
            return " <{}+{:#x}>".format(sym_name, sym_offset)

    @staticmethod
    def get_ksymaddr(sym):
        """e.g., 'commit_creds' -> 0xffffffff9f6bd2a0"""
        try:
            res = gdb.execute("ksymaddr-remote --quiet --no-pager --exact {:s}".format(sym), to_string=True)
            return int(res.split()[0], 16)
        except (gdb.error, IndexError, ValueError):
            return None

    @staticmethod
    def get_ksymaddr_multiple(sym):
        """e.g., 'set_is_seen' -> [0xffffffffba146db0,0xffffffffba6d84e0,0xffffffffba6dd170]"""
        out = []
        try:
            ret = gdb.execute("ksymaddr-remote --quiet --no-pager --exact {:s}".format(sym), to_string=True)
            for line in ret.splitlines():
                addr = int(line.split()[0], 16)
                out.append(addr)
            return out
        except (gdb.error, IndexError, ValueError):
            return None

    @staticmethod
    def get_ksymaddr_symbol(addr):
        """e.g., 0xffffffff9f6bd2a0 -> 'commit_creds'"""
        try:
            res = gdb.execute("ksymaddr-remote --quiet --no-pager {:#x}".format(addr), to_string=True)
            res = res.splitlines()[-1]
            return res.split()[2]
        except (gdb.error, IndexError):
            return None

    @staticmethod
    def get_symbol_by_monitor(symbol):
        from gef.core.process import is_kdb
        if not is_kdb():
            return None
        res = gdb.execute("monitor {:s}".format(symbol), to_string=True)
        r = re.search(symbol + r" = 0x(\S+)", res)
        if not r:
            return None
        v = int(r.group(1), 16)
        if not is_valid_addr(v):
            return None
        return v


class ModuleLoader:
    def load_capstone(f):
        """Decorator wrapper to load capstone."""

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                capstone = __import__("capstone")
                if capstone.cs_version()[0] == 6:
                    from gef.arch.alpha import ALPHA
                    from gef.arch.hppa import HPPA, HPPA64
                    from gef.arch.loongarch64 import LOONGARCH64
                    LOONGARCH64.capstone_support = True
                    ALPHA.capstone_support = True
                    HPPA.capstone_support = True
                    HPPA64.capstone_support = True
                return f(*args, **kwargs)
            except ImportError as err:
                msg = "Missing `capstone` package for Python, try installing with `pip install capstone`"
                raise ImportWarning(msg) from err

        return wrapper


    def load_unicorn(f):
        """Decorator wrapper to load unicorn."""

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                __import__("unicorn")

                from gef.core.process import is_ppc32, is_riscv32, is_riscv64, is_s390x

                if is_ppc32(): # unicorn does not support ppc64
                    try:
                        __import__("unicorn.ppc_const")
                    except ImportError:
                        pass

                if is_riscv32() or is_riscv64():
                    try:
                        __import__("unicorn.riscv_const")
                    except ImportError:
                        pass

                if is_s390x():
                    try:
                        __import__("unicorn.s390x_const")
                    except ImportError:
                        pass

                return f(*args, **kwargs)
            except ImportError as err:
                msg = "Missing `unicorn` package for Python, try installing with `pip install unicorn`"
                raise ImportWarning(msg) from err

        return wrapper


    def load_keystone(f):
        """Decorator wrapper to load keystone."""

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                __import__("keystone")
                return f(*args, **kwargs)
            except ImportError as err:
                msg = "Missing `keystone-engine` package for Python, try installing with `pip install keystone-engine`"
                raise ImportWarning(msg) from err

        return wrapper


    def load_ropper(f):
        """Decorator wrapper to load ropper."""

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                __import__("ropper")
                return f(*args, **kwargs)
            except ImportError as err:
                msg = "Missing `ropper` package for Python, try installing with `pip install ropper`"
                raise ImportWarning(msg) from err

        return wrapper


    def load_binwalk(f):
        """Decorator wrapper to load binwalk."""

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                __import__("binwalk")
                return f(*args, **kwargs)
            except ImportError as err:
                msg = "Missing `binwalk` package for Python, try installing with `apt install binwalk`"
                raise ImportWarning(msg) from err

        return wrapper


    def load_crccheck(f):
        """Decorator wrapper to load crccheck."""

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                __import__("crccheck")
                return f(*args, **kwargs)
            except ImportError as err:
                msg = "Missing `crccheck` package for Python, try installing with `pip install crccheck`"
                raise ImportWarning(msg) from err

        return wrapper


    def load_codext(f):
        """Decorator wrapper to load codext."""

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                __import__("codext")
                return f(*args, **kwargs)
            except ImportError as err:
                msg = "Missing `codext` package for Python, try installing with `pip install codext`"
                raise ImportWarning(msg) from err

        return wrapper


    def load_angr(f):
        """Decorator wrapper to load angr."""

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            try:
                # Angr seems to import readline internally, so tab completion breaks after loading.
                # Therefore, disable readline temporarily.
                readline = sys.modules.get("readline", None)
                sys.modules["readline"] = None
                __import__("angr")
                sys.modules["readline"] = readline
                return f(*args, **kwargs)
            except ImportError as err:
                msg = "Missing `angr` package for Python, try installing with `pip install angr`"
                raise ImportWarning(msg) from err

        return wrapper


