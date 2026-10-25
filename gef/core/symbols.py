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

    @staticmethod
    @Cache.cache_this_session(until_new_objfile=True)
    def resolve_address(name):
        """resolve_address("main") -> 0x401000.
        resolve_address("missing") -> None.
        """
        from gef.core.registers import to_unsigned_long
        try:
            return to_unsigned_long(gdb.parse_and_eval("&{:s}".format(name)))
        except (gdb.error, OverflowError, ValueError):
            return None

    @staticmethod
    def resolve_kdb_address(name):
        """resolve_kdb_address("_stext") -> 0xffffffff81000000.
        resolve_kdb_address("missing") -> None.
        """
        from gef.core.process import is_kdb
        if not is_kdb():
            return None
        text = gdb.execute("monitor {:s}".format(name), to_string=True)
        match = re.search(re.escape(name) + r" = 0x([0-9a-fA-F]+)\b", text)
        if not match:
            return None
        address = int(match.group(1), 16)
        if is_valid_addr(address):
            return address
        else:
            return None


    @staticmethod
    @Cache.cache_this_session(until_new_objfile=True)
    def lookup_gdb(address):
        """lookup_gdb(0x401042) -> ("main", 0x42).
        lookup_gdb(0x1) -> None.
        """
        if address is None:
            return None
        # gdb.format_address can miss symbols loaded by add-symbol-temporary.
        text = gdb.execute("info symbol {:#x}".format(address), to_string=True).strip()
        if not text or text.startswith("No symbol matches"):
            return None
        text = text.partition(" in section ")[0]
        name, separator, offset = text.rpartition(" + ")
        if separator and offset.isdigit():
            return name, int(offset)
        return text, 0

    @staticmethod
    def lookup(address, ksym="cached"):
        """ksym="off": query GDB only.
        ksym="cached" (default): query GDB first; on a miss in kernel mode, use already parsed kallsyms without scanning.
        ksym="prefer": try an exact kallsyms address first (parsing if needed), then use the "cached" policy.

        lookup(0x401042, ksym="off") -> ("main", 0x42).
        lookup(0xffffffff81001042, ksym="cached") -> ("schedule", 0x42).
        lookup(0xffffffff81001000, ksym="prefer") -> ("schedule", 0).
        lookup(0x1) -> None.
        """
        from gef.core.process import is_in_kernel
        # runtime-only core dependency, allowed by layering rule 1
        from gef.core.kernel import Ksym
        if ksym not in ("off", "cached", "prefer"):
            raise ValueError("Unknown kallsyms mode: {!r}".format(ksym))
        if address is None:
            return None
        try:
            if ksym == "prefer":
                name = Ksym.get_name(address)
                if name:
                    return name, 0
            try:
                ret = Symbol.lookup_gdb(address)
            except (ValueError, gdb.error):
                ret = None
            if ret is None and ksym != "off" and is_in_kernel():
                ret = Ksym.get_location_from_peek(address)
            return ret
        except (ValueError, gdb.error):
            return None

    @staticmethod
    def format(addr, missing="", show_offset=True, ksym="cached", bracket="<>", show_address=False, nocolor=False):
        """ksym uses the same "cached" (default), "prefer" and "off" policies as Symbol.lookup().

        format(0x401042) -> "<main+0x42>".
        format(0x401042, show_offset=False) -> "<main>".
        format(0x401042, bracket="") -> "main+0x42".
        format(0x401042, bracket="()") -> "(main+0x42)".
        format(0x401042, bracket="[]") -> "[main+0x42]".
        format(0x401042, show_address=True) -> "0x000000401042 <main+0x42>".
        format(0x401042, show_address=True, nocolor=True) -> "0x000000401042 <main+0x42>" (no mapping lookup or color).
        format(0x1, missing="NO_SYMBOL") -> "<NO_SYMBOL>".
        format(0x1) -> "".
        format(0xffffffff81001000, ksym="prefer") -> "<schedule>".
        """
        from gef.core.address import AddressUtil
        from gef.core.process import ProcessMap

        if len(bracket) not in (0, 2):
            raise ValueError("Expected an empty string or two bracket characters")
        if isinstance(addr, str):
            try:
                addr = int(Color.remove_color(addr), 16)
            except ValueError:
                addr = None

        symbol = missing
        if addr:
            ret = Symbol.lookup(addr, ksym=ksym)
            if ret is not None:
                name, offset = ret
                if addr - offset != 0:
                    name = Instruction.smartify_text(name)
                    if show_offset and offset:
                        name += "+{:#x}".format(offset)
                    symbol = name
        if symbol and bracket:
            symbol = "{:s}{:s}{:s}".format(bracket[0], symbol, bracket[1])
        if show_address and addr is not None:
            if nocolor:
                address = AddressUtil.format_address(addr)
            else:
                address = ProcessMap.lookup(addr)
            return "{!s}{:s}".format(address, " " + symbol if symbol else "")
        return symbol




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


