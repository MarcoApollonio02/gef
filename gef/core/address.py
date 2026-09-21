"""GEF address representation and utilities (Layer 1).

Contains `Address` (pretty representation of a memory address), `AddressUtil`
(address width/format/normalize/dereference helpers), `Permission` and
`Section` (process-map entries) and `Endian` (binary endianness helpers).

Reads of the mutable global `current_arch` go through `runtime.current_arch`
(never a by-name import) to avoid the stale-binding pitfall documented in
runtime.py. References to modules that are not yet extracted (process, memory,
registers, strings, symbols, qemu, utils) are imported lazily inside the
method that needs them, to keep the address<->memory import cycle broken.
"""
import gdb

from gef.core import runtime
from gef.core.cache import Cache
from gef.core.color import Color
from gef.core.config import Config


class Address:
    """GEF representation of memory addresses."""

    def __init__(self, addr):
        from gef.core.registers import to_unsigned_long

        if isinstance(addr, gdb.Value):
            addr = to_unsigned_long(addr)
        self.value = addr
        return

    @property
    def section(self):
        from gef.core.process import ProcessMap

        if hasattr(self, "cached_section"):
            return self.cached_section
        self.cached_section = ProcessMap.process_lookup_address(self.value)
        return self.cached_section

    @property
    def info(self):
        from gef.core.process import ProcessMap

        if hasattr(self, "cached_info"):
            return self.cached_info
        self.cached_info = ProcessMap.file_lookup_address(self.value)
        return self.cached_info

    @property
    def valid(self):
        from gef.core.memory import is_valid_addr

        return is_valid_addr(self.value)

    def __repr__(self):
        return '<{:s}.{:s} object at {:#x}, addr={:#x}, section={}, info={}, valid={}>'.format(
            self.__module__, self.__class__.__name__, id(self),
            self.value, bool(self.section), bool(self.info), self.valid,
        )

    def __str__(self):
        value = AddressUtil.format_address(self.value)
        if not self.valid:
            return value
        line_color = ""
        if self.is_in_stack_segment():
            line_color = Config.get_gef_setting("theme.address_stack")
        elif self.is_in_heap_segment():
            line_color = Config.get_gef_setting("theme.address_heap")
        elif self.is_in_text_segment():
            line_color = Config.get_gef_setting("theme.address_code")
        elif self.is_in_writable():
            line_color = Config.get_gef_setting("theme.address_writable")
        elif self.is_in_readonly():
            line_color = Config.get_gef_setting("theme.address_readonly")
        elif self.is_valid_but_none():
            line_color = Config.get_gef_setting("theme.address_valid_but_none")
        if self.is_rwx():
            line_color += " " + Config.get_gef_setting("theme.address_rwx")
        return Color.colorify(value, line_color)

    def long_fmt(self):
        value = AddressUtil.format_address(self.value, long_fmt=True)
        if not self.valid:
            return value
        line_color = ""
        if self.is_in_stack_segment():
            line_color = Config.get_gef_setting("theme.address_stack")
        elif self.is_in_heap_segment():
            line_color = Config.get_gef_setting("theme.address_heap")
        elif self.is_in_text_segment():
            line_color = Config.get_gef_setting("theme.address_code")
        elif self.is_in_writable():
            line_color = Config.get_gef_setting("theme.address_writable")
        elif self.is_in_readonly():
            line_color = Config.get_gef_setting("theme.address_readonly")
        elif self.is_valid_but_none():
            line_color = Config.get_gef_setting("theme.address_valid_but_none")
        if self.is_rwx():
            line_color += " " + Config.get_gef_setting("theme.address_rwx")
        return Color.colorify(value, line_color)

    def is_in_readable(self): # noqa
        if self.section is None:
            return False
        r = hasattr(self.section, "is_readable") and self.section.is_readable()
        return r

    def is_in_writable(self):
        if self.section is None:
            return False
        w = hasattr(self.section, "is_writable") and self.section.is_writable()
        return w

    def is_in_executable(self):
        if self.section is None:
            return False
        x = hasattr(self.section, "is_executable") and self.section.is_executable()
        return x

    def is_rwx(self):
        if self.section is None:
            return False
        r = hasattr(self.section, "is_readable") and self.section.is_readable()
        w = hasattr(self.section, "is_writable") and self.section.is_writable()
        x = hasattr(self.section, "is_executable") and self.section.is_executable()
        return r and w and x

    def is_in_stack_segment(self):
        if self.section is None:
            return False
        return hasattr(self.section, "path") and self.section.path.startswith("[stack]")

    def is_in_heap_segment(self):
        if self.section is None:
            return False
        return hasattr(self.section, "path") and self.section.path.startswith("[heap]")

    def is_in_text_segment(self):
        if self.section is None:
            return False
        a = hasattr(self.info, "name") and isinstance(self.info.name, str) and ".text" in self.info.name
        e = hasattr(self.section, "is_executable") and self.section.is_executable()
        return a or e

    def is_in_readonly(self):
        if self.section is None:
            return False
        r = hasattr(self.section, "is_readable") and self.section.is_readable()
        w = hasattr(self.section, "is_writable") and self.section.is_writable()
        x = hasattr(self.section, "is_executable") and self.section.is_executable()
        return r and (not w) and (not x)

    def is_valid_but_none(self):
        if self.section is None:
            return False
        r = hasattr(self.section, "is_readable") and self.section.is_readable()
        x = hasattr(self.section, "is_executable") and self.section.is_executable()
        w = hasattr(self.section, "is_writable") and self.section.is_writable()
        return (not r) and (not w) and (not x)

    def dereference(self):
        # Even if the valid flag is not set, it still dereferences.
        # This is because the valid flag is not set during kernel debugging.
        value = AddressUtil.normalize_address(self.value)
        derefed = AddressUtil.dereference(value)
        if derefed is None:
            return None
        return int(derefed)


class AddressUtil:
    """A collection of utility functions that operate on addresses."""

    @staticmethod
    @Cache.cache_this_session
    def ptr_width():
        """Determine whether the environment is 32-bit or 64-bit."""
        from gef.core.utils import GefUtil

        void = GefUtil.cached_lookup_type("void")
        if void:
            return void.pointer().sizeof

        uintptr_t = GefUtil.cached_lookup_type("uintptr_t")
        if uintptr_t:
            return uintptr_t.sizeof

        raise EnvironmentError("GEF is running under an unsupported mode")

    @staticmethod
    @Cache.cache_this_session
    def get_memory_alignment(in_bits=False):
        """Try to determine the size of a pointer on this system."""
        from gef.core.process import is_32bit, is_64bit, is_x86_16

        if is_x86_16():
            if runtime.current_arch.A20:
                return 2 if not in_bits else 21
            else:
                return 2 if not in_bits else 20

        if is_32bit():
            return 4 if not in_bits else 32
        elif is_64bit():
            return 8 if not in_bits else 64

        raise EnvironmentError("GEF is running under an unsupported mode")

    @staticmethod
    def is_msb_on(addr):
        """Return whether provided address MSB is on."""
        align = AddressUtil.get_memory_alignment()
        if align == 8:
            return bool(addr & 0x8000_0000_0000_0000)
        elif align == 4:
            return bool(addr & 0x8000_0000)
        elif align == 2:
            return bool(addr & 0x8000)
        raise EnvironmentError("GEF is running under an unsupported mode")

    @staticmethod
    def get_format_address_width(memalign_size=None):
        """Return the width for compactly displaying the pointer."""
        from gef.core.process import is_32bit, is_alive, is_in_kernel

        if not is_alive():
            return 16 + 2 # '0xAAABBBBCCCCDDDD' # assume 64bit
        if is_32bit() or memalign_size == 4:
            return 8 + 2 # '0xAAAABBBB'
        if not is_in_kernel():
            return 12 + 2 # '0x7fffAAAABBBB'
        return 16 + 2 # '0xAAABBBBCCCCDDDD'

    @staticmethod
    def format_address(addr, memalign_size=None, long_fmt=False):
        """Format the address according to its size."""
        from gef.core.process import is_in_kernel

        # if qemu-xxx(32bit arch) runs on x86-64 machine, memalign_size does not match
        # AddressUtil.get_memory_alignment(), so use the value forcibly if memalign_size is not None
        if memalign_size is None:
            memalign_size = AddressUtil.get_memory_alignment()

        if isinstance(addr, str):
            addr = int(addr, 16)

        addr = AddressUtil.normalize_address(addr, memalign_size)
        if memalign_size == 4:
            return "{:#010x}".format(addr)
        elif memalign_size == 2:
            return "{:#06x}".format(addr)
        elif memalign_size == 2.5:
            if runtime.current_arch.A20:
                return "{:#08x}".format(addr)
            else:
                return "{:#07x}".format(addr)
        if long_fmt:
            return "{:#018x}".format(addr)
        if is_in_kernel():
            return "{:#018x}".format(addr)
        return "{:#014x}".format(addr)

    @staticmethod
    def normalize_address(addr, memalign_size=None):
        """Normalize the provided address to the process's native length.
        e.g., 0x1_2345_6789 -> 0x2345_6789 (for 32-bit arch)"""
        # if qemu-xxx(32bit arch) runs on x86-64 machine, memalign_size does not match
        # AddressUtil.get_memory_alignment(), so use the value forcibly if memalign_size is not None
        if memalign_size is None:
            memalign_size = AddressUtil.get_memory_alignment()

        if memalign_size == 8:
            return addr & 0xffff_ffff_ffff_ffff
        elif memalign_size == 4:
            return addr & 0xffff_ffff
        elif memalign_size == 2:
            return addr & 0xffff
        elif memalign_size == 2.5:
            if runtime.current_arch.A20:
                return addr & 0x1f_ffff
            else:
                return addr & 0x0f_ffff

        raise EnvironmentError("GEF is running under an unsupported mode")

    @staticmethod
    @Cache.cache_until_next
    def get_vmem_end():
        return 1 << AddressUtil.get_memory_alignment(in_bits=True)

    @staticmethod
    @Cache.cache_until_next
    def get_vmem_end_mask():
        return AddressUtil.get_vmem_end() - 1

    @staticmethod
    def parse_address(addr):
        """Parse an address and return it as an Integer."""
        from gef.core.registers import to_unsigned_long

        try:
            return int(addr, 0)
        except ValueError:
            pass
        # on some unsupported architectures (e.g., tricore), gdb.parse_and_eval may cause a crash
        if runtime.current_arch is None:
            raise ValueError
        # Don't enclose it in a try-catch. This is because it is used with argparse,
        # and is intended to raise an exception if parsing fails.
        return to_unsigned_long(gdb.parse_and_eval(addr))

    @staticmethod
    def parse_string_range(s):
        """Parse an address range (e.g., 0x400000-0x401000)"""
        addrs = s.split("-")
        return [int(x, 16) for x in addrs]

    @staticmethod
    @Cache.cache_until_next
    def dereference(addr):
        """GEF wrapper for gdb dereference function."""

        from gef.core.process import is_32bit, is_64bit
        from gef.core.utils import GefUtil

        def use_stdtype():
            if is_32bit():
                return "uint32_t"
            elif is_64bit():
                return "uint64_t"
            return "uint16_t"

        def use_default_type():
            if is_32bit():
                return "unsigned int"
            elif is_64bit():
                return "unsigned long"
            return "unsigned short"

        def use_golang_type():
            if is_32bit():
                return "uint32"
            elif is_64bit():
                return "uint64"
            return "uint16"

        def use_rust_type():
            if is_32bit():
                return "u32"
            elif is_64bit():
                return "u64"
            return "u16"

        ulong_t = GefUtil.cached_lookup_type(use_stdtype())
        if not ulong_t:
            ulong_t = GefUtil.cached_lookup_type(use_default_type())
        if not ulong_t:
            ulong_t = GefUtil.cached_lookup_type(use_golang_type())
        if not ulong_t:
            ulong_t = GefUtil.cached_lookup_type(use_rust_type())
        if not ulong_t:
            return None

        try:
            unsigned_long_type = ulong_t.pointer()
        except (AttributeError, gdb.error):
            return None

        try:
            res = gdb.Value(addr).cast(unsigned_long_type).dereference()
            # GDB does lazy fetch by default so we need to force access to the value
            res.fetch_lazy()
            return res
        except (gdb.MemoryError, gdb.error, ValueError, TypeError):
            return None

    @staticmethod
    @Cache.cache_this_session
    def get_recursive_dereference_blacklist():
        """Return the blacklist of addresses (for caching purposes after eval())."""
        blacklist = eval(Config.get_gef_setting("dereference.blacklist"))
        for range_list in blacklist:
            assert isinstance(range_list, list)
            assert len(range_list) == 2
            assert isinstance(range_list[0], int)
            assert isinstance(range_list[1], int)
        return blacklist

    @staticmethod
    @Cache.cache_until_next
    def recursive_dereference(addr, phys=False):
        """Create dereference array."""
        from gef.core.memory import read_int_from_memory, u32, u64
        from gef.core.process import is_alive

        if not is_alive():
            return [addr], None

        recursion = Config.get_gef_setting("dereference.max_recursion")
        blacklist = AddressUtil.get_recursive_dereference_blacklist()
        addr_list = []
        error = None

        while recursion > 0:
            # check loop
            if addr in addr_list:
                if addr == 0 and len(addr_list) == 1:
                    # the case that address 0x0 is valid and first element is 0x0 (i.e. telescope 0x0).
                    # but no error because it is generally unnecessary information.
                    addr_list.append(addr) # use [0, 0] instead of [0]
                else:
                    error = "[loop detected]"
                break

            # not loop
            addr_list.append(addr)

            # check blacklist
            if any(bstart <= addr < bend for bstart, bend in blacklist):
                error = "[blacklist detected]"
                break

            # check non-address
            if len(addr_list) > 1 and addr < 0x100:
                break

            # goto next
            if phys and len(addr_list) == 1:
                from gef.core.qemu import read_physmem

                mem = read_physmem(addr, runtime.current_arch.ptrsize)
                unpack = u32 if runtime.current_arch.ptrsize == 4 else u64
                addr = unpack(mem)
            else:
                try:
                    addr = read_int_from_memory(addr)
                except gdb.MemoryError:
                    break
            recursion -= 1

        return addr_list, error

    @staticmethod
    @Cache.cache_until_next
    def recursive_dereference_to_string(value, skip_idx=0, phys=False, quiet=False):
        """Create string from dereference array."""
        from gef.core.memory import is_valid_addr, read_cstring_from_memory
        from gef.core.process import ProcessMap
        from gef.core.strings import String
        from gef.core.symbols import Symbol

        string_color = Config.get_gef_setting("theme.dereference_string")
        nb_max_string_length = Config.get_gef_setting("context.nb_max_string_length")
        recursion = Config.get_gef_setting("dereference.max_recursion")

        # dereference
        addrs, error = AddressUtil.recursive_dereference(value, phys=phys)

        # if addrs has one element and it is address with an error (e.g., address_A -> [loop detected]),
        # don't skip the element even if skip_idx=1
        if skip_idx == 1:
            if len(addrs) == 1:
                if error == "[loop detected]":
                    skip_idx = 0

        # add "..."
        if error is None:
            if addrs[-1] > 0x100 and is_valid_addr(addrs[-1]) and recursion > 1:
                error = "..."

        # replace to string if valid
        def to_ascii(v):
            if not isinstance(v, int) or v < 0:
                return ""
            s = ""
            while v & 0xff: # \0
                if chr(v & 0xff) in String.STRING_PRINTABLE:
                    s += chr(v & 0xff)
                else:
                    return ""
                v >>= 8
            return s

        last_elem = None
        if error is None and not quiet:
            s = to_ascii(addrs[-1])
            if len(s) < 2:
                pass
            elif 2 <= len(s) < runtime.current_arch.ptrsize:
                fa = AddressUtil.format_address(addrs[-1], long_fmt=True)
                last_elem = "{:s} ({:s}?)".format(fa, Color.colorify(repr(s), string_color))
                addrs = addrs[:-1]
            else: # len(s) == runtime.current_arch.ptrsize
                if len(addrs) >= 2 and is_valid_addr(addrs[-2]):
                    # read more string
                    s = read_cstring_from_memory(addrs[-2], nb_max_string_length)
                    if s:
                        fa = AddressUtil.format_address(addrs[-1], long_fmt=True)
                        last_elem = "{:s} {:s}".format(fa, Color.colorify(repr(s), string_color))
                        addrs = addrs[:-1]
                    else:
                        # Ignore when the string that do not end with a null character
                        pass
                else:
                    # fallback
                    fa = AddressUtil.format_address(addrs[-1], long_fmt=True)
                    last_elem = "{:s} ({:s}?)".format(fa, Color.colorify(repr(s), string_color))
                    addrs = addrs[:-1]

        # others
        msg = []
        for addr in addrs[skip_idx:]:
            address = ProcessMap.lookup_address(addr)
            if quiet:
                msg.append(address.long_fmt())
            else:
                msg.append(address.long_fmt() + Symbol.get_symbol_string(addr))

        if error:
            msg.append(error)
        elif last_elem:
            msg.append(last_elem)

        return "  ->  ".join(msg)


class Permission:
    """GEF representation of Linux permission."""

    NONE    = 0
    READ    = 1
    WRITE   = 2
    EXECUTE = 4
    ALL     = READ | WRITE | EXECUTE

    def __init__(self, **kwargs):
        self.value = kwargs.get("value", 0)
        return

    def __repr__(self):
        return '<{:s}.{:s} object at {:#x}, perm="{}">'.format(
            self.__module__, self.__class__.__name__, id(self), str(self),
        )

    def __or__(self, value):
        return self.value | value

    def __and__(self, value):
        return self.value & value

    def __xor__(self, value):
        return self.value ^ value

    def __eq__(self, value):
        return self.value == value

    def __ne__(self, value):
        return self.value != value

    def __str__(self):
        perm_str = ""
        perm_str += "r" if self & Permission.READ else "-"
        perm_str += "w" if self & Permission.WRITE else "-"
        perm_str += "x" if self & Permission.EXECUTE else "-"
        return perm_str

    def match(self, perm_str):
        if not isinstance(perm_str, str):
            return False
        if len(perm_str) != 3:
            return False

        if perm_str[0] not in "rR-_?":
            return False
        if perm_str[1] not in "wR-_?":
            return False
        if perm_str[2] not in "xX-_?":
            return False

        if perm_str[0] in "rR" and not bool(self.value & Permission.READ):
            return False
        if perm_str[0] in "-_" and bool(self.value & Permission.READ):
            return False
        if perm_str[1] in "wW" and not bool(self.value & Permission.WRITE):
            return False
        if perm_str[1] in "-_" and bool(self.value & Permission.WRITE):
            return False
        if perm_str[2] in "xX" and not bool(self.value & Permission.EXECUTE):
            return False
        if perm_str[2] in "-_" and bool(self.value & Permission.EXECUTE):
            return False

        return True

    @staticmethod
    def from_process_maps(perm_str):
        perm = Permission()
        if perm_str[0] == "r":
            perm.value += Permission.READ
        if perm_str[1] == "w":
            perm.value += Permission.WRITE
        if perm_str[2] == "x":
            perm.value += Permission.EXECUTE
        return perm


class Section:
    """GEF representation of process memory sections."""

    def __init__(self, *args, **kwargs):
        self.page_start = kwargs.get("page_start")
        self.page_end = kwargs.get("page_end")
        self.offset = kwargs.get("offset", 0)
        self.permission = kwargs.get("permission")
        self.inode = kwargs.get("inode", None)
        self.path = kwargs.get("path", "")
        return

    def __repr__(self):
        return '<{:s}.{:s} object at {:#x}, page_start={:#x}, page_end={:#x}, perm="{}", path="{:s}">'.format(
            self.__module__, self.__class__.__name__, id(self), self.page_start, self.page_end,
            self.permission, self.path,
        )

    def is_readable(self):
        v = self.permission.value
        return v and bool(v & Permission.READ)

    def is_writable(self):
        v = self.permission.value
        return v and bool(v & Permission.WRITE)

    def is_executable(self):
        v = self.permission.value
        return v and bool(v & Permission.EXECUTE)

    @property
    def size(self):
        if self.page_end is None or self.page_start is None:
            return -1
        return self.page_end - self.page_start


class Endian:
    """Manage endianness related functions."""

    @staticmethod
    @Cache.cache_this_session
    def get_endian():
        """Return the binary endianness."""
        from gef.core.elf import Elf

        endian = gdb.execute("show endian", to_string=True).strip().lower()
        if "little endian" in endian:
            return Elf.LITTLE_ENDIAN
        if "big endian" in endian:
            return Elf.BIG_ENDIAN
        raise EnvironmentError("Invalid endianness")

    @staticmethod
    def is_big_endian():
        from gef.core.elf import Elf

        return Endian.get_endian() == Elf.BIG_ENDIAN

    @staticmethod
    def is_little_endian():
        return not Endian.is_big_endian()

    @staticmethod
    @Cache.cache_this_session
    def endian_str():
        return "<" if Endian.is_little_endian() else ">"


