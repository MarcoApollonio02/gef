"""Generic GEF utility helpers (Layer 1).

Module-level constants `GEF_TEMP_DIR`, `GEF_RC`, `GEF_FILEPATH`, the
profiling decorators `perf` / `cperf`, the glibc version detector
`get_libc_version`, the generic binary helpers (`slicer`, `slice_unpack`,
`align`, `align_to_ptrsize`, `align_to_pagesize`, `byteswap`, `xor`, `ror`,
`rol`), the GDB helper decorators `timeout` / `switch_to_intel_syntax`, the
linked-list walk helpers `is_single_link_list` / `is_double_link_list`, the
`GefUtil` collection, and the alignment passthroughs `align_to_ptrsize` etc.

For compatibility with code written against the monolithic gef.py, this
module also re-exports `show_last_exception` (from gef.core.errors) and
`UnicornKeystoneCapstone` (from gef.core.unicorn).

Reads of the mutable global `current_arch` go through `runtime.current_arch`.
`Gef` (gef.py main class, Phase 2) is late-imported inside the method that
needs it.
"""
import datetime
import functools
import io
import math
import os
import re
import struct
import subprocess
import sys
import tempfile
import traceback

import gdb

from gef.core import runtime
from gef.core.address import Endian
from gef.core.cache import Cache
from gef.core.color import Color, err, info
from gef.core.color import gef_print  # noqa: F401  (re-export for GefUtil.show_last_exception users)
from gef.core.config import Config
from gef.core.errors import show_last_exception  # noqa: F401  (re-export)
from gef.core.memory import is_valid_addr, read_int_from_memory, u128
from gef.core.strings import String


GEF_TEMP_DIR = os.path.join(tempfile.gettempdir(), "gef")
GEF_RC = os.getenv("GEF_RC") or os.path.join(os.getenv("HOME") or "~", ".gef.rc")
GEF_FILEPATH = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))



def perf(f): # noqa
    """Decorator wrapper to measure performance."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        import line_profiler
        pr = line_profiler.LineProfiler()
        pr.add_function(f)
        pr.enable()
        ret = f(*args, **kwargs)
        pr.disable()
        s = io.StringIO()
        pr.print_stats(stream=s)
        print(s.getvalue())
        return ret

    return wrapper


def cperf(f): # noqa
    """Decorator wrapper to measure performance."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        import cProfile
        import pstats
        pr = cProfile.Profile()
        pr.enable()
        ret = f(*args, **kwargs)
        pr.disable()
        s = io.StringIO()
        #sortby = pstats.SortKey.CUMULATIVE
        sortby = pstats.SortKey.TIME
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats(20)
        print(s.getvalue())
        return ret




def get_libc_version(verbose=False):
    """Detect and return the glibc version as a tuple, using cache, configuration,
    process maps, or system fallback."""
    from gef.core.process import Path, ProcessMap, is_container_attach, is_qemu_user, is_remote_debug

    RE_LIBC_PATH = re.compile(r"libc6?[-_](\d+)\.(\d+)\.so")
    RE_GLIBC_VERSION = re.compile(rb"glibc (\d+)\.(\d+)")

    def get_libc_version_from_path():
        Cache.reset_gef_caches() # get_process_maps may be caching old information

        sections = ProcessMap.get_process_maps()
        for section in sections:
            r = RE_LIBC_PATH.search(section.path)
            if r:
                return tuple(int(x) for x in r.groups())

            if "libc" not in section.path:
                continue

            if is_container_attach():
                real_libc_path = Path.append_proc_root(section.path)
                if not os.path.exists(real_libc_path):
                    continue
                data = open(real_libc_path, "rb").read()

            elif is_remote_debug():
                if is_qemu_user():
                    data = None
                    for maps in ProcessMap.get_process_maps(outer=True):
                        if os.path.basename(maps.path) != os.path.basename(section.path):
                            continue
                        if maps.size != section.size:
                            continue
                        real_libc_path = maps.path
                        data = open(real_libc_path, "rb").read()
                        break
                else:
                    data = Path.read_remote_file(section.path)
                if not data:
                    continue
            else:
                if not os.path.exists(section.path):
                    continue
                data = open(section.path, "rb").read()

            r = RE_GLIBC_VERSION.search(data)
            if r:
                return tuple(int(x) for x in r.groups())
        return None

    def get_system_libc_version():
        res = GefUtil.gef_execute_external(["cat", "/proc/self/maps"], as_list=True)
        libc_targets = ("libc-2.", "libc.so.6")
        for line in res:
            if not any(kw in line for kw in libc_targets):
                continue
            path = line.split()[-1]
            if not os.path.exists(path):
                continue
            data = open(path, "rb").read()
            r = RE_GLIBC_VERSION.search(data)
            if r:
                return tuple(int(x) for x in r.groups())
        return None

    # use manual settings
    libc_assume_version = eval(Config.get_gef_setting("libc.assume_version"))
    if libc_assume_version != ():
        if verbose:
            info("Use libc.assume_version")
        return libc_assume_version

    # resolve from maps information
    libc_version = get_libc_version_from_path()
    if libc_version is not None:
        if verbose:
            info("Resolve from maps")
        return libc_version

    # resolve from system libc
    if not is_container_attach():
        libc_version = get_system_libc_version()
        if libc_version is not None:
            if verbose:
                info("Resolve from system libc")
            return libc_version

    err("The libc version could not be determined.")
    err("Please specify it with the following command: `gef config libc.assume_version (2,39)`")
    raise





def slicer(data, n):
    """Helper function for slice."""
    return [data[i:i + n] for i in range(0, len(data), n)]


def slice_unpack(data, n):
    """Helper function for slice then unpack."""
    if n in [1, 2, 4, 8]:
        length = len(data) // n
        fmt = "{:s}{:d}{:s}".format(Endian.endian_str(), length, {1: "B", 2: "H", 4: "I", 8: "Q"}[n])
        return struct.unpack(fmt, data)
    elif n == 16:
        return [u128(data[i:i + 16]) for i in range(0, len(data), 16)]
    else:
        raise


def align(value, align):
    """Align the value to the given size.
    e.g., 0xdeadbeef with align 8 -> 0xdeadbef0"""
    return value + ((align - (value % align)) % align)


def align_to_ptrsize(addr):
    """Align the address to the ptrsize."""
    return align(addr, runtime.current_arch.ptrsize)


def align_to_pagesize(addr):
    """Align the address to the pagesize."""
    from gef.core.process import get_pagesize
    return align(addr, get_pagesize())


def byteswap(x, byte_size=None):
    """Helper function for byte swap."""
    byte_size = byte_size or runtime.current_arch.ptrsize
    bit_size = byte_size * 8
    s = 0
    for i in range(0, bit_size, 8):
        s += ((x >> i) & 0xff) << (bit_size - (i + 8))
    return s


def xor(a, b=None):
    """Helper function for xor.
    xor("AAA", "BBB") -> "\x03\x03\x03"
    xor(b"AAA", b"BBB") -> b"\x03\x03\x03"
    xor(["AAA", "BBB", "\x03\x03\x03"]) -> "\0\0\0"
    """

    def _xor(a, b):
        if len(a) < len(b):
            a, b = b, a
        if isinstance(a, str) and isinstance(b, str):
            return ''.join([chr(ord(c1) ^ ord(c2)) for (c1, c2) in zip(a, itertools.cycle(b))])
        elif isinstance(a, bytes) and isinstance(b, bytes):
            return bytes([c1 ^ c2 for (c1, c2) in zip(a, itertools.cycle(b))])
        elif isinstance(a, bytearray) and isinstance(b, bytearray):
            return bytearray([c1 ^ c2 for (c1, c2) in zip(a, itertools.cycle(b))])
        raise

    if b is None:
        if hasattr(a, "__iter__"):
            return functools.reduce(_xor, a)
        raise
    return _xor(a, b)


def ror(val, bits, arch_bits=64):
    """Helper function for rotate right."""
    new_val = (val >> bits) | (val << (arch_bits - bits))
    mask = (1 << arch_bits) - 1
    return new_val & mask


def rol(val, bits, arch_bits=64):
    """Helper function for rotate left."""
    new_val = (val << bits) | (val >> (arch_bits - bits))
    mask = (1 << arch_bits) - 1
    return new_val & mask




def timeout(duration):
    """Decorator to handle timeout."""

    def timeout_worker(conn, function, args, kwargs):
        try:
            result = function(*args, **kwargs)
            conn.send((True, result))
        except BaseException as e:
            try:
                conn.send((False, e))
            except BaseException as send_error:
                conn.send((False, RuntimeError("failed to send child result: %r" % send_error)))
        finally:
            conn.close()

    def wrapper(function):
        import multiprocessing
        import multiprocessing.connection
        import signal

        ctx = multiprocessing.get_context("fork")

        @functools.wraps(function)
        def inner_f(*args, **kwargs):
            parent_conn, child_conn = ctx.Pipe(duplex=False)
            p = ctx.Process(target=timeout_worker, args=(child_conn, function, args, kwargs))
            p.start()
            child_conn.close()

            ready = multiprocessing.connection.wait([parent_conn, p.sentinel], duration)

            if parent_conn in ready:
                success, result = parent_conn.recv()
                parent_conn.close()
                p.join()
                if success:
                    return result
                raise result

            parent_conn.close()
            p.terminate()
            p.join(0.2)

            if p.is_alive():
                if hasattr(p, "kill"):
                    p.kill()
                else:
                    os.kill(p.pid, signal.SIGKILL)
                p.join()

            raise multiprocessing.TimeoutError

        return inner_f

    return wrapper



def switch_to_intel_syntax(f):
    """Decorator to temporarily switch to Intel syntax."""
    from gef.core.process import is_x86

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not is_x86():
            return f(*args, **kwargs)

        att = gdb.parameter("disassembly-flavor") == "att"
        if att:
            gdb.execute("set disassembly-flavor intel", to_string=True)
        ret = f(*args, **kwargs)
        if att:
            gdb.execute("set disassembly-flavor att", to_string=True)
        return ret

    return wrapper






@Cache.cache_until_next
def is_single_link_list(addr):
    # +------+   +------+           +------+
    # | head |-->| next |--> ... -->| next |--> NULL
    # +------+   +------+           +------+

    seen = []
    while True:
        if addr == 0:
            return True
        if addr in seen:
            return False
        if not is_valid_addr(addr):
            return False
        seen.append(addr)
        addr = read_int_from_memory(addr)


@Cache.cache_until_next
def is_double_link_list(addr, min_len=0):
    # +------+<-+   +------+<-+        <-+   +------+<-+   +------+
    # | head |--|-->| next |--|--> ... --|-->| next |--|-->| head |
    # +------+  |   +------+  |          |   +------+  |   +------+
    # | tail |  +---| prev |  +---       +---| prev |  +---| tail |
    # +------+      +------+                 +------+      +------+

    # list next pointer
    seen = []
    while True:
        if not is_valid_addr(addr):
            return False
        if addr in seen:
            break
        seen.append(addr)
        addr = read_int_from_memory(addr)

    if addr != seen[0]:
        return False

    # check prev pointer
    for i, x in enumerate(seen):
        p = read_int_from_memory(x + runtime.current_arch.ptrsize)
        if p != seen[i - 1]:
            return False

    # minimum length check
    return len(seen) > min_len



class GefUtil:
    """A collection of utility functions that are related to GEF basic features."""

    @staticmethod
    @Cache.cache_until_next
    def cached_lookup_type(_type):
        """Look up a GDB type by name and strip typedefs, returning None on failure."""
        try:
            return gdb.lookup_type(_type).strip_typedefs()
        except RuntimeError:
            return None

    @staticmethod
    def get_tqdm(use_tqdm=True):
        """Return the tqdm progress bar if available and enabled;
        otherwise returns a passthrough function."""
        tqdm = lambda x, leave=None, total=None, desc=None: x # noqa: F841
        if not use_tqdm:
            return tqdm
        try:
            from tqdm import tqdm
        except ImportError:
            pass
        return tqdm

    __gef_convenience_vars_index__ = 0 # $_gef1, $_gef2, ...

    @staticmethod
    def gef_convenience(value):
        """Define a new convenience value."""
        var_name = "$_gef{:d}".format(GefUtil.__gef_convenience_vars_index__)
        GefUtil.__gef_convenience_vars_index__ += 1
        gdb.execute('set {:s} = "{:s}"'.format(var_name, value))
        return var_name

    class ArgparseExitProxyException(Exception):
        pass

    @staticmethod
    def get_terminal_size(redirect=""):
        """Return the current terminal size."""
        if redirect and os.getenv("TMUX"):
            res = subprocess.check_output([
                GefUtil.which("tmux"), "list-panes", "-F#{pane_tty}:#{pane_height}:#{pane_width}",
            ]).decode("utf-8").strip()

            for line in res.splitlines():
                tty, height, width = line.split(":")
                if tty == redirect:
                    return int(height), int(width)

        try:
            tty_columns, tty_rows = os.get_terminal_size()
            return tty_rows, tty_columns
        except OSError:
            return 600, 100

    @staticmethod
    def get_source(function):
        """Return the source of function."""
        import inspect
        s = inspect.getsource(function)
        return s.rstrip()

    @staticmethod
    @Cache.cache_this_session
    def log2(x):
        return int(math.log2(x))

    @staticmethod
    def fromhex_ignore_invalid(value, to_str=False):
        """Convert a hex string to bytes or string, ignoring invalid characters."""
        sanitized_value = ""
        for c in value.lower():
            if c in "0123456789abcdef":
                sanitized_value += c
        if len(sanitized_value) % 2 != 0:
            err("Hex value length is odd")
            return None
        if to_str:
            values = ["\\x" + hh for hh in slicer(sanitized_value, 2)]
            values = "".join(values)
        else:
            values = bytes.fromhex(sanitized_value)
        return values

    @staticmethod
    @Cache.cache_this_session
    def which(program):
        """Locate a command on the filesystem."""

        def is_exe(fpath):
            return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

        if not program:
            raise FileNotFoundError("Missing program name")

        if os.path.split(program)[0]: # check dirname
            if is_exe(program):
                return program
        else:
            # search from PATH
            env_path_default = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
            env_path = os.getenv("PATH", env_path_default)
            env_path = env_path.split(os.pathsep)

            from gef import Gef
            if hasattr(Gef, "GEF_VENV_BIN_PATH"):
                env_path.insert(0, Gef.GEF_VENV_BIN_PATH)

            if "/usr/local/bin" not in env_path:
                env_path.insert(0, "/usr/local/bin") # for rp-lin, vmlinux-to-elf

            for path in env_path:
                exe_file = os.path.join(path.strip('"'), program)
                if is_exe(exe_file):
                    return exe_file

        raise FileNotFoundError("Missing file `{:s}`".format(program))

    @staticmethod
    def show_last_exception():
        """Display the last Python exception."""

        def _show_code_line(fname, idx):
            fname = os.path.expanduser(os.path.expandvars(fname))
            __data = open(fname, "r").read().splitlines()
            return __data[idx - 1] if idx < len(__data) else ""

        gef_print("")
        exc_type, exc_value, exc_traceback = sys.exc_info()

        HORIZONTAL_LINE = "-"
        gef_print(" Exception raised ".center(80, HORIZONTAL_LINE))
        gef_print("{}: {}".format(Color.colorify(exc_type.__name__, "bold red underline"), exc_value))
        gef_print(" Detailed stacktrace ".center(80, HORIZONTAL_LINE))

        for fs in traceback.extract_tb(exc_traceback)[::-1]:
            filename, lineno, method, code = fs

            if not code or not code.strip():
                code = _show_code_line(filename, lineno)

            filename_c = Color.yellowify(filename)
            method_c = Color.greenify(method)
            gef_print('File "{}", line {:d}, in {}()'.format(filename_c, lineno, method_c))
            gef_print("    ->     {}".format(code))

        gef_print(" Last 10 GDB commands ".center(80, HORIZONTAL_LINE))
        gdb.execute("show commands")
        gef_print(" Runtime environment ".center(80, HORIZONTAL_LINE))
        gdb.execute("gef version --compact")
        gef_print(HORIZONTAL_LINE * 80)
        gef_print("")
        return

    @staticmethod
    def gef_execute_external(command, as_list=False, *args, **kwargs):
        """Execute an external command and return the result."""
        env = os.environ.copy()
        env["LANG"] = "C"

        res = subprocess.check_output(
            command, stderr=subprocess.STDOUT, env=env,
            shell=kwargs.get("shell", False),
        )
        if as_list:
            return [String.bytes2str(x) for x in res.splitlines()]
        return String.bytes2str(res)

    @staticmethod
    def walk(directory):
        """Return all file path excluding directories and symbolic links."""
        for root, _dirs, files in os.walk(directory):
            for f in sorted(files):
                path = os.path.join(root, f)
                if os.path.islink(path):
                    continue
                yield path
        return

    @staticmethod
    def now_str():
        """Return formatted time."""
        dt = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
        return dt

    @staticmethod
    def mkstemp(prefix="", dir=None, suffix=None, dt=None):
        """Create a temporary file."""
        if dt is None:
            dt = GefUtil.now_str()

        s = []
        if prefix:
            s.append(prefix)
        if dt:
            s.append(dt)
        real_prefix = "-".join(s)
        if real_prefix:
            real_prefix += "-"

        if dir is None:
            dir = GEF_TEMP_DIR
        return tempfile.mkstemp(dir=dir, prefix=real_prefix, suffix=suffix)

    @staticmethod
    def rmdir(directory, verbose=False, keep_root=False):
        """Recursively delete the target directory."""
        for root, dirs, files in os.walk(directory, topdown=False):
            for file in files:
                file_path = os.path.join(root, file)
                if verbose:
                    info("Removed: {:s}".format(file_path))
                os.remove(file_path)

            for dir in dirs:
                dir_path = os.path.join(root, dir)
                if verbose:
                    info("Removed: {:s}".format(dir_path))
                os.rmdir(dir_path)

        if not keep_root:
            os.rmdir(directory)
        return

    @staticmethod
    def make_legend(msg):
        """Apply color settings and generate legend string."""
        color = Config.get_gef_setting("theme.table_heading")
        return Color.colorify(msg.rstrip(), color)

    @staticmethod
    def get_size_str(size, enable_color=True):
        if 0 <= size < 1024:
            return "{:5.1f} B".format(size)
        elif 1024 <= size < 1024 ** 2:
            return "{:5.1f} KB".format(size / 1024)
        elif 1024 ** 2 <= size < 100 * (1024 ** 2): # 1MB~100MB
            return "{:5.1f} MB".format(size / 1024 / 1024)
        elif 100 * (1024 ** 2) <= size < 1024 ** 3: # 100MB~1GB
            if enable_color:
                return Color.colorify("{:5.1f} MB".format(size / 1024 / 1024), "bold yellow")
            else:
                return "{:5.1f} MB".format(size / 1024 / 1024)
        elif 1024 ** 3 <= size:
            if enable_color:
                return Color.colorify("{:5.1f} GB".format(size / 1024 / 1024 / 1024), "bold red")
            else:
                return "{:5.1f} GB".format(size / 1024 / 1024 / 1024)
        return "???"




# Re-export: UnicornKeystoneCapstone lives in gef.core.unicorn, but the monolith
# exposed it from the same namespace as these utilities; keep the old import path working.
from gef.core.unicorn import UnicornKeystoneCapstone  # noqa: E402,F401
