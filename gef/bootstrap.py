"""GEF bootstrap: Gef class, main() entry, and package auto-discovery.

Auto-discovery walks the `gef.commands` and `gef.arch` packages and imports
every submodule in deterministic (alphabetical) order, so dropping a new
command or architecture file registers it with zero edits to any central list.
Import and command-load failures are recorded in runtime.missing_modules,
not fatal — the same state `gef missing` reports.
"""
import gdb
import importlib
import os
import pkgutil
import re
import subprocess
import sys
import time

from gef.core import runtime
from gef.core.arch_base import Architecture
from gef.core.color import Color, err, gef_print, titlify, warn
from gef.core.config import Config
from gef.core.display import hexon
from gef.core.events import EventHandler, EventHooking
from gef.core.http import http_get
from gef.core.process import get_arch, is_alive, set_arch
from gef.core.runtime import ArchRegistry, CommandRegistry
from gef.core.utils import GEF_FILEPATH, GEF_TEMP_DIR, GefUtil


def _discover(package):
    """Import all submodules of `package` (recursive, sorted by name).

    Failures are recorded in runtime.missing_modules keyed by dotted module
    name; a single broken module does not prevent the rest from loading.
    """
    prefix = package.__name__ + "."
    items = list(pkgutil.walk_packages(package.__path__, prefix))
    items.sort(key=lambda item: item[1])  # deterministic alphabetical order
    for _finder, name, _ispkg in items:
        try:
            importlib.import_module(name)
        except Exception as reason:
            runtime.missing_modules[name] = reason
    return


def update_gef(argv):
    """Try to update `gef` to the latest version (fetch+extract the repo archive)."""
    from gef.core.update import upgrade
    return upgrade()


class Gef:
    """A collection of utility functions that are related to GEF start up."""

    @staticmethod
    def list_current_commands():
        command_list = []
        res = gdb.execute("help all", to_string=True)
        for line in res.splitlines():
            line = line.strip()
            if " -- " not in line:
                continue
            commands = line.split(" -- ")[0]
            commands = commands.split(", ")
            command_list.extend(commands)
        return command_list

    @staticmethod
    def load_commands():
        """Load all the commands and functions defined by GEF into GDB."""
        # Imported here rather than at module scope: `gef.commands.base` builds
        # classes on `gdb.Command`, so a module-scope import would make
        # `import gef.bootstrap` fail wherever gdb is absent. Importing at load
        # time keeps the failure loud (no silent `None`) and inside GDB.
        from gef.commands.base import GefAlias

        DEBUG_PERF_TIME = False
        DEBUG_CHECK_COMMAND_CONFLICT = False

        if DEBUG_CHECK_COMMAND_CONFLICT:
            loaded_commands = Gef.list_current_commands()
            FIRST_TIME = "gef reload" not in loaded_commands # skip check when `gef reload`

        nb_missing = 0
        time_elapsed = []
        for cmd_class in runtime.CommandRegistry.registered:
            try:
                if DEBUG_PERF_TIME:
                    start_time_real = time.perf_counter()
                    start_time_proc = time.process_time()

                if DEBUG_CHECK_COMMAND_CONFLICT and FIRST_TIME:
                    if cmd_class._cmdline_ in loaded_commands:
                        warn("{:s} is already loaded".format(Color.boldify(cmd_class._cmdline_)))

                instance = cmd_class() # command loading is here
                runtime.CommandRegistry.instances[cmd_class._cmdline_] = instance

                if DEBUG_PERF_TIME:
                    end_time_real = time.perf_counter()
                    end_time_proc = time.process_time()

                    time_elapsed.append((
                        cmd_class._cmdline_,
                        end_time_real - start_time_real,
                        end_time_proc - start_time_proc,
                    ))

                if hasattr(cmd_class._aliases_, "__iter__"):
                    if isinstance(cmd_class._aliases_, str):
                        cmd_class_aliases = [cmd_class._aliases_]
                    elif isinstance(cmd_class._aliases_, list):
                        cmd_class_aliases = cmd_class._aliases_
                    else:
                        cmd_class_aliases = []

                    for alias in cmd_class_aliases:
                        if DEBUG_CHECK_COMMAND_CONFLICT and FIRST_TIME:
                            if alias in loaded_commands:
                                warn("{:s} is already loaded".format(Color.boldify(alias)))
                        GefAlias(alias, cmd_class._cmdline_, pre_defined=True)

            except Exception as reason:
                runtime.missing_modules[cmd_class._cmdline_] = reason
                nb_missing += 1

        if DEBUG_PERF_TIME:
            gef_print(titlify("Top 10 commands that took the longest to load"))
            for cmdline, real, cpu in sorted(time_elapsed, key=lambda x: x[1], reverse=True)[:10]:
                gef_print("{:30s} Real:{:.10f} s, CPU:{:.10f} s".format(cmdline, real, cpu))
            gef_print(titlify(""))

        # print message
        gef_print("{:s} is ready, type '{:s}' to start, '{:s}' to configure".format(
            Color.greenify("GEF"),
            Color.colorify("gef", "underline yellow"),
            Color.colorify("gef config", "underline magenta")
        ))

        ver = "{:d}.{:d}".format(sys.version_info.major, sys.version_info.minor)
        gef_print("Loaded {:s} commands (+{:s} aliases) for GDB {:s} using Python engine {:s}".format(
            Color.colorify(len(runtime.CommandRegistry.instances), "bold green"),
            Color.colorify(len(getattr(runtime, "alias_instances", {})), "bold green"),
            Color.colorify(gdb.VERSION, "bold yellow"),
            Color.colorify(ver, "bold red")
        ))

        if nb_missing:
            warn("{:s} command{} could not be loaded, run `{:s}` to know why.".format(
                Color.colorify(nb_missing, "bold red"),
                "s" if nb_missing > 1 else "",
                Color.colorify("gef missing", "underline magenta")
            ))
        return

    @staticmethod
    def gef_prompt(_current_prompt):
        """GEF custom prompt function."""
        if Config.get_gef_setting("gef.readline_compat") is True:
            return "gef> "
        if Color.disable_color():
            return "gef> "
        if is_alive():
            return "\001\033[1;32m\002gef> \001\033[0m\002"
        return "\001\033[1;31m\002gef> \001\033[0m\002"

    @staticmethod
    def fix_venv():
        """Detect if you are in a venv environment and adjust GEF settings."""

        def fast_path():
            """If you installed it with the latest installer, there should be a gev.venv.conf file.
            Interpreting this file will speed up the process."""
            gef_venv_conf = os.path.join(os.path.dirname(GEF_FILEPATH), "gef.venv.conf")
            if not os.path.exists(gef_venv_conf):
                return False

            content = open(gef_venv_conf, "rb").read().decode()
            for line in content.splitlines():
                if line.startswith("GEF_VENV_SYS_PATH="):
                    Gef.GEF_VENV_SYS_PATH = line[len("GEF_VENV_SYS_PATH="):]
                    to_add = []
                    for path in Gef.GEF_VENV_SYS_PATH.split(":"):
                        if path and path not in sys.path:
                            to_add.append(path)
                    sys.path = to_add + sys.path
                    continue

                if line.startswith("GEF_VENV_BIN_PATH="):
                    Gef.GEF_VENV_BIN_PATH = line[len("GEF_VENV_BIN_PATH="):] # used by GefUtil.which()
                    continue

                if line.startswith("GEF_VENV_GEM_HOME="):
                    Gef.GEF_VENV_GEM_HOME = line[len("GEF_VENV_GEM_HOME="):]
                    os.environ["GEM_HOME"] = Gef.GEF_VENV_GEM_HOME
                    continue

            if hasattr(Gef, "GEF_VENV_SYS_PATH"):
                return True
            return False

        def create_skip_config():
            # If .venv-gef is in the default location, it is likely that the user simply forgot to activate the venv.
            # Therefore, for convenience, skip-venv-check is not created.
            default_venv = os.path.join(os.path.dirname(GEF_FILEPATH), ".venv-gef")
            if os.path.exists(default_venv):
                return

            skip_config = os.path.join(GEF_TEMP_DIR, "skip-venv-check")
            open(skip_config, "w").close()
            return

        def slow_path():
            """For those who used the old installer or installed manually.
            It launches python via shell and collects and imports its configuration."""
            # venv check is very slow, so skip if unneeded
            skip_config = os.path.join(GEF_TEMP_DIR, "skip-venv-check")
            if os.path.exists(skip_config):
                return

            # GEF supports pyenv, venv, uv, etc.
            # To achieve this, you need to run python outside of gdb.
            # Modify sys.path based on the results of the execution.

            # check python3 command to get prefix
            try:
                pythonbin = GefUtil.which("python3")
            except FileNotFoundError:
                create_skip_config()
                return

            # check prefix
            cmds = [pythonbin, "-c", "import os,sys;print(sys.prefix)"]
            PREFIX = subprocess.check_output(cmds).decode("utf-8").strip()
            if PREFIX == sys.base_prefix:
                create_skip_config()
                return

            # add path
            cmds = [pythonbin, "-c", "import os,sys;print(os.linesep.join(sys.path).strip())"]
            SITE_PACKAGES_DIRS = subprocess.check_output(cmds).decode("utf-8").split()
            to_add = []
            for path in SITE_PACKAGES_DIRS:
                if path not in sys.path:
                    to_add.append(path)
            sys.path = to_add + sys.path
            return

        fast_path() or slow_path()
        return

    @staticmethod
    def main():
        # check gdb version
        GDB_VERSION = tuple(map(int, re.search(r"(\d+)[^\d]+(\d+)", gdb.VERSION).groups()))
        GDB_MIN_VERSION = (9, 2) # ubuntu 20.04
        if GDB_VERSION < GDB_MIN_VERSION:
            err("GDB version ({:s}) is too old (<{:d}.{:d}). Try upgrading it.".format(
                gdb.VERSION, GDB_MIN_VERSION[0], GDB_MIN_VERSION[1],
            ))
            return

        # create tmp dir
        if not os.path.exists(GEF_TEMP_DIR):
            os.mkdir(GEF_TEMP_DIR) # 0o755
            # GEF runs with root privileges, but it may attach to a normal privileges program.
            # If you want to execute a command that involves stdout redirection for that program,
            # you will need write permission to /tmp/gef.
            os.chmod(GEF_TEMP_DIR, 0o777)

        # check tmp dir access permission
        # This check takes into account the cases where GEF is run with root privileges and with normal user privileges.
        if not os.access(GEF_TEMP_DIR, os.W_OK|os.R_OK|os.X_OK):
            err("Permission denied to {:s}. Please delete it first.".format(GEF_TEMP_DIR))
            return

        # When using a python virtual environment (pyenv, venv, etc.), GDB still loads
        # the system-installed python, so GEF doesn't load site-packages dir from environment.
        # In order to fix it, from the shell we run the python3 binary,
        # take and parse its path, add the path to the current python process.
        Gef.fix_venv()

        # setup prompt
        gdb.prompt_hook = Gef.gef_prompt # noqa

        # common config
        gdb.execute("set confirm off")
        gdb.execute("set verbose off")
        gdb.execute("set pagination off")
        gdb.execute("set output-radix 0x10")

        # gdb history
        gdb.execute("set history save on")
        gdb.execute("set history size 1000")
        gdb.execute("set history filename ~/.gdb_history")

        # print
        gdb.execute("set print elements 0") # remove element count limit
        gdb.execute("set print pretty on")
        gdb.execute("set print array on") # use multi-line when print
        gdb.execute("set print array-indexes on") # add index when print
        gdb.execute("set print asm-demangle on") # demangle
        gdb.execute("set print object on")
        gdb.execute("set print vtbl on")

        try:
            # this will raise a gdb.error unless we're on x86
            gdb.execute("set disassembly-flavor intel")
        except gdb.error:
            # we can safely ignore this
            pass

        # SIGALRM will simply display a message, but gdb won't forward the signal to the process
        gdb.execute("handle SIGALRM print nopass")

        # SIGSEGV/SIGTERM/SIG32(for thread creation)
        gdb.execute("handle SIGSEGV print nopass")
        gdb.execute("handle SIGTERM print nopass")
        gdb.execute("handle SIG32 nostop")

        # stops at first instruction of functions without debug info when stepping
        gdb.execute("set step-mode on")

        # frame
        gdb.execute("set backtrace past-main on")
        gdb.execute("set print frame-arguments all")

        # wire ArchRegistry to the concrete Architecture base and auto-discover
        # all architectures and commands
        ArchRegistry._base = Architecture
        from gef import commands as _commands_pkg
        import gef.arch as _arch_pkg
        _discover(_arch_pkg)
        _discover(_commands_pkg)

        # load all commands that has @register_command decorator.
        Gef.load_commands()

        # load the saved settings
        try:
            gdb.execute("gef restore")
        except gdb.error:
            pass  # e.g. no saved settings yet

        # follow mode
        if Config.get_gef_setting("gef.follow_child"):
            gdb.execute("set follow-fork-mode child")

        # index file
        gdb.execute("save gdb-index {:s}".format(GEF_TEMP_DIR)) # don't use {!r}

        # gdb events configuration
        EventHooking.gef_on_continue_hook(EventHandler.continue_handler)
        EventHooking.gef_on_stop_hook(EventHandler.hook_stop_handler)
        EventHooking.gef_on_new_hook(EventHandler.new_objfile_handler)
        EventHooking.gef_on_exit_hook(EventHandler.exit_handler)
        EventHooking.gef_on_memchanged_hook(EventHandler.memchanged_handler)
        EventHooking.gef_on_regchanged_hook(EventHandler.regchanged_handler)

        if gdb.current_progspace().filename is not None:
            # if here, we are sourcing gef from a gdb session already attached
            # we must force a call to the new_objfile handler
            EventHandler.new_objfile_handler(None)

        # python-interactive
        hexon()

        # If GEF is loaded after gdb is connected
        if is_alive():
            if runtime.current_arch is None:
                set_arch(get_arch())
        return
