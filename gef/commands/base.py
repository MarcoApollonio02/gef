"""Command base infrastructure extracted from the monolithic gef.py.

Contains GenericCommand, BufferingOutput, register_command /
register_priority_command and the command-guard decorators.
"""
import abc
import functools

import gdb

from gef.core import runtime
from gef.core.cache import Cache
from gef.core.color import Color, gef_print, ok, err, warn, info
from gef.core.config import Config
from gef.core.memory import is_valid_addr
from gef.core.pagewalk import KernelAddressHeuristicFinder
from gef.core.process import (
    is_alive,
    is_remote_debug,
    is_in_kernel,
    is_kvm_enabled,
    is_smp_enabled,
    is_pin,
    is_qemu_system,
    is_qemu_user,
    is_vmware,
    is_kgdb,
    is_kdb,
    is_qiling,
    is_rr,
    is_wine,
    is_x86_32,
    is_x86_64,
    is_x86_16,
    is_arm32,
    is_arm32_cortex_m,
    is_arm64,
    is_mips32,
    is_mips64,
    is_mipsn32,
    is_ppc32,
    is_ppc64,
    is_sparc32,
    is_sparc32plus,
    is_sparc64,
    is_riscv32,
    is_riscv64,
    is_s390x,
    is_sh4,
    is_m68k,
    is_alpha,
    is_hppa32,
    is_hppa64,
    is_or1k,
    is_nios2,
    is_microblaze,
    is_xtensa,
    is_cris,
    is_loongarch64,
    is_arc32,
    is_arc64,
    is_csky,
)
from gef.core.runtime import CommandRegistry
from gef.core.utils import GefUtil

# Re-exports: these decorators were moved to gef.core by T5.7; keep them
# importable from the command module namespace without duplicating the code.
from gef.core.utils import switch_to_intel_syntax, timeout  # noqa: F401
from gef.core.events import only_if_events_supported  # noqa: F401


def parse_args(f):
    """Decorator wrapper to parse args for command."""

    @functools.wraps(f)
    def wrapper(self, argv, **kwargs):
        try:
            self.parser.exit = lambda *_: exec("if _: print(_[1]);\nraise(GefUtil.ArgparseExitProxyException(_))")
            args = self.parser.parse_args(argv)
        except GefUtil.ArgparseExitProxyException as e:
            if not e.args[0]: # when --help or -h
                self.usage(after_syntax_only=True)
            return
        except Exception as e:
            err("Invalid argument: {}".format(e))
            return
        if hasattr(args, "help_simple") and args.help_simple:
            self.usage(simple=True)
            return
        self.args = args
        return f(self, args, **kwargs)

    return wrapper


def only_if_gdb_running(f):
    """Decorator wrapper to check if GDB is running."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if is_alive():
            return f(*args, **kwargs)
        else:
            warn("No debugging session active")
            return

    return wrapper


def only_if_gdb_target_local(f):
    """Decorator wrapper to check if GDB is running locally (target not remote)."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if not is_remote_debug():
            return f(*args, **kwargs)
        else:
            warn("This command is not supported for remote sessions")
            return

    return wrapper


def only_if_in_kernel(f):
    """Decorator wrapper to check if context is in kernel."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if is_in_kernel():
            return f(*args, **kwargs)
        else:
            warn("Run in kernel context")
            return

    return wrapper


def only_if_in_kernel_or_kpti_disabled(f):
    """Decorator wrapper to check if context is in kernel or kpti disabled."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):

        def is_kpti_enabled():
            try:
                s = KernelAddressHeuristicFinder.get_saved_command_line()
            except gdb.MemoryError:
                return True
            if s and is_valid_addr(s):
                # You can access the kernel's .data area while in userland.
                # This means KPTI is disabled.
                return False
            return True

        if is_in_kernel():
            return f(*args, **kwargs)
        elif not is_kpti_enabled():
            return f(*args, **kwargs)
        else:
            warn("Run in kernel context, or disable KPTI")
            return

    return wrapper


def only_if_kvm_disabled(f):
    """Decorator wrapper to check if there is not `-enable-kvm` option."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if is_kvm_enabled():
            err("Disable `-enable-kvm` option for qemu-system")
            return
        return f(*args, **kwargs)

    return wrapper


def only_if_smp_disabled(f):
    """Decorator wrapper to check if there is not `-smp N` option."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if is_smp_enabled():
            err("Disable `-smp N` option for qemu-system")
            return
        return f(*args, **kwargs)

    return wrapper


def require_arch_set(f):
    """Decorator wrapper to check if current_arch is not None."""

    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        if runtime.current_arch is not None:
            return f(*args, **kwargs)
        else:
            err("Unsupported architecture")
            return

    return wrapper


def only_if_specific_gdb_mode(mode=()):
    """Decorator wrapper to check if the gdb mode is specific."""

    def wrapper(f):

        @functools.wraps(f)
        def inner_f(*args, **kwargs):
            dic = {
                "pin": is_pin,
                "qemu-system": is_qemu_system,
                "qemu-user": is_qemu_user,
                "vmware": is_vmware,
                "kgdb": is_kgdb,
                "kdb": is_kdb,
                "qiling": is_qiling,
                "rr": is_rr,
                "wine": is_wine,
            }
            for m in mode:
                if dic.get(m, lambda: False)():
                    return f(*args, **kwargs)
            warn("This command is not supported in this gdb mode")
            if "kgdb" in mode:
                if is_in_kernel() and not is_qemu_system() and not is_vmware():
                    info("For KGDB: Try `gef config gef.kgdb_force True`")
            return

        return inner_f

    return wrapper


def exclude_specific_gdb_mode(mode=()):
    """Decorator wrapper to check if the gdb mode is specific."""

    def wrapper(f):

        @functools.wraps(f)
        def inner_f(*args, **kwargs):
            dic = {
                "pin": is_pin,
                "qemu-system": is_qemu_system,
                "qemu-user": is_qemu_user,
                "vmware": is_vmware,
                "kgdb": is_kgdb,
                "kdb": is_kdb,
                "qiling": is_qiling,
                "rr": is_rr,
                "wine": is_wine,
            }
            for m in mode:
                if dic.get(m, lambda: False)():
                    warn("This command is not supported in this gdb mode")
                    return
            return f(*args, **kwargs)

        return inner_f

    return wrapper


def only_if_specific_arch(arch=()):
    """Decorator wrapper to check if the architecture is specific."""

    def wrapper(f):

        @functools.wraps(f)
        def inner_f(*args, **kwargs):
            dic = {
                "x86_32": is_x86_32,
                "x86_64": is_x86_64,
                "x86_16": is_x86_16,
                "ARM32": is_arm32,
                "ARM32M": is_arm32_cortex_m,
                "ARM64": is_arm64,
                "MIPS32": is_mips32,
                "MIPS64": is_mips64,
                "MIPSN32": is_mipsn32,
                "PPC32": is_ppc32,
                "PPC64": is_ppc64,
                "SPARC32": is_sparc32,
                "SPARC32PLUS": is_sparc32plus,
                "SPARC64": is_sparc64,
                "RISCV32": is_riscv32,
                "RISCV64": is_riscv64,
                "S390X": is_s390x,
                "SH4": is_sh4,
                "M68K": is_m68k,
                "ALPHA": is_alpha,
                "HPPA32": is_hppa32,
                "HPPA64": is_hppa64,
                "OR1K": is_or1k,
                "NIOS2": is_nios2,
                "MICROBLAZE": is_microblaze,
                "XTENSA": is_xtensa,
                "CRIS": is_cris,
                "LOONGARCH64": is_loongarch64,
                "ARC32": is_arc32,
                "ARC64": is_arc64,
                "CSKY": is_csky,
            }
            for a in arch:
                if dic.get(a, lambda: False)():
                    return f(*args, **kwargs)
            warn("This command is not supported on this architecture")
            return

        return inner_f

    return wrapper


def exclude_specific_arch(arch=()):
    """Decorator wrapper to check if the architecture is specific."""

    def wrapper(f):

        @functools.wraps(f)
        def inner_f(*args, **kwargs):
            dic = {
                "x86_32": is_x86_32,
                "x86_64": is_x86_64,
                "x86_16": is_x86_16,
                "ARM32": is_arm32,
                "ARM32M": is_arm32_cortex_m,
                "ARM64": is_arm64,
                "MIPS32": is_mips32,
                "MIPS64": is_mips64,
                "MIPSN32": is_mipsn32,
                "PPC32": is_ppc32,
                "PPC64": is_ppc64,
                "SPARC32": is_sparc32,
                "SPARC32PLUS": is_sparc32plus,
                "SPARC64": is_sparc64,
                "RISCV32": is_riscv32,
                "RISCV64": is_riscv64,
                "S390X": is_s390x,
                "SH4": is_sh4,
                "M68K": is_m68k,
                "ALPHA": is_alpha,
                "HPPA32": is_hppa32,
                "HPPA64": is_hppa64,
                "OR1K": is_or1k,
                "NIOS2": is_nios2,
                "MICROBLAZE": is_microblaze,
                "XTENSA": is_xtensa,
                "CRIS": is_cris,
                "LOONGARCH64": is_loongarch64,
                "ARC32": is_arc32,
                "ARC64": is_arc64,
                "CSKY": is_csky,
            }
            for a in arch:
                if dic.get(a, lambda: False)():
                    warn("This command is not supported on this architecture")
                    return
            return f(*args, **kwargs)

        return inner_f

    return wrapper


def register_command(cls):
    """Decorator for registering new GEF (sub-)command to GDB."""
    CommandRegistry.register(cls)
    return cls


def register_priority_command(cls):
    """Decorator for registering new command with priority, meaning that it must
    loaded before the other generic commands."""
    CommandRegistry.register(cls)
    # Preserve the old insert-at-front semantics on top of register().
    CommandRegistry.registered.insert(0, CommandRegistry.registered.pop())
    return cls


class GenericCommand(gdb.Command):
    """This is an abstract class for invoking commands, should not be instantiated."""

    __metaclass__ = abc.ABCMeta

    @property
    @abc.abstractmethod
    def _cmdline_(self):
        pass

    @property
    @abc.abstractmethod
    def _syntax_(self):
        pass

    @property
    @abc.abstractmethod
    def _example_(self):
        pass

    @property
    @abc.abstractmethod
    def _note_(self):
        pass

    @property
    @abc.abstractmethod
    def _repeat_(self):
        pass

    @property
    @abc.abstractmethod
    def _aliases_(self):
        pass

    @abc.abstractmethod
    def do_invoke(self, argv):
        pass

    def __init__(self, *args, **kwargs):

        def tab(lines):
            return "\n".join(["  " + line for line in lines.splitlines()])

        self.__doc__ += "\n"

        if self._syntax_:
            self.__doc__ += "\n"
            self.__doc__ += Color.colorify("Syntax:", "bold yellow")
            self.__doc__ += "\n"
            self.__doc__ += self._syntax_.strip()
            self.__doc__ += "\n"

        if self._example_:
            self.__doc__ += "\n"
            self.__doc__ += Color.colorify("Example:", "bold yellow")
            self.__doc__ += "\n"
            self.__doc__ += tab(self._example_.strip())
            self.__doc__ += "\n"

        if self._note_:
            self.__doc__ += "\n"
            self.__doc__ += Color.colorify("Note:", "bold yellow")
            self.__doc__ += "\n"
            self.__doc__ += tab(self._note_.strip())
            self.__doc__ += "\n"

        if hasattr(self._aliases_, "__iter__") and self._aliases_:
            self.__doc__ += "\n"
            self.__doc__ += Color.colorify("Aliases:", "bold yellow")
            self.__doc__ += "\n"
            self.__doc__ += tab(str(self._aliases_))
            self.__doc__ += "\n"

        self.repeat_count = 0
        self.last_command = None

        command_type = kwargs.get("command", gdb.COMMAND_NONE)
        complete_type = kwargs.get("complete", gdb.COMPLETE_NONE)
        prefix = kwargs.get("prefix", False)

        if complete_type == "use_user_complete":
            super().__init__(self._cmdline_, command_type, prefix=prefix)
        else:
            super().__init__(self._cmdline_, command_type, complete_type, prefix)
        return

    def invoke(self, args, from_tty): # noqa
        try:
            argv = gdb.string_to_argv(args)
            if self._repeat_:
                self.set_repeat_count(argv, from_tty)
            else:
                self.dont_repeat()
            self.do_invoke(argv)
        except Exception:
            # Since we are intercepting cleaning exceptions here, commands preferably should avoid
            # catching generic Exception, but rather specific ones. This is allows a much cleaner use.
            GefUtil.show_last_exception()
        return

    def usage(self, simple=False, after_syntax_only=False):

        def tab(lines):
            return "\n".join(["  " + line for line in lines.splitlines()])

        if not after_syntax_only:
            gef_print(Color.colorify("Syntax:", "bold yellow"))
            gef_print(self._syntax_.strip())

        if self._example_:
            gef_print("")
            gef_print(Color.colorify("Example:", "bold yellow"))
            gef_print(tab(self._example_.strip()))

        if self._note_:
            if not simple:
                gef_print("")
                gef_print(Color.colorify("Note:", "bold yellow"))
                gef_print(tab(self._note_.strip()))

        if self._aliases_:
            gef_print("")
            gef_print(Color.colorify("Aliases:", "bold yellow"))
            gef_print("  " + str(self._aliases_))

        this_command_key = self._cmdline_.replace("-", "_").replace(" ", "_").split()
        configs = [k for k in Config.__gef_config__.keys() if k.split(".")[:-1] == this_command_key]
        if configs:
            gef_print("")
            gef_print(Color.colorify("Configs:", "bold yellow"))
            max_width = max(len(x) for x in configs)
            for key in configs:
                value, _types, desc = Config.__gef_config__[key]
                gef_print("  {:{:d}} : {:s} [{}]".format(key, max_width, desc, value))
        return

    def add_setting(self, name, value, description=""):
        # make sure settings are always associated to the root command
        # which derives from GenericCommand directly.
        if "GenericCommand" not in [x.__name__ for x in self.__class__.__bases__]:
            return

        # sanitize
        class_name = self.__class__._cmdline_
        class_name = class_name.replace(" ", "_")
        # gdb's user complete feature does not work well if "-" is included.
        class_name = class_name.replace("-", "_")

        # add
        key = "{:s}.{:s}".format(class_name, name)
        Config.__gef_config__[key] = [value, type(value), description]
        Config.__gef_config_orig__[key] = [value, type(value), description] # for debugging

        # reset cache
        Cache.reset_gef_caches()
        return

    def set_repeat_count(self, argv, from_tty):
        if not from_tty:
            self.repeat_count = 0
            return

        command = gdb.execute("show commands", to_string=True).strip().split("\n")[-1]
        self.repeat_count = self.repeat_count + 1 if self.last_command == command else 0
        self.last_command = command
        return

    def quiet_print(self, msg):
        if not hasattr(self.args, "quiet") or not self.args.quiet:
            gef_print(msg)
        return

    def quiet_ok(self, msg):
        if not hasattr(self.args, "quiet") or not self.args.quiet:
            ok(msg)
        return

    def quiet_info(self, msg):
        if not hasattr(self.args, "quiet") or not self.args.quiet:
            info(msg)
        return

    def quiet_warn(self, msg):
        if not hasattr(self.args, "quiet") or not self.args.quiet:
            warn(msg)
        return

    def quiet_err(self, msg):
        if not hasattr(self.args, "quiet") or not self.args.quiet:
            err(msg)
        return

    def verbose_info(self, msg):
        if hasattr(self.args, "verbose") and self.args.verbose:
            info(msg)
        return

    def verbose_err(self, msg):
        if hasattr(self.args, "verbose") and self.args.verbose:
            err(msg)
        return

class BufferingOutput:
    """A collection of utility functions that append a messages to self.out."""

    def info_add_out(self, msg):
        msg = "{} {}".format(Color.colorify("[+]", "bold blue"), msg)
        self.out.append(msg)
        return

    def warn_add_out(self, msg):
        msg = "{} {}".format(Color.colorify("[*]", "bold yellow"), msg)
        self.out.append(msg)
        return

    def err_add_out(self, msg):
        msg = "{} {}".format(Color.colorify("[!]", "bold red"), msg)
        self.out.append(msg)
        return

    def quiet_info_add_out(self, msg):
        if not hasattr(self.args, "quiet") or not self.args.quiet:
            msg = "{} {}".format(Color.colorify("[+]", "bold blue"), msg)
            self.out.append(msg)
        return

    def quiet_add_out(self, msg):
        if not hasattr(self.args, "quiet") or not self.args.quiet:
            self.out.append(msg)
        return

    def verbose_add_out(self, msg):
        if hasattr(self.args, "verbose") and self.args.verbose:
            self.out.append(msg)
        return

    def print_output(self, check_terminal_size=False, skip_color=False):
        if not hasattr(self, "out"):
            return
        if not self.out:
            return

        def do_check_term_size(lines):
            # rough check
            t_height, t_width = GefUtil.get_terminal_size()
            if len(lines) > t_height:
                return not self.args.no_pager

            # detailed check
            h = 0
            for element in lines:
                for line in element.splitlines():
                    line = Color.remove_color(line)
                    h += (len(line) // t_width) + 1
                    if h > t_height:
                        return not self.args.no_pager
            return False

        if not check_terminal_size:
            less = not self.args.no_pager
        else:
            less = do_check_term_size(self.out)

        gef_print("\n".join(self.out), less=less, skip_color=skip_color)
        return


class GefAlias(gdb.Command):
    """Simple aliasing wrapper because GDB doesn't do what it should."""

    _category_ = "99. GEF Maintenance Command"

    def __init__(self, alias, command, force_repeat=None, pre_defined=False):
        p = command.split()
        if not p:
            return

        # initialize
        self._alias_ = alias
        self._command_ = command
        if force_repeat is None:
            self._repeat_ = False
        else:
            self._repeat_ = force_repeat
        self._pre_defined_ = pre_defined # default alias settings of GEF
        self.__doc__ = "Alias for '{:s}'".format(Color.greenify(command))

        # Inherit settings from the aliased command
        instance = runtime.CommandRegistry.instances.get(command, None)
        if instance:
            # repeat settings
            if force_repeat is None:
                self._repeat_ = instance._repeat_

            # doc
            self.__doc__ += ": {:s}".format(instance.__doc__)

            # complete settings
            if hasattr(instance, "complete"):
                self.complete = instance.complete

        # define aliased command
        if hasattr(instance, "complete"):
            # Aliased commands support only user completion.
            super().__init__(alias, gdb.COMMAND_NONE)
        else:
            super().__init__(alias, gdb.COMMAND_NONE, gdb.COMPLETE_NONE)

        # add or overwrite
        runtime.alias_instances[alias] = self
        return

    def invoke(self, args, from_tty): # noqa
        if not self._repeat_:
            self.dont_repeat()
        gdb.execute("{} {}".format(self._command_, args), from_tty=from_tty)
        return
