"""GDB event handlers and hooking helpers (Layer 1).

`only_if_events_supported` is the decorator that guards hook functions when
the running GDB lacks the corresponding `gdb.events.*` attribute.
`EventHandler` holds the GDB-side event handlers (stop/new_objfile/exit/
memory/reg changed); `EventHooking` holds the static connect/disconnect
helpers.

Reads of the mutable global `current_arch` go through `runtime.current_arch`.
References to `gef.commands.*` (e.g. BreakRelativeVirtualAddressCommand) are
late-imported inside the referencing method.
"""
import contextlib
import os
import re

import gdb

from gef.core import runtime
from gef.core.cache import Cache
from gef.core.color import err, warn


def only_if_events_supported(event_type):
    """Decorator for checking if GDB supports events without crashing."""

    def wrap(f):

        def wrapped_f(*args, **kwargs):
            if hasattr(gdb.events, event_type):
                return f(*args, **kwargs)
            warn("GDB events cannot be set")

        return wrapped_f

    return wrap


class EventHandler:
    """A collection of handler functions that are called when the specified events occur."""

    @staticmethod
    def continue_handler(_event):
        """GDB event handler for new object continue cases."""
        return

    __gef_check_once__ = True # the flag to process only once at startup
    continue_hooks_enabled = False
    kpti_transition_active = False
    qemu_pipe_pids = {}
    __gef_check_disabled_bp__ = False # the flag to remove unnecessary breakpoints

    @staticmethod
    def hook_stop_handler(event):
        """GDB event handler for stop cases."""
        from gef.core.process import is_arm32_cortex_m, is_cris, is_kgdb, is_or1k, is_over_serial, is_pin, is_qemu_system, is_qemu_user, is_vmware, get_arch, set_arch
        Cache.reset_gef_caches()

        # There appears to be a bug on some architectures (e.g., i386) where temporary breakpoints
        # are not deleted even after being hit. The conditions under which this occurs are unknown,
        # so any remaining breakpoints are removed manually by GEF.
        if EventHandler.__gef_check_disabled_bp__:
            for bp in gdb.breakpoints():
                if not bp.visible and bp.temporary:
                    if not bp.enabled:
                        bp.delete()
            EventHandler.__gef_check_disabled_bp__ = False

        # when kgdb, assume x86-64 if /dev/ttyS
        if EventHandler.__gef_check_once__:
            if is_over_serial():
                dev = gdb.selected_inferior().connection.details
                if dev.startswith("/dev/ttyS"):
                    gdb.execute("set architecture i386:x86-64:intel", to_string=True)
                else:
                    # In the case of /dev/ttyAMA, it is not clear whether it is ARM64 or ARM32.
                    # In some cases, /dev/ttyUSB is used.
                    pass
                Cache.reset_gef_caches()

        # GEF will resolve the architecture if it is unknown.
        if runtime.current_arch is None:
            set_arch(get_arch())

        # set `c`, `ni` and `si` command hooks for qemu-user and pin
        if EventHandler.__gef_check_once__:
            if is_qemu_user() or is_pin():
                gdb.execute("define c\ncontinue-for-qemu-user\nend")
                if is_or1k() or is_cris():
                    gdb.execute("define si\nstepi-for-qemu-user\nend")
                    gdb.execute("define ni\nnexti-for-qemu-user\nend")

        # disable for cortex-m
        if EventHandler.__gef_check_once__:
            if is_arm32_cortex_m():
                gdb.execute("gef config context.disable_vmmap True")
                gdb.execute("gef config context.disable_auxv True")

        # If the silent command is specified for a breakpoint, skip `context` command.
        context_flag = True
        if isinstance(event, gdb.BreakpointEvent):
            if event.breakpoint.is_valid() and event.breakpoint.enabled:
                if event.breakpoint.commands:
                    if event.breakpoint.commands.startswith("silent"):
                        context_flag = False
        if context_flag:
            gdb.execute("context")

        # Message if file is not loaded.
        if EventHandler.__gef_check_once__:
            if not (is_qemu_system() or is_kgdb() or is_vmware()):
                if not gdb.current_progspace().filename:
                    err("Missing info about architecture, please set: `file /path/to/target_binary`")
                    err("If the architecture isn't automatically detected, use: `set architecture YOUR_ARCH`")
            EventHandler.__gef_check_once__ = False
        return

    @staticmethod
    def new_objfile_handler(_event):
        """GDB event handler for new object file cases."""
        from gef.core.process import ProcessMap, is_alive, is_kgdb, is_qemu_system, is_vmware, get_arch, set_arch
        Cache.reset_gef_caches(new_objfile=True)
        if runtime.current_arch is None:
            set_arch(get_arch())

        # delayed breakpoint for brva
        try:
            from gef.commands.debugging.breakpoint import BreakRelativeVirtualAddressCommand
        except ModuleNotFoundError:
            BreakRelativeVirtualAddressCommand = None
        if BreakRelativeVirtualAddressCommand and BreakRelativeVirtualAddressCommand.delayed_bp_set is False and is_alive():
            if not (is_qemu_system() or is_kgdb() or is_vmware()):
                codebase = ProcessMap.get_codebase()
                if codebase:
                    for offset in BreakRelativeVirtualAddressCommand.delayed_breakpoints:
                        gdb.execute("b *{:#x}".format(codebase + offset))
                    BreakRelativeVirtualAddressCommand.delayed_bp_set = True
        return

    @staticmethod
    def exit_handler(_event):
        """GDB event handler for exit cases."""
        Cache.reset_gef_caches(all=True)
        return

    @staticmethod
    def memchanged_handler(_event):
        """GDB event handler for mem changes cases."""
        Cache.reset_gef_caches()
        return

    @staticmethod
    def regchanged_handler(_event):
        """GDB event handler for reg changes cases."""
        Cache.reset_gef_caches()
        return

    @staticmethod
    def get_handlers():
        handlers = [
            ("stop", EventHandler.hook_stop_handler),
            ("new_objfile", EventHandler.new_objfile_handler),
            ("free_objfile", EventHandler.del_objfile_handler),
            ("clear_objfiles", EventHandler.del_objfile_handler),
            ("exited", EventHandler.exit_handler),
            ("gdb_exiting", EventHandler.gdb_exiting_handler),
            ("connection_removed", EventHandler.connection_removed_handler),
            ("memory_changed", EventHandler.state_changed_handler),
            ("register_changed", EventHandler.state_changed_handler),
        ]
        if hasattr(gdb.events, "selected_context"):
            handlers.extend([
                ("selected_context", EventHandler.selected_context_handler),
                ("new_thread", EventHandler.new_thread_handler),
            ])
        return handlers

    @staticmethod
    def connect():
        EventHandler.set_continue_hooks(True)
        for name, handler in EventHandler.get_handlers():
            registry = getattr(gdb.events, name, None)
            if registry is not None:
                registry.connect(handler)
        if hasattr(gdb.events, "selected_context"):
            EventHandler.update_continue_hooks()
        return

    @staticmethod
    def set_continue_hooks(enabled):
        from gef.commands.debugging.context import ContextExtraCommand, ContextRegistersCommand
        if enabled == EventHandler.continue_hooks_enabled:
            return

        handlers = (
            ContextRegistersCommand.update_registers,
            ContextExtraCommand.empty_extra_messages,
            EventHandler.continue_handler,
        )
        if enabled:
            hook = EventHooking.gef_on_continue_hook
        else:
            hook = EventHooking.gef_on_continue_unhook
        for handler in handlers:
            hook(handler)
        EventHandler.continue_hooks_enabled = enabled
        return

    @staticmethod
    def update_continue_hooks():
        return EventHandler.set_continue_hooks(gdb.selected_thread() is not None)

    @staticmethod
    def del_objfile_handler(_event):
        from gef.core.utils import GefUtil
        """GDB event handler for removed object file cases.
        `remove-symbol-file`, an actual shared library unload and `file` replacing the whole
        symbol file set stale the same caches as loading a new one does."""
        progspace = getattr(_event, "progspace", None)
        if progspace is not None and not progspace.objfiles():
            GefUtil.clear_user_bases(progspace=progspace)
        Cache.reset_gef_caches(new_objfile=True)
        return

    @staticmethod
    def gdb_exiting_handler(event):
        """Stop QEMU children launched through a pipe before GDB waits for them."""
        for inferior in gdb.inferiors():
            connection = inferior.connection
            if connection is None or connection.type not in ("remote", "extended-remote"):
                continue
            if not (connection.details or "").lstrip().startswith("|"):
                continue
            if inferior != gdb.selected_inferior():
                gdb.execute("inferior {:d}".format(inferior.num), to_string=True)
            Cache.reset_gef_caches(all=True)
            EventHandler.track_qemu_pipe()
            if connection.num not in EventHandler.qemu_pipe_pids:
                continue
            try:
                gdb.execute("kill", to_string=True)
            except gdb.error:
                pass
        return

    @staticmethod
    def connection_removed_handler(_event):
        from gef.commands.memory.patch import PatchCommand
        from gef.core.kernel import KernelVersion
        from gef.core.utils import GefUtil
        """GDB event handler for removed target connections."""
        child = EventHandler.qemu_pipe_pids.pop(_event.connection.num, None)
        if child is not None:
            import signal
            pid, started = child
            try:
                current = open("/proc/{:d}/stat".format(pid)).read().rsplit(")", 1)[1].split()[19]
                if current == started:
                    os.kill(pid, signal.SIGKILL)
            except (FileNotFoundError, ProcessLookupError):
                pass
        PatchCommand.invalidate_history(connection_num=_event.connection.num)
        KernelVersion.clear_override(connection_num=_event.connection.num)
        GefUtil.clear_user_bases(connection_num=_event.connection.num)
        Cache.reset_gef_caches(all=True)
        return

    @staticmethod
    def state_changed_handler(_event):
        """Invalidate caches after memory or register changes."""
        Cache.reset_gef_caches()
        return

    @staticmethod
    def selected_context_handler(_event):
        """Enable continue handlers only when the selected inferior has a thread."""
        return EventHandler.update_continue_hooks()

    @staticmethod
    def new_thread_handler(_event):
        gdb.post_event(EventHandler.update_continue_hooks)
        return

    @staticmethod
    def track_qemu_pipe():
        from gef.core.process import Pid, is_qemu_system
        inferior = gdb.selected_inferior()
        connection = getattr(inferior, "connection", None)
        if connection is None or connection.type not in ("remote", "extended-remote"):
            return
        if connection.num in EventHandler.qemu_pipe_pids:
            return
        if not (connection.details or "").lstrip().startswith("|") or not is_qemu_system():
            return
        qemu_pid = pid = Pid.get_pid()
        while pid and pid != os.getpid():
            try:
                status = open("/proc/{:d}/status".format(pid)).read()
            except OSError:
                return
            parent = re.search(r"^PPid:\s+(\d+)$", status, re.MULTILINE)
            if parent:
                pid = int(parent.group(1))
            else:
                pid = None
        if pid == os.getpid():
            try:
                started = open("/proc/{:d}/stat".format(qemu_pid)).read().rsplit(")", 1)[1].split()[19]
            except OSError:
                return
            EventHandler.qemu_pipe_pids[connection.num] = (qemu_pid, started)
        return

    @staticmethod
    def disconnect():
        EventHandler.set_continue_hooks(False)
        for name, handler in EventHandler.get_handlers():
            registry = getattr(gdb.events, name, None)
            if registry is not None:
                registry.disconnect(handler)
        return


class EventHooking:
    """A collection of utility functions that hook up specified events."""

    @staticmethod
    @contextlib.contextmanager
    def temporary(event_name, callback, once=False):
        registry = getattr(gdb.events, event_name, None)
        if registry is None:
            warn("GDB events cannot be set: {:s}".format(event_name))
            yield
            return

        connected = True

        def dispatch(event):
            nonlocal connected
            if once:
                registry.disconnect(dispatch)
                connected = False
            callback(event)

        registry.connect(dispatch)
        try:
            yield
        finally:
            if connected:
                registry.disconnect(dispatch)
        return

    @staticmethod
    @only_if_events_supported("cont")
    def gef_on_continue_hook(func):
        return gdb.events.cont.connect(func)

    @staticmethod
    @only_if_events_supported("cont")
    def gef_on_continue_unhook(func):
        return gdb.events.cont.disconnect(func)

    @staticmethod
    @only_if_events_supported("stop")
    def gef_on_stop_hook(func):
        return gdb.events.stop.connect(func)

    @staticmethod
    @only_if_events_supported("stop")
    def gef_on_stop_unhook(func):
        return gdb.events.stop.disconnect(func)

    @staticmethod
    @only_if_events_supported("exited")
    def gef_on_exit_hook(func):
        return gdb.events.exited.connect(func)

    @staticmethod
    @only_if_events_supported("exited")
    def gef_on_exit_unhook(func):
        return gdb.events.exited.disconnect(func)

    @staticmethod
    @only_if_events_supported("new_objfile")
    def gef_on_new_hook(func):
        return gdb.events.new_objfile.connect(func)

    @staticmethod
    @only_if_events_supported("new_objfile")
    def gef_on_new_unhook(func):
        return gdb.events.new_objfile.disconnect(func)

    @staticmethod
    @only_if_events_supported("memory_changed")
    def gef_on_memchanged_hook(func):
        return gdb.events.memory_changed.connect(func)

    @staticmethod
    @only_if_events_supported("memory_changed")
    def gef_on_memchanged_unhook(func):
        return gdb.events.memory_changed.disconnect(func)

    @staticmethod
    @only_if_events_supported("register_changed")
    def gef_on_regchanged_hook(func):
        return gdb.events.register_changed.connect(func)

    @staticmethod
    @only_if_events_supported("register_changed")
    def gef_on_regchanged_unhook(func):
        return gdb.events.register_changed.disconnect(func)
