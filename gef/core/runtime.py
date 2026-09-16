"""Runtime state for GEF (Layer 0).

This module is the single home for mutable global state and the C-track seam:
- `current_arch` is the ONE module attribute that gets *rebound* (not mutated in
  place). It must be read as `runtime.current_arch` from other modules, never
  imported by name, to avoid the stale-binding pitfall (see ARCHITECTURE.md).
- The registries (`CommandRegistry`, `ArchRegistry`) wrap what are today bare
  globals, so the C-track can swap their backing store without touching command
  or architecture code.

This module must NOT import gdb or any higher layer (arch/*, commands/*).
"""
import importlib


class CommandRegistry:
    """Holds registered command classes and instantiated commands.

    Backs the old `__gef_commands__` (registered) and
    `__gef_command_instances__` (instances) globals. In-place mutation of the
    list/dict is fine for callers that import them by name; only `current_arch`
    needs the qualified-access rule.
    """

    registered: list = []
    instances: dict = {}

    @classmethod
    def register(cls, cmd_cls):
        """Append a command class (called by @register_command)."""
        cls.registered.append(cmd_cls)
        return cmd_cls

    @classmethod
    def get(cls, name):
        """Return the instantiated command for `name`, or None."""
        return cls.instances.get(name)


class ArchRegistry:
    """Discovers architectures via the Architecture base's subclass tree.

    `find()` replicates the lookup currently inlined in gef.py `set_arch()`
    (L14825-14861): walk `Architecture.__subclasses__()` breadth-first, map each
    `load_condition` entry to the class, case-insensitive match on the key.
    The base is referenced lazily so this module need not import arch_base
    (avoids a core->core cycle at import time).
    """

    _base = None  # test injection hook; production set by bootstrap to Architecture

    @staticmethod
    def _walk(base):
        """Breadth-first walk of base and all transitive subclasses."""
        seen = []
        queue = [base]
        while queue:
            cls = queue.pop(0)
            seen.append(cls)
            queue.extend(cls.__subclasses__())
        return seen

    @classmethod
    def all(cls):
        """Return all concrete architecture classes."""
        base = cls._base
        if base is None:
            return []
        return cls._walk(base)

    @classmethod
    def find(cls, arch_str):
        """Return the arch class whose load_condition matches arch_str (case-insensitive), or None."""
        if arch_str is None:
            return None
        key = arch_str.upper()
        for cls in cls.all():
            for lc in getattr(cls, "load_condition", ()):
                if isinstance(lc, str) and lc.upper() == key:
                    return cls
        return None


current_arch = None
missing_modules: dict = {}


def get_current_arch():
    """Return the current architecture (or None)."""
    return current_arch


def set_current_arch(arch):
    """Rebind the current architecture — the single allowed rebind site."""
    global current_arch
    current_arch = arch
