"""GEF bootstrap: Gef class, main() entry, and package auto-discovery.

Auto-discovery walks the `gef.commands` and `gef.arch` packages and imports
every submodule in deterministic (alphabetical) order, so dropping a new
command or architecture file registers it with zero edits to any central list.
Import failures are recorded per-module (runtime.missing_modules), not fatal —
mirroring the legacy `Gef.missing_commands` / `gef missing` behavior.
"""
import importlib
import pkgutil

from gef.core import runtime


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


# `Gef` class and `main()` are added in Task 7.
