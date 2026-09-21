#!/usr/bin/env python3
"""Phase 1 checkpoint test — boot + arch discovery + set_arch.

Run from the repo root:
    gdb -q -nx -x tests/gdb/test_phase1_checkpoint.py
"""

import os
import sys

sys.path.insert(0, os.getcwd())

import gef.arch  # noqa: E402
import gdb  # noqa: E402

# Avoid interactive paging prompts during assertions.
gdb.execute("set pagination off")
from gef.core.arch_base import Architecture  # noqa: E402
from gef.bootstrap import _discover  # noqa: E402
from gef.core import runtime  # noqa: E402
from gef.core.color import gef_print  # noqa: E402
from gef.core.process import set_arch  # noqa: E402
from gef.core.runtime import ArchRegistry, CommandRegistry  # noqa: E402

# Wire ArchRegistry to the concrete base and auto-discover all arch families.
ArchRegistry._base = Architecture
_discover(gef.arch)

# --- assertions -------------------------------------------------------------

all_archs = ArchRegistry.all()
assert len(all_archs) > 0, "ArchRegistry discovered no architectures"
gef_print("Discovered {:d} arch classes: {:s}".format(
    len(all_archs), ", ".join(cls.__name__ for cls in all_archs)))

set_arch("x86-64")
arch = runtime.current_arch
assert arch is not None, "set_arch('x86-64') did not set runtime.current_arch"
cls_name = type(arch).__name__
gef_print("current_arch class: {:s} (arch={!s})".format(cls_name, getattr(arch, "arch", "?")))
assert cls_name == "X86_64" or getattr(arch, "arch", "") == "X86_64", \
    "expected X86_64 arch, got {:s}".format(cls_name)

assert CommandRegistry.registered == [], \
    "Phase 1: no commands should be registered, found {:d}".format(len(CommandRegistry.registered))

gef_print("hello")

print("PHASE1 CHECKPOINT PASS")
