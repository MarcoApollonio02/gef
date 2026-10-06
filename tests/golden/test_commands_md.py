#!/usr/bin/env python3
"""Golden regression — `gef dump-commands` must reproduce docs/COMMANDS.md.

Run from the repo root:
    gdb -q -nx -x tests/golden/test_commands_md.py
"""

import os
import sys

sys.path.insert(0, os.getcwd())

import gdb  # noqa: E402

# Avoid interactive paging prompts during assertions.
gdb.execute("set pagination off")

from gef import Gef  # noqa: E402
from gef.core import runtime  # noqa: E402

# Boot GEF from the package: auto-discovers arch + commands and registers them.
Gef.main()

# Render the canonical command listing from the registered instance.
instance = runtime.CommandRegistry.instances["gef dump-commands"]
rendered = instance.render_commands()

golden_path = os.path.join(os.getcwd(), "docs", "COMMANDS.md")
with open(golden_path, "rb") as f:
    golden = f.read()

assert rendered.encode("utf-8") == golden, (
    "rendered `gef dump-commands` output differs from docs/COMMANDS.md "
    "(re-run `gef dump-commands docs/COMMANDS.md` if the change is intentional)"
)

print("GOLDEN COMMANDS.MD PASS")
