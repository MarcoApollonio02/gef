#!/usr/bin/env python3
"""Quick-trial bootstrap shim for the modular GEF package.

Use in .gdbinit: `source /path/to/gef-bootstrap.py`. Adds this directory to sys.path, imports the gef package, and runs Gef.main().
(Installed users keep the existing path: `python sys.path.insert(0, "/root/.gef"); from gef import *; Gef.main()` — unchanged.)
"""
import os
import sys

_bootstrap_dir = os.path.dirname(globals().get("__file__", os.path.realpath("gef-bootstrap.py")))
sys.path.insert(0, _bootstrap_dir)
from gef import *  # noqa: F401,F403
Gef.main()
