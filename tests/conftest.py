"""Pytest configuration for GEF unit tests (run outside gdb).

Most GEF modules `import gdb` at the top. The pure-logic modules under test
here (runtime, arch registry, address/color/config pure functions) must NOT
import gdb at module top-level. If a test needs to exercise gdb-dependent code,
mark it and exclude via the gdb tier (tests/gdb/), not here.
"""
