"""Unit tests for gef.core.runtime (no gdb import required)."""
import builtins
import sys
import types

import pytest


def _fresh_runtime():
    """Import runtime fresh so class-level state doesn't leak between tests."""
    sys.modules.pop("gef.core.runtime", None)
    import importlib
    import gef.core.runtime as rt
    importlib.reload(rt)
    return rt


def test_command_registry_register_appends():
    rt = _fresh_runtime()
    class FakeCmd:
        _cmdline_ = "fake-cmd"
    rt.CommandRegistry.registered = []  # reset
    rt.CommandRegistry.register(FakeCmd)
    assert FakeCmd in rt.CommandRegistry.registered


def test_command_registry_get_returns_instance_or_none():
    rt = _fresh_runtime()
    rt.CommandRegistry.instances = {}
    assert rt.CommandRegistry.get("nope") is None
    class FakeCmd:
        _cmdline_ = "x"
    inst = FakeCmd()
    rt.CommandRegistry.instances["x"] = inst
    assert rt.CommandRegistry.get("x") is inst


def test_current_arch_starts_none_and_set_current_arch_rebinds():
    rt = _fresh_runtime()
    rt.current_arch = None
    assert rt.get_current_arch() is None
    sentinel = object()
    rt.set_current_arch(sentinel)
    assert rt.get_current_arch() is sentinel
    assert rt.current_arch is sentinel


def test_arch_registry_find_walks_subclasses_recursively():
    rt = _fresh_runtime()
    # Build a fake Architecture base + subclass hierarchy to test the walk,
    # because the real Architecture base lives in gef.core.arch_base (Task 6).
    class FakeArch:
        load_condition = ("FAKE",)
    class Child(FakeArch):
        load_condition = ("CHILD",)
    class Grandchild(Child):
        load_condition = ("GRAND",)
    # Monkeypatch Architecture.__subclasses__ on the module-level base used by find.
    # ArchRegistry.find references the base via a late lookup; we inject FakeArch.
    rt.ArchRegistry._base = FakeArch  # test injection hook
    assert FakeArch in rt.ArchRegistry.all()
    assert Child in rt.ArchRegistry.all()
    assert Grandchild in rt.ArchRegistry.all()
    assert rt.ArchRegistry.find("GRAND") is Grandchild
    assert rt.ArchRegistry.find("child") is Child  # case-insensitive
    assert rt.ArchRegistry.find("MISSING") is None


def test_missing_modules_is_dict():
    rt = _fresh_runtime()
    assert isinstance(rt.missing_modules, dict)
