"""Unit tests for gef.core.cache (run outside gdb).

`core/cache.py` must stay gdb-free at import time (repo rule 5: it is part of
the pytest tier). The gdb-tier surfaces (`Cache.cpu_context`,
`Cache.reset_gef_caches`) are skipped here and exercised inside gdb instead.
"""

import pytest

from gef.core.cache import Cache


def _fname(f):
    """The per-function cache key built by Cache.cache_wrap."""
    return "{:s}:{:s}".format(f.__module__, f.__qualname__)


def _throwaway(name, value=None):
    """A throwaway function with a unique name and a call counter, so each
    test gets its own cache slot and recomputations are observable."""
    calls = []

    def f():
        calls.append(1)
        return value

    f.__name__ = name
    f.__qualname__ = name
    return f, calls


@pytest.fixture
def clean_caches():
    """Clear the per-function cache dicts in place (as reset_gef_caches does),
    before and after each test, so tests stay independent."""
    def _clear():
        for caches in Cache.__gef_caches__.values():
            for fcache in caches.values():
                fcache.clear()
    _clear()
    yield
    _clear()


def test_cache_until_next_stores_none_by_default(clean_caches):
    # Bare decorator: cache_None defaults to True, so a None result is cached
    # and the wrapped function is not called again.
    f, calls = _throwaway("until_next_stores_none", value=None)
    wrapped = Cache.cache_until_next(f)

    assert wrapped() is None
    assert wrapped() is None
    assert len(calls) == 1
    assert Cache.__gef_caches__["until_next"][_fname(f)] == {(): None}


def test_cache_until_next_cache_none_false_does_not_store_none(clean_caches):
    # With cache_None=False a None result is not cached, so every call recomputes.
    f, calls = _throwaway("until_next_skips_none", value=None)
    wrapped = Cache.cache_until_next(cache_None=False)(f)

    assert wrapped() is None
    assert wrapped() is None
    assert len(calls) == 2
    assert Cache.__gef_caches__["until_next"][_fname(f)] == {}


def test_cache_this_session_cache_none_false_does_not_store_none(clean_caches):
    # The options form used by the converted call sites (kernel.py, types.py,
    # base_address.py): a None result is not cached in "this_session" either.
    f, calls = _throwaway("this_session_skips_none", value=None)
    wrapped = Cache.cache_this_session(cache_None=False)(f)

    assert wrapped() is None
    assert wrapped() is None
    assert len(calls) == 2
    assert Cache.__gef_caches__["this_session"][_fname(f)] == {}


def test_peek_cache_for_and_clear_cache_for(clean_caches):
    f, calls = _throwaway("peek_me", value=0x1234)
    wrapped = Cache.cache_until_next(f)

    assert Cache.peek_cache_for(wrapped) is None # not resolved yet
    assert wrapped() == 0x1234
    assert Cache.peek_cache_for(wrapped) == 0x1234
    assert len(calls) == 1

    Cache.clear_cache_for(wrapped)
    assert Cache.peek_cache_for(wrapped) is None # cleared in place
    assert wrapped() == 0x1234
    assert len(calls) == 2 # recomputed after the clear


@pytest.mark.skip(reason="gdb tier")
def test_cpu_context():
    """Needs a live gdb session (gdb.selected_thread); covered by the gdb tier."""
    Cache.cpu_context()


@pytest.mark.skip(reason="gdb tier")
def test_reset_gef_caches():
    """Needs a live gdb session (gdb maintenance flush dcache); covered by the gdb tier."""
    Cache.reset_gef_caches()
