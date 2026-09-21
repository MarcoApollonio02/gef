"""GEF cache management (Layer 0).

The cache has 2 types: "until_next" and "this_session".
"""
import functools


class Cache:
    """Manage the gef cache. The cache has 2 types: "until_next" and "this_session".
    "until_next": Cached for a very short period of time. Cleared every time an instruction is stepped, etc.
    "this_session": Cached until gdb exits.
    Note: each command may have its own cache outside this mechanism. Not all caches are centralized here."""

    __gef_caches__ = {"until_next": {}, "this_session": {}}

    @staticmethod
    def cache_wrap(life_time, f, skip_None_cache=False):

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            caches = Cache.__gef_caches__[life_time]
            fname = f"{f.__module__}:{f.__qualname__}"
            fcache = caches.setdefault(fname, {})

            try:
                kw = tuple(sorted(kwargs.items()))
                key = (args, kw)
                return fcache[key]
            except KeyError:
                ret = f(*args, **kwargs)
                if skip_None_cache is False or ret is not None:
                    fcache[key] = ret
                return ret
            except TypeError:
                return f(*args, **kwargs)

        return wrapper

    @staticmethod
    def cache_until_next(f):
        return Cache.cache_wrap("until_next", f)

    @staticmethod # noqa
    def cache_until_next_skip_None_cache(f):
        return Cache.cache_wrap("until_next", f, skip_None_cache=True)

    @staticmethod
    def cache_this_session(f):
        return Cache.cache_wrap("this_session", f)

    @staticmethod
    def cache_this_session_skip_None_cache(f):
        return Cache.cache_wrap("this_session", f, skip_None_cache=True)

    @staticmethod
    def reset_gef_caches(all=False):
        """Clear the cache of GEF.
        By default, it only clears caches of `until_next` type."""
        import gdb

        Cache.__gef_caches__["until_next"].clear()

        if all:
            Cache.__gef_caches__["this_session"].clear()

        # gdb cache
        try:
            gdb.execute("maintenance flush dcache", to_string=True)
        except Exception:
            pass
        return

    @staticmethod # noqa
    def clear_cache_for(f):
        """Clear the cache of specified function."""

        fname = f"{f.__module__}:{f.__qualname__}"
        Cache.__gef_caches__["until_next"].pop(fname, None)
        Cache.__gef_caches__["this_session"].pop(fname, None)
        return
