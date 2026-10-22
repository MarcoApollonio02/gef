"""GEF cache management (Layer 0).

The cache has 2 types: "until_next" and "this_session".
"""
import functools


class Cache:
    """Manage the gef cache. The 2 types are named after what invalidates them.
    "until_next": a step, or a memory or register change.
    "this_session": the target itself changing (exit, `set_arch`, `gef reset-cache`, `--rescan`).
    A `this_session` entry declared `until_new_objfile=True` is dropped when a symbol file is loaded or removed too.
    Note: each command may have its own cache outside this mechanism. Not all caches are centralized here."""

    __gef_caches__ = {"until_next": {}, "this_session": {}}
    __objfile_caches__ = [] # the `this_session` caches that a changed symbol file set stales

    @staticmethod
    def cpu_context():
        """Return the identifier of the current CPU context, i.e., the selected gdb thread.
        Some kernel heuristics return a different answer depending on which CPU is selected,
        so their cache must be separated by this value."""

        try:
            import gdb
            thread = gdb.selected_thread()
        except Exception:
            return None
        if thread is None:
            return None
        return getattr(thread, "global_num", None) or thread.num

    @staticmethod
    def inferior_context():
        """Return the identifier of the currently selected inferior.
        Switching inferiors does not clear any cache by itself, so whatever describes the
        debuggee process (its pid, its memory mapping, its section list) must be separated
        by this value. Otherwise the answer resolved for one inferior is served to another."""

        try:
            import gdb
            return gdb.selected_inferior().num
        except Exception:
            return None

    # A marker that never compares equal to a user argument, so a key built from kwargs
    # cannot collide with a key that is the bare `args` tuple.
    __kwargs_marker__ = object()

    @staticmethod
    def cache_wrap(life_time, f, cache_None=True, per_cpu=False, per_inferior=False, until_new_objfile=False):
        # The name and the per-function dict are resolved once here instead of on every call.
        # The dict is therefore kept alive across resets, so the reset clears it in place.
        fname = f"{f.__module__}:{f.__qualname__}"
        fcache = Cache.__gef_caches__[life_time].setdefault(fname, {})
        if until_new_objfile:
            Cache.__objfile_caches__.append(fcache)

        @functools.wraps(f)
        def wrapper(*args, **kwargs):
            if kwargs:
                key = (Cache.__kwargs_marker__, args, tuple(sorted(kwargs.items())))
            else:
                key = args
            if per_cpu:
                key = (Cache.cpu_context(), key)
            if per_inferior:
                key = (Cache.inferior_context(), key)

            try:
                return fcache[key]
            except KeyError:
                ret = f(*args, **kwargs)
                if cache_None or ret is not None:
                    fcache[key] = ret
                return ret
            except TypeError as e:
                bad = []
                for i, a in enumerate(args):
                    try:
                        hash(a)
                    except TypeError:
                        bad.append("args[{:d}]: {:s}".format(i, type(a).__name__))
                for k, v in kwargs.items():
                    try:
                        hash(v)
                    except TypeError:
                        bad.append("{:s}: {:s}".format(k, type(v).__name__))
                raise TypeError(
                    "Cache: {:s} got an unhashable argument ({:s}), so it cannot be cached. "
                    "Pass a hashable value, e.g. tuple(x) instead of a list.".format(fname, ", ".join(bad))
                ) from e

        wrapper.cache_per_cpu = per_cpu
        wrapper.cache_per_inferior = per_inferior
        return wrapper

    @staticmethod
    def cache_until_next(f=None, *, cache_None=True, per_cpu=False, per_inferior=False):
        """Decorator for the "until_next" cache.
        Usable bare (`@Cache.cache_until_next`) or with options
        (`@Cache.cache_until_next(cache_None=False)`)."""

        if f is None: # called with options
            return functools.partial(
                Cache.cache_until_next, cache_None=cache_None, per_cpu=per_cpu,
                per_inferior=per_inferior,
            )
        if not callable(f):
            raise TypeError("Cache.cache_until_next: the options must be keyword arguments")
        return Cache.cache_wrap("until_next", f, cache_None=cache_None, per_cpu=per_cpu, per_inferior=per_inferior)

    @staticmethod
    def cache_this_session(f=None, *, cache_None=True, per_cpu=False, per_inferior=False, until_new_objfile=False):
        """Decorator for the "this_session" cache.
        Usable bare (`@Cache.cache_this_session`) or with options
        (`@Cache.cache_this_session(cache_None=False)`).
        Set `until_new_objfile` if loading a symbol file can change the value."""

        if f is None: # called with options
            return functools.partial(
                Cache.cache_this_session, cache_None=cache_None, per_cpu=per_cpu,
                per_inferior=per_inferior, until_new_objfile=until_new_objfile,
            )
        if not callable(f):
            raise TypeError("Cache.cache_this_session: the options must be keyword arguments")
        return Cache.cache_wrap("this_session", f, cache_None=cache_None, per_cpu=per_cpu,
                                per_inferior=per_inferior, until_new_objfile=until_new_objfile)

    @staticmethod
    def reset_gef_caches(all=False, new_objfile=False):
        """Clear the gef caches. By default only `until_next`.
        `all` also clears `this_session`.
        `new_objfile` clears the `this_session` entries declared `until_new_objfile`."""

        for fcache in Cache.__gef_caches__["until_next"].values():
            fcache.clear()
        # MemoryCache is not extracted yet; the call is a no-op until it lands.
        try:
            from gef.core.memory import MemoryCache
            MemoryCache.reset()
        except ImportError:
            pass
        from gef.core.color import Color
        Color.cached_disabled = None

        if all:
            for fcache in Cache.__gef_caches__["this_session"].values():
                fcache.clear()
        elif new_objfile:
            for fcache in Cache.__objfile_caches__:
                fcache.clear()
        # Upstream also resets its static kallsyms cache (Ksym.reset()) here; our
        # kallsyms state lives on the ksymaddr-remote command instance instead,
        # so there is nothing to reset.

        # gdb cache
        if not new_objfile:
            try:
                import gdb
                gdb.execute("maintenance flush dcache", to_string=True)
            except Exception:
                pass
        return

    @staticmethod
    def peek_cache_for(f, *args):
        """Return the cached value of `f(*args)` without calling it, or None if it is not
        cached yet. For the callers that must not trigger the computation, e.g. to avoid
        a recursion. A function declared `cache_None=False` never stores None, so None
        always means "not resolved yet"."""

        fname = f"{f.__module__}:{f.__qualname__}"
        if hasattr(f, "__self__"):
            args = (f.__self__,) + args
        if getattr(f, "cache_per_cpu", False):
            args = (Cache.cpu_context(), args)
        if getattr(f, "cache_per_inferior", False):
            args = (Cache.inferior_context(), args)
        for caches in Cache.__gef_caches__.values():
            fcache = caches.get(fname)
            if fcache is not None:
                return fcache.get(args)
        return None

    @staticmethod
    def clear_cache_for(f):
        """Clear the cache of specified function."""

        fname = f"{f.__module__}:{f.__qualname__}"
        for caches in Cache.__gef_caches__.values():
            caches.get(fname, {}).clear()
        return
