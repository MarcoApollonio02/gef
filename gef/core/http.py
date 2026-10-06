"""Minimal stdlib-only HTTP helper (Layer 1; importable outside gdb)."""
import urllib.request


def http_get(url, timeout=5):
    """Basic HTTP wrapper for GET request. Returns the body bytes, or None on any failure."""
    try:
        req = urllib.request.Request(url)
        req.add_header("Cache-Control", "no-cache, no-store")
        http = urllib.request.urlopen(req, timeout=timeout)
        if http.getcode() != 200:
            return None
        return http.read()
    except Exception:
        return None
