"""Unit tests for gef.core.hash (class `Hash`), run outside gdb.

In the monolithic gef.py the `Hash` class relied on module-level globals. The
extraction initially dropped those imports, leaving 7 undefined globals that
raised NameError on user-reachable code paths. These tests pin the names as real
module globals *and* exercise the paths that were broken.
"""

import pytest

import gef.core.hash as hash_mod
from gef.core.hash import Hash, String


# The 7 globals that were undefined after the extraction (verbatim from gef.py).
MISSING_GLOBALS = ("GEF_TEMP_DIR", "String", "collections", "math", "os", "re", "sys")


def test_module_imports_without_gdb():
    # Importing must not pull in gdb (the unit tier runs outside a GDB session).
    assert hash_mod is not None


def test_hash_class_exists():
    assert Hash is not None


@pytest.mark.parametrize("name", MISSING_GLOBALS)
def test_previously_missing_names_are_module_globals(name):
    # Regression for the missing-import defect: each name must resolve as a real
    # module global of gef.core.hash, not an undefined global.
    assert name in vars(hash_mod), "gef.core.hash.%s is not a module global" % name


def test_stdlib_globals_are_usable():
    assert hash_mod.collections.namedtuple("CFFI", "ffi lib")(1, 2).lib == 2
    assert hash_mod.math.isqrt(9) == 3
    assert hash_mod.math.e > 2.7 and hash_mod.math.pi > 3.1
    assert hash_mod.os.path.join("a", "b") == "a/b"
    assert hash_mod.re.fullmatch(r"\d+", "123").group() == "123"
    assert hash_mod.sys.maxsize > 0
    assert isinstance(hash_mod.GEF_TEMP_DIR, str)


def test_string_global_is_the_string_class():
    assert hash_mod.String is String
    assert hash_mod.String.bytes2str(b"abc") == "abc"


def test_sha512_224_known_answer():
    # `struct`/`hashlib` path: known-answer check for input b"abc".
    assert Hash.SHA512_224(b"abc").hexdigest() == (
        "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
    )


def test_ntlm_uses_string_bytes2str():
    # `Hash.NTLM.update` calls `String.bytes2str(password)` for bytes input, the
    # exact line that previously raised NameError.
    assert len(Hash.NTLM(b"abc").digest()) == 16
    # str input goes through `update` and must agree with the bytes path.
    assert Hash.NTLM(b"abc").hexdigest() == Hash.NTLM().update("abc").hexdigest()


def test_cubehash_set_params_uses_re():
    # `CubeHash.set_params` calls `re.fullmatch(...)`, reached from __init__.
    h = Hash.CubeHash(params="CubeHash160+16/32+160-256")
    h.update(b"abc")
    assert len(h.digest()) == 32
    # An invalid spec must still be rejected (proves re.fullmatch actually ran).
    with pytest.raises(ValueError):
        Hash.CubeHash(params="not-a-cubehash-spec")


def test_floppsy_update_uses_math():
    # `Floppsy.setup`/`round_seed`/`update` use `math.e`/`math.pi`/`math.isqrt`.
    h = Hash.Floppsy().update(b"abc")
    assert len(h.digest()) == 8
    assert len(Hash.Floppsy(b"abc").hexdigest()) == 16


def test_fsb_pi_bin_uses_os_and_gef_temp_dir(tmp_path, monkeypatch):
    # `FSBPiBin.make_pi_bin` does `os.path.join(GEF_TEMP_DIR, ...)` *before* its
    # try block, so the NameError was uncaught. Shrink the pi-bin size and stub
    # the (heavy) pi digit generation; the file-I/O path around GEF_TEMP_DIR is
    # what this test pins down. Full FSB construction is intentionally avoided:
    # without gmpy2 it would compute a multi-million-digit pi in pure Python.
    monkeypatch.setattr(hash_mod, "GEF_TEMP_DIR", str(tmp_path))
    pi_cls = Hash.FSBBase.FSBPiBin
    monkeypatch.setattr(pi_cls, "size_bytes", 1)
    monkeypatch.setattr(pi_cls, "digits", 8)
    monkeypatch.setattr(pi_cls, "pi_fractional_digits", lambda self, n: "0" * 8)

    data = pi_cls().make_pi_bin()

    assert data == b"\x00"
    assert (tmp_path / "FSB_hash_pi.bin").read_bytes() == data
