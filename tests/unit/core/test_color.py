def test_colorify_wraps_with_color_code():
    from gef.core.color import Color
    out = Color.colorify("hi", "red")
    assert "hi" in out
    assert "\033[" in out


def test_gef_print_no_color_passthrough(capsys):
    from gef.core.color import gef_print
    gef_print("hello", skip_color=True)
    assert "hello" in capsys.readouterr().out
