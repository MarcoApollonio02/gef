"""GEF error types and exception display (Layer 0)."""
import os
import sys
import traceback


class GefError(Exception):
    """Base GEF error."""
    pass


def show_last_exception():
    """Display the last Python exception (moved from GefUtil.show_last_exception)."""
    import gdb
    from gef.core.color import Color, gef_print

    def _show_code_line(fname, idx):
        fname = os.path.expanduser(os.path.expandvars(fname))
        __data = open(fname, "r").read().splitlines()
        return __data[idx - 1] if idx < len(__data) else ""

    gef_print("")
    exc_type, exc_value, exc_traceback = sys.exc_info()

    HORIZONTAL_LINE = "-"
    gef_print(" Exception raised ".center(80, HORIZONTAL_LINE))
    gef_print("{}: {}".format(Color.colorify(exc_type.__name__, "bold red underline"), exc_value))
    gef_print(" Detailed stacktrace ".center(80, HORIZONTAL_LINE))

    for fs in traceback.extract_tb(exc_traceback)[::-1]:
        filename, lineno, method, code = fs

        if not code or not code.strip():
            code = _show_code_line(filename, lineno)

        filename_c = Color.yellowify(filename)
        method_c = Color.greenify(method)
        gef_print('File "{}", line {:d}, in {}()'.format(filename_c, lineno, method_c))
        gef_print("    ->     {}".format(code))

    gef_print(" Last 10 GDB commands ".center(80, HORIZONTAL_LINE))
    gdb.execute("show commands")
    gef_print(" Runtime environment ".center(80, HORIZONTAL_LINE))
    gdb.execute("gef version --compact")
    gef_print(HORIZONTAL_LINE * 80)
    gef_print("")
    return
