"""Display hook for python-interactive (Layer 0), plus the `ProgressBar` used by
slow kernel walks.

`ProgressBar` needs `GefUtil.get_terminal_size`; it is late-imported inside
`render()` so this Layer-0 module stays free of the Layer-1 utils import chain.
"""
import builtins
import re
import sys
import time

from gef.core.color import Color, gef_print


class DisplayHook:
    """It enables pretty printing of list, dict, set, and so on.
    It also displays in hexadecimal by default."""

    @staticmethod
    def pp(o, idt):
        """Create a string for pretty print recursively."""

        from gef.core.utils import GefUtil

        def I1(idt):
            """Create an indent for current level."""
            return "  " * idt

        def I2(idt):
            """Create an indent for next level."""
            return "  " * (idt + 1)

        def R(o, idt):
            return [DisplayHook.pp(x, idt + 1) for x in o]

        def R1(o, idt):
            """Return a string of the elements concatenated with commas (for list, tuple, set, ...)."""
            return ", ".join(R(o, idt))

        def R2(o, idt):
            """Return a list of the elements with indentation and commas (for list, tuple, set, ...)."""
            return [I2(idt) + x + "," for x in R(o, idt)]

        def Z(s, e, o, idt):
            """Return a string of the elements concatenated with commas (for list, tuple, set, ...),
            taking into account the width of the screen."""
            # Create a string without newlines and return it if it's short enough.
            f = s + R1(o, idt) + e
            if len(f) < width:
                return f
            # Return a string with a newline for each element.
            f = [s] + R2(o, idt) + [I1(idt) + e]
            return "\n".join(f)

        def RD(o, idt):
            return [DisplayHook.pp(k, idt + 1) + ": " + DisplayHook.pp(v, idt + 1) for k, v in o]

        def RD1(o, idt):
            """Return a string of the elements concatenated with commas (for dict, ...)."""
            return ", ".join(RD(o, idt))

        def RD2(o, idt):
            """Return a list of the elements with indentation and commas (for dict, ...)."""
            return [I2(idt) + x + "," for x in RD(o, idt)]

        def ZD(s, e, o, idt):
            """Return a string of the elements concatenated with commas (for dict, ...),
            taking into account the width of the screen."""
            # Create a string without newlines and return it if it's short enough.
            f = s + RD1(o, idt) + e
            if len(f) < width:
                return f
            # Return a string with a newline for each element.
            f = [s] + RD2(o, idt) + [I1(idt) + e]
            return "\n".join(f)

        name = type(o).__name__
        width = GefUtil.get_terminal_size()[1] + len(I1(idt))

        if name in ("int", "long"):
            return hex(o)

        if name == "list":
            return Z("[", "]", o, idt)

        elif name == "tuple":
            return Z("(", ")", o, idt)

        elif name == "set":
            return Z("{", "}", o, idt)

        elif name == "dict":
            return ZD("{", "}", o.items(), idt)

        elif name == "dict_keys":
            return Z("dict_keys([", "])", o, idt)

        elif name == "dict_values":
            return Z("dict_values([", "])", o, idt)

        elif name == "dict_items":
            return ZD("dict_items([", "])", o, idt)

        elif name == "Zone":
            return re.sub(r"(zone_start=|zone_end=)(\d+)", lambda x:x.group(1) + hex(int(x.group(2))), str(o))

        elif name == "Table":
            f = "Table(arch={!r}, mode={!r}, name_table={{...}}, nr_table={{\n".format(o.arch, o.mode)
            f += "\n".join(RD2(o.nr_table.items(), idt))
            f += "\n" + I1(idt) + "})"
            return f

        elif name == "Kinfo":
            f = "Kinfo(\n"
            f += I1(idt + 1) + "text_base=" + DisplayHook.pp(o.text_base, 0) + ", "
            f += "text_size=" + DisplayHook.pp(o.text_size, 0) + ", "
            f += "text_end=" + DisplayHook.pp(o.text_end, 0) + ",\n"
            f += I1(idt + 1) + "ro_base=" + DisplayHook.pp(o.ro_base, 0) + ", "
            f += "ro_size=" + DisplayHook.pp(o.ro_size, 0) + ", "
            f += "ro_end=" + DisplayHook.pp(o.ro_end, 0) + ",\n"
            f += I1(idt + 1) + "rw_base=" + DisplayHook.pp(o.rw_base, 0) + ", "
            f += "rw_size=" + DisplayHook.pp(o.rw_size, 0) + ", "
            f += "rw_end=" + DisplayHook.pp(o.rw_end, 0) + ",\n"
            f += I1(idt + 1) + "rwx=" + DisplayHook.pp(o.rwx, 0) + ", "
            f += "has_none=" + DisplayHook.pp(o.has_none, 0) + ", "
            if o.maps is None:
                f += "maps=" + DisplayHook.pp(o.maps, 0) + ",\n"
            else:
                f += "maps=[\n"
                f += "\n".join(R2(o.maps, idt + 1))
                f += "\n" + I1(idt + 1) + "]\n"
            f += I1(idt) + ")"
            return f

        elif name == "Entry":
            f = "Entry(\n"
            f += I2(idt) + "nr={:#x},\n".format(o.nr)
            f += I2(idt) + "name={!r},\n".format(o.name)
            f += I2(idt) + "ret_regs={!s},\n".format(o.ret_regs)
            f += I2(idt) + "arg_regs={!s},\n".format(o.arg_regs)
            f += I2(idt) + "args_full={!s},\n".format(o.args_full)
            f += I2(idt) + "args={!s},\n".format(o.args)
            f += I1(idt) + ")"
            return f
        return repr(o)

    @staticmethod
    def displayhook(o): # noqa
        """An alternative to the default display function."""
        builtins._ = o # noqa

        if o is None:
            return

        out = DisplayHook.pp(o, 0)
        print(out)
        return


class ProgressBar:
    """A progress bar for a slow loop. This is a substitute of the `tqdm` package."""

    # If non-ASCII characters are included, they will affect
    # the processing of dev/update-syscalls/update-syscalls.py and
    # other programs for developing, so they should be written in hexadecimal.
    BLOCKS = b" \xe2\x96\x8f\xe2\x96\x8e\xe2\x96\x8d\xe2\x96\x8c\xe2\x96\x8b\xe2\x96\x8a\xe2\x96\x89\xe2\x96\x88".decode()
    MIN_INTERVAL = 0.1 # the same value as the default of tqdm

    def __init__(self, iterable=None, total=None, desc=None, disable=False):
        self.iterable = iterable
        self.disable = disable
        if total is None and iterable is not None:
            try:
                total = len(iterable)
            except TypeError:
                pass
        self.total = total
        self.desc = desc
        self.n = 0
        self.start_time = time.time()
        self.last_draw_time = 0
        self.last_width = 0
        self.closed = False
        self.refresh(force=True)
        return

    def __iter__(self):
        for elem in self.iterable:
            yield elem
            self.update(1)
        self.close()
        return

    def update(self, n=1):
        self.n += n
        self.refresh()
        return

    def set_description(self, desc):
        self.desc = desc
        self.refresh()
        return

    def __del__(self):
        # some callers leave the bar without closing it, so erase it here like tqdm does
        try:
            self.close()
        except Exception:
            pass
        return

    def close(self):
        if self.closed or self.disable:
            return
        self.closed = True
        sys.stderr.write("\r" + " " * self.last_width + "\r")
        sys.stderr.flush()
        return

    def refresh(self, force=False):
        if self.disable:
            return
        now = time.time()
        if not force and now - self.last_draw_time < self.MIN_INTERVAL:
            return
        self.last_draw_time = now
        line = self.render()
        sys.stderr.write("\r" + line.ljust(self.last_width))
        sys.stderr.flush()
        self.last_width = len(line)
        return

    @staticmethod
    def format_time(sec):
        m, s = divmod(int(sec), 60)
        h, m = divmod(m, 60)
        if h:
            return "{:d}:{:02d}:{:02d}".format(h, m, s)
        return "{:02d}:{:02d}".format(m, s)

    @staticmethod
    def format_rate(rate):
        if rate == 0:
            return "?it/s"
        if rate >= 1:
            return "{:.2f}it/s".format(rate)
        return "{:.2f}s/it".format(1 / rate)

    def make_bar(self, frac, width):
        if width <= 0:
            return ""
        filled, part = divmod(int(frac * width * 8), 8)
        bar = self.BLOCKS[-1] * filled
        if filled < width:
            bar += self.BLOCKS[part] + " " * (width - filled - 1)
        return bar

    def render(self):
        from gef.core.utils import GefUtil

        elapsed = time.time() - self.start_time
        if elapsed:
            rate = self.n / elapsed
        else:
            rate = 0
        if self.desc:
            desc = "{:s}: ".format(self.desc)
        else:
            desc = ""
        if not self.total:
            return "{:s}{:d}it [{:s}, {:s}]".format(desc, self.n, self.format_time(elapsed), self.format_rate(rate))
        frac = min(self.n / self.total, 1.0)
        if rate:
            remain = self.format_time(max(self.total - self.n, 0) / rate)
        else:
            remain = "?"
        left = "{:s}{:3.0f}%|".format(desc, frac * 100)
        right = "| {:d}/{:d} [{:s}<{:s}, {:s}]".format(
            self.n, self.total, self.format_time(elapsed), remain, self.format_rate(rate),
        )
        width = GefUtil.get_terminal_size()[1] - len(left) - len(right) - 1
        return left + self.make_bar(frac, width) + right


def hexon(): # noqa
    """Replace the print function that is implicitly called when running "python-interactive 1" etc."""
    sys.displayhook = DisplayHook.displayhook # noqa
    return


def hexoff(): # noqa
    """Revert the print function that is implicitly called when running "python-interactive 1" etc."""
    sys.displayhook = sys.__displayhook__ # noqa
    return


class BufferingOutput:
    """A collection of utility functions that append a messages to self.out."""

    def info_add_out(self, msg):
        msg = "{} {}".format(Color.colorify("[+]", "bold blue"), msg)
        self.out.append(msg)
        return

    def warn_add_out(self, msg):
        msg = "{} {}".format(Color.colorify("[*]", "bold yellow"), msg)
        self.out.append(msg)
        return

    def err_add_out(self, msg):
        msg = "{} {}".format(Color.colorify("[!]", "bold red"), msg)
        self.out.append(msg)
        return

    def quiet_info_add_out(self, msg):
        if not hasattr(self.args, "quiet") or not self.args.quiet:
            msg = "{} {}".format(Color.colorify("[+]", "bold blue"), msg)
            self.out.append(msg)
        return

    def quiet_add_out(self, msg):
        if not hasattr(self.args, "quiet") or not self.args.quiet:
            self.out.append(msg)
        return

    def verbose_add_out(self, msg):
        if hasattr(self.args, "verbose") and self.args.verbose:
            self.out.append(msg)
        return

    def print_output(self, check_terminal_size=False, skip_color=False):
        from gef.core.utils import GefUtil
        if not hasattr(self, "out"):
            return
        if not self.out:
            return

        def do_check_term_size(lines):
            # rough check
            t_height, t_width = GefUtil.get_terminal_size()
            if len(lines) > t_height:
                return not self.args.no_pager

            # detailed check
            h = 0
            for element in lines:
                for line in element.splitlines():
                    line = Color.remove_color(line)
                    h += (len(line) // t_width) + 1
                    if h > t_height:
                        return not self.args.no_pager
            return False

        if not check_terminal_size:
            less = not self.args.no_pager
        else:
            less = do_check_term_size(self.out)

        gef_print("\n".join(self.out), less=less, skip_color=skip_color)
        return
