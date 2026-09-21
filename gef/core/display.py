"""Display hook for python-interactive (Layer 0)."""
import builtins
import re
import sys


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


def hexon(): # noqa
    """Replace the print function that is implicitly called when running "python-interactive 1" etc."""
    sys.displayhook = DisplayHook.displayhook # noqa
    return


def hexoff(): # noqa
    """Revert the print function that is implicitly called when running "python-interactive 1" etc."""
    sys.displayhook = sys.__displayhook__ # noqa
    return
