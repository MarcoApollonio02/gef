"""GEF alias commands (category 99) extracted from the monolithic gef.py.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages. `GefAlias` is
re-exported from gef.commands.base (extracted in Task 4); it is not redefined
here.
"""
import argparse
import sys

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    GefAlias,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.color import err, gef_print, titlify

__all__ = ["GefAlias"]


@register_command
class AliasesCommand(GenericCommand):
    """The base command to add, remove or list aliases."""

    _cmdline_ = "aliases"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("add")
    subparsers.add_parser("rm")
    subparsers.add_parser("ls")
    _syntax_ = parser.format_help()

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        super().__init__(prefix=prefix)
        return

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class AliasesAddCommand(AliasesCommand):
    """Add the command alias."""

    _cmdline_ = "aliases add"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("alias", metavar="ALIAS", help="the name of new alias.")
    parser.add_argument("command", metavar="COMMAND", nargs="+", help="the command of new alias.")
    parser.add_argument("-r", "--repeat", action="store_true", help="enforce repeat feature.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} scope telescope",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        if args.alias in runtime.CommandRegistry.instances:
            err("Not allowed due to circular references")
            return
        command = " ".join(args.command)
        GefAlias(args.alias, command, force_repeat=args.repeat)
        gef_print("{:s} = {:s}".format(args.alias, command))
        return


@register_command
class AliasesRmCommand(AliasesCommand):
    """Remove the command alias."""

    _cmdline_ = "aliases rm"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("alias", metavar="ALIAS", help="the name of alias to be deleted.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        if args.alias in runtime.alias_instances:
            del runtime.alias_instances[args.alias]
        else:
            err("Could not find {:s} in aliases".format(args.alias))
        return


@register_command
class AliasesListCommand(AliasesCommand, BufferingOutput):
    """List the command alias."""

    _cmdline_ = "aliases ls"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        width = max(len(x) for x in runtime.alias_instances.keys())

        self.out = []
        self.out.append(titlify("Pre-defined aliases"))
        for _, a in sorted(runtime.alias_instances.items(), key=lambda x:x[0]):
            if a._pre_defined_:
                self.out.append("{:{:d}s}  ->  {:s}".format(a._alias_, width, a._command_))

        self.out.append(titlify("User defined aliases"))
        for _, a in sorted(runtime.alias_instances.items(), key=lambda x:x[0]):
            if not a._pre_defined_:
                self.out.append("{:{:d}s}  ->  {:s}".format(a._alias_, width, a._command_))

        self.print_output(check_terminal_size=True)
        return
