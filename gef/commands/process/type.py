"""GEF process-info commands (category 02-h) extracted from the monolithic gef.py.

Type-related commands (display-type, types).

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import re

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    parse_args,
    register_command,
)
from gef.core.address import AddressUtil
from gef.core.color import Color, err
from gef.core.config import Config
from gef.core.instruction import Instruction
from gef.core.memory import is_valid_addr
from gef.core.utils import GefUtil

@register_command
class DisplayTypeCommand(GenericCommand, BufferingOutput):
    """Make it easier to use `ptype /ox TYPE` and `p ((TYPE*) ADDRESS)[0]`."""

    _cmdline_ = "dt"
    _category_ = "02-h. Process Information - Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("type", metavar="TYPE", help="the type name.")
    parser.add_argument("address", metavar="ADDRESS", nargs="?", type=AddressUtil.parse_address,
                        help="the address to apply the type.")
    parser.add_argument("-s", "--smart", action="store_true",
                        help="override `context.smart_cpp_function_name = True` temporarily.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} "struct malloc_state"       # shortcut for `ptype /ox struct malloc_state`',
        '{0:s} "struct malloc_state" $rsp  # shortcut for `p ((struct malloc_state*) $rsp)[0]`',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command is designed for several purposes.",
        "1. When displaying very large struct, you may want to go through a pager because the results will not fit on one screen.",
        "   However, using a pager, the color information disappears. This command calls the pager with preserving colors.",
        "2. When `ptype /ox TYPE`, interpreting member type recursively often result is too long and difficult to read.",
        "   This command keeps result compact by displaying only top-level members.",
        "3. When `p ((TYPE*) ADDRESS)[0]` for large struct, the gdb setting of `max-value-size` is too small to display.",
        "   This command adjusts it automatically.",
        "4. When debugging a binary written in the Golang, the offset information of the type is not displayed.",
        "   This command also displays the offset.",
        "5. When debugging a binary written in the Golang, the `p ((TYPE*) ADDRESS)[0]` command will be broken.",
        "   This is because the Golang helper script is automatically loaded and overwrites the behavior of `p` command.",
        "   This command creates the display results on the python side, so we can display it without any problems.",
    ]
    _note_ = "\n".join(_note_)

    def dump_type(self, tp, args_type):
        if tp.code == gdb.TYPE_CODE_STRUCT:
            type_prefix = "struct"
        elif tp.code == gdb.TYPE_CODE_UNION:
            type_prefix = "union"
        elif tp.code == gdb.TYPE_CODE_ENUM:
            type_prefix = "enum"
        else:
            err("{:s} is not struct or union".format(tp.name or args_type))
            return False

        self.out = [
            "{:s} {:s} {{".format(type_prefix, Instruction.smartify_text(tp.name or args_type)),
            "    /* offset | size   */",
        ]
        for name, field in tp.items():
            if tp.code in [gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION]:
                if hasattr(field, "bitpos") and hasattr(field.type, "sizeof"):
                    offsz_str = "/* {:#06x} | {:#06x} */".format(field.bitpos // 8, field.type.sizeof)
                elif hasattr(field.type, "sizeof"):
                    offsz_str = "/*        | {:#06x} */".format(field.type.sizeof)
                elif hasattr(field, "bitpos"):
                    offsz_str = "/* {:#06x} |        */".format(field.bitpos // 8)
                else:
                    offsz_str = "/*        |        */"
                type_str = Instruction.smartify_text(str(field.type))
                name_str = Color.cyanify(Instruction.smartify_text(name))
                if field.bitsize == 0:
                    msg = "    {:s}    {} {:s};".format(offsz_str, type_str, name_str)
                else:
                    msg = "    {:s}    {} {:s} : {:d};".format(offsz_str, type_str, name_str, field.bitsize)
            else: # gdb.TYPE_CODE_ENUM
                offsz_str = "/* {:#06x} | {:#06x} */".format(0, 4)
                type_str = "int"
                name_str = Color.cyanify(Instruction.smartify_text(name))
                msg = "    {:s}    {} {:s} = {:#x};".format(offsz_str, type_str, name_str, field.enumval)
            self.out.append(msg)
        self.out.append("}} // total: {:#x} bytes".format(tp.sizeof))
        return True

    def apply_type(self, tp, args_address):
        if not is_valid_addr(args_address):
            err("Memory read error")
            return False

        # change setting
        if tp.sizeof > 2200: # 2200 is default value of max-value-size
            gdb.execute("set max-value-size {:#x}".format(tp.sizeof))

        v = gdb.Value(args_address)
        s = v.cast(tp.pointer()).dereference()
        self.out = s.format_string(styling=True).splitlines()
        return True

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        # lookup type
        tp = GefUtil.cached_lookup_type(args.type)
        if not args.type.startswith(("struct", "union", "enum")):
            if tp is None:
                tp = GefUtil.cached_lookup_type("struct {:s}".format(args.type))
            if tp is None:
                tp = GefUtil.cached_lookup_type("union {:s}".format(args.type))
            if tp is None:
                tp = GefUtil.cached_lookup_type("enum {:s}".format(args.type))

        if tp is None:
            err("Could not find {:s}".format(args.type))
            return

        # remove pointer
        while str(tp).endswith("*"):
            tp = tp.target()

        # check if valid type
        if tp.code not in [gdb.TYPE_CODE_STRUCT, gdb.TYPE_CODE_UNION, gdb.TYPE_CODE_ENUM]:
            err("{:s} is not struct or union or enum".format(tp.name or args.type))
            return

        # change setting temporarily
        if args.smart:
            old_smart_setting = Config.get_gef_setting("context.smart_cpp_function_name")
            Config.set_gef_setting("context.smart_cpp_function_name", True)

        # doit
        if args.address is None:
            ret = self.dump_type(tp, args.type)
        else:
            ret = self.apply_type(tp, args.address)

        if ret:
            self.print_output(check_terminal_size=True)

        # revert setting
        if args.smart:
            Config.set_gef_setting("context.smart_cpp_function_name", old_smart_setting)
        return


@register_command
class TypesCommand(GenericCommand, BufferingOutput):
    """List all types (shortcut for `info types`) with compaction."""

    _cmdline_ = "types"
    _category_ = "02-h. Process Information - Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-s", "--smart", action="store_true",
                        help="temporarily override by `context.smart_cpp_function_name = True`.")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[],
                        help="REGEXP include filter.")
    parser.add_argument("-e", "--exclude", action="append", type=re.compile, default=[],
                        help="REGEXP exclude filter.")
    parser.add_argument("-E", "--no-enum", action="store_true", help="without enum.")
    parser.add_argument("-S", "--no-struct", action="store_true", help="without struct.")
    parser.add_argument("-T", "--no-typedef", action="store_true", help="without typedef.")
    parser.add_argument("-U", "--no-union", action="store_true", help="without union.")
    parser.add_argument("-c", "--use-cache", action="store_true", help="use previous result.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="with the output of `dt` command.")
    _syntax_ = parser.format_help()

    def get_type_names(self):
        """Parse and filter type names from GDB's 'info types', skipping basic types and applying
        user-specified filters."""
        basic_types = [
            "char", "unsigned char", "signed char",
            "int", "unsigned int", "signed int",
            "short", "unsigned short", "signed short",
            "long", "unsigned long", "signed long",
            "long long", "unsigned long long", "signed long long",
            "float",
            "double", "long double",
            "void",
            "bool",
        ]

        ret = gdb.execute("info types", to_string=True).strip()

        type_names = []
        for line in ret.splitlines():
            if line == "All defined types:":
                continue
            if line == "":
                continue
            if line.startswith("File "):
                continue

            line = re.sub(r"^\d+:|;$", "", line).strip()
            if line in basic_types:
                continue
            if self.args.filter and not any(filt.search(line) for filt in self.args.filter):
                continue
            if self.args.exclude and any(filt.search(line) for filt in self.args.exclude):
                continue
            if self.args.no_enum and line.startswith("enum "):
                continue
            if self.args.no_struct and line.startswith("struct "):
                continue
            if self.args.no_typedef and line.startswith("typedef "):
                continue
            if self.args.no_union and line.startswith("union "):
                continue
            type_names.append(line)

        type_names = sorted(set(type_names))
        return type_names

    def get_types(self):
        """Display type information for each type name, optionally using verbose output and smart formatting."""
        type_names = self.get_type_names()

        # temporarily changed
        if self.args.smart:
            old_smart_setting = Config.get_gef_setting("context.smart_cpp_function_name")
            Config.set_gef_setting("context.smart_cpp_function_name", True)

        # formatting typenames
        tqdm = GefUtil.get_tqdm()
        for type_name in tqdm(type_names, leave=False):
            if self.args.verbose:
                ret = gdb.execute("dt -n {!r}".format(type_name), to_string=True)
                if not ret or (" is not struct or union" in ret) or ("Could not find " in ret):
                    self.out.append(Instruction.smartify_text(type_name))
                    self.out.append("")
                    continue
                self.out.append(ret)
            else:
                self.out.append(Instruction.smartify_text(type_name))

        # revert
        if self.args.smart:
            Config.set_gef_setting("context.smart_cpp_function_name", old_smart_setting)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if args.use_cache and hasattr(self, "cache") and self.cache:
            self.out = self.cache[::]
            self.print_output()
            return

        self.out = []
        self.get_types()
        self.print_output()
        self.cache = self.out[::]
        return
