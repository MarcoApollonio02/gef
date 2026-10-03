"""GEF misc Diff commands (category 07-f) extracted from the monolithic
gef.py.

Output diffing helpers: save-output, diff-output, diff-output-colordiff,
diff-output-gitdiff, diff-output-list, diff-output-clear. All subclass
DiffOutputCommand and live in this same file.
Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import datetime
import os
import subprocess
import sys

import gdb

from gef.commands.base import GenericCommand, parse_args, register_command
from gef.core.color import Color, err, gef_print, info
from gef.core.config import Config
from gef.core.strings import String
from gef.core.utils import GEF_TEMP_DIR, GefUtil


@register_command
class SaveOutputCommand(GenericCommand):
    """Save the command outputs."""

    _cmdline_ = "saveo"
    _category_ = "07-f. Misc - Diff"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("cmd", metavar="GDB_CMD", help="gdb command.")
    parser.add_argument("arg", metavar="ARG", nargs="*", help="arguments of gdb command.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Saving the output of external commands is unsupported (e.g., pipe, !ls).",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=False, complete=gdb.COMPLETE_COMMAND)
        return

    # Need not @parse_args because argparse can't stop interpreting options for user specified command.
    def do_invoke(self, argv):
        if len(argv) == 1 and argv[0] == "-h":
            self.usage()
            return

        # get settings
        always_no_pager = Config.get_gef_setting("gef.always_no_pager")

        # parse command
        cmd = ""
        for c in argv:
            if "\\" in c or " " in c:
                cmd += " " + repr(c)
            else:
                cmd += " " + c
        cmd = cmd.strip()
        if not cmd:
            self.usage()
            return

        # do the command
        try:
            Config.set_gef_setting("gef.always_no_pager", True) # change temporarily
            current_output = Color.remove_color(gdb.execute(cmd, to_string=True))
            Config.set_gef_setting("gef.always_no_pager", always_no_pager) # revert settings
        except gdb.error:
            Config.set_gef_setting("gef.always_no_pager", always_no_pager) # revert settings
            exc_type, exc_value, exc_traceback = sys.exc_info()
            gef_print(exc_value)
            return

        # remove clear_screen code
        if current_output.startswith("\x1b[H\x1b[2J"):
            current_output = current_output[7:]

        # save
        dloc = os.path.join(GEF_TEMP_DIR, "diff")
        if not os.path.exists(dloc):
            os.mkdir(dloc)
        tmp_fd, tmp_path = GefUtil.mkstemp(dir=dloc, suffix=".txt")
        os.fdopen(tmp_fd, "w").write(current_output)
        open(tmp_path[:-4] + ".cmd", "w").write(cmd)
        info("The output is saved to {:s}.(txt|cmd)".format(tmp_path[:-4]))

        # print
        gef_print(current_output, less=not always_no_pager)
        return


@register_command
class DiffOutputCommand(GenericCommand):
    """The base command to diff of the command outputs."""

    _cmdline_ = "diffo"
    _category_ = "07-f. Misc - Diff"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
        subparsers = parser.add_subparsers(title="command", required=True)
    else:
        subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("colordiff")
    subparsers.add_parser("git-diff")
    subparsers.add_parser("list")
    subparsers.add_parser("clear")
    _syntax_ = parser.format_help()

    def __init__(self, *args, **kwargs):
        prefix = kwargs.get("prefix", True)
        super().__init__(prefix=prefix)
        self.add_setting("colordiff_option", "--left-column -y -W 200", "The option used by colordiff.")
        return

    def get_saved_files(self):
        dloc = os.path.join(GEF_TEMP_DIR, "diff")
        if not os.path.exists(dloc):
            return []

        saved_files = []
        for path in GefUtil.walk(dloc):
            if not path.endswith(".txt"):
                continue
            saved_files.append(path)

        return sorted(saved_files, key=lambda x:os.path.getmtime(x[:-4] + ".cmd"))

    @parse_args
    def do_invoke(self, args):
        self.usage()
        return


@register_command
class DiffOutputColordiffCommand(DiffOutputCommand):
    """Diff the two outputs by colordiff."""

    _cmdline_ = "diffo colordiff"
    _category_ = "07-f. Misc - Diff"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("n1", metavar="N", type=int, help="first diff target got from `diffo list`.")
    parser.add_argument("n2", metavar="M", type=int, help="second diff target got from `diffo list`.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0 1  # diff between 0 and 1",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "You can check the available indexes with `diffo list`.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    def make_diff(self, path1, path2):
        option = Config.get_gef_setting("diffo.colordiff_option")
        cmd = "{:s} {:s} '{:s}' '{:s}'".format(self.colordiff, option, path1, path2)
        result = subprocess.getoutput(cmd)
        return result

    @parse_args
    def do_invoke(self, args):
        try:
            self.colordiff = GefUtil.which("colordiff")
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        saved_files = self.get_saved_files()
        try:
            f1 = saved_files[args.n1]
            f2 = saved_files[args.n2]
        except IndexError:
            err("Out of index error")
            return

        if not os.path.exists(f1):
            err("Could not find {:s}".format(f1))
            return
        if not os.path.exists(f2):
            err("Could not find {:s}".format(f2))
            return

        output = self.make_diff(f1, f2)

        if output:
            gef_print(output, less=not args.no_pager)
        else:
            gef_print("No difference")
        return


@register_command
class DiffOutputGitDiffCommand(DiffOutputCommand):
    """Diff the two outputs by git."""

    _cmdline_ = "diffo git-diff"
    _category_ = "07-f. Misc - Diff"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("n1", metavar="N", type=int, help="first diff target got from `diffo list`.")
    parser.add_argument("n2", metavar="M", type=int, help="second diff target got from `diffo list`.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} 0 1  # diff between 0 and 1",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "You can check the available indexes with `diffo list`.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(prefix=False)
        return

    def make_diff(self, path1, path2):
        cmd = "{:s} diff --color=always '{:s}' '{:s}'".format(self.git, path1, path2)
        result = subprocess.getoutput(cmd)
        return result

    @parse_args
    def do_invoke(self, args):
        try:
            self.git = GefUtil.which("git")
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        saved_files = self.get_saved_files()
        try:
            f1 = saved_files[args.n1]
            f2 = saved_files[args.n2]
        except IndexError:
            err("Out of index error")
            return

        if not os.path.exists(f1):
            err("Could not find {:s}".format(f1))
            return
        if not os.path.exists(f2):
            err("Could not find {:s}".format(f2))
            return

        output = self.make_diff(f1, f2)

        if output:
            gef_print(output, less=not args.no_pager)
        else:
            gef_print("No difference")
        return


@register_command
class DiffOutputListCommand(DiffOutputCommand):
    """List saved outputs."""

    _cmdline_ = "diffo list"
    _category_ = "07-f. Misc - Diff"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        file_list = self.get_saved_files()
        max_path = max([len(fname) for fname in file_list] + [40])

        fmt = "{:<3s}  {:26s}  {:{:d}s}  {:<7s}  {:s}"
        legend = ["#", "mtime", "path", max_path, "size", "command"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        for idx, path in enumerate(file_list):
            data = open(path, "rb").read()
            size = len(data)
            mtime = datetime.datetime.fromtimestamp(os.path.getmtime(path))
            cmd = open(path[:-4] + ".cmd", "rb").read()
            cmd = String.bytes2str(cmd)
            gef_print("{:<3d}  {}  {:{:d}s}  {:<7d}  {:s}".format(idx, mtime, path, max_path, size, cmd))
        return


@register_command
class DiffOutputClearCommand(DiffOutputCommand):
    """Clear all saved outputs."""

    _cmdline_ = "diffo clear"
    _category_ = "07-f. Misc - Diff"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("n", metavar="N", type=int, nargs="*", help="index to be deleted.")
    parser.add_argument("--all", action="store_true", help="delete everything.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=False)
        return

    @parse_args
    def do_invoke(self, args):
        if args.all:
            for path in self.get_saved_files():
                os.unlink(path)
                os.unlink(path[:-4] + ".cmd")
        elif args.n:
            for i, path in enumerate(self.get_saved_files()):
                if i in args.n:
                    os.unlink(path)
                    os.unlink(path[:-4] + ".cmd")
        else:
            self.usage()
            return

        info("Removed")
        return
