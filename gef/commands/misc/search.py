"""GEF misc Search commands (category 07-b) extracted from the monolithic
gef.py.

grepped header search: constgrep.
Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import os
import re

from gef.commands.base import GenericCommand, parse_args, register_command
from gef.core.color import Color, err, gef_print, info
from gef.core.utils import GefUtil


@register_command
class ConstGrepCommand(GenericCommand):
    """Grep for lines with #define in header files (default: host /usr/include)."""

    _cmdline_ = "constgrep"
    _category_ = "07-b. Misc - Search"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("pattern", metavar="GREP_PATTERN", help="filter by regex.")
    parser.add_argument("-r", "--root", metavar="DIRECTORY", default="/usr/include",
                        help="header search directory (e.g. SYSROOT/usr/include; default: host /usr/include).")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} '__NR_*'",
        "{0:s} -r /path/to/sysroot/usr/include '__NR_*'",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def read_normalize(self, path):
        if not os.path.isfile(path):
            return None
        try:
            content = open(path, "rb").read()
        except (FileNotFoundError, IsADirectoryError):
            return None
        except OSError as exception:
            err("Could not read {:s}: {!s}".format(path, exception))
            return None
        content = content.replace(b"\\\n", b"GEF_MARKER")
        content = content.replace(b"\t", b" ")
        for i in range(0x80, 0x100):
            content = content.replace(bytes([i]), b"")
        try:
            content = content.decode("UTF-8")
        except UnicodeDecodeError:
            err("Decode error: " + path)
            return None
        return content

    @parse_args
    def do_invoke(self, args):
        srcdir = os.path.abspath(os.path.expanduser(args.root))
        if not os.path.isdir(srcdir):
            err("Could not find directory: {:s}".format(srcdir))
            return
        try:
            pattern = re.compile(r"^\s*#\s*define\s+\S*" + args.pattern)
        except re.error as e:
            err("Invalid pattern: {!s}".format(e))
            return
        info("Header search directory: {:s}".format(srcdir))
        for path in GefUtil.walk(srcdir):
            content = self.read_normalize(path)
            if content is None:
                continue
            for line in content.splitlines():
                if pattern.search(line):
                    line = line.replace("GEF_MARKER", "\\\n")
                    gef_print("{:s}: {:s}".format(Color.redify(path), line))
        return
