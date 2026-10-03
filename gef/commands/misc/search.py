"""GEF misc Search commands (category 07-b) extracted from the monolithic
gef.py.

grepped header search: constgrep.
Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import re

from gef.commands.base import GenericCommand, parse_args, register_command
from gef.core.color import Color, err, gef_print
from gef.core.utils import GefUtil


@register_command
class ConstGrepCommand(GenericCommand):
    """Grep for lines with #define in files under /usr/include."""

    _cmdline_ = "constgrep"
    _category_ = "07-b. Misc - Search"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("pattern", metavar="GREP_PATTERN", help="filter by regex.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} '__NR_*'",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def read_normalize(self, path):
        try:
            content = open(path, "rb").read()
        except (FileNotFoundError, IsADirectoryError):
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
        srcdir = "/usr/include"
        pattern = re.compile(r"^#define\s+\S*" + args.pattern)
        for path in GefUtil.walk(srcdir):
            content = self.read_normalize(path)
            if content is None:
                continue
            for line in content.splitlines():
                if pattern.search(line):
                    line = line.replace("GEF_MARKER", "\\\n")
                    gef_print("{:s}: {:s}".format(Color.redify(path), line))
        return
