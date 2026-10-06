"""GEF memory commands (category 03-f) extracted from the monolithic gef.py.

Memory dump / load commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""

import argparse
import os
import re

import gdb

from gef.commands.base import (
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.color import err, info, warn
from gef.core.kernel import Kernel
from gef.core.memory import read_memory, write_memory
from gef.core.process import ProcessMap, get_pagesize_mask_high, is_qemu_system
from gef.core.utils import GEF_TEMP_DIR, GefUtil, align_to_pagesize

@register_command
class SmartMemoryDumpCommand(GenericCommand):
    """Dump the memory of the entire process smartly."""

    _cmdline_ = "smart-memory-dump"
    _category_ = "03-f. Memory - Dump/Load"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-p", "--prefix", default="",
                        help="use this name for the dump destination file prefix. (default: '')")
    parser.add_argument("-s", "--suffix", default="",
                        help="use this name for the dump destination file suffix. (default: '')")
    parser.add_argument("-f", "--filter", action="append", type=re.compile, default=[],
                        help="REGEXP include filter.")
    parser.add_argument("-e", "--exclude", action="append", type=re.compile, default=[],
                        help="REGEXP exclude filter.")
    parser.add_argument("-c", "--commit", action="store_true", help="actually perform the dump.")
    parser.add_argument("-m", "--max-region-size", type=AddressUtil.parse_address, default=0x1000_0000,
                        help="maximum size of dump region. (default: %(default)#x; 0: infinity)")
    _syntax_ = parser.format_help()

    def do_dump(self, filepath, start, size):
        if self.args.max_region_size and self.args.max_region_size < size:
            warn("Too large, so skip: {:s}".format(filepath))
            return

        size_str = GefUtil.get_size_str(size)

        if self.args.commit:
            # make dir
            if not os.path.exists(os.path.dirname(filepath)):
                os.mkdir(os.path.dirname(filepath))

            # read
            try:
                data = read_memory(start, size)
            except gdb.MemoryError:
                warn("Memory read error; skipped: {:s} ({:s})".format(filepath, size_str))
                return

            # write
            open(filepath, "wb").write(data)
            info("Saved to {:s} ({:s})".format(filepath, size_str))
        else:
            info("It will be saved to {:s} ({:s})".format(filepath, size_str))
        return

    def smart_memory_dump(self, maps, prefix, suffix):
        dirpath = os.path.join(GEF_TEMP_DIR, "mem-dump-" + GefUtil.now_str())
        width = runtime.current_arch.ptrsize * 2
        total_size = 0

        for entry in maps:
            if isinstance(entry, list):
                start = entry[0]
                end = entry[0] + entry[1]
                size = entry[1]
                perm = entry[2].lower()
                path = ""
            else:
                start = entry.page_start
                end = entry.page_end
                size = end - start
                perm = str(entry.permission)

                if not entry.path.startswith(("[", "<")):
                    path = os.path.basename(entry.path)
                else:
                    path = entry.path
                    path = path.replace("[", "").replace("]", "") # consider [heap], [stack], [vdso]
                    path = path.replace("<", "").replace(">", "") # consider <tls-th1>, <explored>
                path = path.replace(" ", "_") # consider deleted case. e.g., /path/to/file (deleted)

            dumpfile_name = "{:s}{:0{:d}x}-{:0{:d}x}_{:s}_{:s}{:s}.raw".format(
                prefix, start, width, end, width, perm, path, suffix,
            )
            filepath = os.path.join(dirpath, dumpfile_name)

            # filtering
            if self.args.filter and not any(filt.search(dumpfile_name) for filt in self.args.filter):
                continue
            if self.args.exclude and any(ex.search(dumpfile_name) for ex in self.args.exclude):
                continue

            # dump
            self.do_dump(filepath, start, size)
            total_size += size

        info("Total size: {:s}".format(GefUtil.get_size_str(total_size)))

        if not self.args.commit:
            info("The directory name is replaced with the latest timestamp")
            warn('This dry run mode skips dumping; add "--commit" to proceed')
        return

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("kgdb", "vmware"))
    @require_arch_set
    def do_invoke(self, args):
        if is_qemu_system():
            maps = Kernel.get_maps()
        else:
            maps = ProcessMap.get_process_maps_exclude_special_regions(allow_vdso=True)
        if maps is None:
            err("Failed to get maps")
            return

        prefix = self.args.prefix
        if prefix:
            prefix = prefix + "_"

        suffix = self.args.suffix
        if suffix:
            suffix = "_" + suffix

        self.smart_memory_dump(maps, prefix, suffix)
        return


@register_command
class LoadFileCommand(GenericCommand):
    """Load the file into memory."""

    _cmdline_ = "load-file"
    _category_ = "03-f. Memory - Dump/Load"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to load.")
    parser.add_argument("file_path", metavar="FILE_PATH", help="the filepath to load.")
    parser.add_argument("file_offset", metavar="FILE_OFFSET", nargs="?", type=AddressUtil.parse_address, default=0,
                        help="the offset of the file to load.")
    parser.add_argument("load_size", metavar="LOAD_SIZE", nargs="?", type=AddressUtil.parse_address,
                        help="the size of the data to load.")
    _syntax_ = parser.format_help()

    _note_ = [
        "+-memory------+",
        "|             |             +-file_start--+",
        "|             |             | ^           |",
        "|             |             | |           |",
        "|             |             | v           |",
        "| LOCATION <----------------- FILE_OFFSET |",
        "| ...         | ^           | ...         |",
        "|             | | LOAD_SIZE |             |",
        "| ...         | v           | ...         |",
        "| end <---------------------- end         |",
        "|             |             |             |",
        "|             |             |             |",
        "|             |             +-file_end----+",
        "|             |",
        "+-------------+",
        "If there is not enough space, the load will fail halfway.",
    ]
    _note_ = "\n".join(_note_)

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        if not os.path.exists(args.file_path):
            err("Could not find {:s}".format(args.file_path))
            return

        if args.load_size is None:
            data_size = os.path.getsize(args.file_path)
            if data_size == 0:
                err("Unsupported zero size mapping")
                return
        elif args.load_size < 0:
            err("Invalid LOAD_SIZE")
            return
        else:
            data_size = args.load_size

        if args.file_offset < 0:
            err("Invalid FILE_OFFSET")
            return

        # read file and write to memory
        fd = open(args.file_path, "rb")
        if args.file_offset > 0:
            fd.seek(args.file_offset, 0)

        pos = args.location
        remain_size = data_size
        while remain_size > 0:
            data = fd.read(min(0x1000, remain_size))
            if len(data) == 0:
                break
            write_memory(pos, data)
            pos += len(data)
            remain_size -= len(data)
        return


@register_command
class LoadFileMmapCommand(GenericCommand):
    """Load the file into memory that allocated by `mmap`."""

    _cmdline_ = "load-file-mmap"
    _category_ = "03-f. Memory - Dump/Load"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", type=AddressUtil.parse_address,
                        help="the memory address to load.")
    parser.add_argument("file_path", metavar="FILE_PATH", help="the filepath to load.")
    parser.add_argument("file_offset", metavar="FILE_OFFSET", nargs="?", type=AddressUtil.parse_address, default=0,
                        help="the offset of the file to load.")
    parser.add_argument("load_size", metavar="LOAD_SIZE", nargs="?", type=AddressUtil.parse_address,
                        help="the size of the data to load.")
    _syntax_ = parser.format_help()

    _note_ = [
        "+-mmap_start--+",
        "|             |             +-file_start--+",
        "|             |             | ^           |",
        "|             |             | |           |",
        "|             |             | v           |",
        "| LOCATION <----------------- FILE_OFFSET |",
        "| ...         | ^           | ...         |",
        "|             | | LOAD_SIZE |             |",
        "| ...         | v           | ...         |",
        "| end <---------------------- end         |",
        "|             |             |             |",
        "|             |             |             |",
        "|             |             +-file_end----+",
        "|             |",
        "+-mmap_end----+",
    ]
    _note_ = "\n".join(_note_)

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    @require_arch_set
    def do_invoke(self, args):
        if not os.path.exists(args.file_path):
            err("Could not find {:s}".format(args.file_path))
            return

        if args.load_size is None:
            data_size = os.path.getsize(args.file_path)
            if data_size == 0:
                err("Unsupported zero size mapping")
                return
        elif args.load_size < 0:
            err("Invalid LOAD_SIZE")
            return
        else:
            data_size = args.load_size

        if args.file_offset < 0:
            err("Invalid FILE_OFFSET")
            return

        # +-mmap_start--+               ^             ^
        # |             |               |             |
        # |             |               |             | page_size
        # | data_start  | ^             |             |
        # | ...         | |             |             |
        # +-------------+ | data_size   | mmap_size   v
        # | ...         | |             |
        # | data_end    | v             |
        # |             |               |
        # |             |               |
        # +-mmap_end----+               v

        mmap_start = args.location & get_pagesize_mask_high()
        data_start = args.location
        data_end = data_start + data_size
        mmap_end = align_to_pagesize(data_end)
        mmap_size = mmap_end - mmap_start

        # mmap
        res = gdb.execute("mmap {:#x} {:#x}".format(mmap_start, mmap_size), to_string=True)
        if "[!]" in res:
            err("Failed to mmap")
            return

        output_line = res.splitlines()[-1]
        ret = int(output_line.split()[2], 0)

        if AddressUtil.is_msb_on(ret):
            err("Failed to mmap")
            return

        # read file and write to memory
        fd = open(args.file_path, "rb")
        if args.file_offset > 0:
            fd.seek(args.file_offset, 0)

        pos = data_start
        remain_size = data_size
        while remain_size > 0:
            data = fd.read(min(0x1000, remain_size))
            if len(data) == 0:
                break
            write_memory(pos, data)
            pos += len(data)
            remain_size -= len(data)
        return
