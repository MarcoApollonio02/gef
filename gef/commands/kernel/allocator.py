"""GEF kernel commands (category 06-h) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Linux Allocator: slub/slub-tiny/slab/slob/buddy/
vmalloc free-list dumpers, slab-contains and kmem-cache-alias. Auto-discovered
by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import itertools
import re
import struct

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    only_if_in_kernel_or_kpti_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, titlify, warn
from gef.core.config import Config
from gef.core.display import ProgressBar
from gef.core.kernel import AddrMap, Kernel, KernelListHead, KernelRBTree, KernelSlub, Ksym
from gef.core.memory import (
    hexdump,
    is_double_link_list,
    is_valid_addr,
    is_valid_addr_addr,
    read_cstring_from_memory,
    read_int32_from_memory,
    read_int_from_memory,
    read_memory,
)
from gef.core.pagewalk import KernelAddressHeuristicFinder, PageMap
from gef.core.process import (
    get_pagesize,
    get_pagesize_mask_high,
    get_pagesize_mask_low,
    is_32bit,
    is_64bit,
    is_arm32,
    is_arm64,
    is_kgdb,
    is_x86,
    is_x86_64,
)
from gef.core.registers import to_unsigned_long
from gef.core.symbols import Symbol
from gef.core.utils import (
    GefUtil,
    align_to_ptrsize,
    byteswap,
    slice_unpack,
)


@register_command
class SlubDumpCommand(GenericCommand, BufferingOutput):
    """Dump SLUB free-list reachable from slab_caches."""

    _cmdline_ = "slub-dump"
    _category_ = "06-h. Qemu-system/KGDB Cooperation - Linux Allocator"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-hs", "--help-for-slab-virtual", action="store_true",
                        help="show ASCII diagram for CONFIG_SLAB_VIRTUAL=y.")
    parser.add_argument("cache_name", metavar="SLUB_CACHE_NAME", nargs="*",
                        help="filter by specific slub cache name.")
    parser.add_argument("-l", "--list", action="store_true", help="list all slub cache names.")
    parser.add_argument("-L", "--list-no-sort", action="store_true", help="list all slub cache names without sort.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("--cpu", type=int, help="filter by specific cpu.")
    parser.add_argument("-R", "--reverse-walk", action="store_true", help="reverse order walk for slab_caches->list_head.")
    parser.add_argument("-s", "--simple", action="store_true", help="skip displaying layout and freelist.")
    parser.add_argument("-v", "--verbose", "--partial", action="store_true",
                        help="kernel < 7.0: dump partial pages too. kernel >= 7.0: ignored.")
    parser.add_argument("-vv", "--vverbose", "--node", action="store_true",
                        help="kernel < 7.0: dump partial pages and node pages too. kernel >= 7.0: ignored.")
    group = parser.add_mutually_exclusive_group(required=False)
    group.add_argument("--only-partial", action="store_true",
                       help="kernel < 7.0: dump only partial pages. kernel >= 7.0: ignored.")
    group.add_argument("--only-node", action="store_true",
                       help="kernel < 7.0: dump only node pages. kernel >= 7.0: ignored.")
    parser.add_argument("--skip-sheaf", action="store_true", help="skip dumping cpu_sheaves / slab_sheaf path (6.18+).")
    parser.add_argument("--hexdump-used", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="hexdump `used chunks` if layout is resolved.")
    parser.add_argument("--hexdump-freed", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="hexdump `unused (freed) chunks` if layout is resolved.")
    parser.add_argument("--telescope-used", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="telescope `used chunks` if layout is resolved.")
    parser.add_argument("--telescope-freed", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="telescope `unused (freed) chunks` if layout is resolved.")
    parser.add_argument("--slub-debug-y", action="store_true",
                        help="assumes `CONFIG_SLUB_DEBUG=y` and dumps kmem_cache_node->full slabs.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cached offset.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    parser.add_argument("--tlbflush-queue", action="store_true",
                        help="dump `slub_tlbflush_queue` (x86-64 only && CONFIG_SLAB_VIRTUAL=y).")
    parser.add_argument("--skip-page2virt", action="store_true",
                        help="[FOR DEVELOPER] used internally in gef, please don't use it.")
    parser.add_argument("--no-xor", action="store_true",
                        help="[FOR DEVELOPER] skip xor to chunk->next when `kmem_cache.random` is falsely detected.")
    parser.add_argument("--no-byte-swap", action="store_true", default=None,
                        help="[FOR DEVELOPER] skip byteswap to chunk->next when `kmem_cache.random` is falsely detected.")
    parser.add_argument("--offset-random", type=AddressUtil.parse_address,
                        help="[FOR DEVELOPER] user-specified offsetof(kmem_cache, random) when "
                             "`kmem_cache.random` is falsely detected.")
    parser.add_argument("--offset-node", type=AddressUtil.parse_address,
                        help="[FOR DEVELOPER] user-specified offsetof(kmem_cache, "
                             "node/per_node[0].node) when node is falsely detected.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} kmalloc-256             # <7.0: active pages; 7.0+: cpu sheaves and node slabs",
        "{0:s} kmalloc-256 --cpu 1     # dump kmalloc-256 from cpu 1",
        "{0:s} kmalloc-256 --partial   # <7.0 only: show active pages and partial pages",
        "{0:s} kmalloc-256 --node      # <7.0 only: show active pages, partial pages and node pages",
        "{0:s} --list                  # list slub cache names",
        "{0:s} -vv --offset-node 0xc8  # user specified offsetof(kmem_cache, node)",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified SLUB structure:",
        "",
        "                         +-kmem_cache----------+         +-kmem_cache--+   +-kmem_cache--+",
        "                         | cpu_slab (~6.19)    |---+     | cpu_slab    |   | cpu_slab    |",
        "                         | cpu_sheaves (6.18~) |---|-+   | cpu_sheaves |   | cpu_sheaves |",
        "                         | flags               |   | |   | flags       |   | flags       |",
        "                         | size                |   | |   | size        |   | size        |",
        "                         | object_size         |   | |   | object_size |   | object_size |",
        "                         | offset              |   | |   | offset      |   | offset      |",
        "       +-slab_caches-+   | name                |   | |   | name        |   | name        |",
        " ...<->| list_head   |<->| list_head           |<------->| list_head   |<->| list_head   |<-> ...",
        "       +-------------+   | random              |   | |   | random      |   | random      |",
        "                         | node[] (~7.0)       |-+ | |   | node[]      |   | node[]      |",
        "                         | per_node[] (7.1~)   | | | |   +-------------+   +-------------+",
        "  +----------------------|   [0].barn          | | | |",
        "  |                      |   [0].node          |-+ | |",
        "  |                      +---------------------+ | | |",
        "  |                                              | | |",
        "  |                                              | | |     [sheaf/barn (the fastest path)]",
        "  |  +-------------------------------------------+ | |                     +-->+-slab_sheaf-+",
        "  |  |  +------------------------------------------+ |                     |   | barn_list  |",
        "  |  |  |                               +------------+                     |   | size       |",
        "  |  |  |     +-__per_cpu_offset-+      |                                  |   | objects[]  |",
        "  |  |  +-----| cpu0_offset      |------+------->+-slub_percpu_sheaves-+   |   |  ptr       |->chunk",
        "  |  |  |     | cpu1_offset      |               | main                |---+   |  ptr       |->chunk",
        "  |  |  |     | cpu2_offset      |               | spare               |-->... |  ...       |",
        "  |  |  |     | ...              |               +---------------------+       +------------+",
        "  |  |  |     +------------------+",
        "  |  |  |                                                  [active page freelist (fast path)]",
        "  |  |  |                                                    +-chunk---+  +-chunk---+",
        "  |  |  |                                                    | ^       |  | ^       |",
        "  |  |  |                                                    | |offset |  | |offset |",
        "  |  |  |                                                    | v       |  | v       |",
        "  |  |  |                  +-------------------------------->| next    |->| next    |->NULL",
        "  |  |  v (~6.19)          |                                 +---------+  +---------+",
        "  |  | +-kmem_cache_cpu-+  |",
        "  |  | | freelist       |--+                               [active page freelist (slow path)]",
        "  |  | | page/slab      |---->+-page/slab(active)--+         +-chunk---+  +-chunk---+",
        "  |  | | partial        |--+  | freelist           |----+    | ^       |  | ^       |",
        "  |  | +----------------+  |  |                    |    |    | |offset |  | |offset |",
        "  |  |                     |  +------------------ -+    |    | v       |  | v       |",
        "  |  |                     |                            +--->| next    |->| next    |->NULL",
        "  |  |                     |                                 +---------+  +---------+",
        "  |  |                     |",
        "  |  |                     |                               [partial page freelist]",
        "  |  |                     +->+-page/slab(partial)-+         +-chunk---+  +-chunk---+",
        "  |  |                        | freelist           |----+    | ^       |  | ^       |",
        "  |  |                        | next               |--+ |    | |offset |  | |offset |",
        "  |  |                        +--------------------+  | |    | v       |  | v       |",
        "  |  |                                                | +--->| next    |->| next    |->NULL",
        "  |  |                          +---------------------+      +---------+  +---------+",
        "  |  |                          |",
        "  |  |                          v",
        "  |  +-+                       ...",
        "  |    |                                                    [numa node partial page freelist]",
        "  |    v                      +-page/slab(numa-node)+         +-chunk---+  +-chunk---+",
        "  |   +-kmem_cache_node-+     | freelist            |----+    | ^       |  | ^       |",
        "  |   | partial         |---->| next                |--+ |    | |offset |  | |offset |",
        "  |   | (full)          |     +---------------------+  | |    | v       |  | v       |",
        "  +---| barn (6.18~7.0) |                              | +--->| next    |->| next    |->NULL",
        "  |   +-----------------+  +---------------------------+      +---------+  +---------+",
        "  |   | ...             |  |",
        "  |   |                 |  |                                [numa node partial page freelist]",
        "  |   +-----------------+  |  +-page/slab(numa-node)+         +-chunk---+  +-chunk---+",
        "  |                        |  | freelist            |----+    | ^       |  | ^       |",
        "  |                        +->| next                |--+ |    | |offset |  | |offset |",
        "  |                           +---------------------+  | |    | v       |  | v       |",
        "  |                                                    | +--->| next    |->| next    |->NULL",
        "  |                        +---------------------------+      +---------+  +---------+",
        "  +----+                   |",
        "       |                   v",
        "       |                  ...",
        "       v",
        "      +-node_barn-----+         +-slab_sheaf-+    +-slab_sheaf-+",
        "      | sheaves_full  |<------->| barn_list  |<-->| barn_list  |<-->",
        "      | sheaves_empty |<-->...  | ...        |    | ...        |",
        "      +---------------+         +------------+    +------------+",
        "",
        "* `struct page` has been split into `struct page` and `struct slab` since kernel 5.17.",
        "  The structure name used for SLUB has been changed to `struct slab`.",
        "* If all chunks in certain page (or slab) are in use, they will not be displayed by this command.",
        "  This is because they cannot be reached by parsing from `slab_caches`.",
        "  So use `slab-contains` (if you know the address) or `kvmmap` (if you want to see all slabs even if it takes time).",
        "* `slab_sheaf`/`barn` introduced in 6.18 is not used by default, "
        "but used by setting it when calling `kmem_cache_create`.",
        "  `slab_sheaf.objects[]` is a stack that grows downwards and caches freed addresses.",
        "* `kmem_cache_cpu` is removed from 7.0. active/partial slabs no longer exist.",
        "  In kernel >= 7.0, this command dumps `cpu_sheaves` and node slabs by default.",
        "  The top of the stack is represented by `slab_sheaf.size`.",
        "* `--partial`, `--node`, `--only-partial`, and `--only-node` affect only kernel < 7.0.",
        "* To see the CONFIG_SLAB_VIRTUAL ASCII diagram, execute `slub-dump --help-for-slab-virtual`.",
    ]
    _note_ = "\n".join(_note_)

    _note2_ = [
        "* A mitigation called CONFIG_SLAB_VIRTUAL was proposed in September 2023 to prevent cross-cache attacks.",
        "  This config is not merged into mainline as of May 2025, but is used in KernelCTF@Google Security Research.",
        "* A unique feature of CONFIG_SLAB_VIRTUAL is that in addition to the existing SLUB structure,",
        "  it also has a structure for managing released slab structures.",
        "",
        "Structures in `CONFIG_SLAB_VIRTUAL=y`",
        "- v6.1-based, v6.12-based",
        "                                 +---slab----------+    +---slab----------+   +---slab----------+",
        "       (Temporary Lists)         | backing_folio   |    | backing_folio   |   | backing_folio   |",
        "       +-slub_tlbflush_queue-+   | oo              |    | oo              |   | oo              |",
        " ...<->| list_head           |<->| flush_list_elem |<-->| flush_list_elem |<->| flush_list_elem |<->...",
        "       +---------------------+   | slab_list       |    | slab_list       |   | slab_list       |",
        "                                 | slab_cache      |-+  | slab_cache      |   | slab_cache      |",
        "                                 | ...             | |  | ...             |   | ...             |",
        "                                 +-----------------+ |  +-----------------+   +-----------------+",
        "                                                     |",
        "                             +-----------------------+",
        "                             |",
        "                             v",
        "                         +---kmem_cache-------+             +---kmem_cache-------+",
        "                         | cpu_slab           |----+        | cpu_slab           |",
        "                         | flags              |    |        | flags              |",
        "                         | size               |    |        | size               |",
        "                         | object_size        |    |        | object_size        |",
        "                         | offset             |    |        | offset             |",
        "                         | min                |    |        | min                |",
        "                         | oo                 |    |        | oo                 |",
        "                         | freed_slabs_normal |<---------+  | freed_slabs_normal |",
        "                         | freed_slabs_min    |<------+  |  | freed_slabs_min    |",
        "       +-slab_caches-+   | name               |    |  |  |  | name               |",
        " ...<->| list_head   |<->| list_head          |<------|--|->| list_head          |<->...",
        "       +-------------+   | random             |    |  |  |  | random             |",
        "                         | node[]             |-+  |  |  |  | node[]             |",
        "                         +--------------------+ |  |  |  |  +--------------------+",
        "                                                |  |  |  |",
        "    +-------------------------------------------+  |  |  |   +---slab----+   +---slab----+",
        "    |                                              |  |  |   | ...       |   | ...       |",
        "    |    +-----------------------------------------+  |  |   | oo        |   | oo        |",
        "    |    |                                            |  +-->| slab_list |<->| slab_list |<->...",
        "    |    |     +-__per_cpu_offset-+                   |      | ...       |   | ...       |",
        "    |    +-----| ...              |                   |      +-----------+   +-----------+",
        "    |    |     +------------------+                   |",
        "    |    v                                            |      +---slab----+   +---slab----+",
        "    |    +-kmem_cache_cpu-+                           |      | ...       |   | ...       |",
        "    |    | ...            |                           |      | oo        |   | oo        |",
        "    |    +----------------+                           +----->| slab_list |<->| slab_list |<->...",
        "    v                                                        | ...       |   | ...       |",
        "    +-kmem_cache_node-+                                      +-----------+   +-----------+",
        "    | ...             |",
        "    +-----------------+",
        "",
        "",
        "- v6.6-based",
        "                                 +-virtual_slab-+     +-virtual_slab-+   +-virtual_slab-+",
        "       (Temporary Lists)         | ...          |     | ...          |   | ...          |",
        "       +-slub_tlbflush_queue-+   | slab_cache   |--+  | slab_cache   |   | slab_cache   |",
        " ...<->| list_head           |<->| slab_list    |<-|->| slab_list    |<->| slab_list    |<->...",
        "       +---------------------+   | oo           |  |  | oo           |   | oo           |",
        "                                 | ...          |  |  | ...          |   | ...          |",
        "                                 +--------------+  |  +--------------+   +--------------+",
        "                                                   |",
        "                             +---------------------+",
        "                             |",
        "                             v",
        "                         +-kmem_cache------+             +-kmem_cache------+",
        "                         | cpu_slab        |----+        | cpu_slab        |",
        "                         | flags           |    |        | flags           |",
        "                         | size            |    |        | size            |",
        "                         | object_size     |    |        | object_size     |",
        "                         | offset          |    |        | offset          |",
        "                         | oo              |    |        | oo              |",
        "                         | min             |    |        | min             |",
        "                         | freed_slabs     |<---------+  | freed_slabs     |",
        "                         | freed_slabs_min |<------+  |  | freed_slabs_min |",
        "                         | nr_freed_pages  |    |  |  |  | nr_freed_pages  |",
        "       +-slab_caches-+   | name            |    |  |  |  | name            |",
        " ...<->| list_head   |<->| list_head       |<------|--|->| list_head       |<->...",
        "       +-------------+   | random          |    |  |  |  | random          |",
        "                         | node[]          |-+  |  |  |  | node[]          |",
        "                         +-----------------+ |  |  |  |  +-----------------+",
        "                                             |  |  |  |",
        "    +----------------------------------------+  |  |  |   +-virtual_slab-+   +-virtual_slab-+",
        "    |                                           |  |  |   | ...          |   | ...          |",
        "    |    +--------------------------------------+  |  +-->| slab_list    |<->| slab_list    |<->...",
        "    |    |                                         |      | oo           |   | oo           |",
        "    |    |     +-__per_cpu_offset-+                |      | ...          |   | ...          |",
        "    |    +-----| ...              |                |      +--------------+   +--------------+",
        "    |    |     +------------------+                |",
        "    |    v                                         |      +-virtual_slab-+   +-virtual_slab-+",
        "    |    +-kmem_cache_cpu-+                        |      | ...          |   | ...          |",
        "    |    | ...            |                        +----->| slab_list    |<->| slab_list    |<->...",
        "    |    +----------------+                               | oo           |   | oo           |",
        "    v                                                     | ...          |   | ...          |",
        "    +-kmem_cache_node-+                                   +--------------+   +--------------+",
        "    | ...             |",
        "    +-----------------+",
        "",
        "* The freed slab structure is initially connected to `slub_tlbflush_queue`.",
        "  It is then reconnected to kmem_cache->freed_slabs_normal or freed_slabs_min or freed_slabs.",
        "* If oo_order(virtual_slab->slab.oo) == oo_order(kmem_cache->min),",
        "  `slub_tlbflush_worker` uses `kmem_cache->freed_slabs_min` as freelist of pages for the `kmem_cache`.",
        "  Otherwise, it uses `kmem_cache->freed_slabs`.",
    ]
    _note2_ = "\n".join(_note2_)

    def dump_page_print_layout(self, tag, kmem_cache, page, freelist, freelist_fastpath, freelist_sheaf):
        from gef.commands.debugging.context import DereferenceCommand
        pagesize = KernelAddressHeuristicFinder.consts().PAGE_SIZE
        used_address_color = Config.get("theme.heap_chunk_address_used")
        freed_address_color = Config.get("theme.heap_chunk_address_freed")

        if page["virt_addr"] is None:
            self.out.append("        layout: Failed to get the first page")
            return

        end_virt = page["virt_addr"] + page["num_pages"] * pagesize
        start_addr = page["virt_addr"] + kmem_cache["red_left_pad"]

        for idx, chunk in enumerate(range(start_addr, end_virt, kmem_cache["size"])):
            if chunk + kmem_cache["size"] > end_virt:
                break
            if chunk in freelist_fastpath[:-1]:
                next_chunk = freelist_fastpath[freelist_fastpath.index(chunk) + 1]
                if isinstance(next_chunk, str):
                    next_msg = "next: {:s}".format(next_chunk)
                else:
                    next_msg = "next: {:#x}".format(next_chunk)
                chunk_s = Color.colorify_hex(chunk, freed_address_color)
                is_freed = True
            elif chunk in freelist[:-1]:
                next_chunk = freelist[freelist.index(chunk) + 1]
                if isinstance(next_chunk, str):
                    next_msg = "next: {:s}".format(next_chunk)
                else:
                    next_msg = "next: {:#x}".format(next_chunk)
                if tag == "active":
                    next_msg += " (slow path)"
                chunk_s = Color.colorify_hex(chunk, freed_address_color)
                is_freed = True
            elif chunk in freelist_sheaf:
                next_msg = "in-use (sheaf)"
                chunk_s = Color.colorify_hex(chunk, freed_address_color)
                is_freed = True
            else:
                if page["objects"] <= idx:
                    next_msg = "never-used"
                else:
                    next_msg = "in-use"
                chunk_s = Color.colorify_hex(chunk, used_address_color)
                is_freed = False
            self.out.append("        {:7s}   {:#05x} {:s} ({:s})".format(
                "layout:" if idx == 0 else "", idx, chunk_s, next_msg,
            ))

            # dump chunks
            if self.args.hexdump_used and next_msg == "in-use":
                peeked_data = read_memory(chunk, self.args.hexdump_used)
                h = hexdump(peeked_data, 0x10, base=chunk, unit=runtime.current_arch.ptrsize)
                self.out.append(h)

            if self.args.hexdump_freed and is_freed:
                peeked_data = read_memory(chunk, self.args.hexdump_freed)
                h = hexdump(peeked_data, 0x10, base=chunk, unit=runtime.current_arch.ptrsize)
                self.out.append(h)

            if self.args.telescope_used and next_msg == "in-use":
                n = self.args.telescope_used // runtime.current_arch.ptrsize
                for i in range(n):
                    line = DereferenceCommand.pprint_dereferenced(chunk, i)
                    self.out.append(line)

            if self.args.telescope_freed and is_freed:
                n = self.args.telescope_freed // runtime.current_arch.ptrsize
                for i in range(n):
                    line = DereferenceCommand.pprint_dereferenced(chunk, i)
                    self.out.append(line)
        return

    def dump_page_print_freelist(self, tag, kmem_cache, page, freelist, freelist_fastpath):
        pagesize = KernelAddressHeuristicFinder.consts().PAGE_SIZE
        freed_address_color = Config.get("theme.heap_chunk_address_freed")

        def print_freelist(freelist):
            for chunk_addr in freelist:
                if page["virt_addr"] is not None:
                    if chunk_addr == 0:
                        continue
                    if isinstance(chunk_addr, str):
                        chunk_idx = ""
                        msg = chunk_addr
                    else:
                        chunk_offset = chunk_addr - page["virt_addr"] - kmem_cache["red_left_pad"]
                        chunk_idx = chunk_offset // kmem_cache["size"]
                        end_virt = page["virt_addr"] + page["num_pages"] * pagesize
                        if (
                            chunk_offset < 0
                            or chunk_offset % kmem_cache["size"]
                            or chunk_addr + kmem_cache["size"] > end_virt
                            or page["objects"] <= chunk_idx
                        ):
                            chunk_idx = ""
                        else:
                            chunk_idx = "{:#05x}".format(chunk_idx)
                        msg = Color.colorify_hex(chunk_addr, freed_address_color)
                    self.out.append("                  {:5s} {:s}".format(chunk_idx, msg))
                else:
                    if isinstance(chunk_addr, str):
                        msg = chunk_addr
                    else:
                        msg = Color.colorify_hex(chunk_addr, freed_address_color)
                    self.out.append("                        {:s}".format(msg))
            return

        if tag == "active":
            if freelist_fastpath == [] or freelist_fastpath == [0]:
                self.out.append("        freelist (fast path): (none)")
            else:
                self.out.append("        freelist (fast path):")
                print_freelist(freelist_fastpath)
            if freelist == [] or freelist == [0]:
                self.out.append("        freelist (slow path): (none)")
            else:
                self.out.append("        freelist (slow path):")
                print_freelist(freelist)
        else:
            if freelist == [] or freelist == [0]:
                self.out.append("        freelist: (none)")
            else:
                self.out.append("        freelist:")
                print_freelist(freelist)
        return

    def dump_page(self, page, kmem_cache, tag, freelist_fastpath=()):
        from gef.commands.debugging.context import DereferenceCommand
        label_active_color = Config.get("theme.heap_label_active")
        label_inactive_color = Config.get("theme.heap_label_inactive")
        heap_page_color = Config.get("theme.heap_page_address")
        slab_address_color = Config.get("theme.heap_slab_address")
        freelist_fastpath = list(freelist_fastpath)

        # page address
        if tag == "active":
            tag_s = Color.colorify("{:s} page".format(tag), label_active_color)
        else:
            tag_s = Color.colorify("{:s} page".format(tag), label_inactive_color)
        page_addr_s = Color.colorify_hex(page["address"], slab_address_color)
        self.out.append("      {:s}: {:s}".format(tag_s, page_addr_s))

        # fast return if invalid
        if not is_valid_addr(page["address"]):
            return

        # print virtual address
        if page["virt_addr"] is None:
            self.out.append("        virtual address: ???")
        else:
            colored_virt_addr = Color.colorify_hex(page["virt_addr"], heap_page_color)
            self.out.append("        virtual address: {:s}".format(colored_virt_addr))

        # print info
        self.out.append("        num pages: {:d}".format(page["num_pages"]))

        if self.args.simple:
            return

        freelist = page["freelist"]
        freelist_sheaf = self.kslub.get_page_sheaf_objects(kmem_cache, page)
        if tag == "active":
            freelist_len = len({
                x for x in freelist + freelist_fastpath + freelist_sheaf
                if isinstance(x, int) and x != 0 # ignore str and 0
            })
            inuse = page["objects"] - freelist_len
        else:
            freelist_set = {x for x in freelist if isinstance(x, int)}
            inuse = page["inuse"] - len(set(freelist_sheaf) - freelist_set)
        self.out.append("        in-use: {:d}/{:d}".format(inuse, page["objects"]))
        self.out.append("        frozen: {:d}".format(page["frozen"]))

        # print layout
        self.dump_page_print_layout(tag, kmem_cache, page, freelist, freelist_fastpath, freelist_sheaf)

        # print freelist
        self.dump_page_print_freelist(tag, kmem_cache, page, freelist, freelist_fastpath)
        return

    # for CONFIG_SLAB_VIRTUAL
    def dump_slub_tlbflush_queue(self, parsed_slabs):
        chunk_label_color = Config.get("theme.heap_chunk_label")
        not_mapped_virt = Config.get("theme.address_valid_but_none")
        slab_address_color = Config.get("theme.heap_slab_address")
        # dump
        queue_addr_s = Color.colorify_hex(self.kslub.slub_tlbflush_queue, slab_address_color)
        self.out.append("slub_tlbflush_queue @ {:s}".format(queue_addr_s))
        for slab in parsed_slabs:
            slab_addr = slab["address"]
            self.out.append("")
            slab_addr_s = Color.colorify_hex(slab_addr, slab_address_color)
            self.out.append("  slab: {:s}".format(slab_addr_s))
            self.out.append("    kmem_cache: {:s}".format(Color.colorify(slab["slab_cache_name"], chunk_label_color)))
            # virtual address is not mapped here
            if slab["virt_addr"] is not None:
                virt = "{:#x}".format(slab["virt_addr"])
            else:
                virt = "???"
            self.out.append("    virt: {:s}".format(Color.colorify(virt, not_mapped_virt)))
        return

    # for sheaf / barn
    def dump_sheaf(self, sheaf, tag):
        from gef.commands.debugging.context import DereferenceCommand
        freed_address_color = Config.get("theme.heap_chunk_address_freed")
        slab_address_color = Config.get("theme.heap_slab_address")

        sheaf_addr_s = Color.colorify_hex(sheaf["address"], slab_address_color)
        self.out.append("      {:s}: {:s}".format(tag, sheaf_addr_s))
        self.out.append("        size: {:d}".format(sheaf["size"]))

        if self.args.simple:
            return

        for i, chunk in enumerate(sheaf["objects"]):
            chunk_s = Color.colorify_hex(chunk, freed_address_color)
            if i == 0:
                self.out.append("        objects:  {:#05x} {:s}".format(i, chunk_s))
            elif i == len(sheaf["objects"]) - 1:
                self.out.append("                  {:#05x} {:s} <- top".format(i, chunk_s))
            else:
                self.out.append("                  {:#05x} {:s}".format(i, chunk_s))

            if self.args.hexdump_freed:
                peeked_data = read_memory(chunk, self.args.hexdump_freed)
                h = hexdump(peeked_data, 0x10, base=chunk, unit=runtime.current_arch.ptrsize)
                self.out.append(h)
            if self.args.telescope_freed:
                n = self.args.telescope_freed // runtime.current_arch.ptrsize
                for i in range(n):
                    line = DereferenceCommand.pprint_dereferenced(chunk, i)
                    self.out.append(line)
        return

    # for sheaf / barn
    def dump_node_barn(self, node_barn):
        if not node_barn.get("address"):
            return

        slab_address_color = Config.get("theme.heap_slab_address")
        node_barn_addr_s = Color.colorify_hex(node_barn["address"], slab_address_color)
        self.out.append("      node_barn: {:s}".format(node_barn_addr_s))

        for name in ["sheaves_full", "sheaves_empty"]:
            sheaves = node_barn.get(name, [])
            if len(sheaves) == 0:
                self.out.append("        {:14s} (none)".format(name + ":"))
                continue

            for i, sheaf in enumerate(sheaves):
                if i == 0:
                    sheaf_addr_s = Color.colorify_hex(sheaf["address"], slab_address_color)
                    self.out.append("        {:14s} {:s}".format(name + ":", sheaf_addr_s))
                else:
                    sheaf_addr_s = Color.colorify_hex(sheaf["address"], slab_address_color)
                    self.out.append("                       {:s}".format(sheaf_addr_s))
        return

    # for sheaf / barn
    def dump_sheaves(self, cpu_sheaves, kmem_cache, cpu):
        label_active_color = Config.get("theme.heap_label_active")
        label_inactive_color = Config.get("theme.heap_label_inactive")
        slab_address_color = Config.get("theme.heap_slab_address")
        kversion = Kernel.version()

        if not cpu_sheaves.get("address"):
            return

        cpu_sheaves_addr_s = Color.colorify_hex(cpu_sheaves["address"], slab_address_color)
        self.out.append("    slub_percpu_sheaves (cpu{:d}): {:s}".format(cpu, cpu_sheaves_addr_s))

        # main
        if "main" in cpu_sheaves:
            if cpu_sheaves["main"]["address"]:
                if kversion < "7.0":
                    tag = Color.colorify("main sheaf", label_active_color) + " (fastest path)"
                else:
                    tag = Color.colorify("main sheaf", label_active_color)
                self.dump_sheaf(cpu_sheaves["main"], tag)

        # spare
        if "spare" in cpu_sheaves:
            if cpu_sheaves["spare"]["address"]:
                tag = Color.colorify("spare sheaf", label_inactive_color)
                self.dump_sheaf(cpu_sheaves["spare"], tag)
        return

    def dump_caches(self, target_names, cpus, parsed_caches):
        chunk_label_color = Config.get("theme.heap_chunk_label")
        chunk_size_color = Config.get("theme.heap_chunk_size")
        label_inactive_color = Config.get("theme.heap_label_inactive")
        slab_address_color = Config.get("theme.heap_slab_address")

        slab_caches_s = Color.colorify_hex(self.kslub.slab_caches, slab_address_color)
        self.out.append("slab_caches @ {:s}".format(slab_caches_s))
        for kmem_cache in parsed_caches[1:]:
            if target_names != [] and kmem_cache["name"] not in target_names:
                continue

            # dump kmem_cache metadata
            self.out.append("")
            kmem_cache_addr_s = Color.colorify_hex(kmem_cache["address"], slab_address_color)
            self.out.append("  kmem_cache: {:s}".format(kmem_cache_addr_s))
            self.out.append("    name: {:s}".format(Color.colorify(kmem_cache["name"], chunk_label_color)))
            flags_str = kmem_cache["flags_str"]
            self.out.append("    flags: {:#x}{:s}".format(
                kmem_cache["flags"], " ({:s})".format(flags_str) if flags_str is not None else "",
            ))
            object_size_s = Color.colorify_hex(kmem_cache["object_size"], chunk_size_color)
            self.out.append("    object size: {:s} (chunk size: {:#x})".format(object_size_s, kmem_cache["size"]))
            self.out.append("    offset (next pointer in chunk): {:#x}".format(kmem_cache["offset"]))
            if self.kslub.kmem_cache_offset_random is not None:
                if self.args.no_xor is False:
                    if self.kslub.swap is True:
                        fmt = "    random (xor key): {:#x} ^ byteswap(&chunk->next)"
                        self.out.append(fmt.format(kmem_cache["random"]))
                    else:
                        fmt = "    random (xor key): {:#x} ^ &chunk->next"
                        self.out.append(fmt.format(kmem_cache["random"]))
            self.out.append("    red_left_pad: {:#x}".format(kmem_cache["red_left_pad"]))

            # dump freelist in kmem_cache only if CONFIG_SLAB_VIRTUAL=y
            if self.kslub.slab_virtual_enabled:
                nr_freed_pages = kmem_cache["nr_freed_pages"]
                self.out.append("    nr_freed_pages: {:#d}".format(nr_freed_pages))

                # freed_slabs_normal/freed_slabs
                self.out.append("    freed_slabs_normal: {:#d}/{:#d}".format(len(kmem_cache["freed_slabs_normal"]), nr_freed_pages))
                for idx, slab in enumerate(kmem_cache["freed_slabs_normal"]):
                    slab_addr_s = Color.colorify_hex(slab["address"], slab_address_color)
                    self.out.append("             {:#05x} {:s}".format(idx, slab_addr_s))

                # freed_slabs_min
                self.out.append("    freed_slabs_min: {:#d}/{:#d}".format(len(kmem_cache["freed_slabs_min"]), nr_freed_pages))
                for idx, slab in enumerate(kmem_cache["freed_slabs_min"]):
                    slab_addr_s = Color.colorify_hex(slab["address"], slab_address_color)
                    self.out.append("             {:#05x} {:s}".format(idx, slab_addr_s))

            # dump each cpu
            for cpu in cpus:
                # dump kmem_cache_cpu
                if self.dump_target_kmem_cache_cpu:
                    kmem_cache_cpu_addr_s = Color.colorify_hex(
                        kmem_cache["kmem_cache_cpu"][cpu]["address"], slab_address_color,
                    )
                    self.out.append("    kmem_cache_cpu (cpu{:d}): {:s}".format(cpu, kmem_cache_cpu_addr_s))

                    # dump active
                    if self.dump_target_active:
                        active_page = kmem_cache["kmem_cache_cpu"][cpu]["active_page"]
                        freelist_fastpath = kmem_cache["kmem_cache_cpu"][cpu]["freelist"]
                        self.dump_page(active_page, kmem_cache, "active", freelist_fastpath)

                    # dump partial
                    if self.dump_target_partial:
                        printed_count = 0
                        for partial_page in kmem_cache["kmem_cache_cpu"][cpu]["partial_pages"]:
                            self.dump_page(partial_page, kmem_cache, "partial")
                            printed_count += 1
                        if printed_count > 1 : # included address == 0
                            self.out.append("        (end of the list)")

                # dump sheaves
                if self.dump_target_cpu_sheaves:
                    if "cpu_sheaves" in kmem_cache:
                        cpu_sheaves = kmem_cache["cpu_sheaves"][cpu]
                        self.dump_sheaves(cpu_sheaves, kmem_cache, cpu)

            # dump nodes
            if self.dump_target_node and "nodes_partial" in kmem_cache:
                for node_index, node_page_list_partial in enumerate(kmem_cache["nodes_partial"]):
                    node_addr = kmem_cache["node_addresses"][node_index]
                    node_id = kmem_cache["node_ids"][node_index]
                    node_addr_s = Color.colorify_hex(node_addr, slab_address_color)
                    self.out.append("    kmem_cache_node[{:d}]: {:s}".format(node_id, node_addr_s))

                    # node list (partial)
                    printed_count = 0
                    for node_page in node_page_list_partial:
                        self.dump_page(node_page, kmem_cache, "node")
                        printed_count += 1
                    if printed_count == 0:
                        self.out.append("      {:s}: (none)".format(Color.colorify("node pages", label_inactive_color)))

                    # node list (full; exists when CONFIG_SLUB_DEBUG=y)
                    if "nodes_full" in kmem_cache:
                        node_page_list_full = kmem_cache["nodes_full"][node_index]
                        printed_count = 0
                        for node_page in node_page_list_full:
                            self.dump_page(node_page, kmem_cache, "node (full)")
                            printed_count += 1
                        if printed_count == 0:
                            self.out.append("      {:s}: (none)".format(Color.colorify("node (full) pages", label_inactive_color)))

                    # barn list (6.18~)
                    if "node_barn" in kmem_cache and node_index < len(kmem_cache["node_barn"]):
                        self.dump_node_barn(kmem_cache["node_barn"][node_index])

            next_addr_s = Color.colorify_hex(kmem_cache["next"], slab_address_color)
            self.out.append("    next: {:s}".format(next_addr_s))
        return

    def dump_names(self, parsed_caches):
        slab_address_color = Config.get("theme.heap_slab_address")
        name_width = max((len(k["name"]) for k in parsed_caches[1:]), default=4)

        if not self.args.quiet:
            fmt = "{:<18s} {:<18s} {:" + str(name_width) + "s} {:20s}"
            legend = ["Object Size", "Chunk Size", "Name", "kmem_cache"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        if self.args.list_no_sort:
            target_caches = parsed_caches[1:]
        else:
            target_caches = sorted(parsed_caches[1:], key=lambda x: (x["object_size"], x["size"], x["name"]))

        for kmem_cache in target_caches:
            objsz = "{0:d} ({0:#x})".format(kmem_cache["object_size"])
            chunksz = "{0:d} ({0:#x})".format(kmem_cache["size"])
            chunk_name = kmem_cache["name"]
            address = Color.colorify_hex(kmem_cache["address"], slab_address_color)
            self.out.append("{:18s} {:18s} {:{:d}s} {:s}".format(objsz, chunksz, chunk_name, name_width, address))
        return

    def slubwalk(self, target_names, cpu):
        self.kslub = Kernel.slub(
            no_xor=self.args.no_xor,
            byte_swap=None if self.args.no_byte_swap is None else not self.args.no_byte_swap,
            offset_random=self.args.offset_random, offset_node=self.args.offset_node,
        )
        if self.args.rescan:
            Cache.clear_cache_for(self.kslub.initialize)

        ret = self.kslub.initialize()
        if self.args.meta or not ret:
            for func, line in Kernel.export_meta(self, self.kslub.meta):
                func(line)
        if not ret:
            self.quiet_err("Initialization failed")
            return

        if self.args.meta:
            return

        if self.args.list or self.args.list_no_sort:
            target_cpus = None
        elif cpu is None:
            target_cpus = list(range(self.kslub.ncpus))
        else:
            if not 0 <= cpu < self.kslub.ncpus:
                self.quiet_err("CPU number is invalid (valid range: {:d}-{:d})".format(0, self.kslub.ncpus - 1))
                return
            target_cpus = [cpu]

        if self.args.tlbflush_queue and not (self.args.list or self.args.list_no_sort):
            if self.kslub.slab_virtual_enabled:
                parsed_queue = self.kslub.walk_slab_list(
                    self.kslub.slub_tlbflush_queue, self.kslub.page_offset_flush_list_elem, resolve_virt=True,
                )
                self.dump_slub_tlbflush_queue(parsed_queue)
            else:
                self.quiet_warn("CONFIG_SLAB_VIRTUAL is disabled. option `--tlbflush-queue` is ignored")
            return

        parsed_caches = self.kslub.walk_caches(
            target_names, target_cpus,
            names_only=self.args.list or self.args.list_no_sort,
            reverse_walk=self.args.reverse_walk,
            simple=self.args.simple,
            quiet=self.args.quiet,
            skip_page2virt=self.args.skip_page2virt,
            slub_debug_y=self.args.slub_debug_y,
            active=self.dump_target_active,
            partial=self.dump_target_partial,
            node=self.dump_target_node,
            cpu_sheaves=self.dump_target_cpu_sheaves,
        )
        if self.args.list or self.args.list_no_sort:
            self.dump_names(parsed_caches)
            return

        self.dump_caches(target_names, target_cpus, parsed_caches)
        return

    @Cache.cache_this_session
    def warmup_page2virt(self):
        if is_x86() or is_arm32():
            args = self.args # backup
            KernelSlub.warmup_page2virt()
            # self.args will be overwritten. this is workaround.
            self.args = args # revert
        return

    def setup(self, args):
        if args.no_xor or args.no_byte_swap:
            args.rescan = True
        if args.offset_random is not None or args.offset_node is not None:
            args.rescan = True

        kversion = Kernel.version()
        if not kversion:
            self.quiet_err("Failed to resolve kernel version")

        # dump target
        self.dump_target_active = False
        self.dump_target_partial = False
        if kversion < "7.0":
            self.dump_target_kmem_cache_cpu = True
            if kversion < "6.18":
                self.dump_target_cpu_sheaves = False
            else:
                self.dump_target_cpu_sheaves = True
            self.dump_target_active = True
            self.dump_target_partial = args.verbose or args.vverbose
            self.dump_target_node = args.vverbose
            if args.only_partial:
                self.dump_target_active = False
                self.dump_target_partial = True
                self.dump_target_node = False
            elif args.only_node:
                self.dump_target_active = False
                self.dump_target_partial = False
                self.dump_target_node = True
            if args.skip_sheaf:
                self.dump_target_cpu_sheaves = False
        else:
            self.dump_target_kmem_cache_cpu = False
            self.dump_target_cpu_sheaves = True
            self.dump_target_node = True
            if args.skip_sheaf:
                self.dump_target_cpu_sheaves = False
        return

    def get_kmem_caches(self, target_names):
        return Kernel.slub().get_kmem_caches(target_names)

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if args.hexdump_used < 0 or args.hexdump_freed < 0:
            err("Hexdump size must be >= 0")
            return
        if args.help_for_slab_virtual:
            gef_print(self._note2_.strip())
            return

        self.quiet_info("Wait for memory scan")

        allocator = Kernel.get_slab_type()
        if allocator == "SLUB":
            pass
        elif allocator == "SLUB_TINY":
            self.quiet_err("Unsupported; You should use `slub-tiny-dump`")
            return
        elif allocator == "SLAB":
            self.quiet_err("Unsupported; You should use `slab-dump`")
            return
        elif allocator == "SLOB":
            self.quiet_err("Unsupported; You should use `slob-dump`")
            return
        else:
            self.quiet_err("Unsupported: Unknown allocator")
            return

        # The slub-dump command is used by page2virt and kmagic to find vmemmap and sizeof(struct page).
        # Therefore, slub-dump itself may be called recursively (up to once) from slub-dump.
        # If a recursive call is made, various parameters held by self will be destroyed.
        # It's very tricky, but if we make sure to call page2virt first,
        # no further calls will be made and it will work without any problems.
        if not args.skip_page2virt:
            self.warmup_page2virt()

        self.setup(args)
        self.maps = None
        self.out = []
        self.slubwalk(args.cache_name, args.cpu)
        self.print_output()
        return



@register_command
class SlubTinyDumpCommand(GenericCommand, BufferingOutput):
    """Dump SLUB-TINY free-list reachable from slab_caches."""

    _cmdline_ = "slub-tiny-dump"
    _category_ = "06-h. Qemu-system/KGDB Cooperation - Linux Allocator"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("cache_name", metavar="SLUB_CACHE_NAME", nargs="*", help="filter by specific slub cache name.")
    parser.add_argument("-l", "--list", action="store_true", help="list all slub cache names.")
    parser.add_argument("-L", "--list-no-sort", action="store_true", help="list all slub cache names without sort.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-R", "--reverse-walk", action="store_true", help="reverse order walk for slab_caches->list_head.")
    parser.add_argument("-s", "--simple", action="store_true", help="skip displaying layout and freelist.")
    parser.add_argument("--hexdump-used", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="hexdump `used chunks` if layout is resolved.")
    parser.add_argument("--hexdump-freed", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="hexdump `unused (freed) chunks` if layout is resolved.")
    parser.add_argument("--telescope-used", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="telescope `used chunks` if layout is resolved.")
    parser.add_argument("--telescope-freed", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="telescope `unused (freed) chunks` if layout is resolved.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cached offset.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    parser.add_argument("--skip-page2virt", action="store_true",
                        help="[FOR DEVELOPER] used internally in gef, please don't use it.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} kmalloc-256  # dump kmalloc-256",
        "{0:s} --list       # list slub cache names",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified SLUB-TINY structure:",
        "",
        "                         +-kmem_cache----------+     +-kmem_cache--+   +-kmem_cache--+",
        "                         | cpu_sheaves (6.18~) |     | cpu_sheaves |   | cpu_sheaves |",
        "                         | flags               |     | flags       |   | flags       |",
        "                         | size                |     | size        |   | size        |",
        "                         | object_size         |     | object_size |   | object_size |",
        "                         | offset              |     | offset      |   | offset      |",
        "       +-slab_caches-+   | name                |     | name        |   | name        |",
        " ...<->| list_head   |<->| list_head           |<--->| list_head   |<->| list_head   |<-> ...",
        "       +-------------+   | node[]              |--+  | node[]      |   | node[]      |",
        "                         +---------------------+  |  +-------------+   +-------------+",
        "                                                  |",
        "    +---------------------------------------------+",
        "    |                                               [numa node partial page freelist]",
        "    v                     +-slab-----------+          +-chunk---+  +-chunk---+",
        "  +-kmem_cache_node-+     | freelist       |----+     | ^       |  | ^       |",
        "  | partial         |---->| next           |--+ |     | |offset |  | |offset |",
        "  +-----------------+     +----------------+  | |     | v       |  | v       |",
        "  | ...             |                         | +---->| next    |->| next    |->NULL",
        "  +-----------------+  +----------------------+       +---------+  +---------+",
        "                       |",
        "                       |                            [numa node partial page freelist]",
        "                       |  +-slab-----------+          +-chunk---+  +-chunk---+",
        "                       |  | freelist       |----+     | ^       |  | ^       |",
        "                       +->| next           |--+ |     | |offset |  | |offset |",
        "                          +----------------+  | |     | v       |  | v       |",
        "                                              | +---->| next    |->| next    |->NULL",
        "                       +----------------------+       +---------+  +---------+",
        "                       |",
        "                       v",
        "                      ...",
        "* SLUB-TINY was introduced in kernel 6.2.",
    ]
    _note_ = "\n".join(_note_)

    def dump_page_print_layout(self, kmem_cache, page, freelist):
        from gef.commands.debugging.context import DereferenceCommand
        pagesize = KernelAddressHeuristicFinder.consts().PAGE_SIZE
        used_address_color = Config.get("theme.heap_chunk_address_used")
        freed_address_color = Config.get("theme.heap_chunk_address_freed")

        if page["virt_addr"] is None:
            self.out.append("        layout: Failed to get the first page")
            return

        end_virt = page["virt_addr"] + page["num_pages"] * pagesize
        start_addr = page["virt_addr"] + kmem_cache["red_left_pad"]

        if kmem_cache["red_left_pad"]:
            chunk_s = Color.colorify_hex(page["virt_addr"], used_address_color)
            self.out.append("        {:7s}   {:#05x} {:s} ({:s})".format("layout:", 0, chunk_s, "never-used"))
            start_idx = 1
        else:
            start_idx = 0

        for idx, chunk in enumerate(range(start_addr, end_virt, kmem_cache["size"]), start=start_idx):
            if chunk in freelist[:-1]:
                next_chunk = freelist[freelist.index(chunk) + 1]
                if isinstance(next_chunk, str):
                    next_msg = "next: {:s}".format(next_chunk)
                else:
                    next_msg = "next: {:#x}".format(next_chunk)
                chunk_s = Color.colorify_hex(chunk, freed_address_color)
            else:
                if page["objects"] <= idx:
                    next_msg = "never-used"
                else:
                    next_msg = "in-use"
                chunk_s = Color.colorify_hex(chunk, used_address_color)
            if idx == 0:
                layout_msg = "layout:"
            else:
                layout_msg = ""
            self.out.append("        {:7s}   {:#05x} {:s} ({:s})".format(layout_msg, idx, chunk_s, next_msg))

            # dump chunks
            if self.args.hexdump_used and next_msg == "in-use":
                peeked_data = read_memory(chunk, self.args.hexdump_used)
                h = hexdump(peeked_data, 0x10, base=chunk, unit=runtime.current_arch.ptrsize)
                self.out.append(h)

            if self.args.hexdump_freed and next_msg.startswith("next: "):
                peeked_data = read_memory(chunk, self.args.hexdump_freed)
                h = hexdump(peeked_data, 0x10, base=chunk, unit=runtime.current_arch.ptrsize)
                self.out.append(h)

            if self.args.telescope_used and next_msg == "in-use":
                n = self.args.telescope_used // runtime.current_arch.ptrsize
                for i in range(n):
                    line = DereferenceCommand.pprint_dereferenced(chunk, i)
                    self.out.append(line)

            if self.args.telescope_freed and next_msg.startswith("next: "):
                n = self.args.telescope_freed // runtime.current_arch.ptrsize
                for i in range(n):
                    line = DereferenceCommand.pprint_dereferenced(chunk, i)
                    self.out.append(line)
        return

    def dump_page_print_freelist(self, kmem_cache, page, freelist):
        freed_address_color = Config.get("theme.heap_chunk_address_freed")

        if freelist == [] or freelist == [0]:
            self.out.append("        freelist: (none)")
            return

        for idx, chunk_addr in enumerate(freelist):
            if page["virt_addr"] is not None:
                if chunk_addr == 0:
                    continue
                if isinstance(chunk_addr, str):
                    chunk_idx = ""
                    msg = chunk_addr
                else:
                    chunk_idx = (chunk_addr - page["virt_addr"]) // kmem_cache["size"]
                    if chunk_idx < 0 or page["objects"] <= chunk_idx:
                        chunk_idx = ""
                    else:
                        chunk_idx = "{:#05x}".format(chunk_idx)
                    msg = Color.colorify_hex(chunk_addr, freed_address_color)
                if idx == 0:
                    freelist_msg = "freelist:"
                else:
                    freelist_msg = ""
                self.out.append("        {:9s} {:5s} {:s}".format(freelist_msg, chunk_idx, msg))
            else:
                if isinstance(chunk_addr, str):
                    msg = chunk_addr
                else:
                    msg = Color.colorify_hex(chunk_addr, freed_address_color)
                if idx == 0:
                    freelist_msg = "freelist:"
                else:
                    freelist_msg = ""
                self.out.append("        {:9s}       {:s}".format(freelist_msg, msg))
        return

    def dump_page(self, page, kmem_cache, tag, freelist=None):
        from gef.commands.debugging.context import DereferenceCommand
        label_active_color = Config.get("theme.heap_label_active")
        heap_page_color = Config.get("theme.heap_page_address")

        # page address
        tag_s = Color.colorify("{:s} page".format(tag), label_active_color)
        self.out.append("      {:s}: {:#x}".format(tag_s, page["address"]))

        # fast return if invalid
        if not is_valid_addr(page["address"]):
            return

        # for partial or node page
        if freelist is None:
            freelist = page["freelist"]

        # print virtual address
        if page["virt_addr"] is None:
            self.out.append("        virtual address: ???")
        else:
            colored_virt_addr = Color.colorify_hex(page["virt_addr"], heap_page_color)
            self.out.append("        virtual address: {:s}".format(colored_virt_addr))

        # print info
        self.out.append("        num pages: {:d}".format(page["num_pages"]))

        if self.args.simple:
            return

        if tag == "active":
            freelist_len = len({x for x in freelist if isinstance(x, int) and x != 0}) # ignore str and last 0
            inuse = page["objects"] - freelist_len
        else:
            inuse = page["inuse"]
        self.out.append("        in-use: {:d}/{:d}".format(inuse, page["objects"]))
        self.out.append("        frozen: {:d}".format(page["frozen"]))

        # print layout
        self.dump_page_print_layout(kmem_cache, page, freelist)

        # print freelist
        self.dump_page_print_freelist(kmem_cache, page, freelist)
        return

    def dump_caches(self, target_names, parsed_caches):
        chunk_label_color = Config.get("theme.heap_chunk_label")
        chunk_size_color = Config.get("theme.heap_chunk_size")
        label_inactive_color = Config.get("theme.heap_label_inactive")

        self.out.append("slab_caches @ {:#x}".format(self.kslub_tiny.slab_caches))
        for kmem_cache in parsed_caches[1:]:
            if target_names != [] and kmem_cache["name"] not in target_names:
                continue

            # dump kmem_cache metadata
            self.out.append("")
            self.out.append("  kmem_cache: {:#x}".format(kmem_cache["address"]))
            self.out.append("    name: {:s}".format(Color.colorify(kmem_cache["name"], chunk_label_color)))
            flags_str = kmem_cache["flags_str"]
            self.out.append("    flags: {:#x}{:s}".format(
                kmem_cache["flags"], " ({:s})".format(flags_str) if flags_str is not None else "",
            ))
            object_size_s = Color.colorify_hex(kmem_cache["object_size"], chunk_size_color)
            self.out.append("    object size: {:s} (chunk size: {:#x})".format(object_size_s, kmem_cache["size"]))
            self.out.append("    offset (next pointer in chunk): {:#x}".format(kmem_cache["offset"]))
            self.out.append("    red_left_pad: {:#x}".format(kmem_cache["red_left_pad"]))

            # dump nodes
            for node_index, node_page_list in enumerate(kmem_cache["nodes"]):
                node_addr = kmem_cache["node_addresses"][node_index]
                node_id = kmem_cache["node_ids"][node_index]
                self.out.append("    kmem_cache_node[{:d}]: {:#x}".format(node_id, node_addr))
                printed_count = 0
                for node_page in node_page_list:
                    self.dump_page(node_page, kmem_cache, "node")
                    printed_count += 1
                if printed_count == 0:
                    tag = Color.colorify("node pages", label_inactive_color)
                    self.out.append("      {:s}: (none)".format(tag))

            self.out.append("    next: {:#x}".format(kmem_cache["next"]))
        return

    def dump_names(self, parsed_caches):
        name_width = max((len(k["name"]) for k in parsed_caches[1:]), default=4)

        if not self.args.quiet:
            fmt = "{:<18s} {:<18s} {:" + str(name_width) + "s} {:20s}"
            legend = ["Object Size", "Chunk Size", "Name", "kmem_cache"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        if self.args.list_no_sort:
            target_caches = parsed_caches[1:]
        else:
            target_caches = sorted(parsed_caches[1:], key=lambda x: (x["object_size"], x["size"], x["name"]))

        for kmem_cache in target_caches:
            objsz = "{0:d} ({0:#x})".format(kmem_cache["object_size"])
            chunksz = "{0:d} ({0:#x})".format(kmem_cache["size"])
            chunk_name = kmem_cache["name"]
            address = kmem_cache["address"]
            self.out.append("{:18s} {:18s} {:{:d}s} {:#x}".format(objsz, chunksz, chunk_name, name_width, address))
        return

    def slub_tiny_walk(self, target_names):
        self.kslub_tiny = Kernel.slub_tiny()
        if self.args.rescan:
            Cache.clear_cache_for(self.kslub_tiny.initialize)

        ret = self.kslub_tiny.initialize()
        if self.args.meta or not ret:
            for func, line in Kernel.export_meta(self, self.kslub_tiny.meta):
                func(line)
        if not ret:
            self.quiet_err("Initialization failed")
            return

        if self.args.meta:
            return

        parsed_caches = self.kslub_tiny.walk_caches(
            target_names,
            names_only=self.args.list or self.args.list_no_sort,
            reverse_walk=self.args.reverse_walk,
            simple=self.args.simple,
            quiet=self.args.quiet,
            skip_page2virt=self.args.skip_page2virt,
        )
        if self.args.list or self.args.list_no_sort:
            self.dump_names(parsed_caches)
            return

        self.dump_caches(target_names, parsed_caches)
        return

    @Cache.cache_this_session
    def warmup_page2virt(self):
        if is_x86() or is_arm32():
            args = self.args # backup
            KernelSlub.warmup_page2virt()
            # self.args will be overwritten. this is workaround.
            self.args = args # revert
        return

    def get_kmem_caches(self, target_names):
        return Kernel.slub_tiny().get_kmem_caches(target_names)

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if args.hexdump_used < 0 or args.hexdump_freed < 0:
            err("Hexdump size must be >= 0")
            return
        self.quiet_info("Wait for memory scan")

        allocator = Kernel.get_slab_type()
        if allocator == "SLUB":
            self.quiet_err("Unsupported; You should use `slub-dump`")
            return
        elif allocator == "SLUB_TINY":
            pass
        elif allocator == "SLAB":
            self.quiet_err("Unsupported; You should use `slab-dump`")
            return
        elif allocator == "SLOB":
            self.quiet_err("Unsupported; You should use `slob-dump`")
            return
        else:
            self.quiet_err("Unsupported: Unknown allocator")
            return

        # The slub-tiny-dump command is used by page2virt and kmagic to find vmemmap and sizeof(struct page).
        # Therefore, slub-tiny-dump itself may be called recursively (up to once) from slub-tiny-dump.
        # If a recursive call is made, various parameters held by self will be destroyed.
        # It's very tricky, but if we make sure to call page2virt first,
        # no further calls will be made and it will work without any problems.
        if not args.skip_page2virt:
            self.warmup_page2virt()

        self.maps = None
        self.out = []
        self.slub_tiny_walk(args.cache_name)
        self.print_output()
        return



@register_command
class SlabDumpCommand(GenericCommand, BufferingOutput):
    """Dump SLAB free-list reachable from slab_caches."""

    _cmdline_ = "slab-dump"
    _category_ = "06-h. Qemu-system/KGDB Cooperation - Linux Allocator"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("cache_name", metavar="SLAB_CACHE_NAME", nargs="*", help="filter by specific slab cache name.")
    parser.add_argument("-l", "--list", action="store_true", help="list all slab cache names.")
    parser.add_argument("-L", "--list-no-sort", action="store_true", help="list all slab cache names without sort.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("--cpu", type=int, help="filter by specific cpu.")
    parser.add_argument("-R", "--reverse-walk", action="store_true", help="reverse order walk for slab_caches->list_head.")
    parser.add_argument("-s", "--simple", action="store_true", help="skip displaying layout and freelist.")
    parser.add_argument("--skip-partial", action="store_true", help="skip displaying slabs_partial.")
    parser.add_argument("--skip-full", action="store_true", help="skip displaying slabs_full.")
    parser.add_argument("--skip-free", action="store_true", help="skip displaying slabs_free.")
    parser.add_argument("--hexdump-used", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="hexdump `used chunks` if layout is resolved.")
    parser.add_argument("--hexdump-freed", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="hexdump `unused (freed) chunks` if layout is resolved.")
    parser.add_argument("--telescope-used", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="telescope `used chunks` if layout is resolved.")
    parser.add_argument("--telescope-freed", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="telescope `unused (freed) chunks` if layout is resolved.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cached offset.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} kmalloc-256          # dump kmalloc-256 from all cpus",
        "{0:s} kmalloc-256 --cpu 1  # dump kmalloc-256 from cpu 1",
        "{0:s} --list               # list slab cache names",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified SLAB structure:",
        "\n"
        "                         +-kmem_cache--+         +-kmem_cache--+   +-kmem_cache--+",
        "                         | cpu_cache   |---+     | cpu_cache   |   | cpu_cache   |",
        "                         | limit       |   |     | limit       |   | limit       |",
        "                         | size        |   |     | size        |   | size        |",
        "                         | flags       |   |     | flags       |   | flags       |",
        "                         | num         |   |     | num         |   | num         |",
        "                         | gfporder    |   |     | gfporder    |   | gfporder    |",
        "       +-slab_caches-+   | name        |   |     | name        |   | name        |",
        " ...<->| list_head   |<->| list_head   |<------->| list_head   |<->| list_head   |<-> ...",
        "       +-------------+   | object_size |   |     | object_size |   | object_size |",
        "                         | node[]      |------+  | node[]      |   | node[]      |",
        "                         +-------------+   |  |  +-------------+   +-------------+",
        "    +-__per_cpu_offset-+                   |  |",
        "    | cpu0_offset      |--+----------------+  |",
        "    | cpu1_offset      |  |                   |",
        "    | cpu2_offset      |  |                   v                  +-page/slab-+    +-page/slab-+",
        "    | ...              |  |       +-kmem_cache_node-+      +---->| slab_list |--->| slab_list |-->...",
        "    +------------------+  |       | slabs_partial   |------+     | freelist  |    | freelist  |",
        "                          |       | slabs_full      |----->...   | s_mem     |-+  | s_mem     |-+",
        "      +-------------------+       | slabs_free      |----->...   | active    | |  | active    | |",
        "      |                           +-----------------+            +-----------+ |  +-----------+ |",
        "      v                                                                        |                |",
        "    +-array_cache--------+                                         +-----------+    +-----------+",
        "    | avail              |                                         |                |",
        "    | limit              |                                         v                v",
        "    | entry[]            |                                       +-chunk--+       +-chunk--+",
        "    |   freed_chunk_ptr  |-------------------------------------->|        |       |        |",
        "    |   freed_chunk_ptr  |----------------------------+          +-chunk--+       +-chunk--+",
        "    |   freed_chunk_ptr  |                            |          |        |       |        |",
        "    |   freed_chunk_ptr  |                            |          +-chunk--+       +-chunk--+",
        "    |   freed_chunk_ptr  |                            +--------->|        |       |        |",
        "    |   ...              |                                       +-...----+       +-...----+",
        "    +--------------------+",
        "* `struct page` has been split into `struct page` and `struct slab` since kernel 5.17.",
        "  The structure name used for SLAB has been changed to `struct slab`.",
        "* Chunks in array_cache are marked as in-use, even though they are actually reusable.",
        "* SLAB was removed in kernel 6.8.",
    ]
    _note_ = "\n".join(_note_)

    def dump_page(self, page, kmem_cache, tag):
        from gef.commands.debugging.context import DereferenceCommand
        pagesize = KernelAddressHeuristicFinder.consts().PAGE_SIZE
        heap_page_color = Config.get("theme.heap_page_address")
        label_inactive_color = Config.get("theme.heap_label_inactive")
        used_address_color = Config.get("theme.heap_chunk_address_used")
        freed_address_color = Config.get("theme.heap_chunk_address_freed")

        # page address
        tag_s = Color.colorify(tag, label_inactive_color)
        self.out.append("      {:s}: {:#x}".format(tag_s, page["address"]))

        # fast return if invalid
        if not is_valid_addr(page["address"]):
            return

        # print virtual address
        colored_s_mem_base = Color.colorify_hex(page["s_mem_base"], heap_page_color)
        mask = KernelAddressHeuristicFinder.consts().PAGE_SIZE - 1
        self.out.append("        virtual address (s_mem & ~{:#x}): {:s}".format(mask, colored_s_mem_base))

        # print info
        self.out.append("        num pages: {:d}".format(kmem_cache["pagesperslab"]))

        colour_off = page["s_mem"] - page["s_mem_base"]
        self.out.append("        colour offset: {:#x}".format(colour_off))

        if self.args.simple:
            return

        # print layout
        freelist = page["freelist"]
        end_virt = page["s_mem_base"] + kmem_cache["pagesperslab"] * pagesize

        if colour_off:
            chunk_s = Color.colorify_hex(page["s_mem_base"], used_address_color)
            self.out.append("        {:7s}   ---- {:s} ({:s})".format("layout:", chunk_s, "never-used"))

        for idx, chunk in enumerate(range(page["s_mem"], end_virt, kmem_cache["size"])):
            if idx in freelist:
                idxidx = freelist.index(idx)
                if idxidx == len(freelist) - 1:
                    next_msg = "next: None"
                else:
                    next_idx = freelist[idxidx + 1]
                    next_msg = "next: {:#x}".format(next_idx)
                chunk_s = Color.colorify_hex(chunk, freed_address_color)
            elif "array_cache" in kmem_cache and chunk in kmem_cache["array_cache"]["freelist_all"]:
                next_msg = "in-use (array_cache)"
                chunk_s = Color.colorify_hex(chunk, freed_address_color)
            else:
                if kmem_cache["objperslab"] <= idx:
                    next_msg = "never-used"
                else:
                    next_msg = "in-use"
                chunk_s = Color.colorify_hex(chunk, used_address_color)
            self.out.append("        {:7s}   {:#04x} {:s} ({:s})".format(
                "layout:" if idx == 0 else "", idx, chunk_s, next_msg,
            ))

            # dump chunks
            if self.args.hexdump_used and next_msg == "in-use":
                peeked_data = read_memory(chunk, self.args.hexdump_used)
                h = hexdump(peeked_data, 0x10, base=chunk, unit=runtime.current_arch.ptrsize)
                self.out.append(h)

            if self.args.hexdump_freed and next_msg.startswith(("next: ", "in-use (array_cache)")):
                peeked_data = read_memory(chunk, self.args.hexdump_freed)
                h = hexdump(peeked_data, 0x10, base=chunk, unit=runtime.current_arch.ptrsize)
                self.out.append(h)

            if self.args.telescope_used and next_msg == "in-use":
                n = self.args.telescope_used // runtime.current_arch.ptrsize
                for i in range(n):
                    line = DereferenceCommand.pprint_dereferenced(chunk, i)
                    self.out.append(line)

            if self.args.telescope_freed and next_msg.startswith(("next: ", "in-use (array_cache)")):
                n = self.args.telescope_freed // runtime.current_arch.ptrsize
                for i in range(n):
                    line = DereferenceCommand.pprint_dereferenced(chunk, i)
                    self.out.append(line)

        # print freelist
        if freelist == []:
            self.out.append("        freelist: (none)")
        else:
            for i, idx in enumerate(freelist):
                chunk = page["s_mem"] + kmem_cache["size"] * idx
                msg = Color.colorify_hex(chunk, freed_address_color)
                self.out.append("        {:9s} {:#04x} {:s}".format("freelist:" if i == 0 else "", idx, msg))
        return

    def dump_array_cache(self, cpu, kmem_cache):
        label_active_color = Config.get("theme.heap_label_active")
        freed_address_color = Config.get("theme.heap_chunk_address_freed")

        tag_s = Color.colorify("array_cache (cpu{:d})".format(cpu), label_active_color)
        if "array_cache" not in kmem_cache:
            self.out.append("      {:s}: (none)".format(tag_s))
            return
        if "address" not in kmem_cache["array_cache"][cpu]:
            self.out.append("      {:s}: (none)".format(tag_s))
            return
        self.out.append("      {:s}: {:#x}".format(tag_s, kmem_cache["array_cache"][cpu]["address"]))

        self.out.append("        avail: {:d}".format(kmem_cache["array_cache"][cpu]["avail"]))
        self.out.append("        limit: {:d}".format(kmem_cache["array_cache"][cpu]["limit"]))

        if self.args.simple:
            return

        freelist = kmem_cache["array_cache"][cpu]["freelist"]
        if freelist == []:
            self.out.append("        entry: (none)")
        else:
            for idx, f in enumerate(freelist):
                if not is_valid_addr(f):
                    break
                msg = Color.colorify_hex(f, freed_address_color)
                self.out.append("        {:6s} {:s}".format("entry:" if idx == 0 else "", msg))
        return

    def dump_caches(self, target_names, cpus, parsed_caches):
        chunk_label_color = Config.get("theme.heap_chunk_label")
        chunk_size_color = Config.get("theme.heap_chunk_size")
        label_inactive_color = Config.get("theme.heap_label_inactive")

        self.out.append("slab_caches @ {:#x}".format(self.kslab.slab_caches))
        for kmem_cache in parsed_caches[1:]:
            if target_names != [] and kmem_cache["name"] not in target_names:
                continue

            # dump kmem_cache metadata
            self.out.append("")
            self.out.append("  kmem_cache: {:#x}".format(kmem_cache["address"]))
            self.out.append("    name: {:s}".format(Color.colorify(kmem_cache["name"], chunk_label_color)))
            flags_str = kmem_cache["flags_str"]
            self.out.append("    flags: {:#x}{:s}".format(
                kmem_cache["flags"], " ({:s})".format(flags_str) if flags_str is not None else "",
            ))
            object_size_s = Color.colorify_hex(kmem_cache["object_size"], chunk_size_color)
            self.out.append("    object size: {:s} (chunk size: {:#x})".format(object_size_s, kmem_cache["size"]))
            self.out.append("    object per slab: {:#x}".format(kmem_cache["objperslab"]))
            self.out.append("    pages per slab: {:#x}".format(kmem_cache["pagesperslab"]))

            # dump array_cache
            for cpu in cpus:
                self.dump_array_cache(cpu, kmem_cache)

            # dump nodes
            if len(kmem_cache["nodes"]) == 0:
                self.out.append("      {:s}: (none)".format(Color.colorify("node pages", label_inactive_color)))
            else:
                for node_index, slabs_list in enumerate(kmem_cache["nodes"]):
                    node_addr = kmem_cache["node_addresses"][node_index]
                    node_id = kmem_cache["node_ids"][node_index]
                    self.out.append("    kmem_cache_node[{:d}]: {:#x}".format(node_id, node_addr))

                    if not self.args.skip_partial and "slabs_partial" in slabs_list:
                        if len(slabs_list["slabs_partial"]) == 0:
                            tag = Color.colorify("node[{:d}].slabs_partial".format(node_id), label_inactive_color)
                            self.out.append("      {:s}: (none)".format(tag))
                        else:
                            for node_page in slabs_list["slabs_partial"]:
                                self.dump_page(node_page, kmem_cache, tag="node[{:d}].slabs_partial".format(node_id))

                    if not self.args.skip_full and "slabs_full" in slabs_list:
                        if len(slabs_list["slabs_full"]) == 0:
                            tag = Color.colorify("node[{:d}].slabs_full".format(node_id), label_inactive_color)
                            self.out.append("      {:s}: (none)".format(tag))
                        else:
                            for node_page in slabs_list["slabs_full"]:
                                self.dump_page(node_page, kmem_cache, tag="node[{:d}].slabs_full".format(node_id))

                    if not self.args.skip_free and "slabs_free" in slabs_list:
                        if len(slabs_list["slabs_free"]) == 0:
                            tag = Color.colorify("node[{:d}].slabs_free".format(node_id), label_inactive_color)
                            self.out.append("      {:s}: (none)".format(tag))
                        else:
                            for node_page in slabs_list["slabs_free"]:
                                self.dump_page(node_page, kmem_cache, tag="node[{:d}].slabs_free".format(node_id))

            self.out.append("    next: {:#x}".format(kmem_cache["next"]))
        return

    def dump_names(self, parsed_caches):
        name_width = max((len(k["name"]) for k in parsed_caches[1:]), default=4)

        if not self.args.quiet:
            fmt = "{:<18s} {:<18s} {:" + str(name_width) + "s} {:20s}"
            legend = ["Object Size", "Chunk Size", "Name", "kmem_cache"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        if self.args.list_no_sort:
            target_caches = parsed_caches[1:]
        else:
            target_caches = sorted(parsed_caches[1:], key=lambda x: (x["object_size"], x["size"], x["name"]))

        for kmem_cache in target_caches:
            objsz = "{0:d} ({0:#x})".format(kmem_cache["object_size"])
            chunksz = "{0:d} ({0:#x})".format(kmem_cache["size"])
            chunk_name = kmem_cache["name"]
            address = kmem_cache["address"]
            self.out.append("{:18s} {:18s} {:{:d}s} {:#x}".format(objsz, chunksz, chunk_name, name_width, address))
        return

    def slabwalk(self, target_names, cpu):
        self.kslab = Kernel.slab()
        if self.args.rescan:
            Cache.clear_cache_for(self.kslab.initialize)

        ret = self.kslab.initialize()
        if self.args.meta or not ret:
            for func, line in Kernel.export_meta(self, self.kslab.meta):
                func(line)
        if not ret:
            self.quiet_err("Initialization failed")
            return

        if self.args.meta:
            return

        if self.args.list or self.args.list_no_sort:
            target_cpus = None
        elif cpu is None:
            target_cpus = list(range(self.kslab.ncpus))
        else:
            if not 0 <= cpu < self.kslab.ncpus:
                self.quiet_err("CPU number is invalid (valid range: {:d}-{:d})".format(0, self.kslab.ncpus - 1))
                return
            target_cpus = [cpu]

        parsed_caches = self.kslab.walk_caches(
            target_names, target_cpus,
            names_only=self.args.list or self.args.list_no_sort,
            reverse_walk=self.args.reverse_walk,
            simple=self.args.simple,
            quiet=self.args.quiet,
        )
        if self.args.list or self.args.list_no_sort:
            self.dump_names(parsed_caches)
            return

        self.dump_caches(target_names, target_cpus, parsed_caches)
        return

    def get_kmem_caches(self, target_names):
        return Kernel.slab().get_kmem_caches(target_names)

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if args.hexdump_used < 0 or args.hexdump_freed < 0:
            err("Hexdump size must be >= 0")
            return
        self.quiet_info("Wait for memory scan")

        allocator = Kernel.get_slab_type()
        if allocator == "SLUB":
            self.quiet_err("Unsupported; You should use `slub-dump`")
            return
        elif allocator == "SLUB_TINY":
            self.quiet_err("Unsupported; You should use `slub-tiny-dump`")
            return
        elif allocator == "SLAB":
            pass
        elif allocator == "SLOB":
            self.quiet_err("Unsupported; You should use `slob-dump`")
            return
        else:
            self.quiet_err("Unsupported: Unknown allocator")
            return

        self.maps = None
        self.out = []
        self.slabwalk(args.cache_name, args.cpu)
        self.print_output()
        return



@register_command
class SlobDumpCommand(GenericCommand, BufferingOutput):
    """Dump SLOB free-list reachable from slab_caches."""

    _cmdline_ = "slob-dump"
    _category_ = "06-h. Qemu-system/KGDB Cooperation - Linux Allocator"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("cache_name", metavar="SLOB_CACHE_NAME", nargs="*",
                        help="filter by specific slob cache name (need -v option).")
    parser.add_argument("-l", "--list", action="store_true", help="list all slob cache names.")
    parser.add_argument("-L", "--list-no-sort", action="store_true", help="list all slob cache names without sort.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-R", "--reverse-walk", action="store_true", help="reverse order walk for slab_caches->list_head.")
    parser.add_argument("-s", "--simple", action="store_true", help="skip showing freelist.")
    parser.add_argument("--large", action="store_true", help="display only free_slob_large.")
    parser.add_argument("--medium", action="store_true", help="display only free_slob_medium.")
    parser.add_argument("--small", action="store_true", help="display only free_slob_small.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cached offset.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode (print kmem_cache).")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} kmalloc-256  # dump kmalloc-256 kmem_cache and all freelists",
        "{0:s} --list       # list slob cache names",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified SLOB structure:",
        "",
        "                         +-kmem_cache--+   +-kmem_cache--+   +-kmem_cache--+",
        "                         | object_size |   | object_size |   | object_size |",
        "                         | size        |   | size        |   | size        |",
        "                         | flags       |   | flags       |   | flags       |",
        "       +-slab_caches-+   | name        |   | name        |   | name        |",
        " ...<->| list_head   |<->| list_head   |<->| list_head   |<->| list_head   |<-> ...",
        "       +-------------+   +-------------+   +-------------+   +-------------+",
        "* slab_caches is not used when traversing the freelist",
        "",
        "   +-free_slob_large--+              +-page/slab-----+           +-page/slab-----+",
        "   | list_head        |<---------+   | freelist      |-----+     | freelist      |",
        "   +-free_slob_medium-+          |   | units (total) |     |     | units (total) |",
        "   | list_head        |-->...    +-->| list_head     |<----|---->| list_head     |<->...",
        "   +-free_slob_small--+              +---------------+     |     +---------------+",
        "   | list_head        |-->...                              |",
        "   +------------------+                      +-------------+",
        "   small : size < 0x100                      |",
        "   medium: 0x100 <= size < 0x400             |   +-chunk-----+   +-chunk-----+",
        "   large : 0x400 <= size < 0x1000            +-->| units     |-->| -offset   |-->...",
        "* size is only judged when first inserted,       | offset    |   +-----------+",
        "  so divided remainder is stay on.               +-----------+   (when units=1, stored negative offset)",
        "",
        "* `struct page` has been split into `struct page` and `struct slab` since kernel 5.17.",
        "  The structure name used for SLOB has been changed to `struct slab`.",
        "* SLOB was removed in kernel 6.4.",
    ]
    _note_ = "\n".join(_note_)

    def dump_freelist(self, tag, page_freelist):
        pagesize = KernelAddressHeuristicFinder.consts().PAGE_SIZE
        chunk_size_color = Config.get("theme.heap_chunk_size")
        label_active_color = Config.get("theme.heap_label_active")
        heap_page_color = Config.get("theme.heap_page_address")
        freed_address_color = Config.get("theme.heap_chunk_address_freed")

        self.out.append(titlify("{:s} @ {:#x}".format(tag, getattr(self.kslob, tag))))

        for page in page_freelist:
            self.out.append("  {:s}: {:#x}".format(Color.colorify("page", label_active_color), page["address"]))
            colored_virt_addr = Color.colorify_hex(page["virt_addr"], heap_page_color)
            self.out.append("    virtual address: {:s}".format(colored_virt_addr))
            self.out.append("    num pages: {:d}".format(page["num_pages"]))
            self.out.append("    total units: {:#x}".format(page["units"]))
            for i, (chunk, units) in enumerate(page["freelist"]):
                self.out.append("    {:9s} {:s} (units: {:#x}, size: {:s})".format(
                    "freelist:" if i == 0 else "",
                    Color.colorify_hex(chunk, freed_address_color),
                    units,
                    Color.colorify_hex(units * (2 if pagesize <= 32767 else 4),
                                      chunk_size_color),
                ))
            self.out.append("    next: {:#x}".format(page["next"]))
            self.out.append("")
        return

    def dump_caches(self, target_names, parsed_caches, parsed_freelist):
        chunk_label_color = Config.get("theme.heap_chunk_label")
        chunk_size_color = Config.get("theme.heap_chunk_size")

        if self.args.verbose:
            self.out.append(titlify("{:s} @ {:#x}".format("slab_caches", self.kslob.slab_caches)))
            for kmem_cache in parsed_caches[1:]:
                if target_names != [] and kmem_cache["name"] not in target_names:
                    continue
                self.out.append("  kmem_cache: {:#x}".format(kmem_cache["address"]))
                colored_name = Color.colorify(kmem_cache["name"], chunk_label_color)
                self.out.append("    name: {:s}".format(colored_name))
                flags_str = kmem_cache["flags_str"]
                self.out.append("    flags: {:#x}{:s}".format(
                    kmem_cache["flags"], " ({:s})".format(flags_str) if flags_str is not None else "",
                ))
                object_size_s = Color.colorify_hex(kmem_cache["object_size"], chunk_size_color)
                self.out.append("    object size: {:s} (chunk size: {:#x})".format(object_size_s, kmem_cache["size"]))
                self.out.append("    next: {:#x}".format(kmem_cache["next"]))
                self.out.append("")

        if self.args.large:
            self.dump_freelist("free_slob_large", parsed_freelist["large"])
        if self.args.medium:
            self.dump_freelist("free_slob_medium", parsed_freelist["medium"])
        if self.args.small:
            self.dump_freelist("free_slob_small", parsed_freelist["small"])
        return

    def dump_names(self, parsed_caches):
        name_width = max((len(k["name"]) for k in parsed_caches[1:]), default=4)

        if not self.args.quiet:
            fmt = "{:<18s} {:<18s} {:" + str(name_width) + "s} {:20s}"
            legend = ["Object Size", "Chunk Size", "Name", "kmem_cache"]
            self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        if self.args.list_no_sort:
            target_caches = parsed_caches[1:]
        else:
            target_caches = sorted(parsed_caches[1:], key=lambda x: (x["object_size"], x["size"], x["name"]))

        for kmem_cache in target_caches:
            objsz = "{0:d} ({0:#x})".format(kmem_cache["object_size"])
            chunksz = "{0:d} ({0:#x})".format(kmem_cache["size"])
            chunk_name = kmem_cache["name"]
            address = kmem_cache["address"]
            self.out.append("{:18s} {:18s} {:{:d}s} {:#x}".format(objsz, chunksz, chunk_name, name_width, address))
        return

    def slobwalk(self, target_names):
        self.kslob = Kernel.slob()
        if self.args.rescan:
            Cache.clear_cache_for(self.kslob.initialize)

        ret = self.kslob.initialize()
        if self.args.meta or not ret:
            for func, line in Kernel.export_meta(self, self.kslob.meta):
                func(line)
        if not ret:
            self.quiet_err("Initialization failed")
            return

        if self.args.meta:
            return

        parsed_caches, parsed_freelist = self.kslob.walk_caches(
            target_names,
            names_only=self.args.list or self.args.list_no_sort,
            reverse_walk=self.args.reverse_walk,
            simple=self.args.simple,
            large=self.args.large,
            medium=self.args.medium,
            small=self.args.small,
        )
        if self.args.list or self.args.list_no_sort:
            self.dump_names(parsed_caches)
            return

        self.dump_caches(target_names, parsed_caches, parsed_freelist)
        return

    def get_kmem_caches(self, target_names):
        return Kernel.slob().get_kmem_caches(target_names)

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        allocator = Kernel.get_slab_type()
        if allocator == "SLUB":
            self.quiet_err("Unsupported; You should use `slub-dump`")
            return
        elif allocator == "SLUB_TINY":
            self.quiet_err("Unsupported; You should use `slub-tiny-dump`")
            return
        elif allocator == "SLAB":
            self.quiet_err("Unsupported; You should use `slab-dump`")
            return
        elif allocator == "SLOB":
            pass
        else:
            self.quiet_err("Unsupported: Unknown allocator")
            return

        if (args.large, args.medium, args.small) == (False, False, False):
            self.args.large = True
            self.args.medium = True
            self.args.small = True

        self.maps = None
        self.out = []
        self.slobwalk(args.cache_name)
        self.print_output()
        return



@register_command
class SlabContainsCommand(GenericCommand):
    """Resolve the slab cache (kmem_cache) that an object belongs to (for slab/slub/slub-tiny)."""

    _cmdline_ = "slab-contains"
    _category_ = "06-h. Qemu-system/KGDB Cooperation - Linux Allocator"
    _aliases_ = ["xslab"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address, help="target address.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Simplified page/slab structure:",
        "",
        "+-kmem_cache-+",
        "| cpu_slab   |--->+-kmem_cache_cpu-+",
        "| ...        |    | page/slab      |--+",
        "+------------+    | freelist       |  |",
        "      ^           +----------------+  |   <---virt/page translate--->",
        "      |                               v",
        "      |                         +-page/slab---+               +-0x1000-page-+ <--base (named by GEF)",
        "      +-------------------------|  slab_cache |               | chunk       |",
        "      |                         +-page/slab---+               | ...         |",
        "      +-------------------------|  slab_cache |               +-0x1000-page-+",
        "      |                         +-page/slab---+               | chunk       |",
        "      +-------------------------|  slab_cache |               | chunk       | <--user specified address",
        "                                +-------------+               | ...         |",
        "                                                              +-0x1000-page-+",
        "                                                              | chunk       |",
        "                                                              | ...         |",
        "                                                              +-------------+",
        "* Compound pages and huge pages are not supported.",
    ]
    _note_ = "\n".join(_note_)

    @Cache.cache_this_session(cache_None=False)
    def initialize(self, allocator):
        if allocator == "SLAB" and Kernel.version() < "3.13":
            return Kernel.slab().initialize()
        if is_kgdb() and allocator in ("SLAB", "SLUB_TINY"):
            if allocator == "SLAB":
                resolver = Kernel.slab()
            else:
                resolver = Kernel.slub_tiny()
            if not resolver.initialize():
                return None
            if allocator == "SLAB":
                prefix = "page"
            else:
                prefix = "slab"
            self.page_offset_slab_cache = getattr(resolver, prefix + "_offset_slab_cache")
            self.page_offset_next = getattr(resolver, prefix + "_offset_next")
            self.kmem_cache_offset_name = resolver.kmem_cache_offset_name
            self.kmem_cache_offset_size = resolver.kmem_cache_offset_size
            self.kmem_cache_offset_object_size = resolver.kmem_cache_offset_object_size
            self.slab_virtual_enabled = False
            if allocator == "SLAB":
                self.page_offset_s_mem = resolver.page_offset_s_mem
                self.kmem_cache_offset_gfporder = resolver.kmem_cache_offset_gfporder
                self.kmem_cache_offset_num = resolver.kmem_cache_offset_num
            else:
                self.kmem_cache_offset_red_left_pad = resolver.kmem_cache_offset_red_left_pad
                self.page_offset_inuse_objects_frozen = resolver.slab_offset_inuse_objects_frozen
            return True
        cmd = {"SLUB": "slub-dump", "SLAB": "slab-dump", "SLUB_TINY": "slub-tiny-dump"}[allocator]
        res = gdb.execute("{:s} --meta".format(cmd), to_string=True)

        r = re.search(r"offsetof\((?:page|slab), slab_cache\): (0x\S+)", res)
        if not r:
            return None
        self.page_offset_slab_cache = int(r.group(1), 16)

        r = re.search(r"offsetof\((?:page|slab), next\): (0x\S+)", res)
        if not r:
            return None
        self.page_offset_next = int(r.group(1), 16)

        r = re.search(r"offsetof\(kmem_cache, name\): (0x\S+)", res)
        if not r:
            return None
        self.kmem_cache_offset_name = int(r.group(1), 16)

        r = re.search(r"offsetof\(kmem_cache, size\): (0x\S+)", res)
        if not r:
            return None
        self.kmem_cache_offset_size = int(r.group(1), 16)

        r = re.search(r"offsetof\(kmem_cache, object_size\): (0x\S+)", res)
        if not r:
            return None
        self.kmem_cache_offset_object_size = int(r.group(1), 16)

        # for aligned check
        if allocator in ["SLUB", "SLUB_TINY"]:
            r = re.search(r"offsetof\(kmem_cache, red_left_pad\): (0x\S+)", res)
            if not r:
                return None
            self.kmem_cache_offset_red_left_pad = int(r.group(1), 16)

        if allocator == "SLAB":
            r = re.search(r"offsetof\((?:page|slab), s_mem\): (0x\S+)", res)
            if not r:
                return None
            self.page_offset_s_mem = int(r.group(1), 16)

        # for slab-virtual
        self.slab_virtual_enabled = False
        if is_x86_64():
            r = re.search(r"offsetof\(kmem_cache, freed_slabs_min\): (0x\S+)", res)
            if r:
                self.slab_virtual_enabled = True
                self.kmem_cache_offset_freed_slabs_min = int(r.group(1), 16)

        # for num of pages
        if allocator in ["SLUB", "SLUB_TINY"]:
            r = re.search(r"offsetof\((?:page|slab), inuse_objects_frozen\): (0x\S+)", res)
            if not r:
                return None
            self.page_offset_inuse_objects_frozen = int(r.group(1), 16)

        elif allocator == "SLAB":
            r = re.search(r"offsetof\(kmem_cache, gfporder\): (0x\S+)", res)
            if not r:
                return None
            self.kmem_cache_offset_gfporder = int(r.group(1), 16)
            r = re.search(r"offsetof\(kmem_cache, num\): (0x\S+)", res)
            if not r:
                return None
            self.kmem_cache_offset_num = int(r.group(1), 16)
        return True

    def print_meta(self):
        if self.allocator == "SLAB" and Kernel.version() < "3.13":
            for func, line in Kernel.export_meta(self, Kernel.slab().meta):
                func(line)
            return
        info("offsetof({:s}, slab_cache): {:#x}".format(Kernel.slab_page_str(), self.page_offset_slab_cache))
        info("offsetof({:s}, next): {:#x}".format(Kernel.slab_page_str(), self.page_offset_next))
        info("offsetof(kmem_cache, name): {:#x}".format(self.kmem_cache_offset_name))
        info("offsetof(kmem_cache, size): {:#x}".format(self.kmem_cache_offset_size))
        info("offsetof(kmem_cache, object_size): {:#x}".format(self.kmem_cache_offset_object_size))
        if self.allocator in ["SLUB", "SLUB_TINY"]:
            info("offsetof(kmem_cache, red_left_pad): {:#x}".format(self.kmem_cache_offset_red_left_pad))
        if self.allocator == "SLAB":
            info("offsetof({:s}, s_mem): {:#x}".format(Kernel.slab_page_str(), self.page_offset_s_mem))
        if self.slab_virtual_enabled:
            info("offsetof(kmem_cache, freed_slabs_min): {:#x}".format(self.kmem_cache_offset_freed_slabs_min))
        if self.allocator in ["SLUB", "SLUB_TINY"]:
            info("offsetof({:s}, inuse_objects_frozen): {:#x}".format(Kernel.slab_page_str(), self.page_offset_inuse_objects_frozen))
        elif self.allocator == "SLAB":
            info("offsetof(kmem_cache, gfporder): {:#x}".format(self.kmem_cache_offset_gfporder))
        return

    def virt2page_wrapper(self, vaddr):
        if self.slab_virtual_enabled:
            ret = gdb.execute("slab-virtual --quiet from_virt {:#x}".format(vaddr), to_string=True)
            r = re.search(r"Slab: (\S+)", ret)
        else:
            ret = gdb.execute("virt2page {:#x}".format(vaddr), to_string=True)
            r = re.search(r"Page: (\S+)", ret)

        if r:
            return int(r.group(1), 16)
        return None

    @staticmethod
    def is_freed(object_base, slab_cache_name):
        """Return True if `object_base` is in a freelist of the cache, or None if the cache cannot be parsed."""
        allocator, kmem_caches = Kernel.get_slab_caches([slab_cache_name])
        if not kmem_caches:
            return None
        kmem_cache = kmem_caches[0]
        freed_addresses = []
        if allocator == "SLUB":
            for kmem_cache_cpu in kmem_cache.get("kmem_cache_cpu", {}).values():
                freed_addresses += kmem_cache_cpu["freelist"]
                freed_addresses += kmem_cache_cpu.get("active_page", {}).get("freelist", [])
                for page in kmem_cache_cpu.get("partial_pages", []):
                    freed_addresses += page.get("freelist", [])
            for page_list in kmem_cache.get("nodes_partial", []) + kmem_cache.get("nodes_full", []):
                for page in page_list:
                    freed_addresses += page.get("freelist", [])
            freed_addresses += KernelSlub.get_sheaf_objects(kmem_cache)
        elif allocator == "SLUB_TINY":
            for page_list in kmem_cache["nodes"]:
                for page in page_list:
                    freed_addresses += page.get("freelist", [])
        elif allocator == "SLAB":
            freed_addresses += kmem_cache["array_cache"]["freelist_all"]
            for slabs_list in kmem_cache["nodes"]:
                for page_list in slabs_list.values():
                    for page in page_list:
                        freed_addresses += [page["s_mem"] + kmem_cache["size"] * idx for idx in page.get("freelist", [])]
        return object_base in freed_addresses

    def get_slab_object(self, address):
        """Return the dict of the slab object that contains `address`.
        `error` is set if it is not resolved, and the other members are set as far as they are resolved."""
        pagesize = KernelAddressHeuristicFinder.consts().PAGE_SIZE
        allocator = Kernel.get_slab_type()
        if allocator == "SLAB" and Kernel.version() < "3.13":
            return Kernel.slab().get_legacy_slab_object(address)
        obj = {"pages": [], "error": None}
        if not self.initialize(allocator):
            obj["error"] = "Failed to initialize"
            return obj

        current = address & -pagesize
        try:
            while True:
                page = self.virt2page_wrapper(current)
                if page is None:
                    obj["error"] = "Invalid address"
                    return obj

                obj["pages"].append(page)

                page_next = read_int_from_memory(page + self.page_offset_next)
                if page_next & 1:
                    current -= pagesize
                    continue

                kmem_cache = read_int_from_memory(page + self.page_offset_slab_cache)
                if kmem_cache == 0:
                    obj["error"] = "This address is not managed by slab (kmem_cache=0)"
                    return obj

                if (kmem_cache & -pagesize) == 0xdead_0000_0000_0000:
                    current -= pagesize
                    continue

                if kmem_cache & 1:
                    current -= pagesize
                    continue

                obj["kmem_cache"] = kmem_cache
                obj["base"] = current
                break
        except (gdb.MemoryError, ZeroDivisionError):
            obj["error"] = "Memory read error"
            return obj

        try:
            slab_cache_name_ptr = read_int_from_memory(kmem_cache + self.kmem_cache_offset_name)
            slab_cache_name = read_cstring_from_memory(slab_cache_name_ptr)
            if slab_cache_name is None:
                obj["error"] = 'This address is not managed by slab (slab_cache_name="")'
                return obj

            slab_cache_size = read_int32_from_memory(kmem_cache + self.kmem_cache_offset_size)
            slab_cache_object_size = read_int32_from_memory(kmem_cache + self.kmem_cache_offset_object_size)

            if allocator in ["SLUB", "SLUB_TINY"]:
                red_left_pad = read_int32_from_memory(kmem_cache + self.kmem_cache_offset_red_left_pad)
                color_offset = 0
                x = read_int_from_memory(page + self.page_offset_inuse_objects_frozen)
                objects = (x >> 16) & 0x7fff
                pages_needed = (slab_cache_size * objects + (pagesize - 1)) // pagesize
                # Round the required page count up to 2^n.
                if pages_needed:
                    num_pages = 1 << (pages_needed - 1).bit_length()
                else:
                    num_pages = 0
            else:
                red_left_pad = 0
                s_mem = read_int_from_memory(page + self.page_offset_s_mem)
                color_offset = s_mem & (pagesize - 1)
                gfporder = read_int32_from_memory(kmem_cache + self.kmem_cache_offset_gfporder)
                num_pages = 1 << gfporder
                objects = read_int32_from_memory(kmem_cache + self.kmem_cache_offset_num)

            # `inuse` is not resolved because it is not a reliable reference value.
            # The value of `slab->inuse` also includes the number of chunks registered in `kmem_cache_cpu->freelist` etc.
            # However, what the user actually wants is the number of chunks that are truly in use,
            # excluding those accounted for by `kmem_cache_cpu->freelist`.
            # Accurately deriving that value is non-trivial.
            obj["name"] = slab_cache_name
            obj["object_size"] = slab_cache_object_size
            obj["chunk_size"] = slab_cache_size
            obj["num_pages"] = num_pages

            first_object = current + red_left_pad + color_offset
            delta = address - first_object
            if delta < 0 or delta >= objects * slab_cache_size:
                obj["object_base"] = None
                obj["offset"] = None
                if delta < 0:
                    obj["error"] = "before first object"
                else:
                    obj["error"] = "after last object (slab padding)"
            else:
                obj["object_base"] = first_object + (delta // slab_cache_size) * slab_cache_size
                obj["offset"] = delta % slab_cache_size
        except (gdb.MemoryError, ZeroDivisionError):
            obj["error"] = "Memory read error"
        return obj

    def slab_contains(self):
        chunk_label_color = Config.get("theme.heap_chunk_label")
        chunk_size_color = Config.get("theme.heap_chunk_size")

        obj = self.get_slab_object(self.args.address)
        for page in obj["pages"]:
            self.quiet_print("{:s}: {:#x}".format(Kernel.slab_page_str(), page))
        if "kmem_cache" in obj:
            self.quiet_print("kmem_cache: {:#x}".format(obj["kmem_cache"]))
            self.quiet_print("base: {:#x}".format(obj["base"]))
        if "name" in obj:
            gef_print("name: {:s}  object_size: {:s} (chunk_size: {:#x})  num_pages: {:#x}".format(
                Color.colorify(obj["name"], chunk_label_color),
                Color.colorify_hex(obj["object_size"], chunk_size_color),
                obj["chunk_size"], obj["num_pages"],
            ))
            if obj["object_base"] is None:
                gef_print("remarks: {:s}".format(Color.redify(obj["error"])))
                return
            self.quiet_print("object_base: {:#x}".format(obj["object_base"]))
            if obj["offset"] != 0:
                gef_print("remarks: {:s} (offset: +{:#x})".format(Color.redify("unaligned"), obj["offset"]))
        if obj["error"]:
            self.quiet_err(obj["error"])
            return

        # resolve freelist and print chunk status (in-use or freed)
        freed = self.is_freed(obj["object_base"], obj["name"])
        if freed:
            self.quiet_print("status: {:s} (found object base in freelist)".format(
                Color.colorify("freed", Config.get("theme.heap_chunk_address_freed")),
            ))
        elif freed is not None:
            self.quiet_print("status: {:s} (not found object base in freelist)".format(
                Color.colorify("in-use", Config.get("theme.heap_chunk_address_used")),
            ))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        if args.rescan:
            Cache.clear_cache_for(self.initialize)

        self.allocator = Kernel.get_slab_type()
        if self.allocator not in ["SLUB", "SLUB_TINY", "SLAB"]:
            self.quiet_err("Unsupported: SLOB, Unknown allocator")
            return

        if not self.initialize(self.allocator):
            self.quiet_err("Failed to initialize")
            return

        if args.meta:
            self.print_meta()

        self.slab_contains()
        return



@register_command
class KmemCacheAliasCommand(GenericCommand, BufferingOutput):
    """Resolve the slab cache (kmem_cache) alias."""

    _cmdline_ = "kmem-cache-alias"
    _category_ = "06-h. Qemu-system/KGDB Cooperation - Linux Allocator"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("names", nargs="*", help="filter by specific cache name(s) (substring match).")
    parser.add_argument("-s", "--sort-by-size", action="store_true", help="sort by object size.")
    parser.add_argument("-m", "--merged-only", action="store_true",
                        help="show only merged caches grouped by physical cache.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command requires CONFIG_SYSFS=y.",
        "CONFIG_SLUB_TINY=y is unsupported because slab sysfs is unavailable.",
    ]
    _note_ = "\n".join(_note_)

    @Cache.cache_this_session(cache_None=False)
    def initialize(self):
        self.meta = []

        self.slab_kset = KernelAddressHeuristicFinder.get_slab_kset()
        if self.slab_kset is None:
            self.meta.append((self.quiet_err, "Could not find slab_kset"))
            return None
        self.meta.append((self.quiet_info, "slab_kset: {:#x}".format(self.slab_kset)))

        """
        struct kset {
            struct list_head list;
            spinlock_t list_lock;
            struct kobject {
                const char *name; // -> "slab"
                struct list_head entry;
                struct kobject *parent;
                struct kset *kset;
                const struct kobj_type *ktype;
                struct kernfs_node *sd;
                ...
            } kobj;
            const struct kset_uevent_ops *uevent_ops;
        } __randomize_layout;
        """
        kset = read_int_from_memory(self.slab_kset)
        for i in range(0x10):
            if not is_valid_addr(kset + runtime.current_arch.ptrsize * i):
                continue
            name_ptr = read_int_from_memory(kset + runtime.current_arch.ptrsize * i)
            name = read_cstring_from_memory(name_ptr)
            if name != "slab":
                continue
            if not is_double_link_list(kset + runtime.current_arch.ptrsize * (i + 1)):
                continue
            # found
            self.offset_kobj_sd = runtime.current_arch.ptrsize * (i + 6)
            self.meta.append((self.quiet_info, "offsetof(kset, kobj.sd): {:#x}".format(self.offset_kobj_sd)))
            break
        else:
            self.meta.append((self.quiet_err, "Could not find offsetof(kset, kobj.sd)"))
            return None

        """
        struct kernfs_node {
            atomic_t count;
            atomic_t active;
        #ifdef CONFIG_DEBUG_LOCK_ALLOC
            struct lockdep_map dep_map;
        #endif
            struct kernfs_node __rcu *__parent;
            const char __rcu *name;
            struct rb_node {
                unsigned long __rb_parent_color;
                struct rb_node *rb_right;
                struct rb_node *rb_left;
            } __attribute__((aligned(sizeof(long)))) rb;
            const void *ns;
            unsigned int hash;
            unsigned short flags; // v6.9~
            umode_t mode; // unsigned short, v6.9~
            union {
                struct kernfs_elem_dir {
                    unsigned long subdirs;
                    struct rb_root children;
                    struct kernfs_root *root;
                } dir;
                struct kernfs_elem_symlink {
                    struct kernfs_node *target_kn;
                } symlink;
                struct kernfs_elem_attr attr;
            };
            u64 id;
            void *priv;
            struct kernfs_iattrs *iattr;
            struct rcu_head rcu;
        };
        """

        sd = read_int_from_memory(kset + self.offset_kobj_sd)
        for i in range(0x20):
            if not is_valid_addr(sd + runtime.current_arch.ptrsize * i):
                continue
            name_ptr = read_int_from_memory(sd + runtime.current_arch.ptrsize * i)
            name = read_cstring_from_memory(name_ptr)
            if name != "slab":
                continue
            # found
            self.offset_name = runtime.current_arch.ptrsize * i
            self.offset_rb = self.offset_name + runtime.current_arch.ptrsize
            self.offset_union = self.offset_rb + runtime.current_arch.ptrsize * 5
            subdirs = read_int_from_memory(sd + self.offset_union)
            if subdirs == 0 or subdirs > 0x1000:
                # subdirs should be small positive number (~0x200), at most, it should not be 0x1000.
                # so there exists padding or flags||mode if not.
                self.offset_union += runtime.current_arch.ptrsize
            self.offset_dir_children = self.offset_union + runtime.current_arch.ptrsize
            self.offset_symlink_target_kn = self.offset_union
            self.meta.append((self.quiet_info, "offsetof(kernfs_node, name): {:#x}".format(self.offset_name)))
            self.meta.append((self.quiet_info, "offsetof(kernfs_node, rb): {:#x}".format(self.offset_rb)))
            self.meta.append((self.quiet_info, "offsetof(kernfs_node, dir.children): {:#x}".format(self.offset_dir_children)))
            self.meta.append((self.quiet_info, "offsetof(kernfs_node, symlink.target_kn): {:#x}".format(self.offset_symlink_target_kn)))
            break
        else:
            self.meta.append((self.quiet_err, "Could not find offsetof(kernfs_node, name)"))
            return None

        return True

    def get_alias_groups(self):
        self.args = self.parser.parse_args(["--quiet"])
        kversion = Kernel.version()
        if kversion is None or kversion < "3.14":
            return None
        self.allocator = Kernel.get_slab_type()
        if self.allocator != "SLUB" or not self.initialize():
            return None
        return self.parse_kmem_cache_alias()

    def parse_kmem_cache_alias(self):
        # get children_root
        kset = read_int_from_memory(self.slab_kset)
        sd = read_int_from_memory(kset + self.offset_kobj_sd)

        # parse
        alias_groups = {}
        nodes = KernelRBTree(sd + self.offset_dir_children).parse()
        for node in nodes:
            node = node - self.offset_rb
            name_ptr = read_int_from_memory(node + self.offset_name)
            name = read_cstring_from_memory(name_ptr)

            target_kn = read_int_from_memory(node + self.offset_symlink_target_kn)
            alias = "-"
            if is_valid_addr(target_kn):
                alias_ptr = read_int_from_memory(target_kn + self.offset_name)
                alias = read_cstring_from_memory(alias_ptr)
            # rare case: L2TP!IPv6 -> L2TP/IPv6
            if "!" in name:
                name = name.replace("!", "/")
            alias_groups[name] = {
                "alias": alias,
                "slab_cache_name": None,
                "name": name,
                "object_size": 0,
                "chunk_size": 0,
                "kmem_cache": None,
                "unresolved": False,
            }

        def add_unresolved_cache(name, object_size, chunk_size, kmem_cache):
            unresolved_key = "{:s}@{:#x}".format(name, kmem_cache)
            alias_groups[unresolved_key] = {
                "alias": "<UNRESOLVED>",
                "slab_cache_name": name,
                "name": name,
                "object_size": object_size,
                "chunk_size": chunk_size,
                "kmem_cache": kmem_cache,
                "unresolved": True,
            }
            return

        # parse slub-dump
        cmd = {"SLUB": "slub-dump", "SLUB_TINY": "slub-tiny-dump"}[self.allocator]
        res = Color.remove_color(gdb.execute("{:s} --list --no-pager --quiet".format(cmd), to_string=True))
        used_names = []
        for line in res.splitlines():
            r = re.search(r"(\d+)\s+\(0x\S+\)\s+(\d+)\s+\(0x\S+\)\s+(\S+)\s+(0x\S+)$", line)
            if r is None:
                continue
            object_size = int(r.group(1))
            chunk_size = int(r.group(2))
            name = r.group(3)
            kmem_cache = int(r.group(4), 16)
            used_names.append([object_size, chunk_size, name, kmem_cache])

        # identify the actual slab_cache name in use
        for object_size, chunk_size, slab_cache_name, kmem_cache in used_names:
            original_slab_cache_name = slab_cache_name

            # In older kernels, the slab_cache name may include the process name,
            # such as "kmalloc-512(342:serial-getty@ttyAMA0.service)".
            # To support this, anything after the parentheses is ignored.
            if slab_cache_name not in alias_groups:
                if "(" in slab_cache_name:
                    slab_cache_name = slab_cache_name[:slab_cache_name.find("(")]

            # skip if not found
            if slab_cache_name not in alias_groups:
                self.quiet_err("Could not find key: {:s}".format(original_slab_cache_name))
                add_unresolved_cache(original_slab_cache_name, object_size, chunk_size, kmem_cache)
                continue

            target_name = alias_groups[slab_cache_name]["alias"]
            target_size = re.search(r"^:[A-Za-z]*-?(\d+)$", target_name)
            if target_size and int(target_size.group(1)) != chunk_size:
                # Different caches may have the same name. In that case sysfs keeps
                # only the last alias, so use the unclaimed group with the right size.
                candidates = []
                for k, v in alias_groups.items():
                    group_size = re.search(r"^:[A-Za-z]*-?(\d+)$", k)
                    if v["alias"] == "-" and not v["slab_cache_name"] and group_size:
                        if int(group_size.group(1)) == chunk_size:
                            candidates.append(k)
                if len(candidates) != 1:
                    add_unresolved_cache(original_slab_cache_name, object_size, chunk_size, kmem_cache)
                    continue
                target_name = candidates[0]

            resolved = False
            for k in alias_groups.keys():
                # already resolved
                if alias_groups[k]["slab_cache_name"]:
                    continue

                if alias_groups[k]["alias"] == "-":
                    if k == target_name:
                        # k: ":0000256" -> "-"
                        # slab_cache_name: "key_jar" -> ":0000256"
                        alias_groups[k]["slab_cache_name"] = slab_cache_name
                        alias_groups[k]["object_size"] = object_size
                        alias_groups[k]["chunk_size"] = chunk_size
                        alias_groups[k]["kmem_cache"] = kmem_cache
                        resolved = True
                    elif k == slab_cache_name:
                        # k: "kmalloc-256" -> "-"
                        # slab_cache_name: "kmalloc-256" -> "-"
                        alias_groups[k]["slab_cache_name"] = slab_cache_name
                        alias_groups[k]["object_size"] = object_size
                        alias_groups[k]["chunk_size"] = chunk_size
                        alias_groups[k]["kmem_cache"] = kmem_cache
                        resolved = True
                else:
                    if alias_groups[k]["alias"] == target_name:
                        # k: "key_jar" -> ":0000256"
                        # slab_cache_name: "key_jar" -> ":0000256"
                        alias_groups[k]["slab_cache_name"] = slab_cache_name
                        alias_groups[k]["object_size"] = object_size
                        alias_groups[k]["chunk_size"] = chunk_size
                        alias_groups[k]["kmem_cache"] = kmem_cache
                        resolved = True

            # A cache with no unclaimed sysfs node must remain visible as an
            # unresolved physical cache instead of being folded into another
            # cache with the same name.
            if not resolved:
                if not any(v["kmem_cache"] == kmem_cache for v in alias_groups.values()):
                    add_unresolved_cache(original_slab_cache_name, object_size, chunk_size, kmem_cache)
        return alias_groups

    def make_output_merged(self, alias_groups):
        chunk_label_color = Config.get("theme.heap_chunk_label")
        chunk_size_color = Config.get("theme.heap_chunk_size")

        # group entries by their physical sysfs node
        merged_groups = {}
        for name, info in alias_groups.items():
            if not info["slab_cache_name"]:
                continue

            if info["unresolved"]:
                phys_id = name
            else:
                if info["alias"] == "-":
                    phys_id = name
                else:
                    phys_id = info["alias"]
            if phys_id not in merged_groups:
                merged_groups[phys_id] = []

            entry = info.copy()
            entry["logical_name"] = info["name"]
            merged_groups[phys_id].append(entry)

        # list keys
        if self.args.names:
            target_phys_groups = set()

            # Check every physical group
            for phys_id, children in merged_groups.items():
                matched_group = False
                for child in children:
                    child_name = child["logical_name"]
                    for filter_name in self.args.names:
                        if filter_name in child_name:
                            target_phys_groups.add(phys_id)
                            matched_group = True
                            break

                    if matched_group:
                        break # found a match in this group, move to next one
            if not target_phys_groups:
                self.out.append("No caches found matching filter '{}'.".format(", ".join(self.args.names)))
                return

            # Only process the unique set of matching groups
            keys_to_process = [k for k in merged_groups.keys() if k in target_phys_groups]
        else:
            keys_to_process = list(merged_groups.keys())

        # sort by keys
        if self.args.sort_by_size:
            sorted_phys_ids = sorted(keys_to_process,
                key=lambda k: (merged_groups[k][0]["object_size"] if merged_groups[k] else 0))
        else:
            sorted_phys_ids = sorted(keys_to_process,
                key=lambda k: merged_groups[k][0]["slab_cache_name"])

        # print
        self.out.append(titlify("Merged Slab Caches"))
        found_merge = False
        for phys_id in sorted_phys_ids:
            children = merged_groups[phys_id]
            phys_name = children[0]["slab_cache_name"]

            # MERGE-ONLY LOGIC:
            # We want to hide groups that are just [PhysicalOwner, SysfsID]
            # We count how many "real" aliases exist.
            # A "real" alias is one that is NOT the physical owner AND NOT the sysfs group ID (alias == "-")
            real_aliases = 0
            keep_this_group = False
            for child in children:
                # If alias is "-" it's the sysfs group ID (e.g. :0000064)
                # If logical_name == phys_name, it's the physical owner
                if child["alias"] != "-" and child["logical_name"] != phys_name:
                    real_aliases += 1

                # filtering by name
                if self.args.names:
                    for filter_name in self.args.names:
                        if filter_name in child["logical_name"]:
                            keep_this_group = True
                            break
            if real_aliases == 0 and not keep_this_group:
                continue
            found_merge = True

            # print header
            header = "{:s} (Object size: {:s}, Chunk size: {:#x}, kmem_cache: {:#x})".format(
                Color.colorify(phys_name, chunk_label_color),
                Color.colorify_hex(children[0]["object_size"], chunk_size_color),
                children[0]["chunk_size"],
                children[0]["kmem_cache"],
            )
            self.out.append(header)

            # print as tree
            children.sort(key=lambda x: x["logical_name"])
            for i, child in enumerate(children):
                # If non-ASCII characters are included, they will affect
                # the processing of dev/update-syscalls/update-syscalls.py and
                # other programs for developing, so they should be written in hexadecimal.
                if i == len(children) - 1:
                    tree_char = b"\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 ".decode()
                else:
                    tree_char = b"\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 ".decode()

                # coloring
                name_str = child["logical_name"]
                already_colored = False
                # Highlight the specific match if filtering is active
                if self.args.names:
                    for filter_name in self.args.names:
                        if filter_name in name_str:
                            name_str = Color.colorify(name_str, "bold underline orange")
                            already_colored = True
                            break

                if child["unresolved"]:
                    line = tree_char + Color.colorify(name_str, "yellow") + " (Unresolved Physical Cache)"
                elif name_str == phys_name:
                    if not already_colored:
                        name_str = Color.colorify(name_str, "green")
                    line = tree_char + name_str + " (Physical Owner)"
                elif child["alias"] == "-":
                    line = tree_char + Color.colorify(name_str, "gray") + " (Sysfs Group)"
                else:
                    line = tree_char + name_str
                self.out.append(line)
            self.out.append("")

        if not found_merge:
            self.out.append("No interesting merges found (1:1 mappings only).")
        return

    def make_output(self, alias_groups):
        fmt = "{:16s} {:16s} {:30s} {:12s} {:30s} {:s}"
        legend = ["Object Size", "Chunk Size", "Name", "Alias", "slab_cache name", "kmem_cache"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # sort by keys
        if self.args.sort_by_size:
            sorted_alias_groups = sorted(alias_groups.items(),
                key=lambda x: (x[1]["object_size"], x[1]["chunk_size"], x[1]["name"], x[1]["kmem_cache"] or 0))
        else:
            sorted_alias_groups = sorted(alias_groups.items(),
                key=lambda x: (x[1]["name"], x[1]["kmem_cache"] or 0, x[1]["alias"]))

        found = False
        # print
        for _name, v in sorted_alias_groups:
            display_name = v["name"]
            # filtering by name
            if self.args.names:
                for filter_name in self.args.names:
                    if filter_name in display_name:
                        break
                    if filter_name in v["alias"]:
                        break
                    if v["slab_cache_name"] and filter_name in v["slab_cache_name"]:
                        break
                else:
                    continue

            # print flat
            found = True
            if v["object_size"] == 0:
                self.out.append(fmt.format("-", "-", display_name, v["alias"], "<UNUSED>", "-"))
            else:
                object_size = "{0:d} ({0:#x})".format(v["object_size"])
                chunk_size = "{0:d} ({0:#x})".format(v["chunk_size"])
                self.out.append(fmt.format(
                    object_size, chunk_size, display_name, v["alias"], v["slab_cache_name"],
                    "{:#x}".format(v["kmem_cache"]),
                ))

        if self.args.names and not found:
            self.out.append("No caches found matching filters")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        kversion = Kernel.version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "3.14":
            self.quiet_err("Unsupported before v3.14")
            return

        self.allocator = Kernel.get_slab_type()

        if self.allocator == "SLUB_TINY":
            self.quiet_err("Unsupported: CONFIG_SLUB_TINY has no slab sysfs support")
            return

        if self.allocator != "SLUB":
            self.quiet_err("Unsupported: SLAB, SLOB, Unknown allocator")
            return

        ret = self.initialize()
        if args.meta or not ret:
            for func, line in self.meta:
                func(line)
        if not ret:
            self.quiet_err("Failed to initialize")
            return

        if args.meta:
            return

        self.out = []
        alias_groups = self.parse_kmem_cache_alias()
        if self.args.merged_only:
            self.make_output_merged(alias_groups)
        else:
            self.make_output(alias_groups)
        self.print_output()
        return



@register_command
class BuddyDumpCommand(GenericCommand, BufferingOutput):
    """Dump the zone of the page allocator (buddy allocator) free-list."""

    _cmdline_ = "buddy-dump"
    _category_ = "06-h. Qemu-system/KGDB Cooperation - Linux Allocator"
    _aliases_ = ["zone-dump", "pcplist"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("-z", "--zone", dest="zone_filter", action="append",
                        choices=["DMA", "DMA32", "Normal", "HighMem", "Movable", "Device"],
                        help="filter by specified zone name.")
    parser.add_argument("-o", "--order", dest="order_filter", action="append", type=int,
                        help="filter by specified order.")
    parser.add_argument("-m", "--mtype", dest="mtype_filter", action="append", type=int,
                        help="filter by specified mtype.")
    parser.add_argument("-p", "--pcp-index", dest="pcp_index_filter", action="append", type=int,
                        help="filter by specified per-cpu index.")
    parser.add_argument("-P", "--only-pcp", action="store_true", help="dump only per-cpu pages.")
    parser.add_argument("-F", "--skip-pcp", action="store_true", help="skip dumping per-cpu pages (dump only free_area).")
    parser.add_argument("--cpu", action="append", type=int, help="filter by specific cpu for per-cpu pages.")
    parser.add_argument("-s", "--sort", action="store_true",
                        help="sort by page address instead of link list order of each size. overrides -c to 0.")
    parser.add_argument("-S", "--sort-verbose", action="store_true",
                        help="enable --sort and add used area. filtered areas are treated as used. overrides -c to 0.")
    parser.add_argument("-Q", "--skip-phys", action="store_true", help="skip virt -> phys translation.")
    parser.add_argument("-M", "--use-physmap", action="store_true",
                        help="use physmap for virt -> phys translation to speed up (when KGDB mode, x64/arm64 only).")
    parser.add_argument("--MIGRATE_PCPTYPES", type=int, choices=[3, 4], default=3,
                        help="use specify value; linux: 3, android: 4 (2023~).")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-c", "--count", metavar="N", type=AddressUtil.parse_address, default=5,
                        help="max entries to read per list (default: %(default)s, 0=unlimited). "
                             "-s/-S/-v/-vv override this to 0.")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="show all entries for non-sort mode. equivalent to -c 0.")
    parser.add_argument("-vv", "--vverbose", action="store_true",
                        help="show empty entries too for non-sort mode. overrides -c to 0.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -z DMA32",
        "{0:s} -o 1 -o 2",
        "{0:s} --only-pcp --pcp-index 0 --cpu 0",
        "{0:s} --sort-verbose",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified buddy allocator structure:",
        "",
        "  +-node_data[MAX_NUMNODES]-+",
        "  | *pglist_data (node 0)   |--+",
        "  | *pglist_data (node 1)   |  |",
        "  | *pglist_data (node 2)   |  |",
        "  | ...                     |  |",
        "  +-------------------------+  |",
        "                               |",
        "    +--------------------------+",
        "    |",
        "    v",
        "  +-pglist_data------------------------------+",
        "  | node_zones[MAX_NR_ZONES]                 |",
        "  |   +-node_zones[0]----------------------+ |   +--->+-per_cpu_pages--------+",
        "  |   |  ...                               | |   |    | ...                  |",
        "  |   |  per_cpu_pageset                   |-----+    | lists[NR_PCP_LISTS]  |    +-page-----+",
        "  |   |  ...                               | |        |   +-lists[0]-------+ |    | flags    |",
        "  |   |  name                              | |        |   | next           |----->| lru.next |->...",
        "  |   |  ...                               | |        |   | prev           | |    | lru.prev |",
        "  |   |  free_area[MAX_ORDER]              | |        |   +-lists[1]-------+ |    | ...      |",
        "  |   |    +-free_area[0]----------------+ | |        |   | ...            | |    +----------+",
        "  |   |    | free_list[MIGRATE_TYPES]    | | |        |   +----------------+ |",
        "  |   |    |   +-free_list[0]----------+ | | |        +----------------------+",
        "  |   |    |   | next                  |---------+",
        "  |   |    |   | prev                  | | | |   |",
        "  |   |    |   +-free_list[1]----------+ | | |   |    +-page-----+    +-page-----+    +-page-----+",
        "  |   |    |   | ...                   | | | |   |    | flags    |    | flags    |    | flags    |",
        "  |   |    |   +-----------------------+ | | |   +--->| lru.next |--->| lru.next |--->| lru.next |->...",
        "  |   |    | nr_free                     | | |        | lru.prev |    | lru.prev |    | lru.prev |",
        "  |   |    +-free_area[1]----------------+ | |        | ...      |    | ...      |    | ...      |",
        "  |   |    | ...                         | | |        +----------+    +----------+    +----------+",
        "  |   |    +-----------------------------+ | |",
        "  |   +-node_zones[1]----------------------+ |",
        "  |   |  ...                               | |",
        "  |   +------------------------------------+ |",
        "  | ...                                      |",
        "  +------------------------------------------+",
        "",
        "You can combine this result with information of in-use space. Try using `kvmmap` command.",
    ]
    _note_ = "\n".join(_note_)

    def format_entry(self, entry):
        chunk_size_color = Config.get("theme.heap_chunk_size")
        freed_address_color = Config.get("theme.heap_chunk_address_freed")
        heap_page_color = Config.get("theme.heap_page_address")
        align = AddressUtil.get_format_address_width()
        page_str = Color.colorify("{:#0{:d}x}".format(entry["page"], align), freed_address_color)
        size_str = Color.colorify("{:#08x}".format(entry["size"]), chunk_size_color)
        addresses = self.kbuddy.get_entry_addresses(entry, skip_phys=self.args.skip_phys)
        virt, phys = addresses["virt"], addresses["phys"]
        if virt is None:
            virt_str = "???"
        else:
            virt_str = Color.colorify(
                "{:#0{:d}x}-{:#0{:d}x}".format(virt, align, virt + entry["size"], align), heap_page_color,
            )
        if phys is None:
            phys_str = "???"
        else:
            phys_str = "{:#0{:d}x}-{:#0{:d}x}".format(phys, align, phys + entry["size"], align)
        msg = "    page:{:s}  size:{:s}  virt:{:s}  phys:{:s}".format(page_str, size_str, virt_str, phys_str)
        if entry["cpu_num"] is not None:
            msg += " (pcp, cpu={:d})".format(entry["cpu_num"])
        return msg

    @staticmethod
    def format_pcp_list(pcp_list):
        color = Config.get("theme.heap_chunk_size")
        size_str = Color.colorify("{:#08x}".format(pcp_list["size"]), color)
        return "  pcp_index: {:d}, order: {:d} ({:s} bytes), mtype: {:d} (={:s})".format(
            pcp_list["index"], pcp_list["order"], size_str, pcp_list["mtype"], pcp_list["mtype_name"],
        )

    @staticmethod
    def format_free_area(free_area):
        color = Config.get("theme.heap_chunk_size")
        return "order: {:d} ({:s} bytes)".format(free_area["order"], Color.colorify_hex(free_area["size"], color))

    @staticmethod
    def format_free_list(free_list):
        return "  mtype: {:d} (={:s})".format(free_list["mtype"], free_list["mtype_name"])

    def make_output_for_sort(self, nodes):
        entries = []
        for node in nodes:
            for zone in node["zones"]:
                for lists in zone.get("per_cpu_pageset", {}).values():
                    for pcp_list in lists:
                        entries.extend(pcp_list["entries"])
                for free_area in zone.get("free_area", []):
                    for free_list in free_area["free_lists"]:
                        entries.extend(free_list["entries"])
        entries.sort(key=lambda entry: entry["page"])

        prev_virt = None
        prev_size = None
        first = True
        align = AddressUtil.get_format_address_width()
        for entry in ProgressBar(entries, disable=self.args.quiet):
            if not self.args.sort_verbose:
                self.out.append(self.format_entry(entry))
                continue
            addresses = self.kbuddy.get_entry_addresses(
                entry, for_sort=True, skip_phys=self.args.skip_phys if first else True,
                use_physmap=self.args.use_physmap, maps=self.maps,
            )
            virt = addresses["virt"]
            if first:
                phys = addresses["phys"]
                if phys is not None and not self.kbuddy.list_scan_incomplete:
                    self.out.append("    used:{:{:d}s}  size:{:#08x}".format("", align, phys))
                first = False
            elif (not self.kbuddy.list_scan_incomplete and isinstance(virt, int) and isinstance(prev_virt, int)
                  and prev_virt + prev_size != virt):
                self.out.append("    used:{:{:d}s}  size:{:#08x}".format("", align, virt - (prev_virt + prev_size)))
            self.out.append(self.format_entry(entry))
            prev_virt, prev_size = virt, entry["size"]
        return

    def make_output(self, nodes):
        for node in ProgressBar(nodes, desc="node", disable=self.args.quiet):
            self.out.append(titlify("node[{:d}] @ {:#x}".format(node["index"], node["address"])))
            for zone in ProgressBar(node["zones"], desc="zone", disable=self.args.quiet):
                self.out.append(titlify("zone[{:d}] @ {:#x} ({:s})".format(zone["index"], zone["address"], zone["name"])))
                if "per_cpu_pageset" in zone:
                    self.out.append(titlify("per_cpu_pageset"))
                    for cpu_num, lists in ProgressBar(zone["per_cpu_pageset"].items(), desc="cpu", disable=self.args.quiet):
                        self.out.append("cpu: {:d}".format(cpu_num))
                        for pcp_list in ProgressBar(lists, desc="pcplist", disable=self.args.quiet):
                            if not pcp_list["entries"] and not self.args.vverbose:
                                continue
                            self.out.append(self.format_pcp_list(pcp_list))
                            for i, entry in enumerate(pcp_list["entries"]):
                                if self.args.count and i >= self.args.count:
                                    self.out.append("    ...")
                                    break
                                self.out.append(self.format_entry(entry))
                if "free_area" in zone:
                    self.out.append(titlify("free_area"))
                    for free_area in ProgressBar(zone["free_area"], desc="order", disable=self.args.quiet):
                        if not free_area["has_any"] and not self.args.vverbose:
                            continue
                        self.out.append(self.format_free_area(free_area))
                        for free_list in ProgressBar(free_area["free_lists"], desc="mtype", disable=self.args.quiet):
                            if not free_list["entries"] and not self.args.vverbose:
                                continue
                            self.out.append(self.format_free_list(free_list))
                            for i, entry in enumerate(free_list["entries"]):
                                if self.args.count and i >= self.args.count:
                                    self.out.append("    ...")
                                    break
                                self.out.append(self.format_entry(entry))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if any(order < 0 for order in args.order_filter or []):
            err("Order must be >= 0")
            return
        kversion = Kernel.version()
        if kversion is None:
            self.quiet_err("Could not find Linux kernel")
            return
        if kversion < "3.0":
            self.quiet_err("Unsupported before v3.0")
            return

        # parse args
        if self.args.use_physmap:
            if not (is_x86_64() or is_arm64()):
                self.quiet_err("Unsupported architecture")
                return

        self.kbuddy = Kernel.buddy(args.MIGRATE_PCPTYPES)
        if args.rescan:
            Cache.clear_cache_for(self.kbuddy.initialize)

        self.args.sort = args.sort_verbose or args.sort
        self.args.verbose = args.vverbose or args.verbose
        if self.args.sort or self.args.verbose:
            self.args.count = 0

        # initialize
        self.quiet_info("Wait for memory scan")
        ret = self.kbuddy.initialize()
        if args.meta or not ret:
            for func, line in Kernel.export_meta(self, self.kbuddy.meta):
                func(line)
        if not ret:
            return

        if args.meta:
            return

        # migratetype_names
        self.kbuddy.resolve_migratetype_names()

        # do not use cache
        self.maps = None
        if self.args.sort_verbose and not self.args.skip_phys and not self.args.use_physmap:
            self.maps = AddrMap.get_maps()
            if not self.maps:
                self.quiet_err("Failed to resolve maps")
                return

        # dump
        node_entries = self.kbuddy.get_nodes(
            zone_filter=args.zone_filter, order_filter=args.order_filter, mtype_filter=args.mtype_filter,
            pcp_index_filter=args.pcp_index_filter, cpus=args.cpu, count=args.count,
            only_pcp=args.only_pcp, skip_pcp=args.skip_pcp, quiet=args.quiet,
        )
        self.quiet_info("Parse OK, making output...")

        # print
        self.out = []
        if self.args.sort:
            self.make_output_for_sort(node_entries)
        else:
            self.make_output(node_entries)
        if self.kbuddy.list_scan_incomplete:
            self.warn_add_out("Allocator list scan was incomplete due to unreadable or cyclic list data.")
        self.print_output(check_terminal_size=True)
        return



@register_command
class BuddyContainsCommand(BuddyDumpCommand):
    """Resolves which buddy block an address belongs to."""

    _cmdline_ = "buddy-contains"
    _category_ = "06-h. Qemu-system/KGDB Cooperation - Linux Allocator"
    _aliases_ = []

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address, help="target address.")
    parser.add_argument("-p", "--page", action="store_true",
                        help="interpret ADDRESS as a `struct page` address instead of a virtual address.")
    parser.add_argument("-L", "--skip-free-list", action="store_true",
                        help="do not walk the free lists use struct page metadata only. "
                             "pcp free pages and zone/mtype/cpu cannot be reported in this mode.")
    parser.add_argument("-Q", "--skip-phys", action="store_true", help="skip virt -> phys translation.")
    parser.add_argument("-M", "--use-physmap", action="store_true",
                        help="use physmap for virt -> phys translation (x64/arm64 only).")
    parser.add_argument("--MIGRATE_PCPTYPES", type=int, choices=[3, 4], default=3,
                        help="use specify value; linux: 3, android: 4 (2023~).")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "Given an address, resolves which buddy allocator block contains it.",
        "",
        "A free block of order N is described by its head page only, page->private holds the",
        "order and PG_buddy is set on the head, while the tail pages carry neither. So a page",
        "that was merged into a higher order block cannot be identified from its own struct",
        "",
        "Two modes:",
        "  default: walk the free lists like buddy-dump and locate the block.",
        "  -L     : read struct page flags only but cannot report pcp free pages.",
    ]
    _note_ = "\n".join(_note_)

    _example_ = [
        "{0:s} 0xffff96a7c2144000",
        "{0:s} -p 0xffffca7640004040    # ADDRESS is a struct page",
        "{0:s} -L 0xffff96a7c2144000    # Skip free lists",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    def get_page(self):
        if self.args.page:
            page = self.args.address
            if not is_valid_addr(page):
                self.quiet_err("Invalid page address")
                return None
            if Kernel.page2phys(page) is None:
                self.quiet_err("Invalid or unaligned struct page address")
                return None
        else:
            virt = self.args.address
            page = Kernel.virt2page(virt & get_pagesize_mask_high())
            if page is None:
                self.quiet_err("Failed to resolve page from virt")
                return None
        return page

    def resolve_target(self):
        page = self.get_page()
        if page is None:
            return None

        virt = Kernel.page2virt(page)
        if self.args.page:
            offset = 0
        else:
            offset = self.args.address & (KernelAddressHeuristicFinder.consts().PAGE_SIZE - 1)

        phys = Kernel.page2phys(page)
        if phys is None:
            self.quiet_err("Failed to resolve phys from page")
            return None
        return page, virt, phys, offset

    def print_block_info(self, head_page, head_pfn, order):
        chunk_size_color = Config.get("theme.heap_chunk_size")
        freed_address_color = Config.get("theme.heap_chunk_address_freed")
        PAGE_SIZE = KernelAddressHeuristicFinder.consts().PAGE_SIZE
        PAGE_SHIFT = KernelAddressHeuristicFinder.consts().PAGE_SHIFT

        size = PAGE_SIZE << order
        head_phys = head_pfn << PAGE_SHIFT
        head_virt = self.kbuddy.get_entry_addresses(
            {"page": head_page}, for_sort=True, skip_phys=True,
        )["virt"]

        page_str = Color.colorify("{:#x}".format(head_page), freed_address_color)
        size_str = Color.colorify_hex(size, chunk_size_color)

        gef_print("order: {:d} ({:#x} bytes, {:d} pages)".format(order, size, 1 << order))
        if head_virt is not None:
            virt_str = "{:#x}-{:#x}".format(head_virt, head_virt + size)
        else:
            virt_str = "(no direct map)"
        phys_str = "{:#x}-{:#x}".format(head_phys, head_phys + size)
        gef_print("    page:{:s}  size:{:s}  virt:{:s}  phys:{:s}".format(page_str, size_str, virt_str, phys_str))
        return

    def parse_page(self, page, pfn, phys, virt, offset_in_page):
        used_address_color = Config.get("theme.heap_chunk_address_used")
        PAGE_SIZE = KernelAddressHeuristicFinder.consts().PAGE_SIZE

        self.quiet_print("page: {:#x}".format(page))
        if virt is not None:
            self.quiet_print("virt: {:#x}".format(virt))
        self.quiet_print("phys: {:#x} (pfn: {:#x})".format(phys, pfn))
        if offset_in_page:
            self.quiet_print("remarks: {:s} to page (offset: +{:#x})".format(Color.redify("unaligned"), offset_in_page))

        if self.kbuddy.is_page_buddy(page):
            order = self.kbuddy.get_buddy_order(page)
            if order is None:
                self.quiet_print("status: {:s}".format(Color.colorify("unknown", used_address_color)))
                gef_print("remarks: PG_buddy is set but buddy order is invalid or unreadable.")
                return
            head_page, head_pfn = page, pfn
        else:
            head_page, head_pfn, order = self.kbuddy.find_head_page(page, pfn, self.sizeof_struct_page)

        # Not in buddy ?
        if head_page is None:
            self.quiet_print("status: {:s}".format(Color.colorify("unknown", used_address_color)))
            gef_print("remarks: no PG_buddy head page found, run buddy-contains without skipping free lists.")

        # Part of a larger block
        elif head_page != page:
            self.quiet_print("status: {:s}".format(
                Color.colorify("in buddy (part of a larger block)", "bold green"),
            ))
            self.print_block_info(head_page, head_pfn, order)
            gef_print("remarks: this page is page[{:d}] of the block, +{:#x} bytes from base".format(
                pfn - head_pfn, (pfn - head_pfn) * PAGE_SIZE,
            ))

        # Present in the buddy and it's the head of the block
        else:
            self.quiet_print("status: {:s}".format(Color.colorify("in buddy (head page)", "bold green")))
            self.print_block_info(head_page, head_pfn, order)
        return

    def parse_free_lists(self, page):
        used_address_color = Config.get("theme.heap_chunk_address_used")
        PAGE_SIZE = KernelAddressHeuristicFinder.consts().PAGE_SIZE

        lists = self.kbuddy.get_nodes(quiet=self.args.quiet)
        found = self.kbuddy.find_block(lists, page, self.sizeof_struct_page)

        if found is None:
            if self.kbuddy.list_scan_incomplete:
                self.quiet_print("status: {:s}".format(Color.colorify("unknown", used_address_color)))
                gef_print("remarks: allocator list scan was incomplete due to unreadable or cyclic list data.")
            else:
                self.quiet_print("status: {:s}".format(Color.colorify("in-use", used_address_color)))
                gef_print("remarks: not found in any free_area or pcp list.")
            return

        entry = found["entry"]
        node, zone = found["node"], found["zone"]
        gef_print(titlify("node[{:d}] @ {:#x}".format(node["index"], node["address"])))
        gef_print(titlify("zone[{:d}] @ {:#x} ({:s})".format(zone["index"], zone["address"], zone["name"])))
        if found["kind"] == "pcp":
            gef_print(titlify("per_cpu_pageset"))
            gef_print("cpu: {:d}".format(found["cpu_num"]))
            gef_print(self.format_pcp_list(found["list"]))
        else:
            gef_print(titlify("free_area"))
            gef_print(self.format_free_area(found["free_area"]))
            gef_print(self.format_free_list(found["list"]))
        gef_print(self.format_entry(entry).rstrip())

        if entry["page"] != page:
            index = (page - entry["page"]) // self.sizeof_struct_page
            gef_print("remarks: this page is page[{:d}] of the block, +{:#x} bytes from base".format(
                index, index * PAGE_SIZE,
            ))
        return

    def buddy_contains(self):
        PAGE_SHIFT = KernelAddressHeuristicFinder.consts().PAGE_SHIFT

        if self.args.skip_free_list:
            ret = self.resolve_target()
            if ret is None:
                return
            page, virt, phys, offset_in_page = ret
            pfn = phys >> PAGE_SHIFT
            self.parse_page(page, pfn, phys, virt, offset_in_page)
        else:
            page = self.get_page()
            if page is None:
                return
            self.parse_free_lists(page)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        kversion = Kernel.version()
        if kversion is None:
            self.quiet_err("Could not find Linux kernel")
            return
        if kversion < "3.0":
            self.quiet_err("Unsupported before v3.0")
            return

        # parse args
        if self.args.skip_free_list and (self.args.skip_phys or self.args.use_physmap):
            self.quiet_err("options -Q/-M cannot be used with -L")
            return

        if self.args.use_physmap:
            if not (is_x86_64() or is_arm64()):
                self.quiet_err("Unsupported architecture")
                return

        self.kbuddy = Kernel.buddy(args.MIGRATE_PCPTYPES)
        if args.rescan:
            Cache.clear_cache_for(self.kbuddy.initialize)

        # initialize
        self.quiet_info("Wait for memory scan")
        ret = self.kbuddy.initialize()
        if args.meta or not ret:
            for func, line in Kernel.export_meta(self, self.kbuddy.meta):
                func(line)
        if not ret:
            self.quiet_err("Failed to initialize")
            return

        if args.meta:
            return

        # migratetype_names
        self.kbuddy.resolve_migratetype_names()

        self.sizeof_struct_page = KernelAddressHeuristicFinder.consts().sizeof_struct_page
        if self.sizeof_struct_page is None:
            self.quiet_err("Could not find sizeof(struct page)")
            return

        # doit
        self.buddy_contains()
        return




@register_command
class VmallocDumpCommand(GenericCommand, BufferingOutput):
    """Dump vmalloc used list and freed list."""

    _cmdline_ = "vmalloc-dump"
    _category_ = "06-h. Qemu-system/KGDB Cooperation - Linux Allocator"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-hh", "--help-simple", action="store_true", help="show help without ASCII diagram.")
    parser.add_argument("--only-used", action="store_true", help="display only used area.")
    parser.add_argument("--only-freed", action="store_true", help="display only free area.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("--hexdump-used", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="hexdump `used chunks` if layout is resolved.")
    parser.add_argument("--telescope-used", metavar="SIZE", type=lambda x: int(x, 16), default=0,
                        help="telescope `used chunks` if layout is resolved.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -q",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Simplified vmalloc structure:"
        "",
        "                                       +-vmap_area--+",
        "                                       | va_start   |",
        "                                       | va_end     |",
        "+---------------------------------+    | ...        |",
        "| vmap_area_list (~v6.8)          |--->| list       |--->...",
        "| vmap_nodes[i].busy.head (v6.9~) |    | ...        |",
        "+---------------------------------+    | vm         |---->+-vm_struct--+",
        "                                       | ...        |     | ...        |",
        "                                       +------------+     | flags      |",
        "                                                          | ...        |",
        "                                                          +------------+",
        "                           +-vmap_area--+",
        "                           | va_start   |",
        "(v5.2~)                    | va_end     |",
        "+---------------------+    | ...        |",
        "| free_vmap_area_list |--->| list       |--->...",
        "+---------------------+    | ...        |",
        "                           +------------+",
        "",
        "`unpurged` is an area freed lazily but not purged yet. It is still linked to vmap_area_list (~v5.3),",
        "or linked to vmap_purge_list (v5.4~v5.10), purge_vmap_area_list (v5.11~v6.8) or vmap_nodes[i].lazy.head (v6.9~).",
        "`pooled` is a purged area kept in vmap_nodes[i].pool[] for reuse (v6.9~).",
        "`free` is an unallocated range of the vmalloc space, not a history of vfree().",
        "--hexdump-used and --telescope-used skip VM_IOREMAP areas, since reading device registers may have side effects.",
    ]
    _note_ = "\n".join(_note_)

    @Cache.cache_this_session(cache_None=False)
    def initialize(self):
        """
        struct vmap_area {
            unsigned long va_start;
            unsigned long va_end;
            unsigned long subtree_max_size; // v5.2~v5.3
            unsigned long flags;            // ~v5.3
            struct rb_node {
                unsigned long __rb_parent_color;
                struct rb_node *rb_right;
                struct rb_node *rb_left;
            } rb_node;
            struct list_head list;
            union {                             // v5.4~
                unsigned long subtree_max_size; // v5.4~
                struct vm_struct *vm;           // v5.4~
                struct llist_node purge_list;   // v5.4~v5.10
            };                                  // v5.4~
            struct llist_node purge_list; // v4.7~v5.3
            struct list_head purge_list;  // ~v4.6
            struct vm_struct *vm;         // ~v5.3
            unsigned long flags; // v6.3~
        };

        struct vm_struct {
            struct vm_struct *next;
            void *addr;
            unsigned long size;
            unsigned long flags;
            struct page **pages;
        #ifdef CONFIG_HAVE_ARCH_HUGE_VMALLOC // v5.13~
            unsigned int page_order;         // v5.13~
        #endif                               // v5.13~
            unsigned int nr_pages;
            phys_addr_t phys_addr;
            const void *caller;
            unsigned long requested_size; // v6.12~
        };

        struct vmap_node { // v6.9~
            struct vmap_pool {
                struct list_head head;
                unsigned long len;
            } pool[MAX_VA_SIZE_PAGES]; // 256
            spinlock_t pool_lock;
            bool skip_populate;
            struct rb_list {
                struct rb_root root;
                struct list_head head;
                spinlock_t lock;
            } busy;
            struct rb_list lazy;
            struct list_head purge_list;
            struct work_struct purge_work;
            unsigned long nr_purged;
        };
        """

        kversion = Kernel.version()

        # vmap_area->list
        if kversion and "5.4" <= kversion:
            self.offset_list = runtime.current_arch.ptrsize * 5
        elif kversion and "5.2" <= kversion:
            self.offset_list = runtime.current_arch.ptrsize * 7
        else:
            self.offset_list = runtime.current_arch.ptrsize * 6

        # vmap_area->vm
        if kversion and "5.4" <= kversion:
            self.offset_vm = self.offset_list + runtime.current_arch.ptrsize * 2
        elif kversion and "4.7" <= kversion:
            self.offset_vm = self.offset_list + runtime.current_arch.ptrsize * 3
        else:
            self.offset_vm = self.offset_list + runtime.current_arch.ptrsize * 4

        # vmap_area->flags (~v5.3)
        self.offset_va_flags = self.offset_list - runtime.current_arch.ptrsize * 4

        # vmap_area->purge_list (~v5.10)
        self.offset_purge_list = self.offset_list + runtime.current_arch.ptrsize * 2

        # vm_struct->flags
        self.offset_flags = runtime.current_arch.ptrsize * 3

        self.vmap_area_lists = []
        self.lazy_lists = []
        self.vmap_nodes = []
        self.sizeof_vmap_node = None
        if kversion is None:
            pass
        elif kversion < "6.9":
            x = KernelAddressHeuristicFinder.get_vmap_area_list()
            if x:
                self.vmap_area_lists.append(("vmap_area_list", x))
            if "5.11" <= kversion:
                x = KernelAddressHeuristicFinder.get_purge_vmap_area_list()
                if x:
                    self.lazy_lists.append(("purge_vmap_area_list", x))
        else:
            x = KernelAddressHeuristicFinder.get_vmap_nodes_busy_head()
            if x:
                self.vmap_area_lists = self.get_vmap_nodes_busy_heads(x)
                self.lazy_lists = self.get_vmap_nodes_lazy_heads(x)

        # v4.7~v5.10 link lazily freed areas to vmap_purge_list, and ~v5.3 keep them in vmap_area_list too
        if kversion and "4.7" <= kversion < "5.11":
            self.vmap_purge_list = KernelAddressHeuristicFinder.get_vmap_purge_list()
        else:
            self.vmap_purge_list = None

        if kversion and "5.2" <= kversion:
            self.free_vmap_area_list = KernelAddressHeuristicFinder.get_free_vmap_area_list()
        else:
            self.free_vmap_area_list = None

        if not self.vmap_area_lists and not self.free_vmap_area_list:
            return None
        return True

    def get_vmap_nodes_busy_heads(self, head):
        heads = [("vmap_nodes[0].busy.head", head)]

        # vmap_nodes[0] starts at the pool array, and `busy` is behind `pool_lock` (see get_vmap_nodes_busy_head)
        ptrsize = runtime.current_arch.ptrsize
        for i in range(32):
            node = head - ptrsize * (3 * 256 + i)
            if self.is_vmap_node(node, None):
                break
        else:
            return heads
        busy_offset = head - node
        self.vmap_nodes = [node]

        # 32-bit kernels have only one node
        if is_32bit():
            return heads

        # sizeof(struct vmap_node) depends on spinlock_t and work_struct, so find vmap_nodes[1]
        start = node + busy_offset + ptrsize * 2
        data = read_memory(start, ptrsize * 130, safe=True)
        if data is None:
            return heads
        data = slice_unpack(data, ptrsize)
        for i in range(128):
            # the first pool list of vmap_nodes[1] is empty or points to vmap_areas
            next_node = start + ptrsize * i
            if data[i] != next_node and (data[i] == 0 or data[i + 1] == 0 or next_node in data[i:i + 2]):
                continue
            if self.is_vmap_node(next_node, busy_offset):
                break
        else:
            return heads
        self.sizeof_vmap_node = next_node - node

        # nr_vmap_nodes is up to 128
        for i in range(1, 128):
            node_i = node + self.sizeof_vmap_node * i
            if not self.is_vmap_node(node_i, busy_offset):
                break
            self.vmap_nodes.append(node_i)
            heads.append(("vmap_nodes[{:d}].busy.head".format(i), node_i + busy_offset))
        return heads

    def get_vmap_nodes_lazy_heads(self, head):
        if not self.vmap_nodes:
            return []

        # `lazy` follows `busy` (struct rb_list { root; head; lock; }). The gap between pool[] and `busy.head` tells
        # sizeof(spinlock_t) only up to ptrsize, so try both. The wrong one is `lazy.root` or `lazy.head.prev`.
        ptrsize = runtime.current_arch.ptrsize
        busy_offset = head - self.vmap_nodes[0]
        gap = busy_offset - ptrsize * (3 * 256 + 1)
        for lazy_offset in (busy_offset + ptrsize * 2 + gap, busy_offset + ptrsize * 3 + gap):
            if is_double_link_list(self.vmap_nodes[0] + lazy_offset):
                break
        else:
            return []
        return [("vmap_nodes[{:d}].lazy.head".format(i), node + lazy_offset) for i, node in enumerate(self.vmap_nodes)]

    def get_vmap_nodes_pool_heads(self):
        heads = []
        ptrsize = runtime.current_arch.ptrsize
        for i, node in enumerate(self.vmap_nodes):
            data = read_memory(node, ptrsize * 3 * 256, safe=True)
            if data is None:
                continue
            data = slice_unpack(data, ptrsize)
            for j in range(256):
                head = node + ptrsize * 3 * j
                if data[j * 3] != head:
                    heads.append(("vmap_nodes[{:d}].pool[{:d}].head".format(i, j), head))
        return heads

    def is_vmap_node(self, node, busy_offset):
        ptrsize = runtime.current_arch.ptrsize
        data = read_memory(node, ptrsize * 3 * 256, safe=True)
        if data is None:
            return False
        data = slice_unpack(data, ptrsize)

        # pool[] lists
        for i in range(256):
            head = node + ptrsize * 3 * i
            next_entry, prev_entry = data[i * 3], data[i * 3 + 1]
            if next_entry == prev_entry == head:
                continue
            if head in (next_entry, prev_entry) or not is_valid_addr(next_entry) or not is_valid_addr(prev_entry):
                return False

        if busy_offset is None:
            return True

        # busy.head
        head = node + busy_offset
        next_entry = read_int_from_memory(head, safe=True)
        if next_entry is None or not is_valid_addr(next_entry):
            return False
        return read_int_from_memory(next_entry + ptrsize, safe=True) == head

    def print_meta(self):
        kversion = Kernel.version()

        if kversion is not None:
            if self.vmap_area_lists:
                for name, head in self.vmap_area_lists:
                    self.quiet_info("{:s}: {:#x}".format(name, head))
            else:
                if kversion < "6.9":
                    name = "vmap_area_list"
                else:
                    name = "vmap_nodes[0].busy.head"
                self.quiet_err("Could not find {:s}".format(name))

        if self.sizeof_vmap_node:
            self.quiet_info("sizeof(vmap_node): {:#x}".format(self.sizeof_vmap_node))

        if kversion and "4.7" <= kversion < "5.11":
            if self.vmap_purge_list:
                self.quiet_info("vmap_purge_list: {:#x}".format(self.vmap_purge_list))
            else:
                self.quiet_err("Could not find vmap_purge_list")

        if kversion and "5.11" <= kversion:
            if self.lazy_lists:
                for name, head in self.lazy_lists:
                    self.quiet_info("{:s}: {:#x}".format(name, head))
            else:
                if kversion < "6.9":
                    name = "purge_vmap_area_list"
                else:
                    name = "vmap_nodes[0].lazy.head"
                self.quiet_err("Could not find {:s}".format(name))

        if kversion and "5.2" <= kversion:
            if self.free_vmap_area_list:
                self.quiet_info("free_vmap_area_list: {:#x}".format(self.free_vmap_area_list))
            else:
                self.quiet_err("Could not find free_vmap_area_list")

        self.quiet_info("offsetof(vmap_area, list): {:#x}".format(self.offset_list))
        self.quiet_info("offsetof(vmap_area, vm): {:#x}".format(self.offset_vm))
        if kversion and kversion < "5.4":
            self.quiet_info("offsetof(vmap_area, flags): {:#x}".format(self.offset_va_flags))
        if kversion and kversion < "5.11":
            self.quiet_info("offsetof(vmap_area, purge_list): {:#x}".format(self.offset_purge_list))
        self.quiet_info("offsetof(vm_struct, flags): {:#x}".format(self.offset_flags))
        return

    def parse_vmap_purge_list(self):
        unpurged = set()
        if not self.vmap_purge_list:
            return unpurged, None

        node = read_int_from_memory(self.vmap_purge_list, safe=True)
        while node:
            vmap_area = node - self.offset_purge_list
            if vmap_area in unpurged:
                return unpurged, "cyclic at {:#x}".format(vmap_area)
            unpurged.add(vmap_area)
            node = read_int_from_memory(node, safe=True)
        if node is None:
            return unpurged, "unreadable at {:#x}".format(vmap_area if unpurged else self.vmap_purge_list)
        return unpurged, None

    def parse_vmap_area_list(self, head, state, unpurged=()):
        lh = KernelListHead(head, self.offset_list)
        areas, error = self.parse_vmap_areas(lh.iter_entries(), state, unpurged)
        if lh.broken:
            return areas, "{:s} at {:#x}".format(lh.broken_reason, lh.broken_at)
        return areas, error

    def parse_vmap_areas(self, vmap_areas, state, unpurged=()):
        kversion = Kernel.version()

        areas = []
        for vmap_area in vmap_areas:
            va_start = read_int_from_memory(vmap_area, safe=True)
            va_end = read_int_from_memory(vmap_area + runtime.current_arch.ptrsize, safe=True)
            if va_start is None or va_end is None:
                return areas, "unreadable at {:#x}".format(vmap_area)
            va_size = va_end - va_start

            if state != "in-use":
                areas.append([state, va_start, va_end, va_size, None])
                continue

            vm = read_int_from_memory(vmap_area + self.offset_vm, safe=True)
            if kversion and kversion < "5.4":
                # VM_LAZY_FREE|VM_LAZY_FREEING (~v4.6) or VM_LAZY_FREE (v4.13~v5.3) marks a lazily freed area,
                # and ~v3.9 leave VM_VM_AREA and `vm` as they are. ~v3.7 give VM_IOREMAP etc. to the early areas.
                va_flags = read_int_from_memory(vmap_area + self.offset_va_flags, safe=True) or 0
                if vmap_area in unpurged or (va_flags & 0x3 and (vm or not va_flags & 0x4)):
                    areas.append(["unpurged", va_start, va_end, va_size, None])
                    continue
                # `vm` of the vm_map_ram area is not initialized
                if not va_flags & 0x4:
                    vm = 0

            if is_valid_addr(vm):
                flags = read_int_from_memory(vm + self.offset_flags, safe=True)
            else:
                flags = 0
            areas.append(["in-use", va_start, va_end, va_size, flags])
        return areas, None

    def dump_areas(self, areas):
        from gef.commands.debugging.context import DereferenceCommand
        fmt = "{:4s} {:8s} {:37s} {:18s} {:s}"
        legend = ["#", "state", "virtual address", "size", "flags"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        used_address_color = Config.get("theme.heap_chunk_address_used")
        freed_address_color = Config.get("theme.heap_chunk_address_freed")
        chunk_size_color = Config.get("theme.heap_chunk_size")

        for idx, (state, va_start, va_end, va_size, flags) in enumerate(areas):
            used = state == "in-use"
            size_str = "{:<#18x}".format(va_size)
            size_str = Color.colorify(size_str, chunk_size_color)
            virt_str = "{:#018x}-{:#018x}".format(va_start, va_end)
            if used:
                virt_str = Color.colorify(virt_str, used_address_color)
            else:
                virt_str = Color.colorify(virt_str, freed_address_color)
            if flags is None:
                flags_str = "-"
            else:
                flags_str = "{:#x}".format(flags)
            self.out.append("{:<4d} {:8s} {:s} {:s} {:s}".format(
                idx, state, virt_str, size_str, flags_str,
            ))

            # dump chunks
            # VM_IOREMAP maps device registers, whose reads may have side effects (QEMU dies reading the ARM GIC)
            dumpable = used and va_end > va_start and not (flags or 0) & 0x1
            if self.args.hexdump_used and dumpable:
                try:
                    peeked_data = read_memory(va_start, min(self.args.hexdump_used, va_end - va_start))
                    h = hexdump(peeked_data, 0x10, base=va_start, unit=runtime.current_arch.ptrsize)
                    self.out.append(h)
                except Exception:
                    pass

            if self.args.telescope_used and dumpable:
                n = min(self.args.telescope_used, va_end - va_start) // runtime.current_arch.ptrsize
                for i in range(n):
                    try:
                        line = DereferenceCommand.pprint_dereferenced(va_start, i)
                        self.out.append(line)
                    except Exception:
                        pass
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        if args.rescan:
            Cache.clear_cache_for(self.initialize)

        ret = self.initialize()
        if args.meta or not ret:
            self.print_meta()
        if not ret:
            return

        if args.meta:
            return

        self.out = []
        areas = []
        errors = []

        kversion = Kernel.version()

        # parse used list
        if not args.only_freed:
            unpurged, error = self.parse_vmap_purge_list()
            if error:
                errors.append("vmap_purge_list: the walk stopped ({:s})".format(error))
            elif kversion and "4.7" <= kversion < "5.4" and not self.vmap_purge_list:
                errors.append("Could not find vmap_purge_list; lazily freed areas may be shown as in-use")
            elif kversion and "5.4" <= kversion < "5.11" and not self.vmap_purge_list:
                errors.append("Could not find vmap_purge_list; lazily freed areas are not shown")
            elif kversion and "5.11" <= kversion and not self.lazy_lists:
                if kversion < "6.9":
                    name = "purge_vmap_area_list"
                else:
                    name = "vmap_nodes[0].lazy.head"
                errors.append("Could not find {:s}; lazily freed areas are not shown".format(name))

            if not self.vmap_area_lists:
                if kversion and kversion < "6.9":
                    name = "vmap_area_list"
                else:
                    name = "vmap_nodes[0].busy.head"
                errors.append("Could not find {:s}".format(name))

            # v5.4~v5.10 link lazily freed areas only to vmap_purge_list
            if kversion and "5.4" <= kversion < "5.11":
                parsed, error = self.parse_vmap_areas(unpurged, "unpurged")
                areas += parsed
                if error:
                    errors.append("vmap_purge_list: the walk stopped ({:s})".format(error))

            lists = [(name, head, "in-use") for name, head in self.vmap_area_lists]
            lists += [(name, head, "unpurged") for name, head in self.lazy_lists]
            lists += [(name, head, "pooled") for name, head in self.get_vmap_nodes_pool_heads()]
            for name, head, state in lists:
                parsed, error = self.parse_vmap_area_list(head, state, unpurged)
                areas += parsed
                if error:
                    errors.append("{:s}: the walk stopped ({:s})".format(name, error))

        # parse free list
        if not args.only_used:
            if kversion and "5.2" <= kversion:
                if self.free_vmap_area_list:
                    parsed, error = self.parse_vmap_area_list(self.free_vmap_area_list, "free")
                    areas += parsed
                    if error:
                        errors.append("free_vmap_area_list: the walk stopped ({:s})".format(error))
                else:
                    errors.append("Could not find free_vmap_area_list")
            elif args.only_freed:
                errors.append("free_vmap_area_list does not exist before v5.2")

        areas = sorted(areas, key=lambda x:x[1])
        self.dump_areas(areas)
        if not args.quiet:
            for error in errors:
                self.err_add_out(error)

        self.print_output()
        return



@register_command
class KobjCommand(GenericCommand):
    """Identify an arbitrary kernel address: mapping, allocator, slab cache, object base/offset and a type candidate."""

    _cmdline_ = "kobj"
    _category_ = "06-h. Qemu-system/KGDB Cooperation - Linux Allocator"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address", metavar="ADDRESS", type=AddressUtil.parse_address, help="target address.")
    parser.add_argument("-v", "--verbose", action="store_true", help="also list caches merged into the same physical cache.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache in underlying commands.")
    parser.add_argument("-q", "--quiet", action="store_true", help="suppress progress messages, show result only.")
    _syntax_ = parser.format_help()

    _example_ = "{0:s} 0xffff888012345678".format(_cmdline_)

    _note_ = [
        "Unified resolver combining kvmmap/virt2page/pageinfo/slab-contains/buddy-contains/vmalloc-dump.",
        "The type candidate is inferred from the slab cache name, so `Confidence` is reported honestly:",
        "mergeable caches (kmalloc-*) and unaligned addresses lower it. SLUB may merge dedicated caches,",
        "so use -v to list the caches sharing the same physical kmem_cache via kmem-cache-alias.",
        "GEF's pageinfo-based page classification currently supports v4.18 and later;",
        "slab object resolution works on older kernels too.",
    ]
    _note_ = "\n".join(_note_)

    # Well-known caches whose name differs from the struct, or that are frequently targeted.
    # Dedicated caches whose name already matches the struct fall through to the generic guess.
    CACHE_TYPE_HINTS = {
        "filp": "struct file",
        "cred_jar": "struct cred",
        "names_cache": "path name buffer (PATH_MAX)",
        "files_cache": "struct files_struct",
        "fs_cache": "struct fs_struct",
        "sighand_cache": "struct sighand_struct",
        "signal_cache": "struct signal_struct",
        "inode_cache": "struct inode",
        "shmem_inode_cache": "struct shmem_inode_info",
        "proc_inode_cache": "struct proc_inode",
        "sock_inode_cache": "struct socket_alloc",
        "skbuff_head_cache": "struct sk_buff",
        "skbuff_fclone_cache": "struct sk_buff_fclones (paired/fclone sk_buff instances)",
        "kmalloc_large": "large kmalloc allocation (multi-page)",
        "key_jar": "struct key",
        "mnt_cache": "struct mount",
        "uid_cache": "struct user_struct",
        "pool_workqueue": "struct pool_workqueue",
        "task_delay_info": "struct task_delay_info",
        "posix_timers_cache": "struct k_itimer",
        "pde_opener": "struct pde_opener",
        "eventpoll_epi": "struct epitem",
        "eventpoll_pwq": "struct eppoll_entry",
        # Canonical self-named dedicated caches (KMEM_CACHE), rarely merged.
        "dentry": "struct dentry",
        "task_struct": "struct task_struct",
        "mm_struct": "struct mm_struct",
        "vm_area_struct": "struct vm_area_struct",
        "anon_vma": "struct anon_vma",
        "anon_vma_chain": "struct anon_vma_chain",
        "cred": "struct cred",
        "pid": "struct pid",
        "nsproxy": "struct nsproxy",
        "seq_file": "struct seq_file",
        "user_namespace": "struct user_namespace",
    }

    def run(self, cmd):
        try:
            return Color.remove_color(gdb.execute(cmd, to_string=True))
        except gdb.error:
            return ""

    def emit(self, label, value):
        gef_print("{:14s}{}".format(label, value))
        return

    def classify(self, addr):
        """Return (start, end, label, kind) of the most specific known region containing addr, or None."""
        F = KernelAddressHeuristicFinder
        ranges = []

        def add(start, end, label, kind):
            if start and end and start < end and start <= addr < end:
                ranges.append((end - start, start, end, label, kind))
            return

        try:
            klayout = Kernel.layout()
            add(klayout.text_base, klayout.text_end, "kernel image (.text)", "kernel_image")
            add(klayout.ro_base, klayout.ro_end, "kernel image (.rodata)", "kernel_image")
            add(klayout.rw_base, klayout.rw_end, "kernel image (.data/.bss)", "kernel_image")
        except Exception:
            pass

        # On 32-bit the image lives inside the linear map and Kernel.layout() may miss the
        # .data/.bss range, so also derive image bounds from kallsyms when available.
        for start_sym, end_sym, label in (
            ("_stext", "_end", "kernel image"),
            ("_stext", "_etext", "kernel image (.text)"),
            ("__start_rodata", "__end_rodata", "kernel image (.rodata)"),
            ("_sdata", "_edata", "kernel image (.data)"),
        ):
            try:
                add(Ksym.get_addr(start_sym), Ksym.get_addr(end_sym), label, "kernel_image")
            except Exception:
                pass

        # modules may be outside MODULES_VADDR~MODULES_END (e.g., ARM64 with KASLR allocates them in vmalloc)
        for _module, _name, regions in Kernel.modules().get_loaded() or []:
            for _type, base, size in regions:
                add(base, base + size, "modules", "module")

        try:
            consts = F.consts()
            add(consts.MODULES_VADDR, consts.MODULES_END, "modules", "module")
            if is_x86_64() or is_arm64():
                add(F.get_VMEMMAP_START(), F.get_VMEMMAP_END(), "vmemmap (struct page array)", "vmemmap")
            add(F.get_VMALLOC_START(), F.get_VMALLOC_END(), "vmalloc", "vmalloc")
            add(F.get_PAGE_OFFSET(), F.get_PAGE_OFFSET_END(), "direct-map (physmap)", "physmap")
            for start_attr, end_attr, label in (
                ("FIXADDR_START", "FIXADDR_TOP", "fixmap"),
                ("CPU_ENTRY_AREA_BASE", "CPU_ENTRY_AREA_END", "cpu_entry_area"),
                ("VSYSCALL_ADDR", "VSYSCALL_END", "vsyscall"),
                ("LDT_BASE_ADDR", "LDT_END_ADDR", "ldt"),
                ("EFI_VA_START", "EFI_VA_END", "efi"),
            ):
                add(getattr(consts, start_attr, None), getattr(consts, end_attr, None), label, "other")
        except Exception:
            pass

        if not ranges:
            return None
        ranges.sort()
        _size, start, end, label, kind = ranges[0]
        return start, end, label, kind

    def type_candidate(self, name, aligned, object_size=None):
        """Infer a C type candidate from the slab cache name. Returns (candidate, confidence)."""
        if aligned:
            conf_ok = "high"
        else:
            conf_ok = "low"
        if aligned:
            conf_maybe = "medium"
        else:
            conf_maybe = "low"

        if name == "mnt_cache":
            # `mnt_cache` allocated struct vfsmount through v3.2 and struct mount
            # afterwards.  Prefer the target's DWARF and use the version only when
            # neither type can be matched to the allocator's reported object size.
            matches = []
            for type_name in ("struct mount", "struct vfsmount"):
                type_obj = GefUtil.cached_lookup_type(type_name)
                if type_obj is None:
                    continue
                try:
                    size = int(type_obj.sizeof)
                except (gdb.error, TypeError):
                    continue
                if object_size is None or size <= object_size:
                    matches.append((type_name, size))
            if object_size is not None:
                exact = [entry for entry in matches if entry[1] == object_size]
                if len(exact) == 1:
                    return exact[0][0], conf_ok
            if len(matches) == 1:
                return matches[0][0], conf_ok
            kversion = Kernel.version()
            return ("struct vfsmount" if kversion and kversion < "3.3" else "struct mount"), conf_ok

        if name in self.CACHE_TYPE_HINTS:
            return self.CACHE_TYPE_HINTS[name], conf_ok
        for prefix in ("kmalloc-cg-", "dma-kmalloc-", "kmalloc-rcl-", "kmalloc-"):
            if name.startswith(prefix):
                return "generic kmalloc buffer ({:s}); type not determinable".format(name), conf_maybe
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            return "struct {:s} (guessed from cache name)".format(name), conf_maybe
        return "object from '{:s}' cache (type unknown)".format(name), conf_maybe

    def parse_slab(self, out):
        """Parse slab-contains output. Returns dict on success, None if not a slab object."""
        m = re.search(r"^name: (\S+)\s+object_size: (\S+) \(chunk_size: (0x\S+)\)\s+num_pages: (0x\S+)", out, re.M)
        if not m:
            return None
        result = {
            "name": m.group(1), "object_size": int(m.group(2), 0), "chunk_size": int(m.group(3), 16),
            "object_base": None, "offset": 0, "state": None,
        }
        m = re.search(r"^object_base: (0x\S+)", out, re.M)
        if m:
            result["object_base"] = int(m.group(1), 16)
        m = re.search(r"remarks: unaligned \(offset: \+(0x\S+)\)", out)
        if m:
            result["offset"] = int(m.group(1), 16)
        if "before first object" in out or "after last object" in out:
            result["offset"] = -1
            result["padding"] = True
        m = re.search(r"^status: (freed|in-use)", out, re.M)
        if m:
            if m.group(1) == "freed":
                result["state"] = "freed"
            else:
                result["state"] = "allocated"
        return result

    def color_state(self, state):
        if state == "freed":
            return Color.colorify("freed", Config.get("theme.heap_chunk_address_freed"))
        if state == "allocated":
            return Color.colorify("allocated", Config.get("theme.heap_chunk_address_used"))
        return state or "unknown"

    def report_slab(self, addr, page, slab):
        aligned = slab["offset"] == 0
        if page is not None:
            self.emit("Page", "{:#x}".format(page))
        self.emit("Allocator", Kernel.get_slab_type())
        self.emit("Slab cache", Color.colorify(slab["name"], Config.get("theme.heap_chunk_label")))
        if slab["object_base"] is not None:
            self.emit("Object base", "{:#x}".format(slab["object_base"]))
            self.emit("Object offset", "+{:#x}".format(addr - slab["object_base"]))
        if slab.get("padding"):
            self.emit("Candidate", "slab padding (no object)")
            self.emit("Confidence", "high")
            return
        if slab["state"]:
            self.emit("State", self.color_state(slab["state"]))
        candidate, confidence = self.type_candidate(slab["name"], aligned, slab["object_size"])

        # If the physical cache has merged aliases, the reported name is only the owner: the
        # object may belong to any merged cache. Verify for high-confidence (dedicated) names,
        # and always when -v, then downgrade and list the alternatives.
        aliases = None
        if confidence == "high" or self.args.verbose:
            aliases = self.get_merged_aliases(slab["name"])
        if aliases != [] and confidence == "high":
            confidence = "medium"

        self.emit("Candidate", candidate)
        self.emit("Confidence", confidence)
        if not aligned and slab["offset"] != -1:
            self.emit("Remarks", Color.redify("address is not at an object boundary"))
        if aliases is None and confidence == "medium":
            self.emit("Remarks", "cache merge status could not be verified")
        if aliases:
            self.emit("Merged with", ", ".join(aliases))
            self.emit("Remarks", "merged cache: object may instead be one of the above types")
        return

    def get_merged_aliases(self, name):
        """Return the caches merged into the same physical cache as `name` (excluding itself),
        [] when verified not merged, or None when merge status could not be determined."""
        groups = runtime.CommandRegistry.instances["kmem-cache-alias"].get_alias_groups()
        if groups is None:
            return None
        matches = [entry for entry in groups.values() if entry["slab_cache_name"] == name]
        if not matches or any(entry["unresolved"] for entry in matches):
            return None
        if len({entry["kmem_cache"] for entry in matches}) != 1:
            return None
        return sorted({entry["name"] for entry in matches if entry["alias"] != "-" and entry["name"] != name})

    def report_page_alloc(self, addr):
        pi = self.run("pageinfo {:#x}".format(addr)) or ""
        buddy_match = re.search(r"^in_buddy_list\s*:\s*(True|False)\s*$", pi, re.M)
        refcount_match = re.search(r"^refcount\s*:\s*(0x[0-9a-fA-F]+)\s*$", pi, re.M)
        if not buddy_match or not refcount_match:
            self.emit("Allocator", "unknown (not slab; page metadata unavailable)")
            self.emit("State", "unknown")
            self.emit("Candidate", "not a slab object; buddy/page-type data unavailable on this target")
            self.emit("Confidence", "low")
            return

        ptype = ""
        m = re.search(r"page_type\s*:\s*\S+ \((.+)\)", pi)
        if m:
            ptype = m.group(1)
        refcount = int(refcount_match.group(1), 16)
        in_buddy = buddy_match.group(1) == "True"

        self.emit("Allocator", "buddy (page allocator)")
        if in_buddy:
            self.emit("State", self.color_state("freed"))
            block = self.run("buddy-contains -L {:#x}".format(addr))
            m = re.search(r"order: (\d+) \((0x\S+) bytes", block)
            if m:
                self.emit("Block", "order {:s} ({:s} bytes)".format(m.group(1), m.group(2)))
            self.emit("Candidate", "free page block in buddy allocator")
            self.emit("Confidence", "medium")
            return

        self.emit("State", self.color_state("allocated") if refcount else "unknown")
        if "table" in ptype:
            candidate, confidence = "page table page ({:s})".format(ptype), "medium"
        elif "slab" in ptype.lower():
            candidate, confidence = "slab page (cache could not be resolved)", "low"
        else:
            candidate, confidence = "raw page (page cache / anonymous / driver buffer)", "low"
        self.emit("Candidate", candidate)
        self.emit("Confidence", confidence)
        return

    def report_lowmem(self, addr):
        page = Kernel.virt2page(addr & -KernelAddressHeuristicFinder.consts().PAGE_SIZE)
        slab = self.parse_slab(self.run("slab-contains {:s}{:#x}".format(self.rr, addr)))
        if slab:
            self.report_slab(addr, page, slab)
            return
        if page is not None:
            self.emit("Page", "{:#x}".format(page))
        self.report_page_alloc(addr)
        return

    def report_vmemmap(self, addr):
        self.emit("Allocator", "n/a (page descriptor array)")
        consts = KernelAddressHeuristicFinder.consts()
        start = KernelAddressHeuristicFinder.get_VMEMMAP_START()
        if consts is not None:
            stride = consts.sizeof_struct_page
        else:
            stride = None
        if start is None or not stride:
            self.emit("Candidate", "VMEMMAP address; sizeof(struct page) is unknown")
            self.emit("Confidence", "low")
            return

        delta = addr - start
        page = addr - (delta % stride)
        offset = addr - page
        self.emit("Descriptor", "{:#x}".format(page))
        self.emit("Stride", "{:#x} (sizeof(struct page))".format(stride))
        if offset:
            self.emit("Object offset", "+{:#x}".format(offset))

        # Sparse VMEMMAP reserves a broad virtual range but only populates the
        # portions that describe real memory sections.  Check the whole record,
        # rather than treating every canonical address in that range as a page.
        populated = is_valid_addr(page) and is_valid_addr(page + stride - 1)
        if not populated:
            self.emit("Candidate", "unpopulated VMEMMAP range (not a readable struct page)")
            self.emit("Confidence", "low")
        elif offset:
            self.emit("Candidate", "interior pointer into struct page")
            self.emit("Confidence", "low")
            self.emit("Remarks", Color.redify("address is not at a struct page boundary"))
        else:
            self.emit("Candidate", "struct page (describes one physical page frame)")
            self.emit("Confidence", "high")
        return

    def find_vmalloc_chunk(self, addr):
        """Return (start, end, flags) of the vmalloc used chunk containing addr, or None."""
        out = self.run("vmalloc-dump {:s} --quiet --no-pager --only-used".format(self.rr if self.rr else ""))
        for line in out.splitlines():
            fields = line.split()
            if len(fields) < 4 or fields[1] != "in-use" or "-" not in fields[2]:
                continue
            try:
                start_str, end_str = fields[2].split("-")
                start, end = int(start_str, 16), int(end_str, 16)
            except ValueError:
                continue
            if start <= addr < end:
                if len(fields) > 4:
                    flags = " ".join(fields[4:])
                else:
                    flags = ""
                return start, end, flags
        return None

    def emit_vmalloc_chunk(self, addr, chunk, candidate_prefix):
        start, end, flags = chunk
        self.emit("Object base", "{:#x}".format(start))
        self.emit("Object offset", "+{:#x}".format(addr - start))
        self.emit("Size", "{:#x}".format(end - start))
        if flags:
            self.emit("Flags", flags)
        self.emit("Candidate", candidate_prefix + (" ({:s})".format(flags) if flags else ""))
        self.emit("Confidence", "medium")
        return

    def report_vmalloc(self, addr):
        self.emit("Allocator", "vmalloc")
        chunk = self.find_vmalloc_chunk(addr)
        if chunk:
            self.emit_vmalloc_chunk(addr, chunk, "vmalloc allocation")
            return
        self.emit("Candidate", "vmalloc region (no matching used chunk found)")
        self.emit("Confidence", "low")
        return

    def report_module(self, addr):
        self.emit("Allocator", "module loader (vmalloc-backed)")
        for _module, name, regions in Kernel.modules().get_loaded() or []:
            for region_name, base, size in regions:
                if not base <= addr < base + size:
                    continue
                self.emit("Module", name)
                self.emit("Object base", "{:#x}".format(base))
                self.emit("Object offset", "+{:#x}".format(addr - base))
                self.emit("Candidate", "kernel module image ({:s} {:s})".format(name, region_name))
                self.emit("Confidence", "high")
                self.report_symbol(addr)
                return
        # Modules share the vmalloc range on some arches; fall back to the vmalloc chunk lookup.
        chunk = self.find_vmalloc_chunk(addr)
        if chunk:
            self.emit_vmalloc_chunk(addr, chunk, "vmalloc allocation in module VA range")
            self.report_symbol(addr)
            return
        self.emit("Candidate", "module region (module not identified)")
        self.emit("Confidence", "low")
        self.report_symbol(addr)
        return

    def report_kernel_image(self, addr):
        self.emit("Allocator", "n/a (static kernel image)")
        self.emit("Candidate", "static kernel code/data")
        self.emit("Confidence", "high")
        self.report_symbol(addr)
        return

    def report_symbol(self, addr):
        sym = Symbol.format(addr)
        if sym:
            self.emit("Symbol", sym)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if Kernel.version() is None:
            err("Could not find Linux kernel")
            return

        self.quiet_info("Resolving")
        if args.rescan:
            self.rr = "-r "
        else:
            self.rr = ""

        addr = args.address
        self.emit("Address", "{:#x}".format(addr))

        region = self.classify(addr)
        if region is None:
            self.emit("Mapping", "unknown")
            kind = None
        else:
            _start, _end, label, kind = region
            self.emit("Mapping", label)

        if kind == "vmemmap":
            self.report_vmemmap(addr)
        elif kind == "vmalloc":
            self.report_vmalloc(addr)
        elif kind == "module":
            self.report_module(addr)
        elif kind == "kernel_image":
            self.report_kernel_image(addr)
        elif kind == "other":
            self.emit("Allocator", "n/a")
            self.emit("Candidate", "special kernel region")
            self.emit("Confidence", "high")
            self.report_symbol(addr)
        else:
            self.report_lowmem(addr)
        return
