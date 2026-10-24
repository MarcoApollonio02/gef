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
from gef.core.kernel import Kernel
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
                        help="[FOR DEVELOPER] user-specified offsetof(kmem_cache, random) when `kmem_cache.random` is falsely detected.")
    parser.add_argument("--offset-node", type=AddressUtil.parse_address,
                        help="[FOR DEVELOPER] user-specified offsetof(kmem_cache, node/per_node[0].node) when node is falsely detected.")
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
        "* `slab_sheaf`/`barn` introduced in 6.18 is not used by default, but used by setting it when calling `kmem_cache_create`.",
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

    @Cache.cache_until_next
    def parse_kmem_caches_for_initialize(self):
        seen = [self.slab_caches]
        current = self.slab_caches
        while True:
            current = read_int_from_memory(current)
            if current in seen:
                break
            seen.append(current)
        kmem_caches = seen[1:] # skip slab_caches itself
        return kmem_caches

    def resolve_kmem_cache_offset_list(self):
        """
        struct kmem_cache {
            struct kmem_cache_cpu *cpu_slab;         // if kernel < 7.0; In fact, the offset value, not the pointer
            struct lock_class_key {                            // CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                union {                                        // CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                    struct hlist_node hash_entry;              // CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                    struct lockdep_subclass_key {              // CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                        char __one_byte;                       // CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                    } __attribute__ ((__packed__)) subkeys[8]; // CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                };                                             // CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
            } lock_key;                                        // CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
            struct slub_percpu_sheaves __percpu *cpu_sheaves;  // if 6.18 <= kernel
            slab_flags_t flags;                      // unsigned int (+ padding 4 byte)
            unsigned long min_partial;
            unsigned int size;
            unsigned int object_size;
            struct reciprocal_value {                //
                u32 m;                               //
                u8 sh1, sh2;                         // (+ padding 2 byte)
            } reciprocal_size;                       // if 5.9 <= kernel
            unsigned int offset;
            unsigned int cpu_partial;                // if CONFIG_SLUB_CPU_PARTIAL=y && kernel < 7.0
            unsigned int cpu_partial_slabs;          // if CONFIG_SLUB_CPU_PARTIAL=y && 5.16 <= kernel < 7.0
            unsigned int sheaf_capacity;             // if 6.18 <= kernel
            struct kmem_cache_order_objects oo;
            struct kmem_cache_order_objects max;     // if kernel < 5.19
            struct kmem_cache_order_objects min;
            gfp_t allocflags;                        // unsigned int
            int refcount;
            void (*ctor)(void *);
            unsigned int inuse;
            unsigned int align;
            unsigned int red_left_pad;
            const char *name;
            struct list_head list; <-----> struct list_head <-----> struct list_head <-----> ...
            ...
        """

        # fast path
        try:
            self.kmem_cache_offset_list = to_unsigned_long(
                gdb.parse_and_eval("&((struct kmem_cache*)0).list")
            )
            return
        except gdb.error:
            pass

        # slow path
        self.kmem_cache_offset_list = None
        kmem_caches = self.parse_kmem_caches_for_initialize()
        # This value should be at most 0x70 by default. However, cases using offset 0x98 have been observed.
        # This occurs when CONFIG_SLAB_VIRTUAL=y, which is not in the mainline but is introduced by some kernels.
        # Therefore, the search range is expanded.
        max_offset = 0x100
        for candidate_offset in range(runtime.current_arch.ptrsize * 2, max_offset, runtime.current_arch.ptrsize):
            # backward search for the start of `struct kmem_cache`
            found = True
            seen = []
            for kmem_cache in kmem_caches:
                val = read_int_from_memory(kmem_cache - candidate_offset)
                if val in [0, 0xffff_ffff, 0xffff_ffff_ffff_ffff]:
                    found = False
                    break
                if val in seen:
                    found = False
                    break
                else:
                    seen.append(val)

                for cpuoff in self.cpu_offset: # allow []
                    if not is_valid_addr(AddressUtil.normalize_address(val + cpuoff)):
                        found = False
                        break

            if found:
                self.kmem_cache_offset_list = candidate_offset
                return
        return

    def resolve_kmem_cache_offset_random(self):
        # fast path
        try:
            # find kmem_cache.random
            self.kmem_cache_offset_random = to_unsigned_long(
                gdb.parse_and_eval("&((struct kmem_cache*)0).random")
            )
            return
        except gdb.error:
            try:
                # kmem_cache exists but has no random member
                gdb.parse_and_eval("(struct kmem_cache*)0")
                self.kmem_cache_offset_random = None
                return
            except gdb.error:
                pass

        # slow path
        if self.args.no_xor:
            self.kmem_cache_offset_random = None
            return

        if self.args.offset_random is not None:
            self.kmem_cache_offset_random = self.args.offset_random
            return

        self.kmem_cache_offset_random = None # CONFIG_SLAB_FREELIST_HARDENED=n

        """
        struct kmem_cache {
            ...
            struct list_head list; <-----> struct list_head <-----> struct list_head <-----> ...
            struct kobject kobj;                     // if CONFIG_SYSFS=y
            struct work_struct kobj_remove_work;     // if CONFIG_SYSFS=y && kernel < 5.9
            struct memcg_cache_params memcg_params;  // if CONFIG_MEMCG=y && kernel < 5.9
            unsigned int max_attr_size;              // if CONFIG_MEMCG=y && kernel < 5.9
            struct kset *memcg_kset;                 // if CONFIG_MEMCG=y && CONFIG_SYSFS=y && kernel < 5.9
            unsigned long random;                    // if CONFIG_SLAB_FREELIST_HARDENED=y
            unsigned int remote_node_defrag_ratio;   // if CONFIG_NUMA=y
            unsigned int *random_seq;                // if CONFIG_SLAB_FREELIST_RANDOM=y
            struct kasan_cache {
                int alloc_meta_offset;
                int free_meta_offset;
                bool is_kmalloc;
            } kasan_info;                            // if CONFIG_KASAN=y
            unsigned int useroffset;                 // kernel < 6.2 || (6.2 <= kernel && CONFIG_HARDENED_USERCOPY=y)
            unsigned int usersize;                   // kernel < 6.2 || (6.2 <= kernel && CONFIG_HARDENED_USERCOPY=y)
            struct kmem_cache_stats __percpu *cpu_stats // CONFIG_SLUB_STATS && 7.0 <= kernel
            struct kmem_cache_node *node[MAX_NUMNODES]; // kernel < 7.1 (<-- this includes SPINLOCK_MAGIC if CONFIG_DEBUG_SPINLOCK=y)
            struct kmem_cache_per_node_ptrs {           // 7.1 <= kernel
                struct node_barn *barn;                 // 7.1 <= kernel
                struct kmem_cache_node *node;           // 7.1 <= kernel
            } per_node[MAX_NUMNODES];                   // 7.1 <= kernel
        };
        """

        kmem_caches = self.parse_kmem_caches_for_initialize()
        for i in range(2, 0x40):
            candidate_offset = runtime.current_arch.ptrsize * i
            found = True
            count = 0
            seen = []
            for kmem_cache in kmem_caches:
                if not is_valid_addr(kmem_cache + candidate_offset):
                    found = False
                    break

                val = read_int_from_memory(kmem_cache + candidate_offset)
                # random may happen to be a valid address, so some are acceptable
                if is_valid_addr(val):
                    count += 1
                    if count >= 3:
                        found = False
                        break
                else:
                    if val > 0xff_ffff:
                        count -= 1

                # The probability of the same random value appearing multiple times is negligible
                if val != 0:
                    if val in seen:
                        found = False
                        break
                    seen.append(val)

            if found:
                # Too few random numbers
                if len(seen) < 10:
                    found = False

                # Occurrences of non-negative small integers are stochastically rare
                elif sum([0 < x < 0x10_0000 for x in seen]) >= 3:
                    found = False

                # Occurrences of big integers are stochastically rare
                elif sum([0xffff_0000_0000_0000 < x <= 0xffff_ffff_ffff_ffff for x in seen]) >= 3:
                    found = False

                # Occurrences of 0xXXXX000 are stochastically rare
                elif sum([x and (x & 0xfff) == 0 for x in seen]) >= 3:
                    found = False

            if found:
                # search for `struct kmem_cache_node *node` or `unsigned int *random_seq`
                for i in range(1, 9):
                    maybe_ptrs = []
                    for kmem_cache in kmem_caches:
                        v = read_int_from_memory(kmem_cache + candidate_offset + runtime.current_arch.ptrsize * i)
                        maybe_ptrs.append(v)
                    # they should be at the same offset
                    if all(is_valid_addr(p) for p in maybe_ptrs):
                        break
                else:
                    found = False

            if found:
                self.kmem_cache_offset_random = self.kmem_cache_offset_list + candidate_offset
                return
        return

    def resolve_kmem_cache_offset_node(self):
        kversion = Kernel.kernel_version()

        # fast path
        if kversion < "7.1":
            try:
                self.kmem_cache_offset_node = to_unsigned_long(
                    gdb.parse_and_eval("&((struct kmem_cache*)0).node")
                )
                self.kmem_cache_offset_barn = None
                self.kmem_cache_node_step = runtime.current_arch.ptrsize
                return
            except gdb.error:
                pass
        else:
            try:
                self.kmem_cache_offset_barn = to_unsigned_long(
                    gdb.parse_and_eval("&((struct kmem_cache*)0).per_node[0].barn")
                )
                self.kmem_cache_offset_node = to_unsigned_long(
                    gdb.parse_and_eval("&((struct kmem_cache*)0).per_node[0].node")
                )
                self.kmem_cache_node_step = runtime.current_arch.ptrsize * 2
                return
            except gdb.error:
                pass

        # user specified
        if self.args.offset_node is not None:
            if kversion < "7.1":
                self.kmem_cache_offset_node = self.args.offset_node
                self.kmem_cache_offset_barn = None
                self.kmem_cache_node_step = runtime.current_arch.ptrsize
            else:
                self.kmem_cache_offset_node = self.args.offset_node
                self.kmem_cache_offset_barn = self.args.offset_node - runtime.current_arch.ptrsize
                self.kmem_cache_node_step = runtime.current_arch.ptrsize * 2
            return

        # slow path
        self.kmem_cache_offset_node = None
        self.kmem_cache_node_step = None

        def set_kmem_cache_offset_from_node(offset):
            self.kmem_cache_offset_node = offset
            if kversion < "7.1":
                self.kmem_cache_offset_barn = None
                self.kmem_cache_node_step = runtime.current_arch.ptrsize
            else:
                self.kmem_cache_offset_barn = offset - runtime.current_arch.ptrsize
                self.kmem_cache_node_step = runtime.current_arch.ptrsize * 2

        def set_kmem_cache_offset_from_barn(offset):
            if kversion < "7.1":
                self.kmem_cache_offset_barn = None
                self.kmem_cache_offset_node = offset
                self.kmem_cache_node_step = runtime.current_arch.ptrsize
            else:
                self.kmem_cache_offset_barn = offset
                self.kmem_cache_offset_node = offset + runtime.current_arch.ptrsize
                self.kmem_cache_node_step = runtime.current_arch.ptrsize * 2

        """
        struct kmem_cache {
            ...
            unsigned int object_size;
            ...
            struct list_head list; <-----> struct list_head <-----> struct list_head <-----> ...
            struct kobject kobj;                     // if CONFIG_SYSFS=y
            struct work_struct kobj_remove_work;     // if CONFIG_SYSFS=y && kernel < 5.9
            struct memcg_cache_params memcg_params;  // if CONFIG_MEMCG=y && kernel < 5.9
            unsigned int max_attr_size;              // if CONFIG_MEMCG=y && kernel < 5.9
            struct kset *memcg_kset;                 // if CONFIG_MEMCG=y && CONFIG_SYSFS=y && kernel < 5.9
            unsigned long random;                    // if CONFIG_SLAB_FREELIST_HARDENED=y
            unsigned int remote_node_defrag_ratio;   // if CONFIG_NUMA=y (<-- maybe 1000)
            unsigned int *random_seq;                // if CONFIG_SLAB_FREELIST_RANDOM=y
            struct kasan_cache {
                int alloc_meta_offset;
                int free_meta_offset;
                bool is_kmalloc;
            } kasan_info;                            // if CONFIG_KASAN=y
            unsigned int useroffset;                 // kernel < 6.2 || (6.2 <= kernel && CONFIG_HARDENED_USERCOPY=y)
            unsigned int usersize;                   // kernel < 6.2 || (6.2 <= kernel && CONFIG_HARDENED_USERCOPY=y)
            struct kmem_cache_stats __percpu *cpu_stats // CONFIG_SLUB_STATS && 7.0 <= kernel
            struct kmem_cache_node *node[MAX_NUMNODES]; // kernel < 7.1 (<-- this includes SPINLOCK_MAGIC if CONFIG_DEBUG_SPINLOCK=y)
            struct kmem_cache_per_node_ptrs {           // 7.1 <= kernel
                struct node_barn *barn;                 // 7.1 <= kernel
                struct kmem_cache_node *node;           // 7.1 <= kernel
            } per_node[MAX_NUMNODES];                   // 7.1 <= kernel
        }
        """

        kmem_caches = self.parse_kmem_caches_for_initialize()

        # heuristic way 1 (SPINLOCK_MAGIC)
        if is_64bit():
            # kmem_cache_node[0]->list_lock has SPINLOCK_MAGIC when CONFIG_DEBUG_SPINLOCK=y
            start_offset = self.kmem_cache_offset_list + runtime.current_arch.ptrsize * 2 # sizeof(kmem_cache.list)
            search_range = 0x100 if "5.9" <= kversion else 0x200
            for candidate_offset in range(start_offset, start_offset + search_range, runtime.current_arch.ptrsize):
                kmem_cache_top = kmem_caches[0] - self.kmem_cache_offset_list

                x = read_int_from_memory(kmem_cache_top + candidate_offset)
                if not is_valid_addr(x):
                    continue
                y = read_int_from_memory(x)
                if y != 0xdead_4ead_0000_0000: # SPINLOCK_MAGIC
                    continue

                # found
                self.quiet_info("offset of node is found by heuristic way1")
                set_kmem_cache_offset_from_barn(candidate_offset)
                return

        # helper functions (for way2, way4)

        def get_next_valid_ptr_offset(addr, in_range=5):
            """Return the nearest valid pointer within a specified range."""
            # Depending on the configuration, the offset where the address exists will vary,
            # so we need to find the closest valid address.
            for i in range(in_range):
                candidate_offset = runtime.current_arch.ptrsize * i
                v = read_int_from_memory(addr + candidate_offset)
                if is_valid_addr(v):
                    return candidate_offset
            return None

        def is_random_seq(addr, N=8):
            # What random_seq points to is a rearrangement of sequential numbers of type u32.
            # Therefore, no two values will be the same. If the first some elements contain
            # the same value, we can determine that it is not random_seq but node[0].
            #
            # kmem_cache_node example
            # 0xffff888003c40180|+0x0000|+000: 0xb7f638bb00000000
            # 0xffff888003c40188|+0x0008|+001: 0x000000000000000a
            # 0xffff888003c40190|+0x0010|+002: 0xffffea000012da90
            # 0xffff888003c40198|+0x0018|+003: 0xffffea0000118710
            # 0xffff888003c401a0|+0x0020|+004: 0x0000000000000010
            # 0xffff888003c401a8|+0x0028|+005: 0x0000000000000800
            # random_seq example
            # 0xffff8f9d8104c400|+0x0000|+000: 0x00000e8000000b40
            # 0xffff8f9d8104c408|+0x0008|+001: 0x00000f4000000080
            # 0xffff8f9d8104c410|+0x0010|+002: 0x000000a000000ae0
            # 0xffff8f9d8104c418|+0x0018|+003: 0x00000bc0000001e0
            # 0xffff8f9d8104c420|+0x0020|+004: 0x0000020000000360
            # 0xffff8f9d8104c428|+0x0028|+005: 0x0000024000000320
            # random_seq another example
            # 0xffff89c3ce772240|+0x0000|+000: 0x00000000000019e0
            # 0xffff89c3ce772248|+0x0008|+001: 0x00005a9000004da0
            # 0xffff89c3ce772250|+0x0010|+002: 0x00000cf0000026d0
            # 0xffff89c3ce772258|+0x0018|+003: 0x00006780000040b0
            # 0xffff89c3ce772260|+0x0020|+004: 0x00000000000033c0
            # 0xffff89c3ce772268|+0x0028|+005: 0x0000000000000000
            # 0xffff89c3ce772270|+0x0030|+006: 0x0000000000000000
            sizeof_uint32 = 4
            data = read_memory(addr, sizeof_uint32 * N)
            data = slice_unpack(data, sizeof_uint32)
            if len(set(data)) != N:
                return False
            if any(x & 0x80000000 for x in data):
                return False
            return True

        # helper functions end

        # heuristic way 2 (remote_node_defrag_ratio == 1000)
        if is_64bit():
            # Find the offset that has the initial value of 1000 for remote_node_defrag_ratio.
            # The first valid pointer encountered after that is either random_seq or node[0].
            # We look at the contents to determine whether the pointer is random_seq.
            start_offset = self.kmem_cache_offset_list + runtime.current_arch.ptrsize * 2 # sizeof(kmem_cache.list)
            search_range = 0x100 if "5.9" <= kversion else 0x200
            for candidate_offset in range(start_offset, start_offset + search_range, runtime.current_arch.ptrsize):
                # First, we search remote_node_defrag_ratio.
                remote_node_defrag_ratio_1000_count = 0
                for kmem_cache in kmem_caches:
                    kmem_cache_top = kmem_cache - self.kmem_cache_offset_list
                    remote_node_defrag_ratio = read_int32_from_memory(kmem_cache_top + candidate_offset)
                    if remote_node_defrag_ratio == 0x3e8:
                        remote_node_defrag_ratio_1000_count += 1
                if remote_node_defrag_ratio_1000_count < len(kmem_caches) // 10: # heuristic threshold: 10%
                    continue
                offset_remote_node_defrag_ratio = candidate_offset
                offset_random_seq = offset_remote_node_defrag_ratio + runtime.current_arch.ptrsize

                # Check the value next to remote_node_defrag_ratio whether pointer or not.
                kmem_cache_0_top = kmem_caches[0] - self.kmem_cache_offset_list
                x = read_int_from_memory(kmem_cache_0_top + offset_random_seq)
                if is_valid_addr(x):
                    # At this point, x is random_seq or node[0]
                    if not is_random_seq(x):
                        # x is not random_seq, but node[0]
                        self.quiet_info("offset of node is found by heuristic way2-1")
                        set_kmem_cache_offset_from_barn(offset_random_seq)
                        return
                    else:
                        # x is random_seq, so skip it
                        start_offset_node_search = offset_random_seq + runtime.current_arch.ptrsize
                else:
                    # x is kasan_info or user_offset
                    start_offset_node_search = offset_random_seq

                extend_offset = get_next_valid_ptr_offset(kmem_cache_0_top + start_offset_node_search)
                if extend_offset is not None:
                    offset_node = start_offset_node_search + extend_offset
                    y = read_int_from_memory(kmem_cache_0_top + offset_node)
                    # 7.0+: cpu_stats is not a valid pointer, so this check will pass.
                    if is_valid_addr(y) and not is_random_seq(y):
                        self.quiet_info("offset of node is found by heuristic way2-2")
                        set_kmem_cache_offset_from_barn(offset_node)
                        return

        # heuristic way 3 (relationship of user_offset, user_size, and object_size)
        # This method is valid for kernel < 6.2, or (CONFIG_HARDENED_USERCOPY=y and 6.2 <= kernel).
        start_offset = self.kmem_cache_offset_list + runtime.current_arch.ptrsize * 2 # sizeof(kmem_cache.list)
        search_range = 0x100 if "5.9" <= kversion else 0x200
        for candidate_offset in range(start_offset, start_offset + search_range, runtime.current_arch.ptrsize):
            found = True
            user_offset_user_size_non_zero_flag = False
            for kmem_cache in kmem_caches:
                kmem_cache_top = kmem_cache - self.kmem_cache_offset_list

                # Check whether user_offset, user_size, and object_size satisfy some relationships
                user_offset = read_int32_from_memory(kmem_cache_top + candidate_offset)
                user_size = read_int32_from_memory(kmem_cache_top + candidate_offset + 4)
                object_size = read_int32_from_memory(kmem_cache_top + self.kmem_cache_offset_object_size)

                if user_offset == user_size == 0:
                    continue
                user_offset_user_size_non_zero_flag = True

                if user_offset != 0 and user_size == 0:
                    found = False
                    break
                if object_size < user_size:
                    found = False
                    break

                # And check that the immediately following node is a valid address
                node_offset = candidate_offset + 4 + 4
                node_addr = read_int_from_memory(kmem_cache_top + node_offset)
                if not is_valid_addr(node_addr):
                    if kversion < "7.0":
                        found = False
                        break
                    else:
                        # cpu_stats may exist (if CONFIG_SLUB_STATS=y)
                        node_offset = candidate_offset + 4 + 4 + runtime.current_arch.ptrsize
                        node_addr = read_int_from_memory(kmem_cache_top + node_offset)
                        if not is_valid_addr(node_addr):
                            found = False
                            break

            if user_offset_user_size_non_zero_flag is False:
                found = False

            if found:
                self.quiet_info("offset of node is found by heuristic way3")
                set_kmem_cache_offset_from_barn(node_offset)
                return

        # heuristic way 4 (detect random_seq)
        if is_64bit() and self.kmem_cache_offset_random:
            # user_offset and user_size probably don't exist.
            # remote_node_defrag_ratio does not exist either.
            # Search random_seq from random, then go like heuristic way 2.
            offset_random_seq = self.kmem_cache_offset_random + runtime.current_arch.ptrsize

            kmem_cache_0_top = kmem_caches[0] - self.kmem_cache_offset_list
            x = read_int_from_memory(kmem_cache_0_top + offset_random_seq)
            if is_valid_addr(x):
                # At this point, x is random_seq or node[0]
                if not is_random_seq(x):
                    # x is not random_seq, but node[0]
                    self.quiet_info("offset of node is found by heuristic way4-1")
                    set_kmem_cache_offset_from_barn(offset_random_seq)
                    return
                else:
                    # x is random_seq, so skip it
                    start_offset_node_search = offset_random_seq + runtime.current_arch.ptrsize
            else:
                # x is kasan_info or user_offset
                start_offset_node_search = offset_random_seq

            # not found
            extend_offset = get_next_valid_ptr_offset(kmem_cache_0_top + start_offset_node_search)
            if extend_offset is not None:
                offset_node = start_offset_node_search + extend_offset
                y = read_int_from_memory(kmem_cache_0_top + offset_node)
                # 7.0+: cpu_stats is not a valid pointer, so this check will pass.
                if is_valid_addr(y) and not is_random_seq(y):
                    self.quiet_info("offset of node is found by heuristic way4-2")
                    set_kmem_cache_offset_from_barn(offset_node)
                    return

        # heuristic way 5 (consecutive kmem_cache)
        # A kmem_cache may itself be allocated contiguously.
        # It may be possible to find a node from this relationship.
        #          +-kmem_cache-+
        #          | ...        |
        #    ...-->| list       |-->...(*)  (1) detect consecutive kmem_cache
        #          | ...        |  -------^
        #          | node       |         | (2) search this area
        #          | (padding)  |         |
        #          +-kmem_cache-+  -------v
        #          | ...        |
        # (*)...-->| list       |-->...
        #          | ...        |
        #          | node       |
        #          | (padding)  |
        #          +------------+

        # Find the two nearest pairs and count the number of cases
        min_diff_pairs = []
        min_diff = 0xffff_ffff_ffff_ffff
        for km1, km2 in itertools.combinations(kmem_caches, 2):
            diff = abs(km1 - km2)
            if diff < min_diff:
                min_diff_pairs = [(min(km1, km2), max(km1, km2))]
                min_diff = diff
                continue
            if diff == min_diff:
                min_diff_pairs.append((min(km1, km2), max(km1, km2)))
                continue

        # If there are enough such cases, we can determine that they are likely arranged consecutively
        if len(min_diff_pairs) >= 10:
            # Specifies the maximum traversal range for scanning node locations
            # Note that these are kmem_cache.list addresses
            km0_0, km0_1 = min_diff_pairs[0]
            km0_1_top = km0_1 - self.kmem_cache_offset_list
            km0_0_after_list = km0_0 + runtime.current_arch.ptrsize * 2
            max_search_range = km0_1_top - km0_0_after_list

            # Check that the address is valid for all pairs
            for i in range(max_search_range // runtime.current_arch.ptrsize):
                candidate_offset = runtime.current_arch.ptrsize * (i + 1)
                found = True
                for _, m in min_diff_pairs:
                    m_top = m - self.kmem_cache_offset_list
                    x = read_int_from_memory(m_top - candidate_offset)
                    if not is_valid_addr(x):
                        found = False
                        break
                if found:
                    offset_node_from_after_list = max_search_range - candidate_offset
                    offset_after_list = self.kmem_cache_offset_list + runtime.current_arch.ptrsize * 2
                    maxlen = len(list(itertools.combinations(kmem_caches, 2)))
                    msg = "min_diff_pairs:{:d}/{:d}, ".format(len(min_diff_pairs), maxlen)
                    msg += "min_diff:{:#x}".format(min_diff)
                    self.quiet_info("offset of node is found by heuristic way5 ({:s})".format(msg))
                    set_kmem_cache_offset_from_node(offset_after_list + offset_node_from_after_list)
                    return
        return

    def resolve_for_CONFIG_SLAB_VIRTUAL(self):
        kversion = Kernel.kernel_version()

        # Feature: CONFIG_SLAB_VIRTUAL (this patchset is supported x86-64 only).
        # See https://lwn.net/Articles/944647/.
        if not is_x86_64():
            self.slab_virtual_enabled = False
        elif kversion < "6.1":
            self.slab_virtual_enabled = False
        elif not Symbol.get_ksymaddr("slub_tlbflush_worker"):
            self.slab_virtual_enabled = False
        else:
            # Heuristic detection that CONFIG_SLAB_VIRTUAL is enabled or not from `struct kmem_cache`.
            # If enabled, `struct kmem_cache` has 2 doubly-link-lists above `kmem_cache->name`.
            #     - kmem_cache->freed_slabs_normal (6.1.56 <= kernel)
            #     - kmem_cache->freed_slabs (kernel < 6.1.56)
            #     - kmem_cache->freed_slabs_min

            def has_freed_slabs_lists(freed_slabs_normal, freed_slabs_min):
                return is_double_link_list(freed_slabs_normal) and is_double_link_list(freed_slabs_min)

            kmem_caches = self.parse_kmem_caches_for_initialize()
            top = kmem_caches[0] - self.kmem_cache_offset_list

            offset_freed_slabs_normal = runtime.current_arch.ptrsize * 9
            offset_freed_slabs_min = runtime.current_arch.ptrsize * 11
            self.slab_virtual_enabled = has_freed_slabs_lists(
                top + offset_freed_slabs_normal, top + offset_freed_slabs_min,
            )

            # cares CONFIG_SLUB_CPU_PARTIAL=n
            if not self.slab_virtual_enabled:
                offset_freed_slabs_normal = runtime.current_arch.ptrsize * 8
                offset_freed_slabs_min = runtime.current_arch.ptrsize * 10
                self.slab_virtual_enabled = has_freed_slabs_lists(
                    top + offset_freed_slabs_normal, top + offset_freed_slabs_min,
                )

        # parse kmem_cache for CONFIG_SLAB_VIRTUAL
        if self.slab_virtual_enabled:
            self.quiet_info("CONFIG_SLAB_VIRTUAL: detected")

            # 1. get global queue buffering freed slabs
            self.slub_tlbflush_queue = KernelAddressHeuristicFinder.get_slub_tlbflush_queue()
            if not self.slub_tlbflush_queue:
                return False
            self.quiet_info("slub_tlbflush_queue: {:#x}".format(self.slub_tlbflush_queue))

            # 2. parse extra members of kmem_cache
            #   - kmem_cache->nr_freed_pages (6.1-based, 6.12-based) or kmem_cache->virtual.nr_freed_pages (6.6-based)
            #   - kmem_cache->freed_slabs_normal (6.1-based, 6.12-based) or kmem_cache->virtual.freed_slabs (6.6-based)
            #   - kmem_cache->freed_slabs_min (6.1-based, 6.12-based) or kmem_cache->virtual.freed_slabs_min (6.6-based)

            # offsetof(kmem_cache, nr_freed_pages)
            if kversion < "6.1.56":
                self.kmem_cache_offset_nr_freed_pages = offset_freed_slabs_normal - runtime.current_arch.ptrsize * 1
            else:
                self.kmem_cache_offset_nr_freed_pages = offset_freed_slabs_min + runtime.current_arch.ptrsize * 2
            self.quiet_info("offsetof(kmem_cache, nr_freed_pages): {:#x}".format(
                self.kmem_cache_offset_nr_freed_pages,
            ))

            # offsetof(kmem_cache, freed_slabs_normal)
            self.kmem_cache_offset_freed_slabs_normal = offset_freed_slabs_normal
            self.quiet_info("offsetof(kmem_cache, freed_slabs_normal): {:#x}".format(
                self.kmem_cache_offset_freed_slabs_normal,
            ))

            # offsetof(kmem_cache, freed_slabs_min)
            self.kmem_cache_offset_freed_slabs_min = offset_freed_slabs_min
            self.quiet_info("offsetof(kmem_cache, freed_slabs_min): {:#x}".format(
                self.kmem_cache_offset_freed_slabs_min,
            ))
        else:
            if self.args.tlbflush_queue:
                warn("CONFIG_SLAB_VIRTUAL is not enabled (maybe), option `--tlbflush-queue` is ignored.")
        return

    def resolve_kmem_cache_node_offset_partial(self):
        # fast path
        try:
            self.kmem_cache_node_offset_partial = to_unsigned_long(
                gdb.parse_and_eval("&((struct kmem_cache_node*)0).partial")
            )
            return
        except gdb.error:
            pass

        # slow path
        if self.kmem_cache_offset_node is None:
            self.kmem_cache_node_offset_partial = None
            return

        self.kmem_cache_node_offset_partial = None
        kmem_caches = self.parse_kmem_caches_for_initialize()
        top = kmem_caches[0] - self.kmem_cache_offset_list

        node = read_int_from_memory(top + self.kmem_cache_offset_node)
        for i in range(1, 16):
            offset_partial = runtime.current_arch.ptrsize * i
            if is_double_link_list(node + offset_partial):
                self.kmem_cache_node_offset_partial = offset_partial
                return
        return

    def get_slub_percpu_sheaves(self, addr, cpu):
        cpu_sheaves = read_int_from_memory(addr + self.kmem_cache_offset_cpu_sheaves)
        if cpu_sheaves == 0:
            return None
        if len(self.cpu_offset) > 0:
            slub_percpu_sheaves = cpu_sheaves + self.cpu_offset[cpu]
        else:
            slub_percpu_sheaves = cpu_sheaves
        return AddressUtil.normalize_address(slub_percpu_sheaves)

    def resolve_slub_percpu_sheaves_offset_main(self):
        self.slub_percpu_sheaves_offset_main = None

        if self.kmem_cache_offset_cpu_sheaves is None:
            return

        # fast path
        try:
            self.slub_percpu_sheaves_offset_main = to_unsigned_long(
                gdb.parse_and_eval("&((struct slub_percpu_sheaves*)0).main")
            )
            return
        except gdb.error:
            pass

        """
        struct slub_percpu_sheaves {
            struct {
            #ifdef CONFIG_DEBUG_LOCK_ALLOC
                struct lockdep_map {
                    struct lock_class_key *key;
                    struct lock_class *class_cache[2];
                    const char *name;
                    u8 wait_type_outer;
                    u8 wait_type_inner;
                    u8 lock_type;
                #ifdef CONFIG_LOCK_STAT
                    int cpu;
                    unsigned long ip;
                #endif
                } dep_map;
                struct task_struct *owner;
            #endif
                u8 acquired;
            } local_trylock_t lock;
            struct slab_sheaf *main;
            struct slab_sheaf *spare;
            struct slab_sheaf *rcu_free;
        };
        """

        # slow path
        kmem_caches = self.parse_kmem_caches_for_initialize()
        for kmem_cache in kmem_caches:
            kmem_cache_top = kmem_cache - self.kmem_cache_offset_list
            for cpu in range(self.ncpus):
                slub_percpu_sheaves = self.get_slub_percpu_sheaves(kmem_cache_top, cpu)
                if slub_percpu_sheaves is None:
                    continue
                if not is_valid_addr(slub_percpu_sheaves):
                    continue

                # CONFIG_DEBUG_LOCK_ALLOC=n
                acquired = read_int_from_memory(slub_percpu_sheaves)
                main = read_int_from_memory(slub_percpu_sheaves + runtime.current_arch.ptrsize)
                if acquired in [0, 1] and is_valid_addr(main):
                    self.slub_percpu_sheaves_offset_main = runtime.current_arch.ptrsize
                    return

                # CONFIG_DEBUG_LOCK_ALLOC=y
                for i in range(5, 8):
                    v = read_int_from_memory(slub_percpu_sheaves + runtime.current_arch.ptrsize * i)
                    if is_valid_addr(v): # owner
                        acquired = read_int_from_memory(slub_percpu_sheaves + runtime.current_arch.ptrsize * (i + 1))
                        main = read_int_from_memory(slub_percpu_sheaves + runtime.current_arch.ptrsize * (i + 2))
                        if acquired in [0, 1] and is_valid_addr(main):
                            self.slub_percpu_sheaves_offset_main = runtime.current_arch.ptrsize * (i + 2)
                            return
        return

    def resolve_kmem_cache_node_offset_barn(self):
        self.kmem_cache_node_offset_barn = None

        if self.kmem_cache_offset_node is None:
            return

        # fast path
        try:
            self.kmem_cache_node_offset_barn = to_unsigned_long(
                gdb.parse_and_eval("&((struct kmem_cache_node*)0).barn")
            )
            return
        except gdb.error:
            pass

        """
        struct kmem_cache_node {
            spinlock_t list_lock;
            unsigned long nr_partial;
            struct list_head partial;
            atomic_long_t nr_slabs;                  // if CONFIG_SLUB_DEBUG=y
            atomic_long_t total_objects;             // if CONFIG_SLUB_DEBUG=y
            struct list_head full;                   // if CONFIG_SLUB_DEBUG=y
            struct node_barn *barn;                  // 6.18 <= kernel < 7.1
        };
        """

        kmem_caches = self.parse_kmem_caches_for_initialize()
        for kmem_cache in kmem_caches:
            kmem_cache_top = kmem_cache - self.kmem_cache_offset_list
            for cpu in range(self.ncpus):
                # is kmem_cache enabled sheaves?
                slub_percpu_sheaves = self.get_slub_percpu_sheaves(kmem_cache_top, cpu)
                if slub_percpu_sheaves is None:
                    continue

                # get kmem_cache_node
                kmem_cache_node_array = kmem_cache_top + self.kmem_cache_offset_node
                if not is_valid_addr(kmem_cache_node_array):
                    continue
                kmem_cache_node = read_int_from_memory(kmem_cache_node_array)
                if not is_valid_addr(kmem_cache_node): # check 1st element is enough
                    continue

                # search list_head
                for i in range(0x20):
                    offset_candidate_list_head = runtime.current_arch.ptrsize * i
                    if is_double_link_list(kmem_cache_node + offset_candidate_list_head):
                        offset_candidate = offset_candidate_list_head + runtime.current_arch.ptrsize * 2
                        # search valid pointer which locates next to it
                        if is_valid_addr_addr(kmem_cache_node + offset_candidate):
                            self.kmem_cache_node_offset_barn = offset_candidate
                            return
        return

    def get_node_barn(self, kmem_cache_addr, kmem_cache_node, node_index):
        if self.kmem_cache_offset_barn is not None:
            return read_int_from_memory(kmem_cache_addr + self.kmem_cache_offset_barn + self.kmem_cache_node_step * node_index)
        return read_int_from_memory(kmem_cache_node + self.kmem_cache_node_offset_barn)

    def resolve_node_barn_offset_sheaves_full(self):
        self.node_barn_offset_sheaves_full = None

        if self.kmem_cache_offset_node is None:
            return

        # fast path
        try:
            self.node_barn_offset_sheaves_full = to_unsigned_long(
                gdb.parse_and_eval("&((struct node_barn*)0).sheaves_full")
            )
            return
        except gdb.error:
            pass

        """
        struct node_barn {
            spinlock_t lock;
            struct list_head sheaves_full;
            struct list_head sheaves_empty;
            unsigned int nr_full;
            unsigned int nr_empty;
        };
        """

        # slow path
        kmem_caches = self.parse_kmem_caches_for_initialize()
        for kmem_cache in kmem_caches:
            kmem_cache_top = kmem_cache - self.kmem_cache_offset_list
            for cpu in range(self.ncpus):
                # is kmem_cache enabled sheaves?
                slub_percpu_sheaves = self.get_slub_percpu_sheaves(kmem_cache_top, cpu)
                if slub_percpu_sheaves is None:
                    continue

                # get kmem_cache_node
                kmem_cache_node_array = kmem_cache_top + self.kmem_cache_offset_node
                if not is_valid_addr(kmem_cache_node_array):
                    continue
                kmem_cache_node = read_int_from_memory(kmem_cache_node_array)
                if not is_valid_addr(kmem_cache_node): # check 1st element is enough
                    continue

                # get barn
                barn = self.get_node_barn(kmem_cache_top, kmem_cache_node, 0)
                if is_valid_addr(barn):
                    # search list_head
                    for i in range(0x20):
                        offset_candidate = runtime.current_arch.ptrsize * i
                        if is_double_link_list(barn + offset_candidate):
                            self.node_barn_offset_sheaves_full = offset_candidate
                            return
        return

    def resolve_sheaves(self):
        self.sheaves_enabled = False

        kversion = Kernel.kernel_version()
        if kversion < "6.18":
            return

        if self.kmem_cache_offset_cpu_sheaves is None:
            return
        if self.kmem_cache_offset_node is None:
            return

        # offsetof(slub_percpu_sheaves, main)
        self.resolve_slub_percpu_sheaves_offset_main()
        if self.slub_percpu_sheaves_offset_main is None:
            self.quiet_info("offsetof(slub_percpu_sheaves, main): Not found")
            return
        self.quiet_info("offsetof(slub_percpu_sheaves, main): {:#x}".format(self.slub_percpu_sheaves_offset_main))

        # offsetof(kmem_cache_node, barn)
        if kversion < "7.1":
            self.resolve_kmem_cache_node_offset_barn()
            if self.kmem_cache_node_offset_barn is None:
                self.quiet_info("offsetof(kmem_cache_node, barn): Not found")
                return
            else:
                self.quiet_info("offsetof(kmem_cache_node, barn): {:#x}".format(self.kmem_cache_node_offset_barn))

        # offsetof(node_barn, sheaves_full)
        self.resolve_node_barn_offset_sheaves_full()
        if self.node_barn_offset_sheaves_full is None:
            self.quiet_info("offsetof(node_barn, sheaves_full): Not found")
            return
        self.quiet_info("offsetof(node_barn, sheaves_full): {:#x}".format(self.node_barn_offset_sheaves_full))

        # offsetof(slub_percpu_sheaves, spare)
        self.slub_percpu_sheaves_offset_spare = self.slub_percpu_sheaves_offset_main + runtime.current_arch.ptrsize

        """
        struct slab_sheaf {
            union {
                struct rcu_head rcu_head;
                struct list_head barn_list;
                unsigned int capacity; /* only used for prefilled sheafs */
            };
            struct kmem_cache *cache;
            unsigned int size;
            int node; /* only used for rcu_sheaf */
            void *objects[];
        };
        """
        # offsetof(slab_sheaf, barn_list)
        self.slab_sheaf_offset_barn_list = 0
        # offsetof(slab_sheaf, kmem_cache)
        self.slab_sheaf_offset_kmem_cache = self.slab_sheaf_offset_barn_list + runtime.current_arch.ptrsize * 2
        # offsetof(slab_sheaf, size)
        self.slab_sheaf_offset_size = self.slab_sheaf_offset_kmem_cache + runtime.current_arch.ptrsize
        # offsetof(slab_sheaf, objects)
        self.slab_sheaf_offset_objects = self.slab_sheaf_offset_size + runtime.current_arch.ptrsize

        # offsetof(node_barn, sheaves_empty)
        self.node_barn_offset_sheaves_empty = self.node_barn_offset_sheaves_full + runtime.current_arch.ptrsize * 2

        self.sheaves_enabled = True
        return

    # CONFIG_SLAB_VIRTUAL=n
    """
    struct kmem_cache {
        struct kmem_cache_cpu *cpu_slab;         // if kernel < 7.0; In fact, the offset value, not the pointer
        struct lock_class_key {                            // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
            union {                                        // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                struct hlist_node hash_entry;              // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                struct lockdep_subclass_key {              // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                    char __one_byte;                       // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                } __attribute__ ((__packed__)) subkeys[8]; // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
            };                                             // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
        } lock_key;                                        // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
        struct slub_percpu_sheaves __percpu *cpu_sheaves;  // if 6.18 <= kernel
        slab_flags_t flags;                      // unsigned int (+ padding 4 byte)
        unsigned long min_partial;
        unsigned int size;
        unsigned int object_size;
        struct reciprocal_value {                //
            u32 m;                               //
            u8 sh1, sh2;                         // (+ padding 2 byte)
        } reciprocal_size;                       // if 5.9 <= kernel
        unsigned int offset;
        unsigned int cpu_partial;                // if CONFIG_SLUB_CPU_PARTIAL=y && kernel < 7.0
        unsigned int cpu_partial_slabs;          // if CONFIG_SLUB_CPU_PARTIAL=y && 5.16 <= kernel < 7.0
        unsigned int sheaf_capacity;             // if 6.18 <= kernel
        struct kmem_cache_order_objects oo;
        struct kmem_cache_order_objects max;     // if kernel < 5.19
        struct kmem_cache_order_objects min;
        gfp_t allocflags;                        // unsigned int
        int refcount;
        void (*ctor)(void *);
        unsigned int inuse;
        unsigned int align;
        unsigned int red_left_pad;
        const char *name;
        struct list_head list; <-----> struct list_head <-----> struct list_head <-----> ...
        struct kobject kobj;                     // if CONFIG_SYSFS=y
        struct work_struct kobj_remove_work;     // if CONFIG_SYSFS=y && kernel < 5.9
        struct memcg_cache_params memcg_params;  // if CONFIG_MEMCG=y && kernel < 5.9
        unsigned int max_attr_size;              // if CONFIG_MEMCG=y && kernel < 5.9
        struct kset *memcg_kset;                 // if CONFIG_MEMCG=y && CONFIG_SYSFS=y && kernel < 5.9
        unsigned long random;                    // if CONFIG_SLAB_FREELIST_HARDENED=y
        unsigned int remote_node_defrag_ratio;   // if CONFIG_NUMA=y
        unsigned int *random_seq;                // if CONFIG_SLAB_FREELIST_RANDOM=y
        struct kasan_cache {
            int alloc_meta_offset;
            int free_meta_offset;
            bool is_kmalloc;
        } kasan_info;                            // if CONFIG_KASAN=y
        unsigned int useroffset;                 // kernel < 6.2 || (6.2 <= kernel && CONFIG_HARDENED_USERCOPY=y)
        unsigned int usersize;                   // kernel < 6.2 || (6.2 <= kernel && CONFIG_HARDENED_USERCOPY=y)
        struct kmem_cache_stats __percpu *cpu_stats // CONFIG_SLUB_STATS && 7.0 <= kernel
        struct kmem_cache_node *node[MAX_NUMNODES]; // kernel < 7.1 (<-- this includes SPINLOCK_MAGIC if CONFIG_DEBUG_SPINLOCK=y)
        struct kmem_cache_per_node_ptrs {           // 7.1 <= kernel
            struct node_barn *barn;                 // 7.1 <= kernel
            struct kmem_cache_node *node;           // 7.1 <= kernel
        } per_node[MAX_NUMNODES];                   // 7.1 <= kernel
    };

    struct kmem_cache_cpu {
        void **freelist;
        unsigned long tid;
        struct page *page;                       // if kernel < 5.17
        struct page *partial;                    // if kernel < 5.17 && CONFIG_SLUB_CPU_PARTIAL=y
        struct slab *slab;                       // if 5.17 <= kernel
        struct slab *partial;                    // if 5.17 <= kernel && CONFIG_SLUB_CPU_PARTIAL=y
        local_lock_t lock;                       // if 5.15 <= kernel
        unsigned stat[NR_SLUB_STAT_ITEMS];       // if CONFIG_SLUB_STATS=y
    };

    struct page {                                // if kernel < 4.18
        unsigned long flags;
        union { };                               // long
        void *freelist;
        unsigned inuse:16, objects:15, frozen:1;
        atomic_t _refcount;                      // if kernel < 4.16
        struct page *next;
        int pages;                               // if 64bit else `short pages`
        int pobjects;                            // if 64bit else `short pobjects`
        struct kmem_cache *slab_cache;
        struct mem_cgroup *mem_cgroup;           // if CONFIG_MEMCG=y
        void *virtual;                           // if CONFIG_WANT_PAGE_VIRTUAL=y
        void *shadow;                            // if CONFIG_KMEMCHECK=y && kernel < 4.14
        int _last_cpuid;                         // if CONFIG_LAST_CPUPID_NOT_IN_PAGE_FLAGS=y
    };

    struct page {                                // if 4.18 <= kernel < 5.17
        unsigned long flags;
        struct page *next;
        int pages;                               // if 64bit else `short pages`
        int pobjects;                            // if 64bit else `short pobjects`
        struct kmem_cache *slab_cache;
        void *freelist;
        unsigned inuse:16, objects:15, frozen:1;
        union {};                                // unsigned int
        atomic_t _refcount;
        unsigned long memcg_data;                // if CONFIG_MEMCG=y && 5.10 <= kernel
        struct mem_cgroup *mem_cgroup;           // if CONFIG_MEMCG=y && kernel < 5.10
        void *virtual;                           // if CONFIG_WANT_PAGE_VIRTUAL=y
        int _last_cpuid;                         // if CONFIG_LAST_CPUPID_NOT_IN_PAGE_FLAGS=y
    };

    struct slab {                                // if CONFIG_SLAB_VIRTUAL=n && 5.17 <= kernel < 6.2
        unsigned long __page_flags;
        struct slab *next;
        int slabs;
        struct kmem_cache *slab_cache;
        void *freelist;
        unsigned inuse:16, objects:15, frozen:1;
        unsigned int __unused;
        atomic_t __page_refcount;
        unsigned long memcg_data;                // if CONFIG_MEMCG=y
    };

    struct slab {                                // if CONFIG_SLAB_VIRTUAL=n && 6.2 <= kernel < 6.10
        unsigned long __page_flags;
        struct kmem_cache *slab_cache;
        struct slab *next;
        int slabs;
        void *freelist;
        unsigned inuse:16, objects:15, frozen:1;
        unsigned int __unused;
        atomic_t __page_refcount;
        unsigned long memcg_data;                // if CONFIG_MEMCG=y
    };

    struct slab {                                // if CONFIG_SLAB_VIRTUAL=n && 6.10 <= kernel
        unsigned long __page_flags;              // if kernel < 6.18
        memdesc_flags_t flags;                   // if 6.18 <= kernel
        struct kmem_cache *slab_cache;
        struct slab *next;
        int slabs;
        void *freelist;
        unsigned inuse:16, objects:15, frozen:1;
        unsigned int __page_type;
        atomic_t __page_refcount;
        unsigned long obj_exts;                  // if CONFIG_SLAB_OBJ_EXT=y
    };

    struct kmem_cache_node {
        spinlock_t list_lock;
        unsigned long nr_partial;
        struct list_head partial;
        atomic_long_t nr_slabs;                  // if CONFIG_SLUB_DEBUG=y
        atomic_long_t total_objects;             // if CONFIG_SLUB_DEBUG=y
        struct list_head full;                   // if CONFIG_SLUB_DEBUG=y
        struct node_barn *barn;                  // 6.18 <= kernel < 7.1
    };
    """

    # CONFIG_SLAB_VIRTUAL=y
    """
    struct kmem_cache {                          // if CONFIG_SLAB_VIRTUAL=y
        ...
        struct kmem_cache_order_objects min;     // [ANNOTATION]
        struct kmem_cache_order_objects oo;      //    In kernel < 6.1.56, `min` and `oo` are swapped.
        unsigned long nr_freed_pages;            // if CONFIG_SLAB_VIRTUAL=y && kernel < 6.1.56
        struct list_head freed_slabs_normal;     // if CONFIG_SLAB_VIRTUAL=y && kernel < 6.1.56
        struct list_head freed_slabs_min;        // if CONFIG_SLAB_VIRTUAL=y && kernel < 6.1.56
        spinlock_t freed_slabs_lock;             // if CONFIG_SLAB_VIRTUAL=y && kernel < 6.1.56
        struct kmem_cache_virtual {              // if CONFIG_SLAB_VIRTUAL=y && 6.1.56 <= kernel
            spinlock_t freed_slabs_lock;         // if CONFIG_SLAB_VIRTUAL=y && 6.1.56 <= kernel
            struct list_head freed_slabs;        // if CONFIG_SLAB_VIRTUAL=y && 6.1.56 <= kernel
            struct list_head freed_slabs_min;    // if CONFIG_SLAB_VIRTUAL=y && 6.1.56 <= kernel
            unsigned long nr_freed_pages;        // if CONFIG_SLAB_VIRTUAL=y && 6.1.56 <= kernel
        } virtual;                               // if CONFIG_SLAB_VIRTUAL=y && 6.1.56 <= kernel
        gfp_t allocflags;
        ...
        const char * name;
        struct list_head list; <-----> struct list_head <-----> struct list_head <-----> ...
        ...
    };

    struct slab {                                // if CONFIG_SLAB_VIRTUAL=y && kernel < 6.6
        struct slab *compound_slab_head;
        struct folio *backing_folio;
        struct kmem_cache_order_objects oo;
        spinlock_t slab_lists_lock;
        struct list_head flush_list_elem;
        unsigned long align_mask;
        atomic_t pinstate;
        struct slab *next;
        int slabs;
        struct kmem_cache *slab_cache;
        void *freelist;
        unsigned inuse:16, objects:15, frozen:1;
        unsigned int __unused;
        unsigned long memcg_data;                // if CONFIG_MEMCG=y
    };

    struct slab {                                // if CONFIG_SLAB_VIRTUAL=y && 6.6 <= kernel < 6.12
        struct folio *backing_folio;
        struct kmem_cache *slab_cache;
        struct slab *next;
        int slabs;
        void *freelist;
        unsigned inuse:16, objects:15, frozen:1;
        struct kmem_cache_order_objects oo;
        spinlock_t slab_lock;
        unsigned long memcg_data;                // if CONFIG_MEMCG=y
    }

    struct virtual_slab {                        // if CONFIG_SLAB_VIRTUAL=y && 6.6 <= kernel < 6.12
        struct slab slab;
        struct virtual_slab *compound_slab_head;
        unsigned long align_mask;
    };

    struct slab {                                // if CONFIG_SLAB_VIRTUAL=y && 6.12 <= kernel
        struct slab *compound_slab_head;
        struct folio *backing_folio;
        struct kmem_cache_order_objects oo;
        struct list_head flush_list_elem;
        unsigned long align_mask;
        spinlock_t slab_lock;
        struct kmem_cache *slab_cache;
        struct slab *next;
        int slabs;
        void *freelist;
        unsigned inuse:16, objects:15, frozen:1;
        unsigned long obj_exts                   // if CONFIG_SLAB_OBJ_EXT=y
    };
    """

    def initialize(self):
        from gef.commands.kernel.basic import KernelCurrentCommand
        if hasattr(self, "initialized") and self.initialized:
            if not self.args.meta and not self.args.rescan:
                return True

        kversion = Kernel.kernel_version()
        if not kversion:
            self.quiet_err("Failed to resolve kernel version")
            return False

        # resolve slab_caches
        self.slab_caches = KernelAddressHeuristicFinder.get_slab_caches()
        if self.slab_caches is None:
            self.quiet_err("Failed to resolve `slab_caches`")
            return False
        else:
            self.quiet_info("slab_caches: {:#x}".format(self.slab_caches))

        # resolve __per_cpu_offset
        __per_cpu_offset = KernelAddressHeuristicFinder.get_per_cpu_offset()
        if __per_cpu_offset is None:
            self.quiet_info("__per_cpu_offset: Not found")
            self.cpu_offset = []
            self.ncpus = 1
        else:
            self.quiet_info("__per_cpu_offset: {:#x}".format(__per_cpu_offset))
            self.cpu_offset = KernelCurrentCommand.get_each_cpu_offset(__per_cpu_offset)
            self.ncpus = len(self.cpu_offset)

        # offsetof(kmem_cache, list)
        self.resolve_kmem_cache_offset_list()
        if self.kmem_cache_offset_list is None:
            self.quiet_info("offsetof(kmem_cache, list): Not found")
            return False
        self.quiet_info("offsetof(kmem_cache, list): {:#x}".format(self.kmem_cache_offset_list))

        # offsetof(kmem_cache, name)
        self.kmem_cache_offset_name = self.kmem_cache_offset_list - runtime.current_arch.ptrsize
        self.quiet_info("offsetof(kmem_cache, name): {:#x}".format(self.kmem_cache_offset_name))

        # for CONFIG_SLAB_VIRTUAL
        self.resolve_for_CONFIG_SLAB_VIRTUAL()

        # offsetof(kmem_cache, cpu_slab)
        if kversion < "7.0":
            self.kmem_cache_offset_cpu_slab = 0
            self.quiet_info("offsetof(kmem_cache, cpu_slab): {:#x}".format(self.kmem_cache_offset_cpu_slab))

        # offsetof(kmem_cache, flags)
        if kversion < "6.18":
            self.kmem_cache_offset_flags = runtime.current_arch.ptrsize
        elif kversion < "7.0":
            CONFIG_LOCKDEP = Symbol.get_ksymaddr("fs_reclaim_acquire")
            if CONFIG_LOCKDEP:
                self.kmem_cache_offset_flags = runtime.current_arch.ptrsize * 4
            else:
                self.kmem_cache_offset_flags = runtime.current_arch.ptrsize * 2
        else:
            self.kmem_cache_offset_flags = runtime.current_arch.ptrsize
        self.quiet_info("offsetof(kmem_cache, flags): {:#x}".format(self.kmem_cache_offset_flags))

        # offsetof(kmem_cache, cpu_sheaves)
        if kversion < "6.18":
            self.kmem_cache_offset_cpu_sheaves = None
        else:
            self.kmem_cache_offset_cpu_sheaves = self.kmem_cache_offset_flags - runtime.current_arch.ptrsize
            self.quiet_info("offsetof(kmem_cache, cpu_sheaves): {:#x}".format(self.kmem_cache_offset_cpu_sheaves))

        # offsetof(kmem_cache, size)
        self.kmem_cache_offset_size = self.kmem_cache_offset_flags + runtime.current_arch.ptrsize * 2
        self.quiet_info("offsetof(kmem_cache, size): {:#x}".format(self.kmem_cache_offset_size))

        # offsetof(kmem_cache, object_size)
        self.kmem_cache_offset_object_size = self.kmem_cache_offset_size + 4
        self.quiet_info("offsetof(kmem_cache, object_size): {:#x}".format(self.kmem_cache_offset_object_size))

        # offsetof(kmem_cache, offset)
        if kversion < "5.9":
            self.kmem_cache_offset_offset = self.kmem_cache_offset_object_size + 4
        else:
            self.kmem_cache_offset_offset = self.kmem_cache_offset_object_size + 4 + 8
        self.quiet_info("offsetof(kmem_cache, offset): {:#x}".format(self.kmem_cache_offset_offset))

        # offsetof(kmem_cache, red_left_pad)
        self.kmem_cache_offset_red_left_pad = self.kmem_cache_offset_name - runtime.current_arch.ptrsize
        self.quiet_info("offsetof(kmem_cache, red_left_pad): {:#x}".format(self.kmem_cache_offset_red_left_pad))

        # offsetof(kmem_cache, random)
        self.resolve_kmem_cache_offset_random()
        if self.kmem_cache_offset_random is None:
            self.quiet_info("offsetof(kmem_cache, random): Not found")
        else:
            self.quiet_info("offsetof(kmem_cache, random): {:#x}".format(self.kmem_cache_offset_random))

        # offsetof(kmem_cache, node) or offsetof(kmem_cache, per_node[0].node/barn)
        self.resolve_kmem_cache_offset_node()
        if kversion < "7.1":
            if self.kmem_cache_offset_node is None:
                self.quiet_info("offsetof(kmem_cache, node): Not found")
            else:
                self.quiet_info("offsetof(kmem_cache, node): {:#x}".format(self.kmem_cache_offset_node))
        else:
            if self.kmem_cache_offset_node is None:
                self.quiet_info("offsetof(kmem_cache, per_node[0].node): Not found")
            else:
                self.quiet_info("offsetof(kmem_cache, per_node[0].node): {:#x}".format(self.kmem_cache_offset_node))
            if self.kmem_cache_offset_barn is None:
                self.quiet_info("offsetof(kmem_cache, per_node[0].barn): Not found")
            else:
                self.quiet_info("offsetof(kmem_cache, per_node[0].barn): {:#x}".format(self.kmem_cache_offset_barn))

        if kversion < "7.0":
            # offsetof(kmem_cache_cpu, freelist)
            self.kmem_cache_cpu_offset_freelist = 0
            self.quiet_info("offsetof(kmem_cache_cpu, freelist): {:#x}".format(self.kmem_cache_cpu_offset_freelist))

            # offsetof(kmem_cache_cpu, page or slab)
            self.kmem_cache_cpu_offset_page = runtime.current_arch.ptrsize * 2
            self.quiet_info("offsetof(kmem_cache_cpu, {:s}): {:#x}".format(
                Kernel.slab_page_str(), self.kmem_cache_cpu_offset_page,
            ))

            # offsetof(kmem_cache_cpu, partial)
            self.kmem_cache_cpu_offset_partial = runtime.current_arch.ptrsize * 3
            self.quiet_info("offsetof(kmem_cache_cpu, partial): {:#x}".format(self.kmem_cache_cpu_offset_partial))

        # offsetof(page, next) / offsetof(slab, next)
        if self.slab_virtual_enabled:
            if kversion < "6.6":
                self.page_offset_next = runtime.current_arch.ptrsize * 7
            elif kversion < "6.12":
                self.page_offset_next = runtime.current_arch.ptrsize * 2
            else: # 6.12
                self.page_offset_next = runtime.current_arch.ptrsize * 8
        else:
            if kversion < "4.16" and is_32bit():
                self.page_offset_next = runtime.current_arch.ptrsize * 5
            elif kversion < "4.18":
                self.page_offset_next = runtime.current_arch.ptrsize * 4
            elif kversion < "5.17":
                self.page_offset_next = runtime.current_arch.ptrsize
            elif kversion < "6.2":
                self.page_offset_next = runtime.current_arch.ptrsize
            else:
                self.page_offset_next = runtime.current_arch.ptrsize * 2
        self.quiet_info("offsetof({:s}, next): {:#x}".format(
            Kernel.slab_page_str(), self.page_offset_next,
        ))

        # offsetof(page, freelist) / offsetof(slab, freelist)
        if self.slab_virtual_enabled:
            if kversion < "6.6":
                self.page_offset_freelist = runtime.current_arch.ptrsize * 10
            elif kversion < "6.12":
                self.page_offset_freelist = runtime.current_arch.ptrsize * 4
            else: # 6.12
                self.page_offset_freelist = runtime.current_arch.ptrsize * 10
        else:
            if kversion < "4.18":
                self.page_offset_freelist = runtime.current_arch.ptrsize * 2
            elif kversion < "5.17":
                self.page_offset_freelist = runtime.current_arch.ptrsize * 4
            elif kversion < "6.2":
                self.page_offset_freelist = runtime.current_arch.ptrsize * 4
            else:
                self.page_offset_freelist = runtime.current_arch.ptrsize * 4
        self.quiet_info("offsetof({:s}, freelist): {:#x}".format(
            Kernel.slab_page_str(), self.page_offset_freelist,
        ))

        # offsetof(page, slab_cache) / offsetof(slab, slab_cache)
        if self.slab_virtual_enabled:
            if kversion < "6.6":
                self.page_offset_slab_cache = runtime.current_arch.ptrsize * 9
            elif kversion < "6.12":
                self.page_offset_slab_cache = runtime.current_arch.ptrsize
            else: # 6.12
                self.page_offset_slab_cache = runtime.current_arch.ptrsize * 7
        else:
            if kversion < "4.16" and is_32bit():
                self.page_offset_slab_cache = runtime.current_arch.ptrsize * 7
            elif kversion < "4.18":
                self.page_offset_slab_cache = runtime.current_arch.ptrsize * 6
            elif kversion < "5.17":
                self.page_offset_slab_cache = runtime.current_arch.ptrsize * 3
            elif kversion < "6.2":
                self.page_offset_slab_cache = runtime.current_arch.ptrsize * 3
            else:
                self.page_offset_slab_cache = runtime.current_arch.ptrsize
        self.quiet_info("offsetof({:s}, slab_cache): {:#x}".format(
            Kernel.slab_page_str(), self.page_offset_slab_cache,
        ))

        # offsetof(page, inuse_objects_frozen) / offsetof(slab, inuse_objects_frozen)
        self.page_offset_inuse_objects_frozen = self.page_offset_freelist + runtime.current_arch.ptrsize
        self.quiet_info("offsetof({:s}, inuse_objects_frozen): {:#x}".format(
            Kernel.slab_page_str(), self.page_offset_inuse_objects_frozen,
        ))

        # parse extra members of `struct slab` for CONFIG_SLAB_VIRTUAL=y
        if self.slab_virtual_enabled:
            # offsetof(slab, flush_list_elem)
            # [ANNOTATION]
            #   In 6.6-based implementation, the member `flush_list_elem` has been removed from `struct slab`,
            #   however, `slub_tlbflush_queue` uses the member `slab_list` or `next` (which?) for the same purpose.
            #   So, when CONFIG_SLAB_VIRTUAL=y and 6.6 or later, `flush_list_elem` means `next`.
            if kversion < "6.6":
                self.page_offset_flush_list_elem = runtime.current_arch.ptrsize * 3
            elif kversion < "6.12":
                self.page_offset_flush_list_elem = runtime.current_arch.ptrsize * 2
            else: # 6.12
                self.page_offset_flush_list_elem = runtime.current_arch.ptrsize * 3
            self.quiet_info("offsetof(slab, flush_list_elem): {:#x}".format(self.page_offset_flush_list_elem))

        # offsetof(kmem_cache_node, partial)
        self.resolve_kmem_cache_node_offset_partial()
        if self.kmem_cache_node_offset_partial is None:
            self.quiet_info("offsetof(kmem_cache_node, partial): Not found")
        else:
            self.quiet_info("offsetof(kmem_cache_node, partial): {:#x}".format(self.kmem_cache_node_offset_partial))

        # offsetof(kmem_cache_node, full)
        if self.kmem_cache_node_offset_partial is None:
            self.kmem_cache_node_offset_full = None
        else:
            self.kmem_cache_node_offset_full = self.kmem_cache_node_offset_partial + runtime.current_arch.ptrsize * 4

        # for sheaves / barn
        self.resolve_sheaves()

        self.initialized = True
        return True

    @staticmethod
    def get_flags_str(flags_value):
        kversion = Kernel.kernel_version()
        if kversion < "4.6":
            flags_dic = {
                0x8000_0000: "__OBJECT_POISON", # v3.1 <= kernel
                0x4000_0000: "__CMPXCHG_DOUBLE", # v3.1 <= kernel
                #0x2000_0000: "",
                #0x1000_0000: "",
                #0x0800_0000: "",
                0x0400_0000: "SLAB_ACCOUNT", # v4.5 <= kernel
                0x0200_0000: "SLAB_FAILSLAB",
                0x0100_0000: "SLAB_NOTRACK",
                0x0080_0000: "SLAB_NOLEAKTRACE",
                0x0040_0000: "SLAB_DEBUG_OBJECTS",
                0x0020_0000: "SLAB_TRACE",
                0x0010_0000: "SLAB_MEM_SPREAD",
                0x0008_0000: "SLAB_DESTROY_BY_RCU",
                0x0004_0000: "SLAB_PANIC",
                0x0002_0000: "SLAB_RECLAIM_ACCOUNT",
                0x0001_0000: "SLAB_STORE_USER",
                #0x0000_8000: "",
                0x0000_4000: "SLAB_CACHE_DMA",
                0x0000_2000: "SLAB_HWCACHE_ALIGN",
                #0x0000_1000: "",
                0x0000_0800: "SLAB_POISON",
                0x0000_0400: "SLAB_RED_ZONE",
                0x0000_0200: "SLAB_DEBUG_INITIAL", # kernel < v2.6.22
                0x0000_0100: "SLAB_DEBUG_FREE",
            }
        elif kversion < "4.12":
            flags_dic = {
                0x8000_0000: "__OBJECT_POISON",
                0x4000_0000: "__CMPXCHG_DOUBLE",
                #0x2000_0000: "",
                #0x1000_0000: "",
                0x0800_0000: "SLAB_KASAN", # v4.6 <= kernel
                0x0400_0000: "SLAB_ACCOUNT",
                0x0200_0000: "SLAB_FAILSLAB",
                0x0100_0000: "SLAB_NOTRACK",
                0x0080_0000: "SLAB_NOLEAKTRACE",
                0x0040_0000: "SLAB_DEBUG_OBJECTS",
                0x0020_0000: "SLAB_TRACE",
                0x0010_0000: "SLAB_MEM_SPREAD",
                0x0008_0000: "SLAB_DESTROY_BY_RCU",
                0x0004_0000: "SLAB_PANIC",
                0x0002_0000: "SLAB_RECLAIM_ACCOUNT",
                0x0001_0000: "SLAB_STORE_USER",
                #0x0000_8000: "",
                0x0000_4000: "SLAB_CACHE_DMA",
                0x0000_2000: "SLAB_HWCACHE_ALIGN",
                #0x0000_1000: "",
                0x0000_0800: "SLAB_POISON",
                0x0000_0400: "SLAB_RED_ZONE",
                #0x0000_0200: "",
                0x0000_0100: "SLAB_CONSISTENCY_CHECKS", # v4.6 <= kernel
            }
        elif kversion < "5.19":
            flags_dic = {
                0x8000_0000: "__OBJECT_POISON",
                0x4000_0000: "__CMPXCHG_DOUBLE",
                #0x2000_0000: "",
                0x1000_0000: "SLAB_DEACTIVATED", # v5.3 <= kernel < v5.18
                0x0800_0000: "SLAB_KASAN",
                0x0400_0000: "SLAB_ACCOUNT",
                0x0200_0000: "SLAB_FAILSLAB",
                0x0100_0000: "SLAB_NOTRACK", # kernel < v4.14.21
                0x0080_0000: "SLAB_NOLEAKTRACE",
                0x0040_0000: "SLAB_DEBUG_OBJECTS",
                0x0020_0000: "SLAB_TRACE",
                0x0010_0000: "SLAB_MEM_SPREAD",
                0x0008_0000: "SLAB_TYPESAFE_BY_RCU", # v4.12 <= kernel
                0x0004_0000: "SLAB_PANIC",
                0x0002_0000: "SLAB_RECLAIM_ACCOUNT",
                0x0001_0000: "SLAB_STORE_USER",
                0x0000_8000: "SLAB_CACHE_DMA32", # v4.19.33 <= kernel < v4.20, v5.0 <= kernel
                0x0000_4000: "SLAB_CACHE_DMA",
                0x0000_2000: "SLAB_HWCACHE_ALIGN",
                #0x0000_1000: "",
                0x0000_0800: "SLAB_POISON",
                0x0000_0400: "SLAB_RED_ZONE",
                #0x0000_0200: "",
                0x0000_0100: "SLAB_CONSISTENCY_CHECKS",
            }
        elif kversion < "6.9":
            flags_dic = {
                0x8000_0000: "__OBJECT_POISON",
                0x4000_0000: "__CMPXCHG_DOUBLE",
                0x2000_0000: "SLAB_SKIP_KFENCE", # v6.1 <= kernel
                0x1000_0000: "SLAB_NO_USER_FLAGS", # v5.19 <= kernel
                0x0800_0000: "SLAB_KASAN",
                0x0400_0000: "SLAB_ACCOUNT",
                0x0200_0000: "SLAB_FAILSLAB",
                0x0100_0000: "SLAB_NO_MERGE", # v6.5 <= kernel
                0x0080_0000: "SLAB_NOLEAKTRACE",
                0x0040_0000: "SLAB_DEBUG_OBJECTS",
                0x0020_0000: "SLAB_TRACE",
                0x0010_0000: "SLAB_MEM_SPREAD",
                0x0008_0000: "SLAB_TYPESAFE_BY_RCU",
                0x0004_0000: "SLAB_PANIC",
                0x0002_0000: "SLAB_RECLAIM_ACCOUNT",
                0x0001_0000: "SLAB_STORE_USER",
                0x0000_8000: "SLAB_CACHE_DMA32",
                0x0000_4000: "SLAB_CACHE_DMA",
                0x0000_2000: "SLAB_HWCACHE_ALIGN",
                0x0000_1000: "SLAB_KMALLOC", # v6.1 <= kernel
                0x0000_0800: "SLAB_POISON",
                0x0000_0400: "SLAB_RED_ZONE",
                #0x0000_0200: "",
                0x0000_0100: "SLAB_CONSISTENCY_CHECKS",
            }
        else:
            flags_dic = {
                0x0000_0400: "SLAB_TRACE",
                0x0000_0200: "SLAB_TYPESAFE_BY_RCU",
                0x0000_0100: "SLAB_PANIC",
                0x0000_0080: "SLAB_STORE_USER",
                0x0000_0040: "SLAB_CACHE_DMA32",
                0x0000_0020: "SLAB_CACHE_DMA",
                0x0000_0010: "SLAB_HWCACHE_ALIGN",
                0x0000_0008: "SLAB_KMALLOC",
                0x0000_0004: "SLAB_POISON",
                0x0000_0002: "SLAB_RED_ZONE",
                0x0000_0001: "SLAB_CONSISTENCY_CHECKS",
            }
        flags = []
        unparsed_flags = flags_value
        for k, v in flags_dic.items():
            if flags_value & k:
                flags.append(v)
                unparsed_flags &= ~k
        flags.append(hex(unparsed_flags))

        flags_str = " | ".join(flags)
        if flags_str == "":
            flags_str = "none"
        return flags_str

    def get_next_kmem_cache(self, addr, point_to_base=True):
        if point_to_base:
            addr += self.kmem_cache_offset_list
        if self.args.reverse_walk:
            return read_int_from_memory(addr) - self.kmem_cache_offset_list
        else:
            return read_int_from_memory(addr + runtime.current_arch.ptrsize) - self.kmem_cache_offset_list

    def get_name(self, addr):
        name_addr = read_int_from_memory(addr + self.kmem_cache_offset_name)
        return read_cstring_from_memory(name_addr)

    def get_random(self, addr):
        if self.kmem_cache_offset_random is None:
            return 0
        else:
            return read_int_from_memory(addr + self.kmem_cache_offset_random)

    def get_kmem_cache_cpu(self, addr, cpu):
        cpu_slab = read_int_from_memory(addr + self.kmem_cache_offset_cpu_slab)
        if len(self.cpu_offset) > 0:
            kmem_cache_cpu = cpu_slab + self.cpu_offset[cpu]
        else:
            kmem_cache_cpu = cpu_slab
        return AddressUtil.normalize_address(kmem_cache_cpu)

    def page2virt(self, page, kmem_cache, freelist_fastpath=()):
        if self.slab_virtual_enabled:
            ret = gdb.execute("slab-virtual --quiet to_virt {:#x}".format(page["address"]), to_string=True)
            r = re.search(r"Virt: (\S+)", ret)
            if r:
                return int(r.group(1), 16)
            return None

        if not self.args.skip_page2virt:
            r = Kernel.page2virt(page["address"])
            if r is not None:
                return r

        # set up for heuristic search from freelist
        freelist = list(freelist_fastpath) + page["freelist"]
        freelist = [x for x in freelist if isinstance(x, int) and x != 0] # ignore str and 0
        if not freelist:
            return None

        # heuristic detection pattern 1
        # freed chunks are scattered and can be confirmed on each of the pages
        page_heads = [x & get_pagesize_mask_high() for x in freelist]
        uniq_page_heads = list(set(page_heads))
        if page["num_pages"] == len(uniq_page_heads):
            return min(uniq_page_heads)

        # heuristic detection pattern 2
        # if there is only one pattern with good alignment, use it
        # e.g., num_pages = 5
        # 0xXXXX0000
        # 0xXXXX1000   <----------------------------------- most_top_page   ^
        # 0xXXXX2000                                                       ^|
        # 0xXXXX3000   <-- chunk in freelist (min_page) ^                 ^||
        # 0xXXXX4000                                    | known_num_pages |||
        # 0xXXXX5000   <-- chunk in freelist (max_page) v                 ||v pattern 3
        # 0xXXXX6000                                                      |v pattern 2
        # 0xXXXX7000                                                      v pattern 1
        chunk_size = kmem_cache["size"]
        min_page = min(freelist) & get_pagesize_mask_high()
        max_page = max(freelist) & get_pagesize_mask_high()
        known_num_pages = ((max_page - min_page) // get_pagesize()) + 1
        unknown_num_pages = page["num_pages"] - known_num_pages
        most_top_page = min_page - (unknown_num_pages * get_pagesize())
        candidate_top_pages = range(most_top_page, min_page + get_pagesize(), get_pagesize())
        # alignment check for each candidate_top_pages
        valid_top_pages = []
        for cand_top in candidate_top_pages:
            for chunk in freelist:
                # divisible?
                if (chunk - cand_top) % chunk_size != 0:
                    break
            else:
                valid_top_pages.append(cand_top)
            # fast break if invalid
            if len(valid_top_pages) >= 2:
                break
        # confirm if there is only one valid pattern
        if len(valid_top_pages) == 1:
            return valid_top_pages[0]

        # not found
        return None

    def pointer_xor(self, addr, chunk, cache):

        def pattern1(addr, chunk, cache):
            return chunk ^ addr ^ cache["random"]

        def pattern2(addr, chunk, cache):
            return chunk ^ byteswap(addr) ^ cache["random"]

        if is_64bit():
            shift_bits = 48
        else:
            shift_bits = 24

        if self.swap is False:
            chunk = pattern1(addr, chunk, cache)
        elif self.swap is True:
            chunk = pattern2(addr, chunk, cache)

        elif self.swap is None: # swap type is unknown, try heuristic check
            if pattern1(addr, chunk, cache) == 0:
                chunk = pattern1(addr, chunk, cache)
                self.swap = False
            elif (chunk >> shift_bits) == (cache["random"] >> shift_bits):
                chunk = pattern1(addr, chunk, cache)
                self.swap = False
            else:
                chunk = pattern2(addr, chunk, cache)
                self.swap = True
        return chunk

    def walk_freelist(self, chunk, kmem_cache):
        if self.args.simple:
            return [chunk]

        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")

        freelist = [chunk]
        while chunk:
            try:
                addr = chunk + kmem_cache["offset"]
                chunk = read_int_from_memory(addr) # get next chunk
            except gdb.MemoryError:
                freelist.append("{:s}".format(
                    Color.colorify("Corrupted (Memory access denied)", corrupted_msg_color),
                ))
                break
            if self.kmem_cache_offset_random is not None: # fix if randomized
                chunk = self.pointer_xor(addr, chunk, kmem_cache)
            if chunk % 8:
                freelist.append("{:#x}: {:s}".format(
                    chunk, Color.colorify("Corrupted (Not aligned)", corrupted_msg_color),
                ))
                break
            if chunk in freelist:
                freelist.append("{:#x}: {:s}".format(
                    chunk, Color.colorify("Corrupted (Loop detected)", corrupted_msg_color),
                ))
                break
            freelist.append(chunk)
        return freelist

    def walk_caches_active_page(self, cpu, kmem_cache):
        active_page = {}
        active_page["address"] = page = read_int_from_memory(
            kmem_cache["kmem_cache_cpu"][cpu]["address"] + self.kmem_cache_cpu_offset_page,
        )
        if is_valid_addr(page):
            x = read_int_from_memory(page + self.page_offset_inuse_objects_frozen)
            active_page["inuse"] = x & 0xffff
            active_page["objects"] = (x >> 16) & 0x7fff
            active_page["frozen"] = (x >> 31) & 1
            active_chunk = read_int_from_memory(page + self.page_offset_freelist)
            active_page["freelist"] = self.walk_freelist(active_chunk, kmem_cache)
            active_page["num_pages"] = (
                kmem_cache["size"] * active_page["objects"] + get_pagesize_mask_low()
            ) // get_pagesize()

            active_page["virt_addr"] = self.page2virt(
                active_page, kmem_cache, kmem_cache["kmem_cache_cpu"][cpu]["freelist"]
            )

        kmem_cache["kmem_cache_cpu"][cpu]["active_page"] = active_page
        return

    def walk_caches_partial_page(self, cpu, kmem_cache):
        kmem_cache["kmem_cache_cpu"][cpu]["partial_pages"] = []
        current_partial_page = read_int_from_memory(
            kmem_cache["kmem_cache_cpu"][cpu]["address"] + self.kmem_cache_cpu_offset_partial,
        )
        while True:
            partial_page = {}
            partial_page["address"] = current_partial_page
            if not is_valid_addr(current_partial_page):
                kmem_cache["kmem_cache_cpu"][cpu]["partial_pages"].append(partial_page)
                break
            x = read_int_from_memory(current_partial_page + self.page_offset_inuse_objects_frozen)
            partial_page["inuse"] = x & 0xffff
            partial_page["objects"] = (x >> 16) & 0x7fff
            if partial_page["objects"] == 0 or partial_page["inuse"] > partial_page["objects"]:
                break # something is wrong
            partial_page["frozen"] = (x >> 31) & 1
            partial_chunk = read_int_from_memory(current_partial_page + self.page_offset_freelist)
            partial_page["freelist"] = self.walk_freelist(partial_chunk, kmem_cache)
            partial_page["num_pages"] = (
                kmem_cache["size"] * partial_page["objects"] + get_pagesize_mask_low()
            ) // get_pagesize()
            partial_page["virt_addr"] = self.page2virt(partial_page, kmem_cache)
            kmem_cache["kmem_cache_cpu"][cpu]["partial_pages"].append(partial_page)
            next_partial_page = read_int_from_memory(current_partial_page + self.page_offset_next)
            if next_partial_page in [x["address"] for x in kmem_cache["kmem_cache_cpu"][cpu]["partial_pages"]]:
                break
            current_partial_page = next_partial_page
        return

    def walk_node_list(self, kmem_cache, kmem_cache_node, offset_list): # use different offsets
        node_page_list = []
        node_page_head = kmem_cache_node + offset_list
        if not is_valid_addr(node_page_head):
            return node_page_list
        current_node_page = read_int_from_memory(node_page_head)
        while current_node_page != node_page_head:
            node_page = {}
            node_page["address"] = current_node_page - self.page_offset_next
            if not is_valid_addr(node_page["address"]):
                node_page_list.append(node_page)
                break
            x = read_int_from_memory(node_page["address"] + self.page_offset_inuse_objects_frozen)
            node_page["inuse"] = x & 0xffff
            node_page["objects"] = (x >> 16) & 0x7fff
            if node_page["objects"] == 0 or node_page["inuse"] > node_page["objects"]:
                break # something is wrong
            node_page["frozen"] = (x >> 31) & 1
            node_chunk = read_int_from_memory(node_page["address"] + self.page_offset_freelist)
            node_page["freelist"] = self.walk_freelist(node_chunk, kmem_cache)
            node_page["num_pages"] = (
                kmem_cache["size"] * node_page["objects"] + get_pagesize_mask_low()
            ) // get_pagesize()
            node_page["virt_addr"] = self.page2virt(node_page, kmem_cache)
            node_page_list.append(node_page)
            current_node_page = read_int_from_memory(node_page["address"] + self.page_offset_next)
        return node_page_list

    # for sheaf / barn
    def walk_node_barn_list(self, kmem_cache, kmem_cache_node, node_index):
        if not self.sheaves_enabled:
            return

        if "node_barn" not in kmem_cache:
            kmem_cache["node_barn"] = []

        def read_link_list(addr):
            seen = []
            while is_valid_addr(addr):
                if addr in seen:
                    break
                seen.append(addr)
                addr = read_int_from_memory(addr)
            if len(seen) >= 1:
                seen = seen[1:] # skip first
            return seen

        node_barn = {}
        node_barn["address"] = self.get_node_barn(kmem_cache["address"], kmem_cache_node, node_index)
        if is_valid_addr(node_barn["address"]):
            # full
            node_barn["sheaves_full"] = []
            sheaves_full = read_link_list(node_barn["address"] + self.node_barn_offset_sheaves_full)
            for addr in sheaves_full:
                sheaf = self.walk_sheaf(addr - self.slab_sheaf_offset_barn_list, kmem_cache["address"])
                node_barn["sheaves_full"].append(sheaf)

            # empty
            node_barn["sheaves_empty"] = []
            sheaves_empty = read_link_list(node_barn["address"] + self.node_barn_offset_sheaves_empty)
            for addr in sheaves_empty:
                sheaf = self.walk_sheaf(addr - self.slab_sheaf_offset_barn_list, kmem_cache["address"])
                node_barn["sheaves_empty"].append(sheaf)

        kmem_cache["node_barn"].append(node_barn)
        return

    def walk_caches_node_page(self, kmem_cache):
        if not self.kmem_cache_offset_node:
            return
        if not self.kmem_cache_node_offset_partial:
            return

        kmem_cache["nodes_partial"] = []
        if self.args.slub_debug_y:
            kmem_cache["nodes_full"] = []

        kmem_cache_node_array = kmem_cache["address"] + self.kmem_cache_offset_node
        current_kmem_cache_node_ptr = kmem_cache_node_array
        node_index = 0
        while True:
            current_kmem_cache_node = read_int_from_memory(current_kmem_cache_node_ptr)
            if current_kmem_cache_node == 0:
                break
            if current_kmem_cache_node == current_kmem_cache_node_ptr:
                break
            if current_kmem_cache_node & 0b111:
                break

            # node list (partial)
            node_page_list_partial = self.walk_node_list(
                kmem_cache, current_kmem_cache_node, self.kmem_cache_node_offset_partial,
            )
            kmem_cache["nodes_partial"].append(node_page_list_partial)

            # node list (full; exists when CONFIG_SLUB_DEBUG=y)
            if self.args.slub_debug_y and self.kmem_cache_node_offset_full:
                node_page_list_full = self.walk_node_list(
                    kmem_cache, current_kmem_cache_node, self.kmem_cache_node_offset_full,
                )
                kmem_cache["nodes_full"].append(node_page_list_full)

            # node barn
            self.walk_node_barn_list(kmem_cache, current_kmem_cache_node, node_index)

            # goto next
            current_kmem_cache_node_ptr += self.kmem_cache_node_step
            node_index += 1
        return

    # for CONFIG_SLAB_VIRTUAL
    def walk_slab_list(self, list_head, offset_next):
        slab_list = []
        current_slab = read_int_from_memory(list_head) - offset_next
        while is_valid_addr(current_slab) and current_slab + offset_next != list_head:
            slab = {}
            slab["address"] = current_slab
            kmem_cache = read_int_from_memory(current_slab + self.page_offset_slab_cache)
            slab["slab_cache_name"] = self.get_name(kmem_cache)
            slab_list.append(slab)
            # next slab
            current_slab = read_int_from_memory(current_slab + offset_next) - offset_next
        return slab_list

    # for sheaf / barn
    def walk_sheaf(self, addr, kmem_cache_addr):
        sheaf = {}
        sheaf["address"] = addr
        if not is_valid_addr(sheaf["address"]):
            return sheaf
        sheaf["kmem_cache"] = read_int_from_memory(sheaf["address"] + self.slab_sheaf_offset_kmem_cache)
        assert sheaf["kmem_cache"] in [0, kmem_cache_addr]
        sheaf["size"] = read_int32_from_memory(sheaf["address"] + self.slab_sheaf_offset_size)
        sheaf["objects"] = []
        for i in range(sheaf["size"]):
            v = read_int_from_memory(sheaf["address"] + self.slab_sheaf_offset_objects + runtime.current_arch.ptrsize * i)
            sheaf["objects"].append(v)
        return sheaf

    # for sheaf / barn
    def walk_cpu_sheaves(self, cpu, kmem_cache):
        if not self.sheaves_enabled:
            return

        if "cpu_sheaves" not in kmem_cache:
            kmem_cache["cpu_sheaves"] = {}

        # cpu_sheaves
        kmem_cache["cpu_sheaves"][cpu] = {}
        kmem_cache["cpu_sheaves"][cpu]["address"] = self.get_slub_percpu_sheaves(kmem_cache["address"], cpu)
        if kmem_cache["cpu_sheaves"][cpu]["address"] is None:
            return
        if self.slub_percpu_sheaves_offset_main is None:
            return

        # cpu_sheaves->main
        kmem_cache["cpu_sheaves"][cpu]["main"] = self.walk_sheaf(
            read_int_from_memory(kmem_cache["cpu_sheaves"][cpu]["address"] + self.slub_percpu_sheaves_offset_main),
            kmem_cache["address"],
        )

        # cpu_sheaves->spare
        kmem_cache["cpu_sheaves"][cpu]["spare"] = self.walk_sheaf(
            read_int_from_memory(kmem_cache["cpu_sheaves"][cpu]["address"] + self.slub_percpu_sheaves_offset_spare),
            kmem_cache["address"],
        )
        return

    # for sheaf / barn
    def get_sheaf_objects(self, kmem_cache):
        objects = []

        # cpu sheaves
        if "cpu_sheaves" in kmem_cache:
            for cpu_sheaves in kmem_cache["cpu_sheaves"].values():
                for name in ["main", "spare"]:
                    if name in cpu_sheaves and "objects" in cpu_sheaves[name]:
                        objects += cpu_sheaves[name]["objects"]

        # node barn
        if "node_barn" in kmem_cache:
            for node_barn in kmem_cache["node_barn"]:
                for name in ["sheaves_full", "sheaves_empty"]:
                    if name in node_barn:
                        for sheaf in node_barn[name]:
                            if "objects" in sheaf:
                                objects += sheaf["objects"]
        return objects

    # for sheaf / barn
    def get_page_sheaf_objects(self, kmem_cache, page):
        if page["virt_addr"] is None:
            return []

        start_addr = page["virt_addr"] + kmem_cache["red_left_pad"]
        end_addr = page["virt_addr"] + page["num_pages"] * get_pagesize()
        return [
            chunk for chunk in self.get_sheaf_objects(kmem_cache)
            if isinstance(chunk, int)
            and start_addr <= chunk < end_addr
            and (chunk - start_addr) % kmem_cache["size"] == 0
        ]

    def walk_caches(self, target_names, cpus):
        current_kmem_cache = self.get_next_kmem_cache(self.slab_caches, point_to_base=False)
        parsed_caches = [{"name": "slab_caches", "next": current_kmem_cache}]

        # first, parse kmem_cache
        while current_kmem_cache + self.kmem_cache_offset_list != self.slab_caches:
            kmem_cache = {}
            # parse member
            kmem_cache["name"] = self.get_name(current_kmem_cache)
            if target_names != [] and kmem_cache["name"] not in target_names:
                current_kmem_cache = self.get_next_kmem_cache(current_kmem_cache)
                continue
            kmem_cache["address"] = current_kmem_cache
            kmem_cache["flags"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_flags)
            kmem_cache["flags_str"] = SlubDumpCommand.get_flags_str(kmem_cache["flags"])
            kmem_cache["size"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_size)
            kmem_cache["object_size"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_object_size)
            kmem_cache["offset"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_offset)
            kmem_cache["red_left_pad"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_red_left_pad)
            kmem_cache["random"] = self.get_random(current_kmem_cache)
            kmem_cache["next"] = self.get_next_kmem_cache(current_kmem_cache)
            # parse extra members for feat. CONFIG_SLAB_VIRTUAL
            if self.slab_virtual_enabled:
                kmem_cache["nr_freed_pages"] = read_int_from_memory(current_kmem_cache + self.kmem_cache_offset_nr_freed_pages)
                kmem_cache["freed_slabs_normal"] = self.walk_slab_list(
                    current_kmem_cache + self.kmem_cache_offset_freed_slabs_normal, self.page_offset_next,
                )
                kmem_cache["freed_slabs_min"] = self.walk_slab_list(
                    current_kmem_cache + self.kmem_cache_offset_freed_slabs_min, self.page_offset_next,
                )
            parsed_caches.append(kmem_cache)

            # goto next
            current_kmem_cache = kmem_cache["next"]

            # fast break
            if target_names != [] and not (self.args.list or self.args.list_no_sort):
                parsed_names = [x["name"] for x in parsed_caches]
                if all(t in parsed_names for t in target_names):
                    break

        if self.args.list or self.args.list_no_sort:
            return parsed_caches # fast return

        # second, parse kmem_cache_cpu
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for kmem_cache in tqdm(parsed_caches[1:], leave=False): # parsed_caches[0] is slab_caches, so skip
            if self.dump_target_kmem_cache_cpu:
                # parse kmem_cache_cpu
                kmem_cache["kmem_cache_cpu"] = {}
                for cpu in cpus:
                    kmem_cache["kmem_cache_cpu"][cpu] = {}
                    kmem_cache["kmem_cache_cpu"][cpu]["address"] = self.get_kmem_cache_cpu(kmem_cache["address"], cpu)
                    active_chunk_fast = read_int_from_memory(
                        kmem_cache["kmem_cache_cpu"][cpu]["address"] + self.kmem_cache_cpu_offset_freelist,
                    )
                    kmem_cache["kmem_cache_cpu"][cpu]["freelist"] = self.walk_freelist(active_chunk_fast, kmem_cache)
                    # parse active
                    if self.dump_target_active:
                        self.walk_caches_active_page(cpu, kmem_cache)
                    # parse partial
                    if self.dump_target_partial:
                        self.walk_caches_partial_page(cpu, kmem_cache)
            # parse cpu_sheaves
            if self.dump_target_cpu_sheaves:
                # Do not use `cpus` list, use `range(self.ncpus)`.
                # Since a node page is not dedicated to a specific CPU, chunks within the node page might
                # reside in CPU 1's main sheaf, even if, for example, `--cpu 0` is specified.
                for cpu in range(self.ncpus):
                    self.walk_cpu_sheaves(cpu, kmem_cache)
            # parse node
            if self.dump_target_node:
                self.walk_caches_node_page(kmem_cache)
        return parsed_caches

    def dump_page_print_layout(self, tag, kmem_cache, page, freelist, freelist_fastpath, freelist_sheaf):
        from gef.commands.debugging.context import DereferenceCommand
        used_address_color = Config.get_gef_setting("theme.heap_chunk_address_used")
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

        if page["virt_addr"] is None:
            self.out.append("        layout: Failed to the get first page")
            return

        end_virt = page["virt_addr"] + page["num_pages"] * get_pagesize()
        start_addr = page["virt_addr"] + kmem_cache["red_left_pad"]

        if kmem_cache["red_left_pad"]:
            chunk_s = Color.colorify_hex(page["virt_addr"], used_address_color)
            self.out.append("        {:7s}   {:#05x} {:s} ({:s})".format("layout:", 0, chunk_s, "never-used"))
            start_idx = 1
        else:
            start_idx = 0

        for idx, chunk in enumerate(range(start_addr, end_virt, kmem_cache["size"]), start=start_idx):
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
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

        def print_freelist(freelist):
            for chunk_addr in freelist:
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
        label_active_color = Config.get_gef_setting("theme.heap_label_active")
        label_inactive_color = Config.get_gef_setting("theme.heap_label_inactive")
        heap_page_color = Config.get_gef_setting("theme.heap_page_address")
        slab_address_color = Config.get_gef_setting("theme.heap_slab_address")
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
        freelist_sheaf = self.get_page_sheaf_objects(kmem_cache, page)
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
        chunk_label_color = Config.get_gef_setting("theme.heap_chunk_label")
        not_mapped_virt = Config.get_gef_setting("theme.address_valid_but_none")
        slab_address_color = Config.get_gef_setting("theme.heap_slab_address")
        # dump
        queue_addr_s = Color.colorify_hex(self.slub_tlbflush_queue, slab_address_color)
        self.out.append("slub_tlbflush_queue @ {:s}".format(queue_addr_s))
        for slab in parsed_slabs:
            slab_addr = slab["address"]
            self.out.append("")
            slab_addr_s = Color.colorify_hex(slab_addr, slab_address_color)
            self.out.append("  slab: {:s}".format(slab_addr_s))
            self.out.append("    kmem_cache: {:s}".format(Color.colorify(slab["slab_cache_name"], chunk_label_color)))
            # virtual address is not mapped here
            virt = "{:#x}".format(self.page2virt_for_slab_virtual(slab_addr))
            self.out.append("    virt: {:s}".format(Color.colorify(virt, not_mapped_virt)))
        return

    # for sheaf / barn
    def dump_sheaf(self, sheaf, tag):
        from gef.commands.debugging.context import DereferenceCommand
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        slab_address_color = Config.get_gef_setting("theme.heap_slab_address")

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

        slab_address_color = Config.get_gef_setting("theme.heap_slab_address")
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
        label_active_color = Config.get_gef_setting("theme.heap_label_active")
        label_inactive_color = Config.get_gef_setting("theme.heap_label_inactive")
        slab_address_color = Config.get_gef_setting("theme.heap_slab_address")
        kversion = Kernel.kernel_version()

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
        chunk_label_color = Config.get_gef_setting("theme.heap_chunk_label")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")
        label_inactive_color = Config.get_gef_setting("theme.heap_label_inactive")
        slab_address_color = Config.get_gef_setting("theme.heap_slab_address")

        slab_caches_s = Color.colorify_hex(self.slab_caches, slab_address_color)
        self.out.append("slab_caches @ {:s}".format(slab_caches_s))
        for kmem_cache in parsed_caches[1:]:
            if target_names != [] and kmem_cache["name"] not in target_names:
                continue

            # dump kmem_cache metadata
            self.out.append("")
            kmem_cache_addr_s = Color.colorify_hex(kmem_cache["address"], slab_address_color)
            self.out.append("  kmem_cache: {:s}".format(kmem_cache_addr_s))
            self.out.append("    name: {:s}".format(Color.colorify(kmem_cache["name"], chunk_label_color)))
            self.out.append("    flags: {:#x} ({:s})".format(kmem_cache["flags"], kmem_cache["flags_str"]))
            object_size_s = Color.colorify_hex(kmem_cache["object_size"], chunk_size_color)
            self.out.append("    object size: {:s} (chunk size: {:#x})".format(object_size_s, kmem_cache["size"]))
            self.out.append("    offset (next pointer in chunk): {:#x}".format(kmem_cache["offset"]))
            if self.kmem_cache_offset_random is not None:
                if self.args.no_xor is False:
                    if self.swap is True:
                        fmt = "    random (xor key): {:#x} ^ byteswap(&chunk->next)"
                        self.out.append(fmt.format(kmem_cache["random"]))
                    else:
                        fmt = "    random (xor key): {:#x} ^ &chunk->next"
                        self.out.append(fmt.format(kmem_cache["random"]))
            self.out.append("    red_left_pad: {:#x}".format(kmem_cache["red_left_pad"]))

            # dump freelist in kmem_cache only if CONFIG_SLAB_VIRTUAL=y
            if self.slab_virtual_enabled:
                nr_freed_pages = kmem_cache["nr_freed_pages"]
                self.out.append("    nr_freed_pages: {:#d}".format(nr_freed_pages))

                # freed_slabs_normal/freed_slabs
                self.out.append("    freed_slabs_normal: {:#d}/{:#d}".format(
                    len(kmem_cache["freed_slabs_normal"]), nr_freed_pages,
                ))
                for idx, slab in enumerate(kmem_cache["freed_slabs_normal"]):
                    slab_addr_s = Color.colorify_hex(slab["address"], slab_address_color)
                    self.out.append("             {:#05x} {:s}".format(idx, slab_addr_s))

                # freed_slabs_min
                self.out.append("    freed_slabs_min: {:#d}/{:#d}".format(
                    len(kmem_cache["freed_slabs_min"]), nr_freed_pages,
                ))
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
                    self.out.append("    kmem_cache_cpu (cpu{:d}): {:s}".format(
                        cpu, kmem_cache_cpu_addr_s,
                    ))

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
                    node_addr = read_int_from_memory(
                        kmem_cache["address"] + self.kmem_cache_offset_node + self.kmem_cache_node_step * node_index,
                    )
                    node_addr_s = Color.colorify_hex(node_addr, slab_address_color)
                    self.out.append("    kmem_cache_node[{:d}]: {:s}".format(node_index, node_addr_s))

                    # node list (partial)
                    printed_count = 0
                    for node_page in node_page_list_partial:
                        self.dump_page(node_page, kmem_cache, "node")
                        printed_count += 1
                    if printed_count == 0:
                        self.out.append("      {:s}: (none)".format(
                            Color.colorify("node pages", label_inactive_color),
                        ))

                    # node list (full; exists when CONFIG_SLUB_DEBUG=y)
                    if "nodes_full" in kmem_cache:
                        node_page_list_full = kmem_cache["nodes_full"][node_index]
                        printed_count = 0
                        for node_page in node_page_list_full:
                            self.dump_page(node_page, kmem_cache, "node (full)")
                            printed_count += 1
                        if printed_count == 0:
                            self.out.append("      {:s}: (none)".format(
                                Color.colorify("node (full) pages", label_inactive_color),
                            ))

                    # barn list (6.18~)
                    if "node_barn" in kmem_cache and node_index < len(kmem_cache["node_barn"]):
                        self.dump_node_barn(kmem_cache["node_barn"][node_index])

            next_addr_s = Color.colorify_hex(kmem_cache["next"], slab_address_color)
            self.out.append("    next: {:s}".format(next_addr_s))
        return

    def dump_names(self, parsed_caches):
        slab_address_color = Config.get_gef_setting("theme.heap_slab_address")
        name_width = max(len(k["name"]) for k in parsed_caches[1:])

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
        if self.initialize() is False:
            self.quiet_err("Initialization failed")
            return

        if self.args.meta:
            return

        if self.args.list or self.args.list_no_sort:
            parsed_caches = self.walk_caches(target_names, cpus=None)
            self.dump_names(parsed_caches)
            return

        if cpu is None:
            target_cpus = list(range(self.ncpus))
        else:
            if self.ncpus <= cpu:
                self.quiet_err("CPU number is invalid (valid range: {:d}-{:d})".format(0, self.ncpus - 1))
                return
            target_cpus = [cpu]

        if self.args.tlbflush_queue:
            if self.slab_virtual_enabled:
                parsed_queue = self.walk_slab_list(self.slub_tlbflush_queue, self.page_offset_flush_list_elem)
                self.dump_slub_tlbflush_queue(parsed_queue)
            else:
                self.quiet_warn("CONFIG_SLAB_VIRTUAL is disabled. option `--tlbflush-queue` is ignored")
            return

        parsed_caches = self.walk_caches(target_names, target_cpus)
        self.dump_caches(target_names, target_cpus, parsed_caches)
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
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
        if not hasattr(self, "initialized"):
            if is_x86() or is_arm32():
                if not args.skip_page2virt:
                    args = self.args # backup
                    gdb.execute("page2virt 0", to_string=True)
                    # self.args will be overwritten. this is workaround.
                    self.args = args # revert

        if args.no_byte_swap is None:
            self.swap = None
        else:
            self.swap = not args.no_byte_swap

        if args.no_xor or args.no_byte_swap:
            args.rescan = True
        if args.offset_random is not None or args.offset_node is not None:
            args.rescan = True

        kversion = Kernel.kernel_version()
        if not kversion:
            self.quiet_err("Failed to resolve kernel version")

        # dump target
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

    @Cache.cache_until_next
    def parse_kmem_caches_for_initialize(self):
        seen = [self.slab_caches]
        current = self.slab_caches
        while True:
            current = read_int_from_memory(current)
            if current in seen:
                break
            seen.append(current)
        kmem_caches = seen[1:] # skip slab_caches itself
        return kmem_caches

    def resolve_kmem_cache_offset_list(self):
        # fast path
        try:
            self.kmem_cache_offset_list = to_unsigned_long(
                gdb.parse_and_eval("&((struct kmem_cache*)0).list")
            )
            return
        except gdb.error:
            pass

        # slow path
        kmem_caches = self.parse_kmem_caches_for_initialize()
        candidate = (0, -1) # (count, candidate_offset)
        for candidate_offset in range(runtime.current_arch.ptrsize * 2, 0x70, runtime.current_arch.ptrsize):
            # backward search for the start of `struct kmem_cache`
            count = 0
            for kmem_cache in kmem_caches:
                val = read_int_from_memory(kmem_cache - candidate_offset)
                if val & 0x4000_0000: # __CMPXCHG_DOUBLE
                    count += 1
            if candidate[0] < count:
                candidate = (count, candidate_offset)

        self.kmem_cache_offset_list = candidate[1] - self.kmem_cache_offset_flags
        return

    def resolve_kmem_cache_offset_node(self):
        # fast path
        try:
            self.kmem_cache_offset_node = to_unsigned_long(
                gdb.parse_and_eval("&((struct kmem_cache*)0).node")
            )
            return
        except gdb.error:
            pass

        # slow path
        self.kmem_cache_offset_node = None
        kmem_caches = self.parse_kmem_caches_for_initialize()
        start_offset = self.kmem_cache_offset_list + runtime.current_arch.ptrsize * 2 # sizeof(kmem_cache.list)
        for candidate_offset in range(start_offset, start_offset + 0x100, runtime.current_arch.ptrsize):
            # walk from list for heuristic search
            found = True
            for kmem_cache in kmem_caches:
                top = kmem_cache - self.kmem_cache_offset_list
                maybe_node = read_int_from_memory(top + candidate_offset)
                if not is_valid_addr(maybe_node):
                    found = False
                    break
                # skip node[0].{list_lock,nr_partial} and check node[0].partial.next
                if not is_valid_addr(maybe_node + runtime.current_arch.ptrsize * 2):
                    found = False
                    break
                # node[0].partial.next is slab
                # maybe_slab actually points to &slab.next, not to the beginning of the structure
                maybe_slab = read_int_from_memory(maybe_node + runtime.current_arch.ptrsize * 2)
                if not is_valid_addr(maybe_slab):
                    found = False
                    break
                # slab.next (it's actually the list_head)
                a = read_int_from_memory(maybe_slab)
                if not is_valid_addr(a):
                    found = False
                    break
                b = read_int_from_memory(maybe_slab + runtime.current_arch.ptrsize)
                if not is_valid_addr(b):
                    found = False
                    break
                # something is in linklist
                if a != maybe_node + runtime.current_arch.ptrsize * 2:
                    # check slab->slab_cache
                    c = read_int_from_memory(maybe_slab - runtime.current_arch.ptrsize)
                    if c != top:
                        found = False
                        break

            if found:
                self.kmem_cache_offset_node = candidate_offset
                return
        return

    def resolve_kmem_cache_node_offset_partial(self):
        # fast path
        try:
            self.kmem_cache_node_offset_partial = to_unsigned_long(
                gdb.parse_and_eval("&((struct kmem_cache_node*)0).partial")
            )
            return
        except gdb.error:
            pass

        # slow path
        self.kmem_cache_node_offset_partial = None
        kmem_caches = self.parse_kmem_caches_for_initialize()
        node = read_int_from_memory(kmem_caches[0] - self.kmem_cache_offset_list + self.kmem_cache_offset_node)
        for i in range(2, 16):
            offset_partial = runtime.current_arch.ptrsize * i
            if is_double_link_list(node + offset_partial):
                self.kmem_cache_node_offset_partial = offset_partial
                return
        return

    """
    struct kmem_cache {
        struct kmem_cache_cpu *cpu_slab;         // if 6.18 <= kernel < 7.0; In fact, the offset value, not the pointer
        struct lock_class_key {                            // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
            union {                                        // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                struct hlist_node hash_entry;              // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                struct lockdep_subclass_key {              // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                    char __one_byte;                       // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
                } __attribute__ ((__packed__)) subkeys[8]; // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
            };                                             // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
        } lock_key;                                        // if CONFIG_LOCKDEP=y && 6.18 <= kernel < 7.0
        struct slub_percpu_sheaves __percpu *cpu_sheaves;  // if 6.18 <= kernel
        slab_flags_t flags;                      // unsigned int (+ padding 4 byte)
        unsigned long min_partial;
        unsigned int size;
        unsigned int object_size;
        struct reciprocal_value {                //
            u32 m;                               //
            u8 sh1, sh2;                         // (+ padding 2 byte)
        } reciprocal_size;                       //
        unsigned int offset;
        unsigned int cpu_partial;                // if CONFIG_SLUB_CPU_PARTIAL=y && kernel < 7.0
        unsigned int cpu_partial_slabs;          // if CONFIG_SLUB_CPU_PARTIAL=y && kernel < 7.0
        unsigned int sheaf_capacity;             // if 6.18 <= kernel
        struct kmem_cache_order_objects oo;
        struct kmem_cache_order_objects min;
        gfp_t allocflags;                        // unsigned int
        int refcount;
        void (*ctor)(void *);
        unsigned int inuse;
        unsigned int align;
        unsigned int red_left_pad;
        const char *name;
        struct list_head list; <-----> struct list_head <-----> struct list_head <-----> ...
        struct kobject {
            const char *name;
            struct list_head entry;
            struct kobject *parent;
            struct kset *kset;
            const struct kobj_type *ktype;
            struct kernfs_node *sd;
            struct kref kref;
            struct delayed_work release;         // if CONFIG_DEBUG_KOBJECT_RELEASE=y
            unsigned int state_initialized:1;
            unsigned int state_in_sysfs:1;
            unsigned int state_add_uevent_sent:1;
            unsigned int state_remove_uevent_sent:1;
            unsigned int uevent_suppress:1;
        } kobj;                                  // if CONFIG_SYSFS=y
        unsigned int remote_node_defrag_ratio;   // if CONFIG_NUMA=y
        struct kasan_cache {
            int alloc_meta_offset;
            int free_meta_offset;
            bool is_kmalloc;
        } kasan_info;                            // if CONFIG_KASAN=y
        unsigned int useroffset;                 // if CONFIG_HARDENED_USERCOPY=y
        unsigned int usersize;                   // if CONFIG_HARDENED_USERCOPY=y
        struct kmem_cache_stats __percpu *cpu_stats // CONFIG_SLUB_STATS && 7.0 <= kernel
        struct kmem_cache_node *node[MAX_NUMNODES];
    };

    struct slab {
        unsigned long __page_flags;
        struct kmem_cache *slab_cache;
        struct slab *next;
        int slabs;
        void *freelist;
        unsigned inuse:16, objects:15, frozen:1;
        ...
    };

    struct kmem_cache_node {
        spinlock_t list_lock;
        unsigned long nr_partial;
        struct list_head partial;
        atomic_long_t nr_slabs;                  // if CONFIG_SLUB_DEBUG=y
        atomic_long_t total_objects;             // if CONFIG_SLUB_DEBUG=y
        struct list_head full;                   // if CONFIG_SLUB_DEBUG=y
    };
    """

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            if not self.args.meta and not self.args.rescan:
                return True

        kversion = Kernel.kernel_version()
        if not kversion:
            self.quiet_err("Failed to resolve kernel version")
            return False

        # resolve slab_caches
        self.slab_caches = KernelAddressHeuristicFinder.get_slab_caches()
        if self.slab_caches is None:
            self.quiet_err("Failed to resolve `slab_caches`")
            return False
        else:
            self.quiet_info("slab_caches: {:#x}".format(self.slab_caches))

        # offsetof(kmem_cache, flags)
        if kversion < "6.18":
            self.kmem_cache_offset_flags = 0
        elif kversion < "7.0":
            CONFIG_LOCKDEP = Symbol.get_ksymaddr("fs_reclaim_acquire")
            if CONFIG_LOCKDEP:
                self.kmem_cache_offset_flags = runtime.current_arch.ptrsize * 4
            else:
                self.kmem_cache_offset_flags = runtime.current_arch.ptrsize * 2
        else:
            self.kmem_cache_offset_flags = runtime.current_arch.ptrsize
        self.quiet_info("offsetof(kmem_cache, flags): {:#x}".format(self.kmem_cache_offset_flags))

        # offsetof(kmem_cache, list)
        self.resolve_kmem_cache_offset_list()
        self.quiet_info("offsetof(kmem_cache, list): {:#x}".format(self.kmem_cache_offset_list))

        # offsetof(kmem_cache, name)
        self.kmem_cache_offset_name = self.kmem_cache_offset_list - runtime.current_arch.ptrsize
        self.quiet_info("offsetof(kmem_cache, name): {:#x}".format(self.kmem_cache_offset_name))

        # offsetof(kmem_cache, size)
        self.kmem_cache_offset_size = self.kmem_cache_offset_flags + runtime.current_arch.ptrsize * 2
        self.quiet_info("offsetof(kmem_cache, size): {:#x}".format(self.kmem_cache_offset_size))

        # offsetof(kmem_cache, object_size)
        self.kmem_cache_offset_object_size = self.kmem_cache_offset_size + 4
        self.quiet_info("offsetof(kmem_cache, object_size): {:#x}".format(self.kmem_cache_offset_object_size))

        # offsetof(kmem_cache, offset)
        self.kmem_cache_offset_offset = self.kmem_cache_offset_object_size + 4 + 8
        self.quiet_info("offsetof(kmem_cache, offset): {:#x}".format(self.kmem_cache_offset_offset))

        # offsetof(kmem_cache, red_left_pad)
        self.kmem_cache_offset_red_left_pad = self.kmem_cache_offset_name - runtime.current_arch.ptrsize
        self.quiet_info("offsetof(kmem_cache, red_left_pad): {:#x}".format(self.kmem_cache_offset_red_left_pad))

        # offsetof(kmem_cache, node)
        self.resolve_kmem_cache_offset_node()
        if self.kmem_cache_offset_node is None:
            self.quiet_info("offsetof(kmem_cache, node): Not found")
        else:
            self.quiet_info("offsetof(kmem_cache, node): {:#x}".format(self.kmem_cache_offset_node))

        # offsetof(slab, next)
        self.slab_offset_next = runtime.current_arch.ptrsize * 2
        self.quiet_info("offsetof(slab, next): {:#x}".format(self.slab_offset_next))

        # offsetof(slab, freelist)
        self.slab_offset_freelist = runtime.current_arch.ptrsize * 4
        self.quiet_info("offsetof(slab, freelist): {:#x}".format(self.slab_offset_freelist))

        # offsetof(slab, slab_cache)
        self.slab_offset_slab_cache = runtime.current_arch.ptrsize
        self.quiet_info("offsetof(slab, slab_cache): {:#x}".format(self.slab_offset_slab_cache))

        # offsetof(slab, inuse_objects_frozen)
        self.slab_offset_inuse_objects_frozen = self.slab_offset_freelist + runtime.current_arch.ptrsize
        self.quiet_info("offsetof(slab, inuse_objects_frozen): {:#x}".format(self.slab_offset_inuse_objects_frozen))

        # offsetof(kmem_cache_node, partial)
        self.resolve_kmem_cache_node_offset_partial()
        if self.kmem_cache_node_offset_partial is None:
            self.quiet_info("offsetof(kmem_cache_node, partial): Not found")
            return False
        else:
            self.quiet_info("offsetof(kmem_cache_node, partial): {:#x}".format(self.kmem_cache_node_offset_partial))

        self.initialized = True
        return True

    def get_next_kmem_cache(self, addr, point_to_base=True):
        if point_to_base:
            addr += self.kmem_cache_offset_list
        if self.args.reverse_walk:
            return read_int_from_memory(addr) - self.kmem_cache_offset_list
        else:
            return read_int_from_memory(addr + runtime.current_arch.ptrsize) - self.kmem_cache_offset_list

    def get_name(self, addr):
        name_addr = read_int_from_memory(addr + self.kmem_cache_offset_name)
        return read_cstring_from_memory(name_addr)

    def page2virt(self, page, kmem_cache):
        if not self.args.skip_page2virt:
            ret = gdb.execute("page2virt {:#x}".format(page["address"]), to_string=True)
            r = re.search(r"Virt: (\S+)", ret)
            if r:
                return int(r.group(1), 16)

        # set up for heuristic search from freelist
        freelist = page["freelist"]
        freelist = [x for x in freelist if isinstance(x, int) and x != 0] # ignore str and last 0
        if not freelist:
            return None

        # heuristic detection pattern 1
        # freed chunks are scattered and can be confirmed on each of the pages
        page_heads = [x & get_pagesize_mask_high() for x in freelist]
        uniq_page_heads = list(set(page_heads))
        if page["num_pages"] == len(uniq_page_heads):
            return min(uniq_page_heads)

        # heuristic detection pattern 2
        # if there is only one pattern with good alignment, use it
        # e.g., num_pages = 5
        # 0xXXXX0000
        # 0xXXXX1000   <----------------------------------- most_top_page   ^
        # 0xXXXX2000                                                       ^|
        # 0xXXXX3000   <-- chunk in freelist (min_page) ^                 ^||
        # 0xXXXX4000                                    | known_num_pages |||
        # 0xXXXX5000   <-- chunk in freelist (max_page) v                 ||v pattern 3
        # 0xXXXX6000                                                      |v pattern 2
        # 0xXXXX7000                                                      v pattern 1
        chunk_size = kmem_cache["size"]
        min_page = min(freelist) & get_pagesize_mask_high()
        max_page = max(freelist) & get_pagesize_mask_high()
        known_num_pages = ((max_page - min_page) // get_pagesize()) + 1
        unknown_num_pages = page["num_pages"] - known_num_pages
        most_top_page = min_page - (unknown_num_pages * get_pagesize())
        candidate_top_pages = range(most_top_page, min_page + get_pagesize(), get_pagesize())
        # alignment check for each candidate_top_pages
        valid_top_pages = []
        for cand_top in candidate_top_pages:
            for chunk in freelist:
                # divisible?
                if (chunk - cand_top) % chunk_size != 0:
                    break
            else:
                valid_top_pages.append(cand_top)
            # fast break if invalid
            if len(valid_top_pages) >= 2:
                break
        # confirm if there is only one valid pattern
        if len(valid_top_pages) == 1:
            return valid_top_pages[0]

        # not found
        return None

    def walk_freelist(self, chunk, kmem_cache):
        if self.args.simple:
            return [chunk]

        corrupted_msg_color = Config.get_gef_setting("theme.heap_corrupted_msg")

        freelist = [chunk]
        while chunk:
            try:
                addr = chunk + kmem_cache["offset"]
                chunk = read_int_from_memory(addr) # get next chunk
            except gdb.MemoryError:
                freelist.append("{:s}".format(
                    Color.colorify("Corrupted (Memory access denied)", corrupted_msg_color),
                ))
                break
            if chunk % 8:
                freelist.append("{:#x}: {:s}".format(
                    chunk, Color.colorify("Corrupted (Not aligned)", corrupted_msg_color),
                ))
                break
            if chunk in freelist:
                freelist.append("{:#x}: {:s}".format(
                    chunk, Color.colorify("Corrupted (Loop detected)", corrupted_msg_color),
                ))
                break
            freelist.append(chunk)
        return freelist

    def walk_caches_node_page(self, kmem_cache):
        kmem_cache["nodes"] = []
        kmem_cache_node_array = kmem_cache["address"] + self.kmem_cache_offset_node
        current_kmem_cache_node_ptr = kmem_cache_node_array
        while True:
            current_kmem_cache_node = read_int_from_memory(current_kmem_cache_node_ptr)
            if current_kmem_cache_node == 0:
                break
            if current_kmem_cache_node == current_kmem_cache_node_ptr:
                break
            if current_kmem_cache_node & 0b111:
                break

            # node list
            node_page_list = []
            node_page_head = current_kmem_cache_node + self.kmem_cache_node_offset_partial
            if not is_valid_addr(node_page_head):
                break
            current_node_page = read_int_from_memory(node_page_head)
            while current_node_page != node_page_head:
                node_page = {}
                node_page["address"] = current_node_page - self.slab_offset_next
                if not is_valid_addr(node_page["address"]):
                    node_page_list.append(node_page)
                    break
                x = read_int_from_memory(node_page["address"] + self.slab_offset_inuse_objects_frozen)
                node_page["inuse"] = x & 0xffff
                node_page["objects"] = (x >> 16) & 0x7fff
                if node_page["objects"] == 0 or node_page["inuse"] > node_page["objects"]:
                    break # something is wrong
                node_page["frozen"] = (x >> 31) & 1
                node_chunk = read_int_from_memory(node_page["address"] + self.slab_offset_freelist)
                node_page["freelist"] = self.walk_freelist(node_chunk, kmem_cache)
                node_page["num_pages"] = (
                    kmem_cache["size"] * node_page["objects"] + get_pagesize_mask_low()
                ) // get_pagesize()
                node_page["virt_addr"] = self.page2virt(node_page, kmem_cache)
                node_page_list.append(node_page)
                current_node_page = read_int_from_memory(node_page["address"] + self.slab_offset_next)
            kmem_cache["nodes"].append(node_page_list)

            # goto next
            current_kmem_cache_node_ptr += runtime.current_arch.ptrsize
        return

    def walk_caches(self, target_names):
        current_kmem_cache = self.get_next_kmem_cache(self.slab_caches, point_to_base=False)
        parsed_caches = [{"name": "slab_caches", "next": current_kmem_cache}]

        # first, parse kmem_cache
        while current_kmem_cache + self.kmem_cache_offset_list != self.slab_caches:
            kmem_cache = {}
            # parse member
            kmem_cache["name"] = self.get_name(current_kmem_cache)
            if target_names != [] and kmem_cache["name"] not in target_names:
                current_kmem_cache = self.get_next_kmem_cache(current_kmem_cache)
                continue
            kmem_cache["address"] = current_kmem_cache
            kmem_cache["flags"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_flags)
            kmem_cache["flags_str"] = SlubDumpCommand.get_flags_str(kmem_cache["flags"])
            kmem_cache["size"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_size)
            kmem_cache["object_size"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_object_size)
            kmem_cache["offset"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_offset)
            kmem_cache["red_left_pad"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_red_left_pad)
            kmem_cache["next"] = self.get_next_kmem_cache(current_kmem_cache)
            parsed_caches.append(kmem_cache)
            # goto next
            current_kmem_cache = kmem_cache["next"]
            # fast break
            if target_names != [] and not (self.args.list or self.args.list_no_sort):
                parsed_names = [x["name"] for x in parsed_caches]
                if all(t in parsed_names for t in target_names):
                    break

        if self.args.list or self.args.list_no_sort:
            return parsed_caches # fast return

        # second, parse node then update
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for kmem_cache in tqdm(parsed_caches[1:], leave=False): # parsed_caches[0] is slab_caches, so skip
            # parse node
            self.walk_caches_node_page(kmem_cache)

        return parsed_caches

    def dump_page_print_layout(self, kmem_cache, page, freelist):
        from gef.commands.debugging.context import DereferenceCommand
        used_address_color = Config.get_gef_setting("theme.heap_chunk_address_used")
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

        if page["virt_addr"] is None:
            self.out.append("        layout: Failed to the get first page")
            return

        end_virt = page["virt_addr"] + page["num_pages"] * get_pagesize()
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
            layout_msg = "layout:" if idx == 0 else ""
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
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

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
                freelist_msg = "freelist:" if idx == 0 else ""
                self.out.append("        {:9s} {:5s} {:s}".format(freelist_msg, chunk_idx, msg))
            else:
                if isinstance(chunk_addr, str):
                    msg = chunk_addr
                else:
                    msg = Color.colorify_hex(chunk_addr, freed_address_color)
                freelist_msg = "freelist:" if idx == 0 else ""
                self.out.append("        {:9s}       {:s}".format(freelist_msg, msg))
        return

    def dump_page(self, page, kmem_cache, tag, freelist=None):
        label_active_color = Config.get_gef_setting("theme.heap_label_active")
        heap_page_color = Config.get_gef_setting("theme.heap_page_address")

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
        chunk_label_color = Config.get_gef_setting("theme.heap_chunk_label")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")
        label_inactive_color = Config.get_gef_setting("theme.heap_label_inactive")

        self.out.append("slab_caches @ {:#x}".format(self.slab_caches))
        for kmem_cache in parsed_caches[1:]:
            if target_names != [] and kmem_cache["name"] not in target_names:
                continue

            # dump kmem_cache metadata
            self.out.append("")
            self.out.append("  kmem_cache: {:#x}".format(kmem_cache["address"]))
            self.out.append("    name: {:s}".format(Color.colorify(kmem_cache["name"], chunk_label_color)))
            self.out.append("    flags: {:#x} ({:s})".format(kmem_cache["flags"], kmem_cache["flags_str"]))
            object_size_s = Color.colorify_hex(kmem_cache["object_size"], chunk_size_color)
            self.out.append("    object size: {:s} (chunk size: {:#x})".format(object_size_s, kmem_cache["size"]))
            self.out.append("    offset (next pointer in chunk): {:#x}".format(kmem_cache["offset"]))
            self.out.append("    red_left_pad: {:#x}".format(kmem_cache["red_left_pad"]))

            # dump nodes
            for node_index, node_page_list in enumerate(kmem_cache["nodes"]):
                node_addr = read_int_from_memory(
                    kmem_cache["address"] + self.kmem_cache_offset_node + runtime.current_arch.ptrsize * node_index,
                )
                self.out.append("    kmem_cache_node[{:d}]: {:#x}".format(node_index, node_addr))
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
        name_width = max(len(k["name"]) for k in parsed_caches[1:])

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
        if self.initialize() is False:
            self.quiet_err("Initialization failed")
            return

        if self.args.meta:
            return

        if self.args.list or self.args.list_no_sort:
            parsed_caches = self.walk_caches(target_names)
            self.dump_names(parsed_caches)
            return

        parsed_caches = self.walk_caches(target_names)
        self.dump_caches(target_names, parsed_caches)
        return

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
        if not hasattr(self, "initialized"):
            if is_x86() or is_arm32():
                if not args.skip_page2virt:
                    args = self.args # backup
                    gdb.execute("page2virt 0", to_string=True)
                    # self.args will be overwritten. this is workaround.
                    self.args = args # revert

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

    """
    struct kmem_cache {
        struct array_cache __percpu *cpu_cache;  // In fact, the offset value, not the pointer. if 3.18 <= kernel
        unsigned int batchcount;
        unsigned int limit;
        unsigned int shared;
        unsigned int size;
        struct reciprocal_value {
            u32 m;
            u8 sh1, sh2;
        } reciprocal_buffer_size;
        slab_flags_t flags;                      // unsigned int
        unsigned int num;
        unsigned int gfporder;
        gfp_t allocflags;                        // unsigned int
        size_t colour;
        unsigned int colour_off;
        struct kmem_cache *freelist_cache;       // if kernel < 6.1
        unsigned int freelist_size;
        void (*ctor)(void *obj);
        const char *name;
        struct list_head list;  <-----> struct list_head <-----> struct list_head <-----> ...
        int refcount;
        int object_size;
        int align;
        unsigned long num_active;                // if CONFIG_DEBUG_SLAB=y
        unsigned long num_allocations;           // if CONFIG_DEBUG_SLAB=y
        unsigned long high_mark;                 // if CONFIG_DEBUG_SLAB=y
        unsigned long grown;                     // if CONFIG_DEBUG_SLAB=y
        unsigned long reaped;                    // if CONFIG_DEBUG_SLAB=y
        unsigned long errors;                    // if CONFIG_DEBUG_SLAB=y
        unsigned long max_freeable;              // if CONFIG_DEBUG_SLAB=y
        unsigned long node_allocs;               // if CONFIG_DEBUG_SLAB=y
        unsigned long node_frees;                // if CONFIG_DEBUG_SLAB=y
        unsigned long node_overflow;             // if CONFIG_DEBUG_SLAB=y
        atomic_t allochit;                       // if CONFIG_DEBUG_SLAB=y
        atomic_t allocmiss;                      // if CONFIG_DEBUG_SLAB=y
        atomic_t freehit;                        // if CONFIG_DEBUG_SLAB=y
        atomic_t freemiss;                       // if CONFIG_DEBUG_SLAB=y
        atomic_t store_user_clean;               // if CONFIG_DEBUG_SLAB=y && CONFIG_DEBUG_SLAB_LEAK=y && 4.6 <= kernel < 5.2
        int obj_offset;                          // if CONFIG_DEBUG_SLAB=y
        struct memcg_cache_params memcg_params;  // if CONFIG_MEMCG=y && kernel < 5.9
        struct kasan_cache kasan_info;           // if CONFIG_KASAN=y && 4.6 <= kernel
        unsigned int *random_seq;                // if CONFIG_SLAB_FREELIST_RANDOM=y && 4.7 <= kernel
        unsigned int useroffset;                 // if 4.16 <= kernel
        unsigned int usersize;                   // if 4.16 <= kernel
        struct kmem_cache_node *node[MAX_NUMNODES]; // if 3.18 <= kernel
        struct kmem_cache_node **node;           // if kernel < 3.18
        struct array_cache *array[NR_CPUS + MAX_NUMNODES];  // if kernel < 3.18
    };

    struct array_cache {
        unsigned int avail;
        unsigned int limit;
        unsigned int batchcount;
        unsigned int touched;
        spinlock_t lock;                         // if kernel < 3.17
        void *entry[];
    };

    struct kmem_cache_node {
        raw_spinlock_t list_lock;
        struct list_head slabs_partial;
        struct list_head slabs_full;
        struct list_head slabs_free;
        unsigned long total_slabs;               // if 4.10 <= kernel
        unsigned long free_slabs;                // if 4.10 <= kernel
        unsigned long num_slabs;                 // if 4.9 <= kernel < 4.10
        unsigned long free_objects;
        unsigned int free_limit;
        unsigned int colour_next;
        struct array_cache *shared;
        struct alien_cache **alien;
        unsigned long next_reap;
        int free_touched;
    };

    struct page {                                // if kernel < 4.18
        unsigned long flags;
        void *s_mem;
        void *freelist;
        unsigned int active;
        atomic_t refcount;                       // if kernel < 4.16
        struct rcu_head rcu_head;
        struct kmem_cache *slab_cache;
        ...
    };

    struct page {                                // if 4.18 <= kernel < 5.17
        unsigned long flags;
        struct list_head slab_list;
        struct kmem_cache *slab_cache;
        void *freelist;
        void *s_mem;
        unsigned int active;
        ...
    };

    struct slab {                                // if 5.17 <= kernel
        unsigned long __page_flags;
        struct kmem_cache *slab_cache;           // if 6.2 <= kernel
        struct list_head slab_list;
        struct kmem_cache *slab_cache;           // if kernel < 6.2
        void *freelist;
        void *s_mem;
        unsigned int active;
        ...
    };
    """

    @Cache.cache_until_next
    def parse_kmem_caches_for_initialize(self):
        seen = [self.slab_caches]
        current = self.slab_caches
        while True:
            current = read_int_from_memory(current)
            if current in seen:
                break
            seen.append(current)
        kmem_caches = seen[1:] # skip slab_caches itself
        return kmem_caches

    def resolve_kmem_cache_offset_node(self):
        # fast path
        try:
            self.kmem_cache_offset_node = to_unsigned_long(
                gdb.parse_and_eval("&((struct kmem_cache*)0).node")
            )
            return
        except gdb.error:
            pass

        # slow path
        kversion = Kernel.kernel_version()
        if kversion < "4.16":
            self.kmem_cache_offset_node = self.kmem_cache_offset_object_size + 4 * 2 # heuristic could not use, so hard-coded
            return

        self.kmem_cache_offset_node = None
        kmem_caches = self.parse_kmem_caches_for_initialize()
        # Search heuristically using useroffset and usersize as markers
        start_offset = self.kmem_cache_offset_list + runtime.current_arch.ptrsize * 2
        for candidate_offset in range(start_offset, start_offset + 0x100, 4):
            found = True
            for kmem_cache in kmem_caches:
                kmem_cache_top = kmem_cache - self.kmem_cache_offset_list
                user_offset = read_int32_from_memory(kmem_cache_top + candidate_offset)
                user_size = read_int32_from_memory(kmem_cache_top + candidate_offset + 4)
                object_size = read_int32_from_memory(kmem_cache_top + self.kmem_cache_offset_object_size)
                if user_offset == user_size == 0:
                    continue
                if user_offset != 0 and user_size == 0:
                    found = False
                    break
                if object_size < user_size:
                    found = False
                    break
                node_addr_ptr = kmem_cache_top + candidate_offset + 4 + 4
                node_addr_ptr = align_to_ptrsize(node_addr_ptr)
                node_addr = read_int_from_memory(node_addr_ptr)
                if not is_valid_addr(node_addr):
                    found = False
                    break

            if found:
                self.kmem_cache_offset_node = align_to_ptrsize(candidate_offset + 4 * 2)
                return
        return

    def resolve_kmem_cache_node_offset_slabs_partial(self):
        # fast path
        try:
            self.kmem_cache_node_offset_slabs_partial = to_unsigned_long(
                gdb.parse_and_eval("&((struct kmem_cache_node*)0).slabs_partial")
            )
            return
        except gdb.error:
            pass

        # slow path
        kversion = Kernel.kernel_version()
        self.kmem_cache_node_offset_slabs_partial = None
        kmem_caches = self.parse_kmem_caches_for_initialize()
        # sizeof(raw_spinlock_t) can take many different values and must be determined heuristically.
        for candidate_offset in range(0, 0x80, runtime.current_arch.ptrsize):
            found = True
            for _kmem_cache in kmem_caches:
                kmem_cache = _kmem_cache - self.kmem_cache_offset_list
                if "3.18" <= kversion:
                    kmem_cache_node_array = kmem_cache + self.kmem_cache_offset_node
                else:
                    kmem_cache_node_array = read_int_from_memory(kmem_cache + self.kmem_cache_offset_node)
                kmem_cache_node_0 = read_int_from_memory(kmem_cache_node_array)

                # slabs_partial
                if not is_double_link_list(kmem_cache_node_0 + candidate_offset + runtime.current_arch.ptrsize * 0):
                    found = False
                    break
                # slabs_full
                if not is_double_link_list(kmem_cache_node_0 + candidate_offset + runtime.current_arch.ptrsize * 2):
                    found = False
                    break
                # slabs_free
                if not is_double_link_list(kmem_cache_node_0 + candidate_offset + runtime.current_arch.ptrsize * 4):
                    found = False
                    break

            if found:
                self.kmem_cache_node_offset_slabs_partial = candidate_offset
                return
        return

    def initialize(self):
        from gef.commands.kernel.basic import KernelCurrentCommand
        if hasattr(self, "initialized") and self.initialized:
            if not self.args.meta and not self.args.rescan:
                return True

        kversion = Kernel.kernel_version()
        if not kversion:
            self.quiet_err("Failed to resolve kernel version")
            return False

        # resolve slab_caches
        self.slab_caches = KernelAddressHeuristicFinder.get_slab_caches()
        if self.slab_caches is None:
            self.quiet_err("Failed to resolve `slab_caches`")
            return False
        else:
            self.quiet_info("slab_caches: {:#x}".format(self.slab_caches))

        # resolve __per_cpu_offset
        __per_cpu_offset = KernelAddressHeuristicFinder.get_per_cpu_offset()
        if __per_cpu_offset is None:
            self.quiet_info("__per_cpu_offset: Not found")
            self.cpu_offset = []
            self.ncpus = 1
        else:
            self.quiet_info("__per_cpu_offset: {:#x}".format(__per_cpu_offset))
            self.cpu_offset = KernelCurrentCommand.get_each_cpu_offset(__per_cpu_offset)
            self.ncpus = len(self.cpu_offset)

        # offsetof(kmem_cache, list)
        if kversion < "3.18":
            self.kmem_cache_offset_list = runtime.current_arch.ptrsize * 6 + 4 * 10
        elif kversion < "6.1":
            self.kmem_cache_offset_list = runtime.current_arch.ptrsize * 7 + 4 * 10
        else:
            self.kmem_cache_offset_list = runtime.current_arch.ptrsize * 4 + 4 * 12
        self.quiet_info("offsetof(kmem_cache, list): {:#x}".format(self.kmem_cache_offset_list))

        # offsetof(kmem_cache, name)
        self.kmem_cache_offset_name = self.kmem_cache_offset_list - runtime.current_arch.ptrsize
        self.quiet_info("offsetof(kmem_cache, name): {:#x}".format(self.kmem_cache_offset_name))

        # offsetof(kmem_cache, size)
        if "3.18" <= kversion:
            self.kmem_cache_offset_size = runtime.current_arch.ptrsize + 4 * 3
        else:
            self.kmem_cache_offset_size = 4 * 3
        self.quiet_info("offsetof(kmem_cache, size): {:#x}".format(self.kmem_cache_offset_size))

        # offsetof(kmem_cache, flags)
        self.kmem_cache_offset_flags = self.kmem_cache_offset_size + 4 * 3
        self.quiet_info("offsetof(kmem_cache, flags): {:#x}".format(self.kmem_cache_offset_flags))

        # offsetof(kmem_cache, num)
        self.kmem_cache_offset_num = self.kmem_cache_offset_flags + 4
        self.quiet_info("offsetof(kmem_cache, num): {:#x}".format(self.kmem_cache_offset_num))

        # offsetof(kmem_cache, gfporder)
        self.kmem_cache_offset_gfporder = self.kmem_cache_offset_num + 4
        self.quiet_info("offsetof(kmem_cache, gfporder): {:#x}".format(self.kmem_cache_offset_gfporder))

        # offsetof(kmem_cache, object_size)
        self.kmem_cache_offset_object_size = self.kmem_cache_offset_list + runtime.current_arch.ptrsize * 2 + 4
        self.quiet_info("offsetof(kmem_cache, object_size): {:#x}".format(self.kmem_cache_offset_object_size))

        # offsetof(kmem_cache, node)
        self.resolve_kmem_cache_offset_node()
        if self.kmem_cache_offset_node is None:
            self.quiet_info("offsetof(kmem_cache, node): Not found")
            return False
        else:
            self.quiet_info("offsetof(kmem_cache, node): {:#x}".format(self.kmem_cache_offset_node))

        # offsetof(kmem_cache, cpu_cache) / offsetof(kmem_cache, array)
        if "3.18" <= kversion:
            self.kmem_cache_offset_cpu_cache = 0
            self.quiet_info("offsetof(kmem_cache, cpu_cache): {:#x}".format(self.kmem_cache_offset_cpu_cache))
        else:
            self.kmem_cache_offset_array = self.kmem_cache_offset_node + runtime.current_arch.ptrsize
            self.quiet_info("offsetof(kmem_cache, array): {:#x}".format(self.kmem_cache_offset_array))

        # offsetof(page, next) / offsetof(slab, next)
        if kversion < "4.16":
            self.page_offset_next = runtime.current_arch.ptrsize * 3 + 4 * 2
        elif kversion < "4.18":
            self.page_offset_next = runtime.current_arch.ptrsize * 3 + 4
        elif kversion < "5.17":
            self.page_offset_next = runtime.current_arch.ptrsize
        elif kversion < "6.2":
            self.page_offset_next = runtime.current_arch.ptrsize
        else:
            self.page_offset_next = runtime.current_arch.ptrsize * 2
        self.quiet_info("offsetof({:s}, next): {:#x}".format(Kernel.slab_page_str(), self.page_offset_next))

        # offsetof(page, freelist) / offsetof(slab, freelist)
        if kversion < "4.18":
            self.page_offset_freelist = runtime.current_arch.ptrsize * 2
        elif kversion < "5.17":
            self.page_offset_freelist = runtime.current_arch.ptrsize * 4
        elif kversion < "6.2":
            self.page_offset_freelist = runtime.current_arch.ptrsize * 4
        else:
            self.page_offset_freelist = runtime.current_arch.ptrsize * 4
        self.quiet_info("offsetof({:s}, freelist): {:#x}".format(Kernel.slab_page_str(), self.page_offset_freelist))

        # offsetof(page, slab_cache) / offsetof(slab, slab_cache)
        if kversion < "4.16" and is_32bit():
            self.page_offset_slab_cache = runtime.current_arch.ptrsize * 7
        elif kversion < "4.18":
            self.page_offset_slab_cache = runtime.current_arch.ptrsize * 6
        elif kversion < "5.17":
            self.page_offset_slab_cache = runtime.current_arch.ptrsize * 3
        elif kversion < "6.2":
            self.page_offset_slab_cache = runtime.current_arch.ptrsize * 3
        else:
            self.page_offset_slab_cache = runtime.current_arch.ptrsize
        self.quiet_info("offsetof({:s}, slab_cache): {:#x}".format(Kernel.slab_page_str(), self.page_offset_slab_cache))

        # offsetof(page, s_mem) / offsetof(slab, s_mem)
        if kversion < "4.18":
            self.page_offset_s_mem = runtime.current_arch.ptrsize
        elif kversion < "5.17":
            self.page_offset_s_mem = runtime.current_arch.ptrsize * 5
        elif kversion < "6.2":
            self.page_offset_s_mem = 8 + runtime.current_arch.ptrsize * 5
        else:
            self.page_offset_s_mem = 8 + runtime.current_arch.ptrsize * 5
        self.quiet_info("offsetof({:s}, s_mem): {:#x}".format(Kernel.slab_page_str(), self.page_offset_s_mem))

        # offsetof(page, active) / offsetof(slab, active)
        if kversion < "4.18":
            self.page_offset_active = runtime.current_arch.ptrsize * 3
        elif kversion < "5.17":
            self.page_offset_active = runtime.current_arch.ptrsize * 6
        elif kversion < "6.2":
            self.page_offset_active = runtime.current_arch.ptrsize * 6
        else:
            self.page_offset_active = runtime.current_arch.ptrsize * 6
        self.quiet_info("offsetof({:s}, active): {:#x}".format(Kernel.slab_page_str(), self.page_offset_active))

        # offsetof(kmem_cache_node, slabs_partial)
        self.resolve_kmem_cache_node_offset_slabs_partial()
        if self.kmem_cache_node_offset_slabs_partial is None:
            self.quiet_info("offsetof(kmem_cache_node, slabs_partial): Not found")
            return False
        else:
            self.quiet_info("offsetof(kmem_cache_node, slabs_partial): {:#x}".format(self.kmem_cache_node_offset_slabs_partial))

        # offsetof(kmem_cache_node, slabs_full)
        self.kmem_cache_node_offset_slabs_full = self.kmem_cache_node_offset_slabs_partial + runtime.current_arch.ptrsize * 2
        self.quiet_info("offsetof(kmem_cache_node, slabs_full): {:#x}".format(self.kmem_cache_node_offset_slabs_full))

        # offsetof(kmem_cache_node, slabs_free)
        self.kmem_cache_node_offset_slabs_free = self.kmem_cache_node_offset_slabs_full + runtime.current_arch.ptrsize * 2
        self.quiet_info("offsetof(kmem_cache_node, slabs_free): {:#x}".format(self.kmem_cache_node_offset_slabs_free))

        # offsetof(array_cache, avail)
        self.array_cache_offset_avail = 0
        self.quiet_info("offsetof(array_cache, avail): {:#x}".format(self.array_cache_offset_avail))

        # offsetof(array_cache, limit)
        self.array_cache_offset_limit = 4
        self.quiet_info("offsetof(array_cache, limit): {:#x}".format(self.array_cache_offset_limit))

        # offsetof(array_cache, entry)
        if "3.17" <= kversion:
            self.array_cache_offset_entry = 4 * 4
        else:
            sizeof_raw_spinlock_t = self.kmem_cache_node_offset_slabs_partial
            self.array_cache_offset_entry = 4 * 4 + sizeof_raw_spinlock_t
        self.quiet_info("offsetof(array_cache, entry): {:#x}".format(self.array_cache_offset_entry))

        self.initialized = True
        return True

    def get_next_kmem_cache(self, addr, point_to_base=True):
        if point_to_base:
            addr += self.kmem_cache_offset_list
        if self.args.reverse_walk:
            return read_int_from_memory(addr) - self.kmem_cache_offset_list
        else:
            return read_int_from_memory(addr + runtime.current_arch.ptrsize) - self.kmem_cache_offset_list

    def get_name(self, addr):
        name_addr = read_int_from_memory(addr + self.kmem_cache_offset_name)
        return read_cstring_from_memory(name_addr)

    def get_array_cache_cpu(self, addr, cpu):
        kversion = Kernel.kernel_version()
        if "3.18" <= kversion:
            cpu_cache = read_int_from_memory(addr + self.kmem_cache_offset_cpu_cache)
            if len(self.cpu_offset) > 0:
                # __percpu
                return AddressUtil.normalize_address(cpu_cache + self.cpu_offset[cpu])
            else:
                # not __percpu
                return cpu_cache
        else:
            return read_int_from_memory(addr + self.kmem_cache_offset_array + runtime.current_arch.ptrsize * cpu)

    def walk_array_cache(self, array_cache, cpu, kmem_cache):
        if self.args.simple:
            return []

        freelist = []
        entry = array_cache + self.array_cache_offset_entry
        end = entry + kmem_cache["array_cache"][cpu]["avail"] * runtime.current_arch.ptrsize
        for current in range(entry, end, runtime.current_arch.ptrsize):
            chunk = read_int_from_memory(current)
            freelist.append(chunk)
        return freelist

    def walk_node_list(self, node_page_head, current_node_page, kmem_cache):
        kversion = Kernel.kernel_version()
        node_page_list = []
        seen = [] # avoid infinity loop
        while current_node_page != node_page_head:
            if current_node_page in seen:
                break
            seen.append(current_node_page)
            node_page = {}
            node_page["address"] = current_node_page - self.page_offset_next
            if not is_valid_addr(node_page["address"]):
                node_page_list.append(node_page)
                break
            node_page["s_mem"] = read_int_from_memory(node_page["address"] + self.page_offset_s_mem)
            node_page["s_mem_base"] = node_page["s_mem"] & get_pagesize_mask_high()

            if not self.args.simple:
                freelist_addr = read_int_from_memory(node_page["address"] + self.page_offset_freelist)
                if is_valid_addr(freelist_addr):
                    active = read_int32_from_memory(node_page["address"] + self.page_offset_active)
                    if "3.15" <= kversion:
                        freelist_byteseq = read_memory(freelist_addr, kmem_cache["objperslab"])
                        node_page["freelist"] = list(freelist_byteseq[active:])
                    else:
                        freelist_intseq = read_memory(freelist_addr, kmem_cache["objperslab"] * 4)
                        node_page["freelist"] = slice_unpack(freelist_intseq, runtime.current_arch.ptrsize)[active:]
                else:
                    node_page["freelist"] = []

            node_page_list.append(node_page)
            current_node_page = read_int_from_memory(node_page["address"] + self.page_offset_next)
        return node_page_list

    def walk_caches(self, target_names, cpus):
        kversion = Kernel.kernel_version()
        current_kmem_cache = self.get_next_kmem_cache(self.slab_caches, point_to_base=False)
        parsed_caches = [{"name": "slab_caches", "next": current_kmem_cache}]

        # first, parse kmem_cache
        while current_kmem_cache + self.kmem_cache_offset_list != self.slab_caches:
            kmem_cache = {}
            # parse member
            kmem_cache["name"] = self.get_name(current_kmem_cache)
            if target_names != [] and kmem_cache["name"] not in target_names:
                current_kmem_cache = self.get_next_kmem_cache(current_kmem_cache)
                continue
            kmem_cache["address"] = current_kmem_cache
            kmem_cache["flags"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_flags)
            kmem_cache["flags_str"] = SlubDumpCommand.get_flags_str(kmem_cache["flags"])
            kmem_cache["size"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_size)
            kmem_cache["object_size"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_object_size)
            kmem_cache["objperslab"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_num)
            gfporder = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_gfporder)
            kmem_cache["pagesperslab"] = 1 << gfporder
            kmem_cache["next"] = self.get_next_kmem_cache(current_kmem_cache)
            parsed_caches.append(kmem_cache)
            # goto next
            current_kmem_cache = kmem_cache["next"]
            # fast break
            if target_names != [] and not (self.args.list or self.args.list_no_sort):
                parsed_names = [x["name"] for x in parsed_caches]
                if all(t in parsed_names for t in target_names):
                    break

        if self.args.list or self.args.list_no_sort:
            return parsed_caches

        # second, parse array_cache and node
        tqdm = GefUtil.get_tqdm(not self.args.quiet)
        for kmem_cache in tqdm(parsed_caches[1:], leave=False): # parsed_caches[0] is slab_caches, so skip
            # parse array_cache
            kmem_cache["array_cache"] = {}
            kmem_cache["array_cache"]["freelist_all"] = []
            for cpu in cpus:
                kmem_cache["array_cache"][cpu] = {}
                if not is_valid_addr(self.get_array_cache_cpu(kmem_cache["address"], cpu)):
                    continue
                kmem_cache["array_cache"][cpu]["address"] = array_cache = self.get_array_cache_cpu(kmem_cache["address"], cpu)
                kmem_cache["array_cache"][cpu]["avail"] = read_int32_from_memory(array_cache + self.array_cache_offset_avail)
                kmem_cache["array_cache"][cpu]["limit"] = read_int32_from_memory(array_cache + self.array_cache_offset_limit)
                kmem_cache["array_cache"][cpu]["freelist"] = self.walk_array_cache(array_cache, cpu, kmem_cache)
                kmem_cache["array_cache"]["freelist_all"].extend(kmem_cache["array_cache"][cpu]["freelist"])

            # parse node
            kmem_cache["nodes"] = []
            if "3.18" <= kversion:
                kmem_cache_node_array = kmem_cache["address"] + self.kmem_cache_offset_node
            else:
                kmem_cache_node_array = read_int_from_memory(kmem_cache["address"] + self.kmem_cache_offset_node)
            current_kmem_cache_node_ptr = kmem_cache_node_array
            while True:
                # 3.18 or after: node is array (node[MAX_NUMNODES]), so need loop until invalid address
                current_kmem_cache_node = read_int_from_memory(current_kmem_cache_node_ptr)
                if not is_valid_addr(current_kmem_cache_node):
                    break
                slabs_list = {}

                node_page_head = current_kmem_cache_node + self.kmem_cache_node_offset_slabs_partial
                if is_valid_addr(node_page_head):
                    current_node_page = read_int_from_memory(node_page_head)
                    slabs_list["slabs_partial"] = self.walk_node_list(node_page_head, current_node_page, kmem_cache)

                node_page_head = current_kmem_cache_node + self.kmem_cache_node_offset_slabs_full
                if is_valid_addr(node_page_head):
                    current_node_page = read_int_from_memory(node_page_head)
                    slabs_list["slabs_full"] = self.walk_node_list(node_page_head, current_node_page, kmem_cache)

                node_page_head = current_kmem_cache_node + self.kmem_cache_node_offset_slabs_free
                if is_valid_addr(node_page_head):
                    current_node_page = read_int_from_memory(node_page_head)
                    slabs_list["slabs_free"] = self.walk_node_list(node_page_head, current_node_page, kmem_cache)

                kmem_cache["nodes"].append(slabs_list)

                if kversion < "3.18":
                    # 3.17 or before: node is single element (**node), so skip loop
                    break
                current_kmem_cache_node_ptr += runtime.current_arch.ptrsize
        return parsed_caches

    def dump_page(self, page, kmem_cache, tag):
        from gef.commands.debugging.context import DereferenceCommand
        heap_page_color = Config.get_gef_setting("theme.heap_page_address")
        label_inactive_color = Config.get_gef_setting("theme.heap_label_inactive")
        used_address_color = Config.get_gef_setting("theme.heap_chunk_address_used")
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

        # page address
        tag_s = Color.colorify(tag, label_inactive_color)
        self.out.append("      {:s}: {:#x}".format(tag_s, page["address"]))

        # fast return if invalid
        if not is_valid_addr(page["address"]):
            return

        # print virtual address
        colored_s_mem_base = Color.colorify_hex(page["s_mem_base"], heap_page_color)
        self.out.append("        virtual address (s_mem & ~0xfff): {:s}".format(colored_s_mem_base))

        # print info
        self.out.append("        num pages: {:d}".format(kmem_cache["pagesperslab"]))

        colour_off = page["s_mem"] - page["s_mem_base"]
        self.out.append("        colour offset: {:#x}".format(colour_off))

        if self.args.simple:
            return

        # print layout
        freelist = page["freelist"]
        end_virt = page["s_mem_base"] + kmem_cache["pagesperslab"] * get_pagesize()

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
        label_active_color = Config.get_gef_setting("theme.heap_label_active")
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

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
        chunk_label_color = Config.get_gef_setting("theme.heap_chunk_label")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")
        label_inactive_color = Config.get_gef_setting("theme.heap_label_inactive")

        self.out.append("slab_caches @ {:#x}".format(self.slab_caches))
        for kmem_cache in parsed_caches[1:]:
            if target_names != [] and kmem_cache["name"] not in target_names:
                continue

            # dump kmem_cache metadata
            self.out.append("")
            self.out.append("  kmem_cache: {:#x}".format(kmem_cache["address"]))
            self.out.append("    name: {:s}".format(Color.colorify(kmem_cache["name"], chunk_label_color)))
            self.out.append("    flags: {:#x} ({:s})".format(kmem_cache["flags"], kmem_cache["flags_str"]))
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
                    node_addr = read_int_from_memory(
                        kmem_cache["address"] + self.kmem_cache_offset_node + runtime.current_arch.ptrsize * node_index,
                    )
                    self.out.append("    kmem_cache_node[{:d}]: {:#x}".format(node_index, node_addr))

                    if not self.args.skip_partial and "slabs_partial" in slabs_list:
                        if len(slabs_list["slabs_partial"]) == 0:
                            tag = Color.colorify("node[{:d}].slabs_partial".format(node_index), label_inactive_color)
                            self.out.append("      {:s}: (none)".format(tag))
                        else:
                            for node_page in slabs_list["slabs_partial"]:
                                self.dump_page(node_page, kmem_cache, tag="node[{:d}].slabs_partial".format(node_index))

                    if not self.args.skip_full and "slabs_full" in slabs_list:
                        if len(slabs_list["slabs_full"]) == 0:
                            tag = Color.colorify("node[{:d}].slabs_full".format(node_index), label_inactive_color)
                            self.out.append("      {:s}: (none)".format(tag))
                        else:
                            for node_page in slabs_list["slabs_full"]:
                                self.dump_page(node_page, kmem_cache, tag="node[{:d}].slabs_full".format(node_index))

                    if not self.args.skip_free and "slabs_free" in slabs_list:
                        if len(slabs_list["slabs_free"]) == 0:
                            tag = Color.colorify("node[{:d}].slabs_free".format(node_index), label_inactive_color)
                            self.out.append("      {:s}: (none)".format(tag))
                        else:
                            for node_page in slabs_list["slabs_free"]:
                                self.dump_page(node_page, kmem_cache, tag="node[{:d}].slabs_free".format(node_index))

            self.out.append("    next: {:#x}".format(kmem_cache["next"]))
        return

    def dump_names(self, parsed_caches):
        name_width = max(len(k["name"]) for k in parsed_caches[1:])

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
        if self.initialize() is False:
            self.quiet_err("Initialization failed")
            return

        if self.args.meta:
            return

        if self.args.list or self.args.list_no_sort:
            parsed_caches = self.walk_caches(target_names, cpus=None)
            self.dump_names(parsed_caches)
            return

        if cpu is None:
            target_cpus = list(range(self.ncpus))
        else:
            if self.ncpus <= cpu:
                self.quiet_err("CPU number is invalid (valid range: {:d}-{:d})".format(0, self.ncpus - 1))
                return
            target_cpus = [cpu]

        parsed_caches = self.walk_caches(target_names, target_cpus)
        self.dump_caches(target_names, target_cpus, parsed_caches)
        return

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

    """
    struct kmem_cache {
        unsigned int object_size;
        unsigned int size;
        unsigned int align;
        slab_flags_t flags;                      // unsigned int
        unsigned int useroffset;                 // if 4.16 <= kernel
        unsigned int usersize;                   // if 4.16 <= kernel
        const char *name;
        int refcount;
        void (*ctor)(void *);
        struct list_head list;
    };

    struct page {                                // if kernel < 4.18
        unsigned long flags;
        void *__unused_1;
        void *freelist;
        int units;
        atomic_t refcount;                       // if kernel < 4.16
        struct list_head lru;
        ...
    };

    struct page {                                // if 4.18 <= kernel < 5.17
        unsigned long flags;
        struct list_head lru;
        struct kmem_cache *__unused_1;
        void *freelist;
        void *__unused_2;
        int units;
        ...
    };

    struct slab {                                // if 5.17 <= kernel
        unsigned long __page_flags;
        struct list_head slab_list;
        void *__unused_1;
        void *freelist
        long units;
        unsigned int __unused_2;
    };
    """

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            if not self.args.meta and not self.args.rescan:
                return True

        kversion = Kernel.kernel_version()
        if not kversion:
            self.quiet_err("Failed to resolve kernel version")
            return False

        # resolve slab_caches
        self.slab_caches = KernelAddressHeuristicFinder.get_slab_caches()
        if self.slab_caches is None:
            self.quiet_err("Failed to resolve `slab_caches`")
            return False
        else:
            self.quiet_info("slab_caches: {:#x}".format(self.slab_caches))

        # resolve global freelists
        self.free_slob_large = Symbol.get_ksymaddr("free_slob_large")
        if self.free_slob_large is None:
            self.quiet_err("Failed to resolve `free_slob_large`")
            return False
        else:
            self.quiet_info("free_slob_large: {:#x}".format(self.free_slob_large))

        self.free_slob_medium = Symbol.get_ksymaddr("free_slob_medium")
        if self.free_slob_medium is None:
            self.quiet_err("Failed to resolve `free_slob_medium`")
            return False
        else:
            self.quiet_info("free_slob_medium: {:#x}".format(self.free_slob_medium))

        self.free_slob_small = Symbol.get_ksymaddr("free_slob_small")
        if self.free_slob_small is None:
            self.quiet_err("Failed to resolve `free_slob_small`")
            return False
        else:
            self.quiet_info("free_slob_small: {:#x}".format(self.free_slob_small))

        # offsetof(kmem_cache, list)
        if kversion < "4.16":
            self.kmem_cache_offset_list = runtime.current_arch.ptrsize * 3 + 4 * 4
        else:
            self.kmem_cache_offset_list = runtime.current_arch.ptrsize * 3 + 4 * 6
        self.quiet_info("offsetof(kmem_cache, list): {:#x}".format(self.kmem_cache_offset_list))

        # offsetof(kmem_cache, name)
        self.kmem_cache_offset_name = self.kmem_cache_offset_list - runtime.current_arch.ptrsize * 3
        self.quiet_info("offsetof(kmem_cache, name): {:#x}".format(self.kmem_cache_offset_name))

        # offsetof(kmem_cache, object_size)
        self.kmem_cache_offset_object_size = 0
        self.quiet_info("offsetof(kmem_cache, object_size): {:#x}".format(self.kmem_cache_offset_object_size))

        # offsetof(kmem_cache, size)
        self.kmem_cache_offset_size = 4
        self.quiet_info("offsetof(kmem_cache, size): {:#x}".format(self.kmem_cache_offset_size))

        # offsetof(kmem_cache, flags)
        self.kmem_cache_offset_flags = 4 * 3
        self.quiet_info("offsetof(kmem_cache, flags): {:#x}".format(self.kmem_cache_offset_flags))

        # offsetof(page, next) / offsetof(slab, next)
        if kversion < "4.16":
            self.page_offset_next = runtime.current_arch.ptrsize * 3 + 4 * 2
        elif kversion < "4.18":
            self.page_offset_next = runtime.current_arch.ptrsize * 4
        elif kversion < "5.17":
            self.page_offset_next = runtime.current_arch.ptrsize
        else:
            self.page_offset_next = runtime.current_arch.ptrsize
        self.quiet_info("offsetof({:s}, next): {:#x}".format(Kernel.slab_page_str(), self.page_offset_next))

        # offsetof(page, freelist) / offsetof(slab, freelist)
        if kversion < "4.18":
            self.page_offset_freelist = runtime.current_arch.ptrsize * 2
        elif kversion < "5.17":
            self.page_offset_freelist = runtime.current_arch.ptrsize * 4
        else:
            self.page_offset_freelist = runtime.current_arch.ptrsize * 4
        self.quiet_info("offsetof({:s}, freelist): {:#x}".format(Kernel.slab_page_str(), self.page_offset_freelist))

        # offsetof(page, units) / offsetof(slab, units)
        if kversion < "4.18":
            self.page_offset_units = runtime.current_arch.ptrsize * 3
        elif kversion < "5.17":
            self.page_offset_freelist = runtime.current_arch.ptrsize * 6
        else:
            self.page_offset_freelist = runtime.current_arch.ptrsize * 5
        self.quiet_info("offsetof({:s}, units): {:#x}".format(Kernel.slab_page_str(), self.page_offset_units))

        self.initialized = True
        return True

    def get_next_kmem_cache(self, addr, point_to_base=True):
        if point_to_base:
            addr += self.kmem_cache_offset_list
        if self.args.reverse_walk:
            return read_int_from_memory(addr) - self.kmem_cache_offset_list
        else:
            return read_int_from_memory(addr + runtime.current_arch.ptrsize) - self.kmem_cache_offset_list

    def get_name(self, addr):
        name_addr = read_int_from_memory(addr + self.kmem_cache_offset_name)
        return read_cstring_from_memory(name_addr)

    def walk_freelist(self, head, page):
        if self.args.simple:
            return []

        freelist = []
        current = head
        while True:
            base = current & get_pagesize_mask_high()
            units = struct.unpack("<h", read_memory(current, 2))[0]
            if units < 0:
                next = -units
                units = 1
            else:
                next = struct.unpack("<h", read_memory(current + 2, 2))[0]
            freelist.append([current, units])
            current = base + next * 2
            if (current & 0xfff) == 0:
                break
        return freelist

    def walk_page_freelist(self, head):
        seen = [head]
        page_freelist = []
        current = read_int_from_memory(head)
        while True:
            seen.append(current)
            page = {}
            page["address"] = current - self.page_offset_next
            page["units"] = read_int32_from_memory(page["address"] + self.page_offset_units)
            freelist_head = read_int_from_memory(page["address"] + self.page_offset_freelist)
            page["virt_addr"] = freelist_head & get_pagesize_mask_high()
            page["num_pages"] = 1
            page["freelist"] = self.walk_freelist(freelist_head, page)
            page["next"] = next = read_int_from_memory(current)
            page_freelist.append(page)
            if next in seen:
                break
            current = next
        return page_freelist

    def walk_caches(self, target_names):
        current_kmem_cache = self.get_next_kmem_cache(self.slab_caches, point_to_base=False)
        parsed_caches = [{"name": "slab_caches", "next": current_kmem_cache}]

        while current_kmem_cache + self.kmem_cache_offset_list != self.slab_caches:
            kmem_cache = {}
            # parse member
            kmem_cache["name"] = self.get_name(current_kmem_cache)
            if target_names != [] and kmem_cache["name"] not in target_names:
                current_kmem_cache = self.get_next_kmem_cache(current_kmem_cache)
                continue
            kmem_cache["address"] = current_kmem_cache
            kmem_cache["flags"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_flags)
            kmem_cache["flags_str"] = SlubDumpCommand.get_flags_str(kmem_cache["flags"])
            kmem_cache["size"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_size)
            kmem_cache["object_size"] = read_int32_from_memory(current_kmem_cache + self.kmem_cache_offset_object_size)
            kmem_cache["next"] = self.get_next_kmem_cache(current_kmem_cache)
            parsed_caches.append(kmem_cache)
            # goto next
            current_kmem_cache = kmem_cache["next"]
            # fast break
            if target_names != [] and not (self.args.list or self.args.list_no_sort):
                parsed_names = [x["name"] for x in parsed_caches]
                if all(t in parsed_names for t in target_names):
                    break

        if self.args.list or self.args.list_no_sort:
            return parsed_caches, None

        parsed_freelist = {}
        if self.args.large:
            parsed_freelist["large"] = self.walk_page_freelist(self.free_slob_large)
        if self.args.medium:
            parsed_freelist["medium"] = self.walk_page_freelist(self.free_slob_medium)
        if self.args.small:
            parsed_freelist["small"] = self.walk_page_freelist(self.free_slob_small)

        return parsed_caches, parsed_freelist

    def dump_freelist(self, tag, page_freelist):
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")
        label_active_color = Config.get_gef_setting("theme.heap_label_active")
        heap_page_color = Config.get_gef_setting("theme.heap_page_address")
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")

        self.out.append(titlify("{:s} @ {:#x}".format(tag, getattr(self, tag))))

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
                    Color.colorify_hex(units * 2, chunk_size_color),
                ))
            self.out.append("    next: {:#x}".format(page["next"]))
            self.out.append("")
        return

    def dump_caches(self, target_names, parsed_caches, parsed_freelist):
        chunk_label_color = Config.get_gef_setting("theme.heap_chunk_label")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")

        if self.args.verbose:
            self.out.append(titlify("{:s} @ {:#x}".format("slab_caches", self.slab_caches)))
            for kmem_cache in parsed_caches[1:]:
                if target_names != [] and kmem_cache["name"] not in target_names:
                    continue
                self.out.append("  kmem_cache: {:#x}".format(kmem_cache["address"]))
                colored_name = Color.colorify(kmem_cache["name"], chunk_label_color)
                self.out.append("    name: {:s}".format(colored_name))
                self.out.append("    flags: {:#x} ({:s})".format(kmem_cache["flags"], kmem_cache["flags_str"]))
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
        name_width = max(len(k["name"]) for k in parsed_caches[1:])

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
        if self.initialize() is False:
            self.quiet_err("Initialization failed")
            return

        if self.args.meta:
            return

        if self.args.list or self.args.list_no_sort:
            parsed_caches, _ = self.walk_caches(target_names)
            self.dump_names(parsed_caches)
            return

        parsed_caches, parsed_freelist = self.walk_caches(target_names)
        self.dump_caches(target_names, parsed_caches, parsed_freelist)
        return

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
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
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

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            return True

        cmd = {"SLUB": "slub-dump", "SLAB": "slab-dump", "SLUB_TINY": "slub-tiny-dump"}[self.allocator]
        res = gdb.execute("{:s} --meta".format(cmd), to_string=True)

        r = re.search(r"offsetof\((?:page|slab), slab_cache\): (0x\S+)", res)
        if not r:
            return False
        self.page_offset_slab_cache = int(r.group(1), 16)
        if self.args.verbose:
            info("offsetof({:s}, slab_cache): {:#x}".format(Kernel.slab_page_str(), self.page_offset_slab_cache))

        r = re.search(r"offsetof\((?:page|slab), next\): (0x\S+)", res)
        if not r:
            return False
        self.page_offset_next = int(r.group(1), 16)
        if self.args.verbose:
            info("offsetof({:s}, next): {:#x}".format(Kernel.slab_page_str(), self.page_offset_next))

        r = re.search(r"offsetof\(kmem_cache, name\): (0x\S+)", res)
        if not r:
            return False
        self.kmem_cache_offset_name = int(r.group(1), 16)
        if self.args.verbose:
            info("offsetof(kmem_cache, name): {:#x}".format(self.kmem_cache_offset_name))

        r = re.search(r"offsetof\(kmem_cache, size\): (0x\S+)", res)
        if not r:
            return False
        self.kmem_cache_offset_size = int(r.group(1), 16)
        if self.args.verbose:
            info("offsetof(kmem_cache, size): {:#x}".format(self.kmem_cache_offset_size))

        r = re.search(r"offsetof\(kmem_cache, object_size\): (0x\S+)", res)
        if not r:
            return False
        self.kmem_cache_offset_object_size = int(r.group(1), 16)
        if self.args.verbose:
            info("offsetof(kmem_cache, object_size): {:#x}".format(self.kmem_cache_offset_object_size))

        # for aligned check
        if self.allocator in ["SLUB", "SLUB_TINY"]:
            r = re.search(r"offsetof\(kmem_cache, red_left_pad\): (0x\S+)", res)
            if not r:
                return False
            self.kmem_cache_offset_red_left_pad = int(r.group(1), 16)
            if self.args.verbose:
                info("offsetof(kmem_cache, red_left_pad): {:#x}".format(self.kmem_cache_offset_red_left_pad))

        if self.allocator == "SLAB":
            r = re.search(r"offsetof\((?:page|slab), s_mem\): (0x\S+)", res)
            if not r:
                return False
            self.page_offset_s_mem = int(r.group(1), 16)
            if self.args.verbose:
                info("offsetof({:s}, s_mem): {:#x}".format(Kernel.slab_page_str(), self.page_offset_s_mem))

        # for slab-virtual
        if is_x86_64():
            r = re.search(r"offsetof\(kmem_cache, freed_slabs_min\): (0x\S+)", res)
            if r:
                self.slab_virtual_enabled = True
                if self.args.verbose:
                    info("offsetof(kmem_cache, freed_slabs_min): {:#x}".format(int(r.group(1), 16)))
            else:
                self.slab_virtual_enabled = False
        else:
            self.slab_virtual_enabled = False

        # for num of pages
        if self.allocator in ["SLUB", "SLUB_TINY"]:
            r = re.search(r"offsetof\((?:page|slab), inuse_objects_frozen\): (0x\S+)", res)
            if not r:
                return False
            self.page_offset_inuse_objects_frozen = int(r.group(1), 16)
            if self.args.verbose:
                info("offsetof({:s}, inuse_objects_frozen): {:#x}".format(
                    Kernel.slab_page_str(), self.page_offset_inuse_objects_frozen,
                ))

        elif self.allocator == "SLAB":
            r = re.search(r"offsetof\(kmem_cache, gfporder\): (0x\S+)", res)
            if not r:
                return False
            self.kmem_cache_offset_gfporder = int(r.group(1), 16)
            if self.args.verbose:
                info("offsetof(kmem_cache, gfporder): {:#x}".format(self.kmem_cache_offset_gfporder))

        self.initialized = True
        return True

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

    def check_slab_dump(self, target_addr, slab_cache_name):

        def get_freed_addresses(res):
            freed_addresses = []
            res = Color.remove_color(res)
            in_freelist_section = 0
            for line in res.splitlines():
                line = line.rstrip()
                if not in_freelist_section:
                    if re.match(r"^        (freelist|objects:)", line):
                        in_freelist_section = 1
                    elif re.match(r"^        entry:", line):
                        in_freelist_section = 2
                elif in_freelist_section == 1:
                    if not line.startswith("                  0x"):
                        in_freelist_section = 0
                elif in_freelist_section == 2:
                    if not line.startswith("               0x"):
                        in_freelist_section = 0
                if in_freelist_section == 1:
                    r = re.search(r"0x\S+ (0x\S+)", line)
                    if r:
                        freed_chunk = int(r.group(1), 16)
                        freed_addresses.append(freed_chunk)
                elif in_freelist_section == 2:
                    r = re.search(r"(0x\S+)", line)
                    if r:
                        freed_chunk = int(r.group(1), 16)
                        freed_addresses.append(freed_chunk)
            return freed_addresses

        if self.allocator == "SLUB":
            res = gdb.execute("slub-dump --node --no-pager --quiet {:s}".format(slab_cache_name), to_string=True)
        elif self.allocator == "SLUB_TINY":
            res = gdb.execute("slub-tiny-dump --no-pager --quiet {:s}".format(slab_cache_name), to_string=True)
        elif self.allocator == "SLAB":
            res = gdb.execute("slab-dump --no-pager --quiet {:s}".format(slab_cache_name), to_string=True)
        else:
            return

        freed_addresses = get_freed_addresses(res)

        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        used_address_color = Config.get_gef_setting("theme.heap_chunk_address_used")
        if target_addr in freed_addresses:
            self.quiet_print("status: {:s} (found object base in freelist)".format(
                Color.colorify("freed", freed_address_color),
            ))
        else:
            self.quiet_print("status: {:s} (not found object base in freelist)".format(
                Color.colorify("in-use", used_address_color),
            ))
        return

    def slab_contains(self):
        current = self.args.address & get_pagesize_mask_high()
        chunk_label_color = Config.get_gef_setting("theme.heap_chunk_label")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")

        try:
            while True:
                page = self.virt2page_wrapper(current)
                if page is None:
                    self.quiet_err("Invalid address")
                    return

                self.quiet_print("{:s}: {:#x}".format(Kernel.slab_page_str(), page))

                page_next = read_int_from_memory(page + self.page_offset_next)
                if page_next & 1:
                    current -= get_pagesize()
                    continue

                kmem_cache = read_int_from_memory(page + self.page_offset_slab_cache)
                if kmem_cache == 0:
                    self.quiet_err("This address is not managed by slab (kmem_cache=0)")
                    return

                if (kmem_cache & get_pagesize_mask_high()) == 0xdead_0000_0000_0000:
                    current -= get_pagesize()
                    continue

                if kmem_cache & 1:
                    current -= get_pagesize()
                    continue

                self.quiet_print("kmem_cache: {:#x}".format(kmem_cache))
                self.quiet_print("base: {:#x}".format(current))
                break
        except (gdb.MemoryError, ZeroDivisionError):
            self.quiet_err("Memory read error")
            return

        try:
            slab_cache_name_ptr = read_int_from_memory(kmem_cache + self.kmem_cache_offset_name)
            slab_cache_name = read_cstring_from_memory(slab_cache_name_ptr)
            if slab_cache_name is None:
                self.quiet_err("This address is not managed by slab (slab_cache_name=\"\")")
                return

            slab_cache_size = read_int32_from_memory(kmem_cache + self.kmem_cache_offset_size)
            slab_cache_object_size = read_int32_from_memory(kmem_cache + self.kmem_cache_offset_object_size)

            if self.allocator in ["SLUB", "SLUB_TINY"]:
                red_left_pad = read_int_from_memory(kmem_cache + self.kmem_cache_offset_red_left_pad)
                color_offset = 0
                x = read_int_from_memory(page + self.page_offset_inuse_objects_frozen)
                objects = (x >> 16) & 0x7fff
                num_pages = (slab_cache_size * objects + get_pagesize_mask_low()) // get_pagesize()
            else:
                red_left_pad = 0
                s_mem = read_int_from_memory(page + self.page_offset_s_mem)
                color_offset = s_mem & get_pagesize_mask_low()
                gfporder = read_int32_from_memory(kmem_cache + self.kmem_cache_offset_gfporder)
                num_pages = 1 << gfporder

            # `inuse` is not displayed because it is not a reliable reference value.
            # The value of `slab->inuse` also includes the number of chunks registered in `kmem_cache_cpu->freelist` etc.
            # However, what the user actually wants is the number of chunks that are truly in use,
            # excluding those accounted for by `kmem_cache_cpu->freelist`.
            # Accurately deriving that value is non-trivial.
            gef_print("name: {:s}  object_size: {:s} (chunk_size: {:#x})  num_pages: {:#x}".format(
                Color.colorify(slab_cache_name, chunk_label_color),
                Color.colorify_hex(slab_cache_object_size, chunk_size_color),
                slab_cache_size, num_pages,
            ))

            first_object = current + red_left_pad + color_offset
            delta = self.args.address - first_object

            if delta < 0:
                gef_print("remarks: {:s}".format(Color.redify("before first object")))
                return

            object_base = first_object + (delta // slab_cache_size) * slab_cache_size
            object_offset = delta % slab_cache_size

            self.quiet_print("object_base: {:#x}".format(object_base))

            if object_offset != 0:
                gef_print("remarks: {:s} (offset: +{:#x})".format(Color.redify("unaligned"), object_offset))

            # resolve freelist and print chunk status (in-use or freed)
            self.check_slab_dump(object_base, slab_cache_name)
        except (gdb.MemoryError, ZeroDivisionError):
            self.quiet_err("Memory read error")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        self.quiet_info("Wait for memory scan")

        if not hasattr(self, "initialized"):
            self.initialized = False

        if args.rescan:
            self.initialized = False

        if not hasattr(self, "allocator"):
            self.allocator = Kernel.get_slab_type()

        if self.allocator not in ["SLUB", "SLUB_TINY", "SLAB"]:
            self.quiet_err("Unsupported: SLOB, Unknown allocator")
            return

        ret = self.initialize()
        if not ret:
            self.quiet_err("Failed to initialize")
            return

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
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="show result only.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command requires CONFIG_SYSFS=y.",
    ]
    _note_ = "\n".join(_note_)

    def parse_rb_node(self, rb_node):
        if not rb_node or not is_valid_addr(rb_node):
            return []

        right = read_int_from_memory(rb_node + runtime.current_arch.ptrsize * 1) & ~1 # remove RB_BLACK
        left = read_int_from_memory(rb_node + runtime.current_arch.ptrsize * 2) & ~1 # remove RB_BLACK

        ret = [rb_node]
        if right:
            ret += self.parse_rb_node(right)
        if left:
            ret += self.parse_rb_node(left)
        return ret

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            return True

        self.slab_kset = KernelAddressHeuristicFinder.get_slab_kset()
        if self.slab_kset is None:
            self.quiet_err("Could not find slab_kset")
            return False
        self.quiet_info("slab_kset: {:#x}".format(self.slab_kset))

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
            self.quiet_info("offsetof(kset, kobj.sd): {:#x}".format(self.offset_kobj_sd))
            break
        else:
            self.quiet_err("Could not find offsetof(kset, kobj.sd)")
            return False

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
            self.quiet_info("offsetof(kernfs_node, name): {:#x}".format(self.offset_name))
            self.quiet_info("offsetof(kernfs_node, rb): {:#x}".format(self.offset_rb))
            self.quiet_info("offsetof(kernfs_node, dir.children): {:#x}".format(self.offset_dir_children))
            self.quiet_info("offsetof(kernfs_node, symlink.target_kn): {:#x}".format(self.offset_symlink_target_kn))
            break
        else:
            self.quiet_err("Could not find offsetof(kernfs_node, name)")
            return False

        self.initialized = True
        return True

    def parse_kmem_cache_alias(self):
        # get children_root
        kset = read_int_from_memory(self.slab_kset)
        sd = read_int_from_memory(kset + self.offset_kobj_sd)
        children_root = read_int_from_memory(sd + self.offset_dir_children)

        # parse
        alias_groups = {}
        nodes = self.parse_rb_node(children_root)
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
            }

        # parse slub-dump
        cmd = {"SLUB": "slub-dump", "SLUB_TINY": "slub-tiny-dump"}[self.allocator]
        res = gdb.execute("{:s} --list --no-pager --quiet".format(cmd), to_string=True)
        used_names = []
        for line in res.splitlines():
            r = re.search(r"(\d+)\s+\(0x\S+\)\s+(\d+)\s+\(0x\S+\)\s+(\S+)\s+0x\S+$", line)
            object_size = int(r.group(1))
            chunk_size = int(r.group(2))
            name = r.group(3)
            used_names.append([object_size, chunk_size, name])

        # identify the actual slab_cache name in use
        for object_size, chunk_size, slab_cache_name in used_names:
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
                continue

            for k in alias_groups.keys():
                # already resolved
                if alias_groups[k]["slab_cache_name"]:
                    continue

                if alias_groups[k]["alias"] == "-":
                    if k == alias_groups[slab_cache_name]["alias"]:
                        # k: ":0000256" -> "-"
                        # slab_cache_name: "key_jar" -> ":0000256"
                        alias_groups[k]["slab_cache_name"] = slab_cache_name
                        alias_groups[k]["object_size"] = object_size
                        alias_groups[k]["chunk_size"] = chunk_size
                    elif k == slab_cache_name:
                        # k: "kmalloc-256" -> "-"
                        # slab_cache_name: "kmalloc-256" -> "-"
                        alias_groups[k]["slab_cache_name"] = slab_cache_name
                        alias_groups[k]["object_size"] = object_size
                        alias_groups[k]["chunk_size"] = chunk_size
                else:
                    if alias_groups[k]["alias"] == alias_groups[slab_cache_name]["alias"]:
                        # k: "key_jar" -> ":0000256"
                        # slab_cache_name: "key_jar" -> ":0000256"
                        alias_groups[k]["slab_cache_name"] = slab_cache_name
                        alias_groups[k]["object_size"] = object_size
                        alias_groups[k]["chunk_size"] = chunk_size
        return alias_groups

    def make_output_merged(self, alias_groups):
        chunk_label_color = Config.get_gef_setting("theme.heap_chunk_label")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")

        # group entries by their Physical Cache Name
        merged_groups = {}
        for name, info in alias_groups.items():
            if not info["slab_cache_name"]:
                continue

            phys_name = info["slab_cache_name"]
            if phys_name not in merged_groups:
                merged_groups[phys_name] = []

            entry = info.copy()
            entry["logical_name"] = name
            merged_groups[phys_name].append(entry)

        # list keys
        if self.args.names:
            target_phys_groups = set()

            # Check every physical group
            for phys_name, children in merged_groups.items():
                matched_group = False
                for child in children:
                    child_name = child["logical_name"]
                    for filter_name in self.args.names:
                        if filter_name in child_name:
                            target_phys_groups.add(phys_name)
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
            sorted_phys_names = sorted(keys_to_process,
                key=lambda k: (merged_groups[k][0]["object_size"] if merged_groups[k] else 0))
        else:
            sorted_phys_names = sorted(keys_to_process)

        # print
        self.out.append(titlify("Merged Slab Caches"))
        found_merge = False
        for phys_name in sorted_phys_names:
            children = merged_groups[phys_name]

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
                        if child["logical_name"] in filter_name:
                            keep_this_group = True
                            break
            if real_aliases == 0 and not keep_this_group:
                continue
            found_merge = True

            # print header
            header = "{:s} (Object size: {:s}, Chunk size: {:#x})".format(
                Color.colorify(phys_name, chunk_label_color),
                Color.colorify_hex(children[0]["object_size"], chunk_size_color),
                children[0]["chunk_size"],
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

                if name_str == phys_name:
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
        fmt = "{:16s} {:16s} {:30s} {:12s} {:s}"
        legend = ["Object Size", "Chunk Size", "Name", "Alias", "slab_cache name"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        # sort by keys
        if self.args.sort_by_size:
            sorted_alias_groups = sorted(alias_groups.items(),
                key=lambda x: (x[1]["object_size"], x[1]["chunk_size"], x[1]["name"]))
        else:
            sorted_alias_groups = sorted(alias_groups.items())

        found = False
        # print
        for name, v in sorted_alias_groups:
            # filtering by name
            if self.args.names:
                for filter_name in self.args.names:
                    if filter_name in name:
                        break
                    if filter_name in v["alias"]:
                        break
                    if filter_name in v["slab_cache_name"]:
                        break
                else:
                    continue

            # print flat
            found = True
            if v["object_size"] == 0:
                self.out.append("{:16s} {:16s} {:30s} {:12s} {:s}".format(
                    "-", "-", name, v["alias"], "<UNUSED>",
                ))
            else:
                object_size = "{0:d} ({0:#x})".format(v["object_size"])
                chunk_size = "{0:d} ({0:#x})".format(v["chunk_size"])
                self.out.append("{:16s} {:16s} {:30s} {:12s} {:s}".format(
                    object_size, chunk_size, name, v["alias"], v["slab_cache_name"],
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

        kversion = Kernel.kernel_version()
        if kversion is None:
            err("Could not find Linux kernel")
            return
        if kversion < "3.14":
            self.quiet_err("Unsupported before v3.14")
            return

        if not hasattr(self, "allocator"):
            self.allocator = Kernel.get_slab_type()

        if self.allocator not in ["SLUB", "SLUB_TINY"]:
            self.quiet_err("Unsupported: SLAB, SLOB, Unknown allocator")
            return

        ret = self.initialize()
        if not ret:
            self.quiet_err("Failed to initialize")
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
    parser.add_argument("--only-freed", action="store_true", help="display only freed area.")
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
        "                           +-vmap_area--+",
        "                           | va_start   |",
        "(~v6.8)                    | va_end     |",
        "+---------------------+    | ...        |",
        "| vmap_area_list      |--->| list       |--->...",
        "+---------------------+    | ...        |",
        "                           | vm         |---->+-vm_struct--+",
        "                           | ...        |     | ...        |",
        "                           +------------+     | flags      |",
        "                                              | ...        |",
        "                                              +------------+",
        "                           +-vmap_area--+",
        "                           | va_start   |",
        "(v5.2~)                    | va_end     |",
        "+---------------------+    | ...        |",
        "| free_vmap_area_list |--->| list       |--->...",
        "+---------------------+    | ...        |",
        "                           +------------+",
    ]
    _note_ = "\n".join(_note_)

    def initialize(self):
        if hasattr(self, "initialized") and self.initialized:
            if not self.args.meta and not self.args.rescan:
                return True

        """
        struct vmap_area {
            unsigned long va_start;
            unsigned long va_end;
            unsigned long subtree_max_size; // v5.2.0~v5.2.21
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
            struct list_head purge_list;  // ~v4.7
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
        """

        kversion = Kernel.kernel_version()

        if kversion and kversion < "6.9":
            self.vmap_area_list = KernelAddressHeuristicFinder.get_vmap_area_list()
            if not self.vmap_area_list:
                self.quiet_err("Could not find vmap_area_list")
            else:
                self.quiet_info("vmap_area_list: {:#x}".format(self.vmap_area_list))
        else:
            self.vmap_area_list = None

        if kversion and "5.2" <= kversion:
            self.free_vmap_area_list = KernelAddressHeuristicFinder.get_free_vmap_area_list()
            if not self.free_vmap_area_list:
                self.quiet_err("Could not find free_vmap_area_list")
            else:
                self.quiet_info("free_vmap_area_list: {:#x}".format(self.free_vmap_area_list))
        else:
            self.free_vmap_area_list = None

        if not self.vmap_area_list and not self.free_vmap_area_list:
            return False

        # vmap_area->list
        if kversion and "5.4" <= kversion:
            self.offset_list = runtime.current_arch.ptrsize * 5
        elif kversion and "5.2" <= kversion:
            self.offset_list = runtime.current_arch.ptrsize * 7
        else:
            self.offset_list = runtime.current_arch.ptrsize * 6
        self.quiet_info("offsetof(vmap_area, list): {:#x}".format(self.offset_list))

        # vmap_area->vm
        if kversion and "5.4" <= kversion:
            self.offset_vm = self.offset_list + runtime.current_arch.ptrsize * 2
        elif kversion and "4.7" <= kversion:
            self.offset_vm = self.offset_list + runtime.current_arch.ptrsize * 3
        else:
            self.offset_vm = self.offset_list + runtime.current_arch.ptrsize * 4
        self.quiet_info("offsetof(vmap_area, vm): {:#x}".format(self.offset_vm))

        # vm_struct->flags
        self.offset_flags = runtime.current_arch.ptrsize * 3
        self.quiet_info("offsetof(vm_struct, flags): {:#x}".format(self.offset_flags))

        self.initialized = True
        return True

    def parse_vmap_area_list(self, head, used):
        if head is None or not is_valid_addr(head):
            return []

        seen = [head]
        current = read_int_from_memory(head)
        idx = 0
        areas = []
        while True:
            if current in seen:
                break
            seen.append(current)

            vmap_area = current - self.offset_list
            va_start = read_int_from_memory(vmap_area)
            va_end = read_int_from_memory(vmap_area + runtime.current_arch.ptrsize)
            va_size = va_end - va_start

            flags = None
            if used:
                vm = read_int_from_memory(vmap_area + self.offset_vm)
                if is_valid_addr(vm):
                    flags = read_int_from_memory(vm + self.offset_flags)
                else:
                    flags = 0
            areas.append([used, va_start, va_end, va_size, flags])

            try:
                current = read_int_from_memory(current)
            except gdb.MemoryError:
                break

            idx += 1
        return areas

    def get_flags(self, flags_value):
        flags_dic = {
            0x0000_0001: "VM_IOREMAP",
            0x0000_0002: "VM_ALLOC",
            0x0000_0004: "VM_MAP",
            0x0000_0008: "VM_USERMAP",
            0x0000_0010: "VM_DMA_COHERENT",
            0x0000_0020: "VM_UNINITIALIZED",
            0x0000_0040: "VM_NO_GUARD",
            0x0000_0080: "VM_KASAN",
            0x0000_0100: "VM_FLUSH_RESET_PERMS",
            0x0000_0200: "VM_MAP_PUT_PAGES",
        }
        flags = []
        for k, v in flags_dic.items():
            if flags_value & k:
                flags.append(v)
        return "|".join(flags)

    def dump_areas(self, areas):
        from gef.commands.debugging.context import DereferenceCommand
        fmt = "{:4s} {:6s} {:37s} {:18s} {:s}"
        legend = ["#", "state", "virtual address", "size", "flags"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        used_address_color = Config.get_gef_setting("theme.heap_chunk_address_used")
        freed_address_color = Config.get_gef_setting("theme.heap_chunk_address_freed")
        chunk_size_color = Config.get_gef_setting("theme.heap_chunk_size")

        for idx, (used, va_start, va_end, va_size, flags) in enumerate(areas):
            size_str = "{:<#18x}".format(va_size)
            size_str = Color.colorify(size_str, chunk_size_color)
            virt_str = "{:#018x}-{:#018x}".format(va_start, va_end)
            if used:
                virt_str = Color.colorify(virt_str, used_address_color)
                state = "in-use"
                flags_str = self.get_flags(flags)
                flags_str = flags_str.rstrip()
                if not flags_str:
                    flags_str = "-"
            else:
                virt_str = Color.colorify(virt_str, freed_address_color)
                state = "freed"
                flags_str = "-"
            self.out.append("{:<4d} {:6s} {:s} {:s} {:s}".format(idx, state, virt_str, size_str, flags_str))

            # dump chunks
            if self.args.hexdump_used and used:
                try:
                    peeked_data = read_memory(va_start, self.args.hexdump_used)
                    h = hexdump(peeked_data, 0x10, base=va_start, unit=runtime.current_arch.ptrsize)
                    self.out.append(h)
                except Exception:
                    pass

            if self.args.telescope_used and used:
                n = self.args.telescope_used // runtime.current_arch.ptrsize
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

        ret = self.initialize()
        if ret is False:
            return

        if self.args.meta:
            return

        self.out = []
        areas = []

        kversion = Kernel.kernel_version()

        # parse used list
        if not args.only_freed:
            if kversion and kversion < "6.9":
                areas += self.parse_vmap_area_list(self.vmap_area_list, used=True)

        # parse freed list
        if not args.only_used:
            if kversion and "5.2" <= kversion:
                areas += self.parse_vmap_area_list(self.free_vmap_area_list, used=False)

        areas = sorted(areas, key=lambda x:x[1])
        self.dump_areas(areas)

        self.print_output()
        return
