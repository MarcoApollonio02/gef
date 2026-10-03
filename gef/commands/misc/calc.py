"""GEF misc Calculation commands (category 07-e) extracted from the
monolithic gef.py.

distance (address difference) and crc32rev (reverse a CRC32).
Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import collections
import itertools

from gef.commands.base import (
    GenericCommand,
    exclude_specific_gdb_mode,
    only_if_gdb_running,
    parse_args,
    register_command,
)
from gef.core.address import AddressUtil
from gef.core.color import err, gef_print, info
from gef.core.process import ProcessMap
from gef.core.strings import String
from gef.core.utils import GefUtil


@register_command
class DistanceCommand(GenericCommand):
    """Calculate the offset from its base address."""

    _cmdline_ = "distance"
    _category_ = "07-e. Misc - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("address_a", metavar="ADDRESS_A", type=AddressUtil.parse_address,
                        help="the address to calculate the offset as (A - base_addr_of(A)).")
    parser.add_argument("address_b", metavar="ADDRESS_B", type=AddressUtil.parse_address, nargs="?",
                        help="the address to calculate the offset as abs(A - B).")
    _syntax_ = parser.format_help()

    @parse_args
    @only_if_gdb_running
    @exclude_specific_gdb_mode(mode=("qemu-system", "kgdb", "vmware"))
    def do_invoke(self, args):
        if args.address_b is not None:
            offset = abs(args.address_a - args.address_b)
            gef_print("Offset:  {:#x}".format(offset))
            return

        addr_a = ProcessMap.lookup_address(args.address_a)
        if addr_a.section is None:
            err("Could not find the base address")
            return

        if addr_a.section.path:
            base_address = ProcessMap.get_section_base_address(addr_a.section.path)
        else:
            base_address = addr_a.section.page_start

        offset = args.address_a - base_address
        gef_print("Address: {:#x}".format(args.address_a))
        gef_print("Base:    {:#x}".format(base_address))
        gef_print("Offset:  {:#x}".format(offset))
        return


@register_command
class Crc32revCommand(GenericCommand):
    """Perform CRC32 reverse calculation limited to ASCII character range."""

    _cmdline_ = "crc32rev"
    _category_ = "07-e. Misc - Calculation"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-p", "--poly", type=lambda x: int(x, 16), help="generator polynomial in MSB form.")
    parser.add_argument("--poly-reflected", action="store_true",
                        help="treat --poly as already reflected (LSB form, e.g., 0xedb88320).")
    parser.add_argument("-i", "--init-value", type=lambda x: int(x, 16), help="initial CRC register value.")
    parser.add_argument("-o", "--xorout", type=lambda x: int(x, 16), help="final XOR value applied after output reflection.")
    parser.add_argument("--refin", action="store_true", help="enable input reflection (LSB-first).")
    parser.add_argument("--no-refin", action="store_true", help="disable input reflection (MSB-first).")
    parser.add_argument("--refout", action="store_true", help="enable output reflection.")
    parser.add_argument("--no-refout", action="store_true", help="disable output reflection.")
    parser.add_argument("--preset", choices=[
        "", "base", "ieee", "isohdlc", "adccp", "v42", "xz", "pkzip",
        "aixm", "q",
        "autosar",
        "base91d", "d",
        "bzip2", "aal5", "dectb", "b",
        "cdromedc",
        "cksum", "posix",
        "iscsi", "base91c", "castagnoli", "interlaken", "c", "nvme",
        "jamcrc",
        "mef",
        "mpeg2", "ether",
        "xfer",
        "koopman", "k",
    ], default="", help="quick parameter presets, explicit flags override preset values.")
    parser.add_argument("-l", "--list", action="store_true", help="print CRC presets.")
    parser.add_argument("wanted_crc", metavar="WANTED_CRC", nargs="?", type=lambda x: int(x, 16),
                        help="target CRC value (hex).")
    parser.add_argument("--prefix", default="", help="prefix string (ASCII).")
    parser.add_argument("--suffix", default="", help="suffix string (ASCII).")
    parser.add_argument("--prefix-hex", default="", help="prefix string (HEX).")
    parser.add_argument("--suffix-hex", default="", help="suffix string (HEX).")
    parser.add_argument("--charset", default="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz_",
                        help="the character set for bruteforce (default: %(default)s).")
    parser.add_argument("-b", "--bridge-length", type=AddressUtil.parse_address,
                        help="specific bridge length.")
    parser.add_argument("-c", dest="cont", action="store_true", help="do not terminate midway.")
    parser.add_argument("-k", "--known", nargs=2, action="append", metavar=("IDX", "CHAR"),
                        help="specified known fixed value.")
    parser.add_argument("-K", "--known-hex", nargs=2, action="append", metavar=("IDX", "HEX_CHAR"),
                        help="specified known fixed value.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} --list",
        "{0:s} 0x41414141",
        "{0:s} 0x41414141 --prefix AAAA --suffix BBBB",
        "{0:s} 0x41414141 --prefix flag{{ --suffix-hex 7d00 -b 8 -k 1 A -k 3 A",
        "{0:s} 0x41414141 --preset mpeg2",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "wanted_crc == crc(prefix + bridge + suffix).",
    ]
    _note_ = "\n".join(_note_)

    preset_dic = {
        # https://reveng.sourceforge.io/crc-catalogue/all.htm
        # preset name: (poly,        init_value,  xorout,      refin, refout, alias)
        "":            (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, True,  True,   False),
        "base":        (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "ieee":        (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "isohdlc":     (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "adccp":       (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "v42":         (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "xz":          (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "pkzip":       (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "aixm":        (0x8141_41ab, 0x0000_0000, 0x0000_0000, False, False,  False),
        "q":           (0x8141_41ab, 0x0000_0000, 0x0000_0000, False, False,  True),
        "autosar":     (0xf4ac_fb13, 0xffff_ffff, 0xffff_ffff, True,  True,   False),
        "base91d":     (0xa833_982b, 0xffff_ffff, 0xffff_ffff, True,  True,   False),
        "d":           (0xa833_982b, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "bzip2":       (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, False, False,  False),
        "aal5":        (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, False, False,  True),
        "dectb":       (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, False, False,  True),
        "b":           (0x04c1_1db7, 0xffff_ffff, 0xffff_ffff, False, False,  True),
        "cdromedc":    (0x8001_801b, 0x0000_0000, 0x0000_0000, True,  True,   False),
        "cksum":       (0x04c1_1db7, 0x0000_0000, 0xffff_ffff, False, False,  False),
        "posix":       (0x04c1_1db7, 0x0000_0000, 0xffff_ffff, False, False,  True),
        "iscsi":       (0x1edc_6f41, 0xffff_ffff, 0xffff_ffff, True,  True,   False),
        "base91c":     (0x1edc_6f41, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "castagnoli":  (0x1edc_6f41, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "interlaken":  (0x1edc_6f41, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "c":           (0x1edc_6f41, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "nvme":        (0x1edc_6f41, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
        "jamcrc":      (0x04c1_1db7, 0xffff_ffff, 0x0000_0000, True,  True,   False),
        "mef":         (0x741b_8cd7, 0xffff_ffff, 0x0000_0000, True,  True,   False),
        "mpeg2":       (0x04c1_1db7, 0xffff_ffff, 0x0000_0000, False, False,  False),
        "ether":       (0x04c1_1db7, 0xffff_ffff, 0x0000_0000, False, False,  True),
        "xfer":        (0x0000_00af, 0x0000_0000, 0x0000_0000, False, False,  False),
        "koopman":     (0x741b_8cd7, 0xffff_ffff, 0xffff_ffff, True,  True,   False),
        "k":           (0x741b_8cd7, 0xffff_ffff, 0xffff_ffff, True,  True,   True),
    }

    def print_preset_dict(self):
        fmt = "{:<10s}  {:<10s}  {:<10s}  {:<10s}  {:<10s}  {:5s}  {:6s}  {:5s}"
        legend = ["name", "poly", "rpoly", "init_value", "xorout", "refin", "refout", "alias"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        for k, v in self.preset_dic.items():
            if v[5]:
                alias = "(alias)"
            else:
                alias = ""
            gef_print("{:10s}  {:#010x}  {:#010x}  {:#010x}  {:#010x}  {!s:5s}  {!s:6s}  {:s}".format(
                k or "''", v[0], self.reflect32(v[0]), v[1], v[2], v[3], v[4], alias),
            )
        return

    def reflect32(self, x):
        """bit reverse."""
        return int("{:032b}".format(x)[::-1], 2) & 0xffff_ffff

    def build_crc(self):
        """Apply preset parameters if requested. Explicit CLI flags override these."""
        poly, init_value, xorout, refin, refout, _ = self.preset_dic[self.args.preset]
        # override from CLI
        if self.args.poly is not None:
            poly = self.args.poly & 0xffff_ffff
        if self.args.poly_reflected:
            poly = self.reflect32(poly)
        rpoly = self.reflect32(poly)
        if self.args.init_value is not None:
            init_value = self.args.init_value & 0xffff_ffff
        if self.args.xorout is not None:
            xorout = self.args.xorout & 0xffff_ffff
        if self.args.refin:
            refin = True
        if self.args.no_refin:
            refin = False
        if self.args.refout:
            refout = True
        if self.args.no_refout:
            refout = False
        assert refin == refout
        # build
        CRC = collections.namedtuple("CRC", ["poly", "rpoly", "init_value", "xorout", "refin", "refout"])
        self.CRC = CRC(poly, rpoly, init_value, xorout, refin, refout)
        return

    def build_tables(self):
        """Build forward / reverse table and the inverse index used by backward steps."""
        self.FT = [] # used always
        self.RT = [] # used when refin == refout == True
        self.inv_idx = [0] * 256 # used when refin == refout == False

        if not self.CRC.refin and not self.CRC.refout:
            for i in range(256):
                fwd = i << 24
                for _ in range(8):
                    if fwd & 0x8000_0000:
                        fwd = ((fwd << 1) ^ self.CRC.poly) & 0xffff_ffff
                    else:
                        fwd = (fwd << 1) & 0xffff_ffff
                self.FT.append(fwd)
            for i in range(256):
                self.inv_idx[self.FT[i] & 0xff] = i
        else:
            for i in range(256):
                fwd = i
                rev = i << 24
                for _ in range(8):
                    if fwd & 1:
                        fwd = ((fwd >> 1) ^ self.CRC.rpoly) & 0xffff_ffff
                    else:
                        fwd = (fwd >> 1) & 0xffff_ffff
                    if (rev >> 31) & 1:
                        rev = (((rev ^ self.CRC.rpoly) << 1) | 1) & 0xffff_ffff
                    else:
                        rev = (rev << 1) & 0xffff_ffff
                self.FT.append(fwd)
                self.RT.append(rev)
        return

    def calc_forward(self, accum, data_bytes):
        crc = accum
        if not self.CRC.refin and not self.CRC.refout:
            for c in data_bytes:
                idx = ((crc >> 24) ^ c) & 0xff
                crc = ((crc << 8) & 0xffff_ffff) ^ self.FT[idx]
        else:
            for c in data_bytes:
                idx = (crc ^ c) & 0xff
                crc = (crc >> 8) ^ self.FT[idx]
        return crc

    def calc_backward(self, wanted, data_bytes):
        crc = wanted
        if not self.CRC.refin and not self.CRC.refout:
            for c in data_bytes[::-1]:
                b = self.inv_idx[crc & 0xff]
                prev_top = b ^ c
                q = crc ^ self.FT[b]
                crc = ((q >> 8) & 0xffff_ffff) | ((prev_top & 0xff) << 24)
        else:
            for c in data_bytes[::-1]:
                idx = crc >> 24
                crc = ((crc << 8) & 0xffff_ffff) ^ self.RT[idx] ^ c
        return crc

    def calc_crc32(self, msg_bytes):
        crc = self.CRC.init_value
        crc = self.calc_forward(crc, msg_bytes)
        return crc ^ self.CRC.xorout

    def find_bridge_tail(self, init_value, wanted_crc, prefix, suffix):
        """Compute a 4-byte bridge so that CRC(prefix + bridge + suffix) == wanted_crc."""
        # forward state after prefix (raw)
        fwd_crc = self.calc_forward(init_value, prefix)

        # map external wanted -> raw wanted (invert output formatting)
        wanted_raw = wanted_crc ^ self.CRC.xorout

        # rewind suffix to get the raw state right before suffix
        bkd_crc = self.calc_backward(wanted_raw, suffix)

        def state_bytes(x):
            if not self.CRC.refin and not self.CRC.refout:
                xs = [(x >> 24) & 0xff, (x >> 16) & 0xff, (x >> 8) & 0xff, (x >> 0) & 0xff]
                return xs
            else:
                xs = [(x >> 0) & 0xff, (x >> 8) & 0xff, (x >> 16) & 0xff, (x >> 24) & 0xff]
                return xs

        # 4-byte exact bridge between fwd_crc and bkd_crc
        bridge_word = self.calc_backward(bkd_crc, state_bytes(fwd_crc))
        bridge_bytes = state_bytes(bridge_word)

        # sanity check
        test_seq = prefix + bridge_bytes + suffix
        assert self.calc_crc32(test_seq) == wanted_crc
        return bridge_bytes

    def build_known_map(self):
        """Build map from --known and --known-hex."""
        known_map = {}
        for raw_idx, raw_char in self.args.known or []:
            idx = int(raw_idx, 0)
            if idx < 0:
                err("known IDX must be >= 0")
                return None
            bs = String.str2bytes(raw_char)
            if len(bs) != 1:
                err("known CHAR must be exactly 1 byte")
                return None
            b = bs[0]
            if idx in known_map and known_map[idx] != b:
                err("conflicting known values for index {}".format(idx))
                return None
            known_map[idx] = b

        for raw_idx, hex_char in self.args.known_hex or []:
            idx = int(raw_idx, 0)
            if idx < 0:
                err("known IDX must be >= 0")
                return None
            bs = GefUtil.fromhex_ignore_invalid(hex_char)
            if bs is None:
                err("Invalid HEX_CHAR")
                return None
            if len(bs) != 1:
                err("known HEX_CHAR must be exactly 1 byte")
                return None
            b = bs[0]
            if idx in known_map and known_map[idx] != b:
                err("conflicting known values for index {}".format(idx))
                return None
            known_map[idx] = b
        return known_map

    def build_known_constraints(self, bridge_length, charset, known_map):
        """Return per-position choices for head and fixed-byte checks for tail."""
        tail_length = 4
        head_length = bridge_length - tail_length
        head_choices = [charset for _ in range(head_length)]
        tail_checks = []
        for idx, b in known_map.items():
            if idx >= bridge_length:
                return None
            if b not in charset:
                return None
            if idx < head_length:
                head_choices[idx] = (b,)
            else:
                tail_checks.append((idx - head_length, b))
        return head_choices, tuple(tail_checks)

    def find_reverse(self, prefix, suffix, lengths, charset, known_map):
        """Search charset-limited bridges of lengths."""
        self.build_crc()
        self.build_tables()

        init_value = self.CRC.init_value
        wanted_crc = self.args.wanted_crc & 0xffff_ffff

        found = False
        for bridge_length in lengths:
            #            bridge
            #          ~~~~~~~~~~~
            # prefix + head + tail + suffix
            # ~~~~~~~~~~~~~   ~~~~
            #  new_prefix     4bytes
            constraints = self.build_known_constraints(bridge_length, charset, known_map)
            if constraints is None:
                continue
            head_choices, tail_checks = constraints

            for head in itertools.product(*head_choices):
                head = list(head)
                new_prefix = prefix + head
                tail = list(self.find_bridge_tail(init_value, wanted_crc, new_prefix, suffix))

                if not all(c in charset for c in tail):
                    continue

                if not all(tail[pos] == b for pos, b in tail_checks):
                    continue

                bridge = head + tail
                msg = prefix + bridge + suffix
                crc = self.calc_crc32(msg)
                gef_print("{}: CRC32({}) = {:#010x}".format(bytes(bridge), bytes(msg), crc))
                found |= True

            if found:
                if bridge_length >= 6 and not self.args.cont:
                    break

        if not found:
            err("No bridge found under given constraints.")
        return

    @parse_args
    def do_invoke(self, args):
        if self.args.list == (self.args.wanted_crc is not None):
            self.usage()
            return

        if self.args.list:
            self.print_preset_dict()
            return

        if self.args.bridge_length is not None:
            if self.args.bridge_length < 4:
                err("bridge_length must be >= 4")
                return
            lengths = (self.args.bridge_length,)
        else:
            max_length = 10
            lengths = range(4, max_length + 1)

        if args.prefix and args.prefix_hex:
            err("duplicate prefix")
            return
        if args.suffix and args.suffix_hex:
            err("duplicate suffix")
            return

        if args.prefix_hex:
            prefix = GefUtil.fromhex_ignore_invalid(args.prefix_hex)
            if prefix is None:
                err("Invalid prefix")
                return
            prefix = list(prefix)
        else:
            prefix = [ord(c) for c in self.args.prefix]

        if args.suffix_hex:
            suffix = GefUtil.fromhex_ignore_invalid(args.suffix_hex)
            if suffix is None:
                err("Invalid suffix")
                return
            suffix = list(suffix)
        else:
            suffix = [ord(c) for c in self.args.suffix]

        if prefix:
            info("prefix: {}".format(bytes(prefix)))
        if suffix:
            info("suffix: {}".format(bytes(suffix)))

        known_map = self.build_known_map()
        if known_map is None:
            return

        charset = tuple(String.str2bytes(self.args.charset))
        if not charset:
            err("charset must not be empty")
            return

        self.find_reverse(prefix, suffix, lengths, charset, known_map)
        return
