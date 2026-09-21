"""System-register bit-field pretty-printing helper (Layer 1).

`BitInfo` renders a register value's bits/fields with colors (used by the
`sreg` / qemu-register commands, which will live in gef.commands).
"""
import itertools

from gef.core import runtime
from gef.core.color import Color, gef_print


class BitInfo:
    """Printing various bit information of the register."""

    def __init__(self, name, register_bit=None, bit_info=(), desc=None):
        self.name = name
        if register_bit is None:
            self.register_bit = runtime.current_arch.ptrsize * 8
        else:
            self.register_bit = register_bit
        self.description = desc

        # bit_info: [[bits, short_name, short_description, long_description], ...]
        self.bit_info = bit_info
        return

    @staticmethod
    def bits_split(x, bits):
        # split by 4bits. e.g., 0bXXYYYY -> 0b00XX_YYYY
        out = ""
        for i in range(bits):
            if x & (1 << i):
                out = "1" + out
            else:
                out = "0" + out
            if i % 4 == 3:
                out = "_" + out
        return "0b" + out[1:]

    def print_value(self, regval, split=False):
        regname = Color.colorify(self.name, "bold red")
        value_str = Color.colorify_hex(regval, "bold yellow")
        if split:
            bit_split_str = BitInfo.bits_split(regval, self.register_bit)
            value_str += Color.colorify(" (={:s})".format(bit_split_str), "bold yellow")
        self.out.append("{:s} = {:s}".format(regname, value_str))
        return

    def print_description(self):
        if self.description:
            self.out.append(Color.boldify(self.description))
        return

    def print_bitinfo(self, regval):
        # preprocess
        max_width_bits = 2 # default
        max_width_sym = 0
        max_width_val = 0
        bit_range_strs = []
        bit_values = []
        for bits, sym, *_ in self.bit_info:
            if isinstance(bits, range):
                bits = list(bits)

            # search for max width for bit_ragne_string
            if isinstance(bits, int):
                b = "{:d}".format(bits)
                bit_range_strs.append(b)
            else:
                # e.g., [11, 12, 0, 1, 2, 10] -> [0, 1, 2, 10, 11, 12]
                bits = sorted(bits)
                # e.g., [0, 1, 2, 10, 11, 12] -> [[0, 1, 2], [10, 11, 12]]
                gen = itertools.groupby(bits, key=lambda n, c=itertools.count(): n - next(c)) # noqa: B008
                gr_bits = [list(g) for _, g in gen]

                tmp = []
                for gb in gr_bits:
                    if len(gb) == 1:
                        tmp.append("{:d}".format(gb[0]))
                    else:
                        tmp.append("{:d}-{:d}".format(gb[-1], gb[0]))
                bit_str = ",".join(tmp[::-1])
                bit_range_strs.append(bit_str)
                max_width_bits = max(max_width_bits, len(bit_str))

            # search for max width for sym
            if sym:
                max_width_sym = max(max_width_sym, len(sym))

            # search for max width for val
            if isinstance(bits, int):
                val = (regval & (1 << bits)) >> bits
                bit_values.append(val)
            else:
                val = 0
                for i, x in enumerate(bits):
                    val |= (regval & (1 << x)) >> (x - i)
                bit_values.append(val)
            max_width_val = max(max_width_val, len("{:#x}".format(val)))

        # here, preprocess is finieshed.
        # - max_width_bits
        # - max_width_sym
        # - max_width_val
        # - bit_range_strs # e.g., ["0", "4-1", "8-7,5"]
        # - bit_values     # e.g., [0b1, 0b1111, 0b1101]

        # actual perform
        for i, (_, sym, *desc) in enumerate(self.bit_info):
            b = bit_range_strs[i]
            val = bit_values[i]

            msg = "bit{:>{:d}s}: ".format(b, max_width_bits)

            if val:
                msg += Color.boldify("{:>#{:d}x} ".format(val, max_width_val))
            else:
                msg += "{:>#{:d}x} ".format(val, max_width_val)

            if sym is not None:
                msg += "{:{:d}s}  ".format(sym, max_width_sym)

            if len(desc) == 1:
                # short description only
                if desc[0]:
                    msg += desc[0]

            elif len(desc) >= 2:
                # short description and long description
                if desc[0]:
                    msg += desc[0] + "; "
                msg += "; ".join(desc[1:])

            self.out.append(msg)
        return

    def make_out(self, regval, split=False):
        self.out = []
        self.print_value(regval, split)
        self.print_description()
        self.print_bitinfo(regval)
        return self.out

    def print(self, regval, split=False):
        self.make_out(regval, split)
        if self.out:
            gef_print("\n".join(self.out))
        return
