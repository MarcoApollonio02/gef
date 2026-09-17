"""GEF instruction model and disassembly helpers (Layer 1).

Contains `Instruction` (GEF representation of a CPU instruction, with
display/coloring helpers), `Disasm` (gdb- and capstone-backed disassembler
frontends) and the module-level helpers `get_insn`, `get_insn_next` and
`get_insn_prev`.

Reads of the mutable global `current_arch` go through `runtime.current_arch`
(never a by-name import) to avoid the stale-binding pitfall documented in
runtime.py. References to modules that are not yet extracted (symbols,
process, utils, gef.commands) are imported lazily inside the method that
needs them. `gef.core.utils` is referenced through a late-bound
`ModuleLoader` trampoline inside the `Disasm` class body, so this module
stays importable before `gef.core.utils` exists.
"""
import functools
import gdb
import re
import sys

from gef.core import runtime
from gef.core.cache import Cache
from gef.core.color import Color, err
from gef.core.config import Config
from gef.core.memory import is_valid_addr, read_cstring_from_memory, read_memory


class Instruction:
    """GEF representation of a CPU instruction."""

    RE_SPLIT_LAST_OPERAND_X86_64 = re.compile(r"(.*?)\s+(#.+)$")
    RE_SPLIT_LAST_OPERAND_ARM64 = re.compile(r"//.+$")
    RE_SPLIT_LAST_OPERAND_ARM32 = re.compile(r";.+$")
    RE_SPLIT_LAST_OPERAND_MICROBLAZE = re.compile(r"//.+$")
    RE_SPLIT_LAST_OPERAND_LOONGARCH64 = re.compile(r"(# .*)$")
    RE_SPLIT_ELEM = re.compile(r"([*%\[\](): ]|(?<![#@%])(?<=.)[-+]|<.+>)")
    RE_IS_DIGIT_COMMENT = re.compile(r"#?-?(0x[0-9a-f]+|\d+)")
    RE_SPLIT_SYMBOL = re.compile(r"(.*?)<(.+)>(.*)$")
    RE_SPLIT_SYMBOL_OFFSET = re.compile(r"(.+)\+(\d+)$")

    def __init__(self, address, mnemo, operands, opcodes):
        # example:
        #   address: 0x55555555a7d0
        #   mnemo: "lea"
        #   operands: "rcx, [rip+0x11ee5]        # 0x55555556c69a"
        #     -> ["rcx", "[rip+0x11ee5]        # 0x55555556c69a"]
        #   opcodes: b'H\x8d\r\xe5\x1e\x01\x00'
        self.address = address
        self.mnemonic = mnemo

        # merge symbol includes ","; e.g., <... , ...>
        operands = [x.strip() for x in operands.split(",")]
        if len(operands) > 1:
            operands, o = operands[:-1], operands[-1]
            while (o.count("<") - o.count("operator<<") * 2) != (o.count(">") - o.count("operator>>") * 2):
                # The split location is incorrect, so fix it.
                # This is because there are cases where symbols contain `,`, such as C++ binaries.
                if len(operands) > 1:
                    operands, oo = operands[:-1], operands[-1]
                    o = oo + ", " + o
                else:
                    o = operands[0] + ", " + o
                    operands = []
                    break
            operands += [o]

        self.operands = operands
        self.opcodes = opcodes
        self.size = len(opcodes)
        return

    @property
    def location(self):
        if hasattr(self, "__location"):
            return self.__location
        # evaluate when needed
        from gef.core.symbols import Symbol
        self.__location = Symbol.get_symbol_string(self.address, nosymbol_string=" <NO_SYMBOL>")
        return self.__location

    @property
    def is_branch(self):
        """Return whether it is a branch instruction. Cache the results."""
        if hasattr(self, "__is_branch"):
            return self.__is_branch

        if runtime.current_arch.is_syscall(self):
            self.__is_branch = True
        elif runtime.current_arch.is_call(self):
            self.__is_branch = True
        elif runtime.current_arch.is_jump(self):
            self.__is_branch = True
        elif runtime.current_arch.is_ret(self):
            self.__is_branch = True
        elif runtime.current_arch.is_conditional_branch(self):
            self.__is_branch = True
        else:
            self.__is_branch = False
        return self.__is_branch

    def get_color(self, highlight, config_name):
        """A wrapper to easily retrieve color-related configurations."""
        if highlight:
            return Config.get_gef_setting(config_name + "_highlight")
        else:
            return Config.get_gef_setting(config_name)

    def get_string_if_valid_addr(self, operands):
        """If the last operand is an address and is valid, read and return the string."""
        if not operands:
            return None
        last_operand = operands[-1]
        if " " in last_operand:
            last_operand = last_operand.split()[-1]
        if len(last_operand) < 10: # len("0xXXXXXXXX") or len("0xXXXXXXXXXXXXXXXX")
            return None
        try:
            v = int(last_operand, 0)
        except ValueError:
            return None
        if not is_valid_addr(v):
            return None
        s = read_cstring_from_memory(v)
        return s

    def split_last_operands(self, operands):
        """Separate `operands` into real operands and comment for each architecture."""
        if len(operands) == 0:
            return [], ""

        from gef.core.process import is_arm32, is_arm32_cortex_m, is_arm64, is_loongarch64, is_microblaze, is_x86_64

        comment = ""
        last_operand = operands[-1]
        if is_x86_64():
            r = self.RE_SPLIT_LAST_OPERAND_X86_64.match(last_operand) # r"(.*?)\s+(#.+)$"
            if r:
                last_operand = r.group(1)
                comment = r.group(2)
                operands = operands[:-1] + [last_operand]
        elif is_arm64():
            r = self.RE_SPLIT_LAST_OPERAND_ARM64.match(last_operand) # r"//.+$"
            if r:
                comment = last_operand
                operands = operands[:-1]
        elif is_arm32() or is_arm32_cortex_m():
            r = self.RE_SPLIT_LAST_OPERAND_ARM32.match(last_operand) # r";.+$"
            if r:
                comment = last_operand
                operands = operands[:-1]
        elif is_microblaze():
            r = self.RE_SPLIT_LAST_OPERAND_MICROBLAZE.match(last_operand) # r"//.+$"
            if r:
                comment = last_operand
                operands = operands[:-1]
        elif is_loongarch64():
            r = self.RE_SPLIT_LAST_OPERAND_LOONGARCH64.match(last_operand) # r"(# .*)$"
            if r:
                comment = r.group(1)
                operands = operands[:-1]
        return operands, comment

    def colored_operands_text(self, highlight, operands):
        """Parse the operands, color each element, and return it as a string."""
        color_operands_normal = self.get_color(highlight, "theme.disassemble_operands_normal")
        color_operands_const = self.get_color(highlight, "theme.disassemble_operands_const")
        color_operands_symbol = self.get_color(highlight, "theme.disassemble_operands_symbol")

        # extract -> coloring -> join
        colored_operands = []
        for o1 in operands:
            colored_o1 = []
            # split by *, [, ], (, ), %, :, space, non-first +, - (without #, @, %), <...>
            for o2 in self.RE_SPLIT_ELEM.split(o1): # r"([*%\[\](): ]|(?<![#@%])(?<=.)[-+]|<.+>)"
                o2 = o2.strip()
                if o2 == "":
                    continue
                if o2[0] == "<":
                    colored_o1.append(self.hexlify_symbol_offset(o2))
                    colored_o1.append(" ")
                elif o2 in ["-", "+", "*"]:
                    colored_o1.append(Color.colorify(o2, color_operands_symbol))
                    colored_o1.append(" ")
                elif o2 in [":", "%"]:
                    if colored_o1 and colored_o1[-1] == " ":
                        colored_o1 = colored_o1[:-1]
                    colored_o1.append(Color.colorify(o2, color_operands_symbol))
                elif o2 in ["[", "("]:
                    colored_o1.append(Color.colorify(o2, color_operands_symbol))
                elif o2 in ["]", ")"]:
                    if colored_o1 and colored_o1[-1] == " ":
                        colored_o1 = colored_o1[:-1]
                    colored_o1.append(Color.colorify(o2, color_operands_symbol))
                elif self.RE_IS_DIGIT_COMMENT.match(o2): # r"#?-?(0x[0-9a-f]+|\d+)"
                    colored_o1.append(Color.colorify(o2, color_operands_const))
                    colored_o1.append(" ")
                else:
                    colored_o1.append(Color.colorify(o2, color_operands_normal))
                    colored_o1.append(" ")
            colored_operands.append("".join(colored_o1).strip())
        operands_text = Color.colorify(", ", color_operands_symbol).join(colored_operands)
        return operands_text

    def hexlify_symbol_offset(self, x):
        """i.e., <memcmp+20> -> <memcmp+0x14>"""
        r1 = self.RE_SPLIT_SYMBOL.match(x) # r"(.*?)<(.+)>(.*)$"
        if not r1:
            return x
        r2 = self.RE_SPLIT_SYMBOL_OFFSET.match(r1.group(2)) # r"(.+)\+(\d+)$"
        if r2:
            sym_x = "{}+{:#x}".format(self.smartify_text(r2.group(1)), int(r2.group(2)))
        else:
            sym_x = self.smartify_text(r1.group(2))
        return "{:s}<{:s}>{:s}".format(r1.group(1), sym_x, r1.group(3))

    def get_opcodes_hex(self, opcodes_len):
        opcodes_hex = "".join("{:02x}".format(b) for b in self.opcodes) # e.g., "488d0de51e0100"
        # e.g., len=4: opcodes:01020304   -> 01020304
        # e.g., len=4: opcodes:0102030405 -> 010203..
        if opcodes_len < len(self.opcodes):
            opcodes_hex = opcodes_hex[:opcodes_len * 2 - 2] + ".."
        opcodes_hex = "{:{:d}}".format(opcodes_hex, opcodes_len * 2)
        return opcodes_hex

    def colored_text(self, opcodes_len=0, highlight=False, disable_color=False):
        """Color the entire instruction, format it as a string and return it."""
        if opcodes_len == 0:
            return str(self)

        enable_color = not disable_color

        # format address
        address_text = hex(self.address)

        # format location
        location_text = self.smartify_text(self.location)

        if enable_color:
            color_address = self.get_color(highlight, "theme.disassemble_address")
            address_text = Color.colorify(address_text, color_address)
            location_text = Color.colorify(location_text, color_address)

        # format opcode
        opcodes_hex = self.get_opcodes_hex(opcodes_len)

        if enable_color:
            color_opcode = self.get_color(highlight, "theme.disassemble_opcode")
            opcodes_hex = Color.colorify(opcodes_hex, color_opcode)

        # format mnemonic
        mnemonic_text = "{:6s}".format(self.mnemonic)

        if enable_color:
            if self.is_branch:
                color_mnemonic = self.get_color(highlight, "theme.disassemble_mnemonic_branch")
            else:
                color_mnemonic = self.get_color(highlight, "theme.disassemble_mnemonic_normal")
            mnemonic_text = Color.colorify(mnemonic_text, color_mnemonic)

        # split last operand by ;, #, //
        operands_array, comment = self.split_last_operands(self.operands[::])
        comment = self.hexlify_symbol_offset(comment)

        # format operands
        if enable_color:
            operands_text = self.colored_operands_text(highlight, operands_array)
        else:
            operands_text = ", ".join(operands_array)

        # the case that gdb does not append symbol but symbol exists
        if self.is_branch:
            if "<" not in operands_text and "<" not in comment:
                if self.operands and self.operands[-1]:
                    from gef.commands.context import ContextCodeCommand
                    addr = ContextCodeCommand.get_branch_addr(self)
                    # Not using += is intentional; useless comments are discarded
                    comment = Symbol.get_symbol_string(addr).lstrip()

        # add strings
        if not self.is_branch:
            if not comment:
                s = self.get_string_if_valid_addr(operands_array)
            else:
                s = self.get_string_if_valid_addr([comment])
            if s:
                if enable_color:
                    string_color = Config.get_gef_setting("theme.dereference_string")
                    if len(s) < runtime.current_arch.ptrsize:
                        comment += " ({:s}?)".format(Color.colorify(repr(s), string_color))
                    else:
                        comment += " ({:s})".format(Color.colorify(repr(s), string_color))
                else:
                    if len(s) < runtime.current_arch.ptrsize:
                        comment += " ({:s}?)".format(repr(s))
                    else:
                        comment += " ({:s})".format(repr(s))

        # formatting
        out = "{:s} {:s} {:s}   {:s} {:s} {:s}".format(
            address_text, opcodes_hex, location_text, mnemonic_text, operands_text, comment,
        ).rstrip()
        return out

    def __repr__(self):
        return '<{:s}.{:s} object at {:#x}, asm="{:s}">'.format(
            self.__module__, self.__class__.__name__, id(self), str(self),
        )

    def __str__(self):
        location = self.smartify_text(self.location)
        operands = self.smartify_text(", ".join(self.operands))
        return "{:#10x} {:20s} {:6s} {:s}".format(self.address, location, self.mnemonic, operands)

    def is_valid(self):
        return "(bad)" not in self.mnemonic

    @staticmethod
    def smartify_text(text):
        """Simplify and shorten C++ function/type names for improved readability."""
        smart_cpp_function_name = Config.get_gef_setting("context.smart_cpp_function_name")
        if not smart_cpp_function_name:
            return text

        if text is None:
            return text

        if len(text) == 0:
            return text

        text = re.sub(r"\bstd::__1::", "", text)

        old_text = text[::]
        while True:
            text = re.sub(r"\([^(]+?\)", "__MARKER_GEF__", text)
            if text == old_text:
                break
            old_text = text[::]
        text = re.sub("__MARKER_GEF__", "(...)", text)

        m = re.match(r"^(\s*\<)(.*)(\>\s*)$", text)
        if m:
            text_0, text, text_end = m.group(1), m.group(2), m.group(3)
        else:
            text_0, text, text_end = "", text, ""

        while True:
            text = re.sub(r"\<[^<]+?\>", "__MARKER_GEF__", text)
            if text == old_text:
                break
            old_text = text[::]
        text = re.sub("__MARKER_GEF__", "<...>", text)
        if text_0:
            text = text_0 + text
        if text_end:
            text = text + text_end
        return text


class Disasm:
    """A collection of utility functions that makes disassemble."""

    __gef_prev_arch__ = None # previous valid result of gdb.selected_frame().architecture()

    # Late-bound trampoline: resolves to gef.core.utils.ModuleLoader at call
    # time, keeping this module importable before gef.core.utils exists.
    class ModuleLoader:
        def load_capstone(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                from gef.core.utils import ModuleLoader
                return ModuleLoader.load_capstone(f)(*args, **kwargs)
            return wrapper

    @staticmethod
    def gdb_disassemble(start_pc, nb_insn=None, end_pc=None):
        """Disassemble instructions from `start_pc` (Integer). Return an iterator of Instruction objects.
        This is the backend used by Disasm.gef_disassemble by default."""
        if start_pc is None:
            return None

        try:
            arch = gdb.selected_frame().architecture()
            Disasm.__gef_prev_arch__ = arch
        except gdb.error:
            # gdb.selected_frame() may error for unknown reasons (often during kernel startup).
            # At this time arch cannot be resolved, but if it was successful before, it will be used.
            if Disasm.__gef_prev_arch__ is None:
                raise
            arch = Disasm.__gef_prev_arch__

        kwargs = {}
        if nb_insn is not None:
            kwargs["count"] = nb_insn
        if end_pc is not None:
            kwargs["end_pc"] = end_pc

        insn_list = list(arch.disassemble(start_pc, **kwargs))
        if not insn_list:
            return None

        from gef.core.process import is_arm32, is_arm32_cortex_m

        is_thumb = (is_arm32() or is_arm32_cortex_m())

        def eff_addr(a):
            return a - 1 if is_thumb and (a & 1) else a

        def get_mnemo_operands(insn):
            asm = insn["asm"].rstrip().split(None, 1)
            if len(asm) > 1:
                mnemo = asm[0]
                operands = asm[1].replace("\t", " ")
            else:
                mnemo, operands = asm[0], ""
            return mnemo, operands

        try:
            # fast path: read each instruction at once

            # calc size
            base = None
            end = None
            for insn in insn_list:
                ea = eff_addr(insn["addr"])
                if base is None or ea < base:
                    base = ea
                e = ea + insn["length"]
                if end is None or e > end:
                    end = e

            blob = read_memory(base, end - base)

            for insn in insn_list:
                address = insn["addr"]
                mnemo, operands = get_mnemo_operands(insn)

                ea = eff_addr(address)
                off = ea - base
                opcodes = blob[off: off + insn["length"]]

                yield Instruction(address, mnemo, operands, opcodes)

        except gdb.MemoryError:
            # slow path: read each instruction sequentially
            for insn in insn_list:
                address = insn["addr"]
                mnemo, operands = get_mnemo_operands(insn)

                if is_thumb and (address & 1):
                    opcodes = read_memory(address - 1, insn["length"])
                else:
                    opcodes = read_memory(address, insn["length"])

                yield Instruction(address, mnemo, operands, opcodes)

        return None

    @staticmethod
    def gdb_get_nth_previous_instruction_address(addr, n):
        """Return the address (Integer) of the `n`-th instruction before `addr`."""
        if addr is None:
            return None

        # fixed-length ABI
        if runtime.current_arch.instruction_length:
            return max(0, addr - n * runtime.current_arch.instruction_length)

        # variable-length ABI
        cur_insn_addr = get_insn(addr).address

        # we try to find a good set of previous instructions by "guessing" disassembling backwards
        # the 15 comes from the longest instruction valid size
        for i in range(15 * n, 0, -1):
            try:
                insns = list(Disasm.gdb_disassemble(addr - i, end_pc=cur_insn_addr))
            except gdb.MemoryError:
                # this is because we can hit an unmapped page trying to read backward
                break

            # 1. check that the disassembled instructions list size can satisfy
            if len(insns) < n + 1: # we expect the current instruction plus the n before it
                continue

            # If the list of instructions is longer than what we need, then we
            # could get lucky and already have more than what we need, so slice down
            insns = insns[-n - 1:]

            # 2. check that the sequence ends with the current address
            if insns[-1].address != cur_insn_addr:
                continue

            # 3. check all instructions are valid
            if all(insn.is_valid() for insn in insns):
                return insns[0].address
        return None

    @staticmethod
    @ModuleLoader.load_capstone
    def capstone_get_nth_previous_instruction_address(addr, n, cs=None):
        """Return the address (Integer) of the `n`-th instruction before `addr`."""
        if addr is None:
            return None

        if cs is None:
            from gef.core.utils import UnicornKeystoneCapstone
            cs = sys.modules["capstone"].Cs(*UnicornKeystoneCapstone.get_capstone_arch())

        # fixed-length ABI
        if runtime.current_arch.instruction_length:
            return max(0, addr - n * runtime.current_arch.instruction_length)

        # variable-length ABI

        # we try to find a good set of previous instructions by "guessing" disassembling backwards
        # the 15 comes from the longest instruction valid size
        for i in range(15 * n, 0, -1):
            try:
                code = read_memory(addr - i, i)
            except gdb.MemoryError:
                continue

            insns = list(cs.disasm(code, addr - i))

            # 1. check that the disassembled instructions list size can satisfy
            if len(insns) < n:
                continue
            insns = insns[-n:]

            # 2. check that the sequence ends with the current address
            if insns[-1].address + insns[-1].size != addr:
                continue

            return insns[0].address
        return None

    @staticmethod
    @ModuleLoader.load_capstone
    def capstone_disassemble(location, nb_insn, **kwargs):
        """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before `addr`
        using the capstone disassembler. Return an iterator of Instruction objects.
        This is the backend used by Disasm.gef_disassemble if specified in the config.
        It is also called directly from some commands such as Disasm.capstone_disassemble."""

        def cs_insn_to_gef_insn(cs_insn):
            return Instruction(cs_insn.address, cs_insn.mnemonic, cs_insn.op_str, cs_insn.bytes)

        from gef.core.process import get_pagesize, get_pagesize_mask_low, is_arm32, is_arm32_cortex_m
        from gef.core.utils import UnicornKeystoneCapstone

        capstone = sys.modules["capstone"]
        arch, mode = UnicornKeystoneCapstone.get_capstone_arch(
            arch=kwargs.get("arch", None),
            mode=kwargs.get("mode", None),
            endian=kwargs.get("endian", None),
        )
        try:
            cs = capstone.Cs(arch, mode)
            cs.detail = True # noqa
        except capstone.CsError:
            err("CsError")
            return

        # fix location by nb_prev
        nb_prev = kwargs.get("nb_prev", 0)
        if nb_prev > 0:
            location_tmp = Disasm.capstone_get_nth_previous_instruction_address(
                location, nb_prev, capstone.Cs(arch, mode),
            )
            if location_tmp is not None:
                location = location_tmp
                nb_insn += nb_prev

        # split reading by page_size
        read_addr = location
        read_size = get_pagesize() - (location & get_pagesize_mask_low())

        # fix for arm thumb2 mode
        if (is_arm32() or is_arm32_cortex_m()) and read_addr & 1:
            read_addr -= 1
            read_size += 1

        skip = kwargs.get("skip", 0)
        arch_inst_length = runtime.current_arch.instruction_length or 1
        used_bytes = 0
        code_remain = bytes.fromhex(kwargs.get("code", ""))
        dont_read = "code" in kwargs

        # A loop to read the required memory until the specified length is reached
        while True:
            if not dont_read and len(code_remain) < get_pagesize():
                # not enough code to disassemble, so read the memory to pool
                try:
                    read_data = read_memory(read_addr, read_size)
                except gdb.MemoryError:
                    err("Memory read error at {:#x}-{:#x}".format(read_addr, read_addr + read_size))
                    return
                code_remain += read_data

            # cs.disasm will terminate disassembling if an invalid instruction is detected.
            # This is a loop to display "(bad)" and increment PC and reinterpret code.
            while True:
                # disasm
                for insn in cs.disasm(code_remain, location):
                    used_bytes += len(insn.bytes)
                    if skip:
                        skip -= 1
                        continue
                    yield cs_insn_to_gef_insn(insn)
                    nb_insn -= 1
                    if nb_insn == 0:
                        return

                # success (disassembled something)
                if used_bytes > 0:
                    break

                # failure (maybe the code is invalid)
                yield Instruction(location, "(bad)", "", code_remain[:arch_inst_length])
                nb_insn -= 1
                if nb_insn == 0:
                    return
                location += arch_inst_length
                code_remain = code_remain[arch_inst_length:]

            # go away only the size used
            code_remain = code_remain[used_bytes:] # There may be instructions placed across page boundaries.
            location += used_bytes
            used_bytes = 0

            read_addr += read_size # 1st loop is the offset size. 2nd~ loops are the page size.
            read_size = get_pagesize()
        return

    @staticmethod
    def gef_disassemble(addr, nb_insn, nb_prev=0):
        """Disassemble `nb_insn` instructions after `addr` and `nb_prev` before `addr`.
        Return an iterator of Instruction objects.
        Use Disasm.gdb_disassemble or Disasm.capstone_disassemble according to the settings."""
        if Config.get_gef_setting("context_code.use_capstone"):
            get_nth_prev_address = Disasm.capstone_get_nth_previous_instruction_address
            get_insns = Disasm.capstone_disassemble
        else:
            get_nth_prev_address = Disasm.gdb_get_nth_previous_instruction_address
            get_insns = Disasm.gdb_disassemble

        if nb_prev:
            for i in range(nb_prev):
                nb_prev_addr = get_nth_prev_address(addr, nb_prev - i)
                if not nb_prev_addr:
                    continue
                for insn in get_insns(nb_prev_addr, nb_prev):
                    if insn.address == addr:
                        break
                    yield insn
                break

        nb_insn = max(1, nb_insn)
        for insn in get_insns(addr, nb_insn):
            yield insn
        return None

    @staticmethod
    def gef_instruction_n(addr, n):
        """Return the `n`-th instruction after `addr` as an Instruction object."""
        try:
            return list(Disasm.gef_disassemble(addr, n + 1))[n]
        except IndexError:
            return None


def get_insn(addr=None):
    """Return the current instruction as an Instruction object."""
    from gef.core.process import is_alive

    if addr is None:
        if not is_alive():
            return None
        addr = runtime.current_arch.pc
    return Disasm.gef_instruction_n(addr, 0)


def get_insn_next(addr=None):
    """Return the next instruction as an Instruction object."""
    from gef.core.process import is_alive

    if addr is None:
        if not is_alive():
            return None
        addr = runtime.current_arch.pc
    return Disasm.gef_instruction_n(addr, 1)


def get_insn_prev(addr=None):
    """Return the prev instruction as an Instruction object."""
    from gef.core.process import is_alive

    if addr is None:
        if not is_alive():
            return None
        addr = runtime.current_arch.pc
    try:
        gen = Disasm.gef_disassemble(addr, 0, nb_prev=2)
        gen.__next__()
        return gen.__next__()
    except (gdb.error, StopIteration):
        return None

