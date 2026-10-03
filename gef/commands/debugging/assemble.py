"""GEF debugging commands (category 01-e) extracted from the monolithic gef.py.

Assemble/disassemble/patch and the capstone-based helper commands.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import binascii
import itertools
import json
import os
import re
import sys

import gdb

from gef.bootstrap import http_get
from gef.commands.base import (
    GenericCommand,
    only_if_gdb_running,
    parse_args,
    register_command,
    require_arch_set,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.cache import Cache
from gef.core.color import err, gef_print, info
from gef.core.config import Config
from gef.core.instruction import Disasm
from gef.core.memory import read_memory
from gef.core.process import is_alive
from gef.core.strings import String
from gef.core.symbols import ModuleLoader
from gef.core.unicorn import UnicornKeystoneCapstone
from gef.core.utils import GEF_TEMP_DIR, GefUtil


@register_command
class CapstoneDisassembleCommand(GenericCommand):
    """Use capstone disassembly framework to disassemble code."""

    _cmdline_ = "capstone-disassemble"
    _category_ = "01-e. Debugging Support - Assemble"
    _repeat_ = True
    _aliases_ = ["cs-dis", "pdisas", "nearpc"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the address to disassemble. (default: current_arch.pc)")
    parser.add_argument("-l", "--length", type=AddressUtil.parse_address,
                        help="the length to disassemble. (default: context.nb_lines_code)")
    parser.add_argument("args", metavar="ARGS", nargs="*", help="arguments for capstone. see following example.")
    _syntax_ = parser.format_help()

    valid_arch_modes = {
        "ARM" : ["ARM", "THUMB"],
        "ARM64" : ["ARM"],
        "MIPS" : ["32", "64"],
        "PPC" : ["32", "64"],
        "SPARC" : ["32", "32PLUS", "64"],
        "X86" : ["16", "32", "64"],
    }

    _example_ = [
        "{0:s} -l 50 $pc                             # dump from $pc up to 50 lines later",
        "{0:s} -l 50 $pc arch=ARM mode=ARM endian=1  # specify arch, mode and endian (1:big endian)",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "Available architectures and modes:"
    ]
    for arch in valid_arch_modes:
        _note_.append(" - {:8s} {}".format(arch, " / ".join(valid_arch_modes[arch])))
    _note_ = "\n".join(_note_)

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        self.add_setting("nb_lines_code_default", 50, "Number of instruction if no length is specified.")
        return

    @parse_args
    @only_if_gdb_running
    @ModuleLoader.load_capstone
    @require_arch_set
    def do_invoke(self, args):
        kwargs = {}
        for arg in args.args:
            if "=" in arg:
                key, value = arg.split("=", 1)
                kwargs[key] = value
            else:
                err("ARGS must be KEY=VALUE style")
                return

        length = args.length or Config.get_gef_setting("capstone_disassemble.nb_lines_code_default")
        location = args.location or runtime.current_arch.pc

        try:
            skip = length * self.repeat_count
            for insn in Disasm.capstone_disassemble(location, length, skip=skip, **kwargs):
                if insn.address == runtime.current_arch.pc:
                    msg = " -> {:s}".format(insn.colored_text(10, highlight=True))
                else:
                    msg = "    {:s}".format(insn.colored_text(10, highlight=False))
                gef_print(msg)
        except AttributeError:
            err("Maybe unsupported architecture")
        except gdb.error:
            pass
        return


@register_command
class AssembleCommand(GenericCommand):
    """Assemble inline code using Keystone."""

    _cmdline_ = "asm"
    _category_ = "01-e. Debugging Support - Assemble"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", dest="arch", help="specify the architecture. (default: current_arch.arch)")
    parser.add_argument("-m", dest="mode", help="specify the mode. (default: current_arch.mode)")
    parser.add_argument("-e", dest="big_endian", action="store_true", help="use big-endian.")
    parser.add_argument("-s", dest="as_shellcode", action="store_true", help="output like shellcode style.")
    parser.add_argument("-l", dest="overwrite_location", metavar="LOCATION",
                        type=AddressUtil.parse_address, help="write to memory address.")
    parser.add_argument("-H", "--hex", action="store_true", help="show in hex style.")
    parser.add_argument("instruction", metavar="INSTRUCTION", nargs="+", help="the code to assemble.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} -a X86 -m 64 "mov rax, qword ptr [rax] ; inc rax ;"',
        '{0:s} -a X86 -m 32 "mov eax, dword ptr [eax] ; inc eax ;"',
        '{0:s} -a X86 -m 16 "mov ax, word ptr [ax] ; inc ax"',
        '{0:s} -a ARM -m ARM      "sub r1, r2, r3"',
        '{0:s} -a ARM -m ARM -e   "sub r1, r2, r3"',
        '{0:s} -a ARM -m THUMB    "movs r4, #0xf0"',
        '{0:s} -a ARM -m THUMB -e "movs r4, #0xf0"',
        '{0:s} -a ARM64 -m ARM    "ldr w1, [sp, #0x8]"',
        '{0:s} -a MIPS -m 32    "and $9, $6, $7"',
        '{0:s} -a MIPS -m 32 -e "and $9, $6, $7"',
        '{0:s} -a MIPS -m 64    "and $9, $6, $7"',
        '{0:s} -a MIPS -m 64 -e "and $9, $6, $7"',
        '{0:s} -a PPC -m 32 -e "add 1, 2, 3"',
        '{0:s} -a PPC -m 64    "add 1, 2, 3"',
        '{0:s} -a PPC -m 64 -e "add 1, 2, 3"',
        '{0:s} -a SPARC -m 32 -e "add %g1, %g2, %g3"',
        '{0:s} -a SPARC -m 32PLUS -e "add %g1, %g2, %g3"',
        '{0:s} -a SPARC -m 64 -e "add %g1, %g2, %g3"',
        '{0:s} -a S390X -m 64 -e "a %r0, 4095(%r15,%r1)"',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @ModuleLoader.load_keystone
    def do_invoke(self, args):
        if (args.arch, args.mode) == (None, None):
            if is_alive() and runtime.current_arch:
                arch, mode = UnicornKeystoneCapstone.get_keystone_arch(
                    arch=runtime.current_arch.arch, mode=runtime.current_arch.mode, endian=Endian.is_big_endian(),
                )
                arch_mode_s = ":".join([runtime.current_arch.arch, runtime.current_arch.mode])
                endian_s = "big" if Endian.is_big_endian() else "little"
            else:
                # if not alive, defaults to x86-64
                arch, mode = UnicornKeystoneCapstone.get_keystone_arch(arch="X86", mode="64", endian=False)
                arch_mode_s = "X86:64"
                endian_s = "little"
        elif not args.arch:
            err("An architecture (-a) must be provided")
            return
        elif not args.mode:
            # keystone gives no error so check here
            err("A mode (-m) must be provided")
            return
        elif args.arch in ["SPARC", "S390X"] and args.big_endian is False:
            # keystone gives no error so check here
            err("A big endian flag (-e) must be provided")
            return
        else:
            try:
                arch, mode = UnicornKeystoneCapstone.get_keystone_arch(
                    arch=args.arch, mode=args.mode, endian=args.big_endian,
                )
                arch_mode_s = ":".join([args.arch, args.mode])
                endian_s = "big" if args.big_endian else "little"
            except AttributeError:
                self.usage()
                return

        insns = " ".join(args.instruction)
        insns = [x.strip() for x in insns.split(";") if x is not None and x.strip() != ""]

        info("Assembling {:d} instruction{:s} for {:s} ({:s} endian)".format(
            len(insns), "s" if len(insns) > 1 else "", arch_mode_s, endian_s,
        ))

        if args.as_shellcode:
            gef_print('sc = ""')

        raw = b""
        for insn in insns:
            res = UnicornKeystoneCapstone.keystone_assemble(insn, arch, mode, raw=True)
            if not res:
                gef_print("(Invalid)")
                continue

            if args.overwrite_location is not None:
                raw += res
                continue

            s = binascii.hexlify(res)
            if args.hex:
                res = String.bytes2str(s)
            else:
                res = b"\\x" + b"\\x".join([s[i:i + 2] for i in range(0, len(s), 2)])
                res = res.decode("utf-8")

            if args.as_shellcode:
                res = 'sc += "{:s}"'.format(res)

            gef_print("{:60s} # {:s}".format(res, insn))

        if args.overwrite_location is not None:
            hex_code = binascii.hexlify(raw).decode()
            gdb.execute("patch hex {:#x} {:s}".format(args.overwrite_location, hex_code))
        return


@register_command
class DisassembleCommand(GenericCommand):
    """Disassemble inline code using Capstone."""

    _cmdline_ = "dasm"
    _category_ = "01-e. Debugging Support - Assemble"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", dest="arch", help="specify the architecture. (default: current_arch.arch)")
    parser.add_argument("-m", dest="mode", help="specify the mode. (default: current_arch.mode)")
    parser.add_argument("-e", dest="big_endian", action="store_true", help="use big-endian.")
    parser.add_argument("hex_code", metavar="HEX_CODE", nargs="+", help="the hex code to disassemble.")
    _syntax_ = parser.format_help()

    _example_ = [
        '{0:s} -a X86 -m 64 "488b00 48ffc0"',
        '{0:s} -a X86 -m 32 "8b00 40"',
        '{0:s} -a X86 -m 16 "8b00 40"',
        '{0:s} -a ARM -m ARM      "031042e0"',
        '{0:s} -a ARM -m ARM -e   "e0421003"',
        '{0:s} -a ARM -m THUMB    "f024"',
        '{0:s} -a ARM -m THUMB -e "24f0"',
        '{0:s} -a ARM64 -m ARM    "e10b40b9"',
        '{0:s} -a MIPS -m 32    "2448c700"',
        '{0:s} -a MIPS -m 32 -e "00c74824"',
        '{0:s} -a MIPS -m 64    "2448c700"',
        '{0:s} -a MIPS -m 64 -e "00c74824"',
        '{0:s} -a PPC -m 32 -e "7c221a14"',
        '{0:s} -a PPC -m 64    "141a227c"',
        '{0:s} -a PPC -m 64 -e "7c221a14"',
        '{0:s} -a SPARC -m 32 -e "86004002"',
        '{0:s} -a SPARC -m 32PLUS -e "86004002"',
        '{0:s} -a SPARC -m 64 -e "86004002"',
        '{0:s} -a RISCV -m 32 "97c10600"',
        '{0:s} -a RISCV -m 64 "97c10600"',
        '{0:s} -a S390X -m 64 -e "5a0f1fff"',
        '{0:s} -a M68K -m 32 -e "9dce"',
        '{0:s} -a LOONGARCH -m 64 "89001500" # capstone v6.x~',
        '{0:s} -a LOONGARCH -m 32 "89001500" # capstone v6.x~',
        '{0:s} -a ALPHA -m 64    "0b00bd27" # capstone v6.x~',
        '{0:s} -a ALPHA -m 64 -e "27bd000b" # capstone v6.x~',
        '{0:s} -a HPPA -m 32 -e "0fc01299" # capstone v6.x~',
        '{0:s} -a HPPA -m 64 -e "0fc01299" # capstone v6.x~',
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    @parse_args
    @ModuleLoader.load_capstone
    def do_invoke(self, args):
        if (args.arch, args.mode) == (None, None):
            if is_alive() and runtime.current_arch:
                arch, mode = UnicornKeystoneCapstone.get_capstone_arch(
                    arch=runtime.current_arch.arch, mode=runtime.current_arch.mode, endian=Endian.is_big_endian(),
                )
                arch_mode_s = ":".join([runtime.current_arch.arch, runtime.current_arch.mode])
                endian_s = "big" if Endian.is_big_endian() else "little"
            else:
                # if not alive, defaults to x86-64
                arch, mode = UnicornKeystoneCapstone.get_capstone_arch(
                    arch="X86", mode="64", endian=False,
                )
                arch_mode_s = "X86:64"
                endian_s = "little"
        elif not args.arch:
            err("An architecture (-a) must be provided")
            return
        elif not args.mode:
            err("A mode (-m) must be provided")
            return
        elif args.arch in ["SPARC", "S390X", "M68K", "HPPA"] and args.big_endian is False:
            # capstone gives no error so check here
            err("A big endian flag (-e) must be provided")
            return
        else:
            try:
                arch, mode = UnicornKeystoneCapstone.get_capstone_arch(
                    arch=args.arch, mode=args.mode, endian=args.big_endian,
                )
                arch_mode_s = ":".join([args.arch, args.mode])
                endian_s = "big" if args.big_endian else "little"
            except AttributeError:
                self.usage()
                return

        insns = " ".join(args.hex_code)
        insns = insns.replace(" ", "").replace("\t", "")
        try:
            insns = binascii.unhexlify(insns)
        except binascii.Error:
            err("Invalid format")
            return

        info("Disassembling {:d} bytes for {:s} ({:s} endian)".format(
            len(insns), arch_mode_s, endian_s,
        ))

        capstone = sys.modules["capstone"]
        try:
            cs = capstone.Cs(arch, mode)
        except capstone.CsError:
            err("CsError")
            return
        cs.detail = True # noqa

        for insn in cs.disasm(insns, 0x0):
            b = binascii.hexlify(insn.bytes).decode("utf-8")
            gef_print("{:>#6x}:\t{:<10s}\t{:s}\t{:s}".format(insn.address, b, insn.mnemonic, insn.op_str))
        return


@register_command
class AsmListCommand(GenericCommand):
    """List general instructions by capstone (x64/x86 only)."""

    _cmdline_ = "asm-list"
    _category_ = "01-e. Debugging Support - Assemble"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-a", dest="arch", help="specify the architecture. (default: current_arch.arch)")
    parser.add_argument("-m", dest="mode", help="specify the mode. (default: current_arch.mode)")
    parser.add_argument("-e", dest="big_endian", action="store_true", help="use big-endian.")
    parser.add_argument("-b", dest="nbyte", type=int, help="filter by the length of asm byte.")
    parser.add_argument("-f", dest="include", action="append", help="filter by specified string.")
    parser.add_argument("-v", dest="exclude", action="append", help="filter by specified string.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} -a X86 -m 64",
        "{0:s} -a X86 -m 32",
        "{0:s} -a X86 -m 16",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "- F0 (LOCK prefix) is ignored",
        "- F2/F3 (REPNE/REP prefix) are ignored",
        "- 2E/36/3E/26/64/65 (CS/SS/DS/ES/FS/GS override prefix) are ignored",
        "- 2E/3E (branch hint prefix) are ignored",
        "- 66 (operand size prefix) is included",
        "- 67 (address size prefix) is ignored",
        "- 40-4F (REX prefix) are ignored",
        "- C4/C5 (VEX prefix) are ignored",
        "- 8F (XOP prefix) is ignored",
        "- 62 (EVEX prefix) is ignored",
    ]
    _note_ = "\n".join(_note_)

    cache = None

    def listup_x86(self, arch, mode):
        if self.cache:
            return self.cache

        DISP64 = "1122334455667788"
        DISP32 = "11223344"
        DISP16 = "1122"
        DISP8 = "11"

        @Cache.cache_this_session
        def get_typical_bytecodes_modrm(reg_value):
            mod_list = range(4)
            assert 0 <= reg_value <= 7
            reg_list = [reg_value]
            rm_list = [0, 0b100] # The correct value is range(8), but it is reduced for speed.
            sib_list = [0, 0b01001001] # The correct value is range(256), but it is reduced for speed.

            bytecodes = []
            for mod, reg, rm in itertools.product(mod_list, reg_list, rm_list):
                modrm = "{:02X}".format((mod << 6) | (reg << 3) | rm)
                if mod == 0b00:
                    if rm == 0b101: # special case; [REG + disp32]
                        bytecode = modrm + DISP32
                    elif rm == 0b100: # use sib; [INDEX * SCALE + BASE]
                        for sib in sib_list:
                            bytecode = modrm + "{:02X}".format(sib)
                    else: # [REG]
                        bytecode = modrm
                elif mod == 0b01:
                    if rm == 0b100: # use sib; [INDEX * SCALE + BASE + disp8]
                        bytecode = []
                        for sib in sib_list:
                            b = modrm + "{:02X}".format(sib) + DISP8
                            bytecode.append(b)
                    else: # [REG + disp8]
                        bytecode = modrm + DISP8
                elif mod == 0b10:
                    if rm == 0b100: # use sib; [INDEX * SCALE + BASE + disp32]
                        bytecode = []
                        for sib in sib_list:
                            b = modrm + "{:02X}".format(sib) + DISP32
                            bytecode.append(b)
                    else: # [REG + disp32]
                        bytecode = modrm + DISP32
                elif mod == 0b11: # REG
                    bytecode = modrm
                if isinstance(bytecode, list):
                    bytecodes.extend(bytecode)
                else:
                    bytecodes.append(bytecode)
            return bytecodes

        def get_typical_bytecodes(opcodes):
            bytecodes = []
            for operand in opcodes.split():
                if operand in ["ib", "cb"]:
                    bytecode = [DISP8]
                elif operand in ["iw", "cw"]:
                    bytecode = [DISP16]
                elif operand in ["id", "cd"]:
                    bytecode = [DISP32]
                elif operand in ["iq"]:
                    bytecode = [DISP64]
                elif operand in ["/0", "/1", "/2", "/3", "/4", "/5", "/6", "/7"]:
                    bytecode = get_typical_bytecodes_modrm(int(operand[1]))
                elif operand == "/r":
                    bytecode = get_typical_bytecodes_modrm(0)
                elif operand.endswith(("+r", "+i")):
                    b = int(operand.split("+")[0], 16)
                    bytecode = ["{:02X}".format(b + x) for x in range(8)]
                else:
                    bytecode = [operand]
                bytecodes.append(bytecode)
            return ["".join(b) for b in itertools.product(*bytecodes)]

        def load_x86_json():
            x86data_js = os.path.join(GEF_TEMP_DIR, "x86data.js")
            if os.path.exists(x86data_js) and os.path.getsize(x86data_js) > 0:
                x86 = open(x86data_js, "rb").read()
            else:
                url = "https://raw.githubusercontent.com/MarcoApollonio02/gef/dev/asmdb/x86data.js"
                x86 = http_get(url)
                if x86 is None:
                    err("Connection timed out: {:s}".format(url))
                    return None
                open(x86data_js, "wb").write(x86)

            x86 = x86.split(b"// ${JSON:BEGIN}")[1].split(b"// ${JSON:END}")[0]
            return json.loads(x86)

        # load capstone
        capstone = sys.modules["capstone"]
        try:
            cs = capstone.Cs(arch, mode)
        except capstone.CsError:
            err("CsError")
            return None

        # default instruction set
        x86 = load_x86_json()
        # manually added
        x86_insns = x86["instructions"]
        # [opcode_str, unused, unused, opcodes, attr]
        x86_insns.append(["icebp", "", "", "F1", "Undocumented"])
        x86_insns.append(["salc", "", "", "D6", "Undocumented"])
        #x86_insns.append(["umov", "", "", "0F 10 /r", "Undocumented"]) # used by another opcode
        #x86_insns.append(["umov", "", "", "0F 11 /r", "Undocumented"]) # used by another opcode
        #x86_insns.append(["umov", "", "", "0F 12 /r", "Undocumented"]) # used by another opcode
        #x86_insns.append(["umov", "", "", "0F 13 /r", "Undocumented"]) # used by another opcode
        #x86_insns.append(["loadall", "", "", "0F 05", "Undocumented"]) # used by another opcode
        #x86_insns.append(["loadall", "", "", "0F 07", "Undocumented"]) # used by another opcode
        #x86_insns.append(["xbts", "", "", "0F A6", "Undocumented"]) # removed now
        #x86_insns.append(["ibts", "", "", "0F A7", "Undocumented"]) # removed now

        # parse it
        valid_patterns = []
        seen_patterns = []
        for insn in x86_insns:
            opcodes = insn[3]
            attr = insn[4].split()

            # filter ignore prefix pattern
            if "REX.W" in opcodes.split():
                continue
            if "VEX" in opcodes.split()[0].split("."):
                continue
            if "EVEX" in opcodes.split()[0].split("."):
                continue
            if "XOP" in opcodes.split()[0].split("."):
                continue

            # e.g., "FF /2" -> ["FF10", "FF5011", ...]
            bytecodes = get_typical_bytecodes(opcodes)

            # check it is valid or not
            for hex_code in bytecodes:
                # dup check
                if hex_code in seen_patterns:
                    continue
                # disasm
                code = bytes.fromhex(hex_code)
                try:
                    asm = cs.disasm(code, 0).__next__()
                except StopIteration:
                    continue
                opstr = asm.mnemonic + " " + asm.op_str
                # add
                valid_patterns.append([hex_code, opstr, opcodes, attr])
                seen_patterns.append(hex_code)

        self.cache = valid_patterns
        return valid_patterns

    @parse_args
    @ModuleLoader.load_capstone
    @require_arch_set
    def do_invoke(self, args):
        if (args.arch, args.mode) == (None, None):
            if is_alive():
                arch, mode = UnicornKeystoneCapstone.get_capstone_arch(
                    arch=runtime.current_arch.arch, mode=runtime.current_arch.mode, endian=Endian.is_big_endian(),
                )
                arch_mode_s = ":".join([runtime.current_arch.arch, runtime.current_arch.mode])
                endian_s = "big" if Endian.is_big_endian() else "little"
            else:
                # if not alive, defaults to x86-64
                arch, mode = UnicornKeystoneCapstone.get_capstone_arch(arch="X86", mode="64", endian=False)
                arch_mode_s = "X86:64"
                endian_s = "little"
        elif not args.arch:
            err("An architecture (-a) must be provided")
            return
        elif not args.mode:
            err("A mode (-m) must be provided")
            return
        elif args.arch in ["SPARC", "S390X", "M68K"] and args.big_endian is False:
            # capstone gives no error so check here
            err("A big endian flag (-e) must be provided")
            return
        else:
            try:
                arch, mode = UnicornKeystoneCapstone.get_capstone_arch(
                    arch=args.arch, mode=args.mode, endian=args.big_endian,
                )
                arch_mode_s = ":".join([args.arch, args.mode])
                endian_s = "big" if args.big_endian else "little"
            except AttributeError:
                self.usage()
                return

        # list bytecode pattern
        if arch_mode_s.startswith("X86:"):
            if endian_s == "big":
                err("X86 is not big endian")
                return
            patterns = self.listup_x86(arch, mode)
        else:
            err("Unsupported other than x86/x64")
            return

        if patterns is None:
            err("Failed to list entries")
            return

        # filter and print
        self.out = []
        fmt = "{:22s} {:70s} {:22s} {!s}"
        legend = ["Hex code", "Assembly code", "Opcode", "Attributes"]
        self.out.append(GefUtil.make_legend(fmt.format(*legend)))

        for hex_code, opstr, opcodes, attr in patterns:
            # byte length filter
            if args.nbyte is not None and args.nbyte * 2 != len(hex_code):
                continue

            # keyword filter
            line = "{:22s} {:70s} {:22s} {!s}".format(hex_code, opstr, opcodes, ",".join(attr))
            if args.include and any(f not in line for f in args.include):
                continue
            if args.exclude and any(f in line for f in args.exclude):
                continue

            # not filtered
            self.out.append(line)

        gef_print("\n".join(self.out), less=not args.no_pager)
        return


@register_command
class IiCommand(GenericCommand):
    """Shortcut `x/50i $pc` with opcode bytes."""

    _cmdline_ = "ii"
    _category_ = "01-e. Debugging Support - Assemble"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("location", metavar="LOCATION", nargs="?", type=AddressUtil.parse_address,
                        help="the dump start address.")
    parser.add_argument("-l", "--length", type=AddressUtil.parse_address, default=50,
                        help="the dump instruction length.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_LOCATION)
        return

    def ii(self, addr, N):
        try:
            res = read_memory(addr, N)
        except gdb.MemoryError:
            err("Memory read error")
            return

        if N >= 50 and res[0:1] * N == res:
            info("all targeted area is {:#04x}".format(res[0]))
            return

        # get instruction size
        try:
            res = gdb.execute("x/{:d}i {:#x}".format(N + 1, addr), to_string=True)
        except gdb.MemoryError:
            err("Memory read error")
            return
        addrs = []
        for line in res.splitlines():
            # [x64]
            # "=> 0x55555555aac0:      endbr64"
            # "   0x55555555aac4:      xor    ebp,ebp"
            # [arm]
            # "=> 0x10340 <_start>:    mov.w   r11, #0"
            # "   0x10344 <_start+4>:  mov.w   lr, #0"
            r = re.search("^(?:=>|  ) (0x[0-9a-f]+)", line)
            if r:
                addrs.append(int(r.group(1), 16))
        insn_sizes = [(x, y - x) for x, y in zip(addrs[:-1], addrs[1:])]
        max_insn_width = max(x[1] for x in insn_sizes) * 2

        # print
        for i, line in enumerate(res.splitlines()[:-1]):
            addr, size = insn_sizes[i]
            bytecode = read_memory(addr, size)
            bytecode_hex = "{:{:d}s}".format(bytecode.hex(), max_insn_width)

            line = line.rstrip()
            line = line.expandtabs(8)

            # get position to split
            # [x64]
            # "0x55555555aac0:      endbr64"
            # "0x55555555aac4:      xor    ebp,ebp"
            #                ^
            # [arm]
            # "0x10340 <_start>:    mov.w   r11, #0"
            # "0x10344 <_start+4>:  mov.w   lr, #0"
            #         ^
            # Since it depends on the presence or absence of symbols, it must be calculated line by line each time.
            pos = None
            r = re.search("[: ]", line[3:])
            if r:
                pos = 3 + r.span()[0]

            if pos is None:
                # somethinig is wrong
                gef_print(line)
            else:
                gef_print(line[:pos] + ": " + bytecode_hex + " " + line[pos:])
        return

    @parse_args
    @only_if_gdb_running
    @require_arch_set
    def do_invoke(self, args):
        if args.location is None:
            location = runtime.current_arch.pc
        else:
            location = args.location

        self.ii(location, args.length)
        return
