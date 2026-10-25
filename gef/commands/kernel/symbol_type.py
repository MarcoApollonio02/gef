"""GEF kernel commands (category 06-e) extracted from the monolithic gef.py.

Qemu-system/KGDB Cooperation - Linux Symbol/Type: kernel/module loading, kernel
types (ktypes / ktypes-load), remote kallsyms (ksymaddr-remote), vmlinux-to-elf
apply and ksymaddr-remote-apply. Auto-discovered by gef.bootstrap via
pkgutil.walk_packages.
"""
import argparse
import configparser
import hashlib
import os
import re
import shlex
import struct
import subprocess
import tempfile

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    only_if_gdb_running,
    only_if_in_kernel,
    only_if_in_kernel_or_kpti_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.cache import Cache
from gef.core.color import err, gef_print, info, titlify, warn
from gef.core.config import Config
from gef.core.elf import Elf
from gef.core.kernel import Kernel, KernelLayout, Ksym
from gef.core.memory import (
    is_ascii_string,
    is_valid_addr,
    p16,
    p32,
    p64,
    read_cstring_from_memory,
    read_int_from_memory,
    read_memory,
    u32,
)
from gef.core.pagewalk import KernelAddressHeuristicFinder
from gef.core.process import (
    get_pagesize,
    get_pagesize_mask_high,
    get_pagesize_mask_low,
    is_32bit,
    is_64bit,
    is_arm32,
    is_arm64,
    is_in_kernel,
    is_riscv32,
    is_riscv64,
    is_x86,
    is_x86_32,
    is_x86_64,
)
from gef.core.registers import to_unsigned_long
from gef.core.strings import String
from gef.core.symbols import Symbol
from gef.core.utils import GEF_TEMP_DIR, GefUtil, align, slice_unpack, slicer


@register_command
class KernelLoadCommand(GenericCommand):
    """Load the vmlinux without a load address."""

    _cmdline_ = "kload"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("path", metavar="VMLINUX_PATH", type=str, help="path of the vmlinux.")
    parser.add_argument("-f", "--force", action="store_true", help="load the vmlinux even if it does not match the running kernel.")
    _syntax_ = parser.format_help()

    _note_ = [
        "The KASLR offset is resolved in the following order and applied to all sections.",
        "  1. The address of `linux_banner` in memory and in the vmlinux (this also checks that they match)",
        "  2. The address of `_stext` in kallsyms and in the vmlinux",
        "  3. The exception vector address and its symbol in the vmlinux",
        "Sections linked below the image (e.g., x86_64 zero-based .data..percpu, ARM32 .vectors) are not relocated.",
        "",
        "Then the vmlinux is verified against the running kernel with:",
        "  - the ELF class, machine and endianness",
        "  - the GNU build ID in `.notes`, read from the relocated address in memory",
        "  - the linux_banner",
        "  - the addresses of sampled global functions in kallsyms",
        "A clear mismatch is not loaded without `--force`.",
    ]
    _note_ = "\n".join(_note_)

    KALLSYMS_SAMPLES = 64

    def __init__(self):
        super().__init__(complete=gdb.COMPLETE_FILENAME)
        return

    @staticmethod
    def get_elf_symbols(elf, names):
        symtab = elf.read_shdr(".symtab")
        strtab = elf.read_shdr(".strtab")
        if not symtab or not strtab:
            return {}

        # A name may be the tail of a longer string, so do not require a preceding NUL
        name_offsets = {}
        for name in names:
            needle = String.str2bytes(name) + b"\0"
            pos = strtab.find(needle)
            while pos != -1:
                name_offsets[pos] = name
                pos = strtab.find(needle, pos + 1)

        if elf.e_endianness == Elf.LITTLE_ENDIAN:
            endian = "<"
        else:
            endian = ">"
        if elf.e_class == Elf.ELF_64_BITS:
            # Elf64_Sym: st_name, st_info, st_other, st_shndx, st_value, st_size
            fmt, index_shndx, index_value = "IBBHQQ", 3, 4
        else:
            # Elf32_Sym: st_name, st_value, st_size, st_info, st_other, st_shndx
            fmt, index_shndx, index_value = "IIIBBH", 5, 1
        ret = {}
        for sym in struct.iter_unpack(endian + fmt, symtab):
            name = name_offsets.get(sym[0])
            if name and sym[index_shndx] and name not in ret: # skip SHN_UNDEF
                ret[name] = sym[index_value]
        return ret

    @staticmethod
    def is_valid_slide(slide):
        return slide & get_pagesize_mask_low() == 0

    def get_slide_from_banner(self, elf):
        kversion = Kernel.version()
        if kversion is None or not kversion.address:
            return None
        shdr = elf.get_shdr(".rodata")
        if shdr is None:
            return None
        rodata = elf.read_shdr(".rodata")
        needle = String.str2bytes(kversion.version_string)
        pos = rodata.find(needle)
        while pos != -1:
            slide = kversion.address - (shdr.sh_addr + pos)
            if self.is_valid_slide(slide):
                return slide
            pos = rodata.find(needle, pos + 1)
        warn("The linux_banner of the vmlinux does not match the running kernel")
        return None

    def get_slide_from_stext(self, elf):
        stext = Ksym.get_addr("_stext")
        if stext is None:
            return None
        elf_stext = self.get_elf_symbols(elf, ["_stext"]).get("_stext")
        if elf_stext is None:
            return None
        slide = stext - elf_stext
        if self.is_valid_slide(slide):
            return slide
        return None

    @staticmethod
    def check_elf_header(elf):
        """Return the list of the ELF header fields that do not match the target."""
        mismatches = []
        if (elf.e_class == Elf.ELF_64_BITS) != is_64bit():
            mismatches.append("{:d}-bit".format(elf.get_bits()))
        if (elf.e_endianness == Elf.LITTLE_ENDIAN) != Endian.is_little_endian():
            mismatches.append("{:s}-endian".format("little" if elf.e_endianness == Elf.LITTLE_ENDIAN else "big"))
        if is_x86_64():
            expected = Elf.EM_X86_64
        elif is_x86_32():
            expected = Elf.EM_386
        elif is_arm64():
            expected = Elf.EM_AARCH64
        elif is_arm32():
            expected = Elf.EM_ARM
        elif is_riscv32() or is_riscv64():
            expected = Elf.EM_RISCV
        else:
            expected = None
        if expected is not None and elf.e_machine != expected:
            mismatches.append("e_machine={:d}".format(elf.e_machine))
        return mismatches

    @staticmethod
    def get_build_id(elf):
        """Return (address, build ID) of the NT_GNU_BUILD_ID note in the loaded sections, or None."""
        if elf.e_endianness == Elf.LITTLE_ENDIAN:
            endian = "<"
        else:
            endian = ">"
        for shdr in elf.shdrs:
            if shdr.sh_type != Elf.Shdr.SHT_NOTE or not shdr.sh_flags & Elf.Shdr.SHF_ALLOC:
                continue
            data = elf.read_shdr(shdr.sh_name)
            pos = 0
            while pos + 12 <= len(data):
                namesz, descsz, note_type = struct.unpack(endian + "III", data[pos:pos + 12])
                name_pos = pos + 12
                desc_pos = name_pos + align(namesz, 4)
                if desc_pos + descsz > len(data):
                    break
                if note_type == 3 and data[name_pos:name_pos + namesz] == b"GNU\0": # NT_GNU_BUILD_ID
                    return shdr.sh_addr + desc_pos, data[desc_pos:desc_pos + descsz]
                pos = desc_pos + align(descsz, 4)
        return None

    @staticmethod
    def get_elf_function_samples(elf, count):
        """Return {name: address} of the global functions spread over the whole .symtab."""
        symtab = elf.read_shdr(".symtab")
        strtab = elf.read_shdr(".strtab")
        if not symtab or not strtab:
            return {}

        if elf.e_endianness == Elf.LITTLE_ENDIAN:
            endian = "<"
        else:
            endian = ">"
        if elf.e_class == Elf.ELF_64_BITS:
            fmt, index_info, index_shndx, index_value = "IBBHQQ", 1, 3, 4
        else:
            fmt, index_info, index_shndx, index_value = "IIIBBH", 3, 5, 1
        functions = []
        for sym in struct.iter_unpack(endian + fmt, symtab):
            # STB_GLOBAL, STT_FUNC, not SHN_UNDEF/SHN_ABS
            if sym[index_info] != 0x12 or sym[index_shndx] in (0, 0xfff1) or not sym[index_value]:
                continue
            functions.append((sym[index_value], sym[0]))
        functions.sort()
        step = max(1, len(functions) // count)
        samples = {}
        for value, name_offset in functions[::step][:count]:
            name = strtab[name_offset:strtab.find(b"\0", name_offset)].decode("ascii", "replace")
            samples[name] = value
        return samples

    def verify(self, elf, slide):
        """Return ([(source, result, remark), ...], whether a clear mismatch is found) of the checks after relocation."""
        results = []
        mismatched = False

        # build ID
        build_id = self.get_build_id(elf)
        if build_id is None:
            results.append(("build ID", "unknown", "no NT_GNU_BUILD_ID note in the vmlinux"))
        else:
            address, desc = build_id
            actual = read_memory(address + slide, len(desc), safe=True)
            if actual is None:
                results.append(("build ID", "unknown", "{:s} is unreadable in memory".format(desc.hex())))
            elif actual == desc:
                results.append(("build ID", "match", desc.hex()))
            else:
                results.append(("build ID", "mismatch", "{:s} in the vmlinux, {:s} in memory".format(desc.hex(), actual.hex())))

        # linux_banner
        kversion = Kernel.version()
        rodata = elf.read_shdr(".rodata")
        if kversion is None or not kversion.address or rodata is None:
            results.append(("linux_banner", "unknown", "not found"))
        elif String.str2bytes(kversion.version_string) in rodata:
            results.append(("linux_banner", "match", ""))
        else:
            results.append(("linux_banner", "mismatch", "another build or version"))

        # kallsyms
        samples = self.get_elf_function_samples(elf, self.KALLSYMS_SAMPLES)
        matched = compared = 0
        for name, value in samples.items():
            addr = Ksym.get_addr(name)
            if addr is None:
                continue
            compared += 1
            if addr == AddressUtil.normalize_address(value + slide):
                matched += 1
        if compared < 8:
            results.append(("kallsyms", "unknown", "{:d} of {:d} sampled functions found".format(compared, len(samples))))
        elif matched * 10 >= compared * 9:
            results.append(("kallsyms", "match", "{:d}/{:d} sampled functions".format(matched, compared)))
        elif matched * 2 >= compared:
            results.append(("kallsyms", "partial", "{:d}/{:d} sampled functions".format(matched, compared)))
        else:
            results.append(("kallsyms", "MISMATCH", "{:d}/{:d} sampled functions".format(matched, compared)))
            mismatched = True

        # Matching symbol addresses do not establish that a different build has the same type layout.
        if results[0][1] == "mismatch":
            results[0] = ("build ID", "MISMATCH", results[0][2])
            mismatched = True
        return results, mismatched

    def get_slide_from_vector(self, elf):
        hint = KernelLayout.get_exception_vector()
        if hint is None:
            return None
        if is_x86():
            names = ["asm_exc_divide_error", "divide_error"]
        elif is_arm32():
            names = ["vector_swi"]
        elif is_arm64():
            names = ["vectors"]
        elif is_riscv32() or is_riscv64():
            names = ["handle_exception"]
        else:
            return None
        elf_symbols = self.get_elf_symbols(elf, names)
        for name in names:
            if name not in elf_symbols:
                continue
            slide = hint - elf_symbols[name]
            if self.is_valid_slide(slide):
                return slide
        return None

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    def do_invoke(self, args):
        if not os.path.exists(args.path):
            err("Invalid path")
            return

        elf = Elf.get_elf(args.path)
        if elf is None or not elf.is_valid() or not elf.shdrs:
            err("Invalid ELF")
            return

        mismatches = self.check_elf_header(elf)
        if mismatches:
            message = "The vmlinux is for another target ({:s})".format(", ".join(mismatches))
            if not args.force:
                err(message)
                info("Use `--force` to load it anyway")
                return
            warn(message)

        # `add-symbol-file FILE ADDR` relocates only .text, so pass the slide of the whole image instead.
        # ADDR must be the runtime .text, which is not the mapping start of the kernel (e.g., ARM64 .head.text).
        image_bases = [shdr.sh_addr for shdr in elf.shdrs if shdr.sh_name in (".head.text", ".text", ".init.text")]
        if not image_bases:
            err("Could not find .text")
            return
        image_base = min(image_bases)

        info("Wait for memory scan")
        slide_sources = [
            ("linux_banner", self.get_slide_from_banner),
            ("_stext in kallsyms", self.get_slide_from_stext),
            ("exception vector", self.get_slide_from_vector),
        ]
        slide = slide_source = None
        for source, get_slide in slide_sources:
            slide = get_slide(elf)
            if slide is not None:
                slide_source = source
                break
        if slide is None:
            err("Failed to resolve the KASLR offset")
            return
        info("KASLR offset: {:#x} (from {:s})".format(slide, slide_source))

        results, mismatched = self.verify(elf, slide)
        for source, result, remark in results:
            info("{:s}: {:s}{:s}".format(source, result, " ({:s})".format(remark) if remark else ""))
        summary = {source: result for source, result, _remark in results}
        if mismatched:
            if not args.force:
                err("The vmlinux does not match the running kernel")
                info("Use `--force` to load it anyway")
                return
            warn("The vmlinux does not match the running kernel")
        elif summary["build ID"] == "match" or (summary["linux_banner"] == "match" and summary["kallsyms"] != "partial"):
            info("Confidence: high")
        elif summary["kallsyms"] == "match":
            info("Confidence: medium{:s}".format(" (another build, but the sampled symbols match)" if summary["build ID"] == "mismatch" else ""))
        else:
            warn("Confidence: low (nothing but the KASLR offset shows that the vmlinux matches)")

        cmd = "add-symbol-file {:s} -o {:#x}".format(GefUtil.quote_gdb_argument(args.path), slide)
        for shdr in elf.shdrs:
            if shdr.sh_flags & Elf.Shdr.SHF_ALLOC and shdr.sh_addr < image_base:
                cmd += " -s {:s} {:#x}".format(GefUtil.quote_gdb_argument(shdr.sh_name), shdr.sh_addr)
        info("Execute `{:s}`".format(cmd))
        gdb.execute(cmd)
        return



@register_command
class KernelModuleLoadCommand(GenericCommand):
    """Load the kernel module without a load address."""

    _cmdline_ = "kmod-load"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("name", type=str, help="name of the loaded module to search for by `kmod`.")
    parser.add_argument("path", type=str, help="path to compiled kernel module.")
    parser.add_argument("--force", action="store_true", help="load even if the file does not match the loaded module.")
    parser.add_argument("--meta", action="store_true", help="display offset information.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} sample /path/to/sample.ko",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "This command requires CONFIG_RANDSTRUCT=n, CONFIG_KALLSYMS=y and CONFIG_SYSFS=y (module->sect_attrs).",
        "It is useful if you have a kernel module with debuginfo at hand.",
        "",
        "The file is verified against the loaded module before loading:",
        "- ELF type, machine, class and endianness",
        "- The allocated section names",
        "- The .note.gnu.build-id section in memory, or the symbol addresses of the module kallsyms if it is unavailable",
        "A clear mismatch is rejected unless --force is specified.",
    ]
    _note_ = "\n".join(_note_)

    def get_module_kallsyms(self, module):
        if not self.kmod.initialize_kallsyms(self.module_addrs):
            return {}
        kallsyms = {}
        for addr, _type, name in self.kmod.parse_kallsyms(module):
            kallsyms.setdefault(name, set()).add(addr)
        return kallsyms

    def verify_file(self, module, sections):
        # Returns (mismatches, verified_by)
        elf = Elf.get_elf(self.args.path)
        if elf is None or not elf.is_valid() or not elf.shdrs:
            return ["It is not a valid ELF"], None

        # architecture
        if is_x86_64():
            machine = Elf.EM_X86_64
        elif is_x86_32():
            machine = Elf.EM_386
        elif is_arm64():
            machine = Elf.EM_AARCH64
        elif is_arm32():
            machine = Elf.EM_ARM
        else:
            machine = Elf.EM_RISCV
        mismatches = []
        if elf.e_type != Elf.ET_REL:
            mismatches.append("e_type is {:#x}, not ET_REL".format(elf.e_type))
        if elf.e_machine != machine:
            mismatches.append("e_machine is {:#x}, but the target is {:#x}".format(elf.e_machine, machine))
        if elf.e_class != (Elf.ELF_64_BITS if is_64bit() else Elf.ELF_32_BITS):
            mismatches.append("ELF class does not match the pointer size of the target")
        if (elf.e_endianness == Elf.BIG_ENDIAN) != Endian.is_big_endian():
            mismatches.append("ELF endianness does not match the target")
        if mismatches:
            return mismatches, None

        # section names; the loader allocates .symtab and .strtab, and drops some sections (e.g., .modinfo)
        runtime_sections = dict(sections)
        missing = [name for name in runtime_sections if elf.get_shdr(name) is None]
        if missing:
            mismatches.append("sections not found in the file: {:s}".format(", ".join(missing)))
        file_sections = [s.sh_name for s in elf.shdrs if s.sh_flags & Elf.Shdr.SHF_ALLOC and s.sh_size]
        dropped = [name for name in file_sections if name not in runtime_sections]
        dropped = [name for name in dropped if name not in (".modinfo", "__versions", ".data..percpu")]
        if dropped:
            self.quiet_warn("Sections not loaded (GDB uses the address in the file): {:s}".format(", ".join(dropped)))

        # build-id
        note = elf.read_shdr(".note.gnu.build-id")
        note_addr = runtime_sections.get(".note.gnu.build-id")
        if note and note_addr:
            if is_valid_addr(note_addr + len(note) - 1):
                loaded_note = read_memory(note_addr, len(note))
            else:
                loaded_note = None
            if loaded_note == note:
                return mismatches, "build-id"
            if loaded_note is not None:
                mismatches.append("build-id does not match")
                return mismatches, None

        # module kallsyms
        symtab = elf.read_shdr(".symtab")
        strtab = elf.read_shdr(".strtab")
        if not symtab or not strtab:
            return mismatches, None
        kallsyms = self.get_module_kallsyms(module)
        if elf.e_endianness == Elf.LITTLE_ENDIAN:
            endian = "<"
        else:
            endian = ">"
        if elf.e_class == Elf.ELF_64_BITS:
            # Elf64_Sym: st_name, st_info, st_other, st_shndx, st_value, st_size
            fmt, index_info, index_shndx, index_value = "IBBHQQ", 1, 3, 4
        else:
            # Elf32_Sym: st_name, st_value, st_size, st_info, st_other, st_shndx
            fmt, index_info, index_shndx, index_value = "IIIBBH", 3, 5, 1
        matched = 0
        different = []
        for sym in struct.iter_unpack(endian + fmt, symtab):
            if sym[index_info] & 0xf not in (1, 2): # STT_OBJECT, STT_FUNC
                continue
            if not 0 < sym[index_shndx] < len(elf.shdrs):
                continue
            section_addr = runtime_sections.get(elf.shdrs[sym[index_shndx]].sh_name)
            if section_addr is None:
                continue
            name = strtab[sym[0]:strtab.find(b"\0", sym[0])].decode("utf-8", "replace")
            if name not in kallsyms:
                continue
            if section_addr + sym[index_value] in kallsyms[name]:
                matched += 1
            else:
                different.append(name)
        if different:
            names = ", ".join(different[:5]) + (", ..." if len(different) > 5 else "")
            mismatches.append("{:d} symbols differ from the module kallsyms: {:s}".format(len(different), names))
            return mismatches, None
        if matched:
            return mismatches, "{:d} symbols of the module kallsyms".format(matched)
        return mismatches, None

    def kmod_load(self):
        module = self.kmod.find(self.module_addrs, self.args.name)
        if module is None:
            self.quiet_err("Could not find {:s}".format(self.args.name))
            return

        sections = self.kmod.get_sections(module)
        if not sections:
            self.quiet_err("module->sect_attrs of {:s} is NULL or invalid".format(self.args.name))
            return
        for name, addr in sections:
            self.quiet_info("name={:s}, addr={:#x}".format(name, addr))
            # unneeded, but for convenience
            gdb.set_convenience_variable(name.replace(".", "").replace("-", ""), addr)

        # verify
        mismatches, verified_by = self.verify_file(module, sections)
        for mismatch in mismatches:
            self.quiet_err("Mismatch: {:s}".format(mismatch))
        if mismatches:
            if not self.args.force:
                self.quiet_err("{:s} does not match the loaded module {:s} (use --force to load anyway)".format(self.args.path, self.args.name))
                return
        elif verified_by:
            self.quiet_info("Verified by {:s}".format(verified_by))
        else:
            self.quiet_warn("Could not verify beyond the architecture and the section names")

        # load; .symtab and .strtab are allocated only in memory for the module kallsyms
        if not self.kmod.initialize_memory(self.module_addrs):
            self.quiet_err("Could not find module memory regions")
            return
        regions = self.kmod.get_regions(module)
        loaded = []
        for name, addr in sections:
            if name in (".symtab", ".strtab"):
                continue
            if any(base <= addr < base + size for _, base, size in regions):
                loaded.append((name, addr))
            else:
                self.quiet_warn("Skipping unloaded section {:s}".format(name))
        if not loaded:
            self.quiet_err("Could not find loaded module sections")
            return
        command = " ".join(['-s {:s} {:#x}'.format(GefUtil.quote_gdb_argument(name), addr)
                            for name, addr in loaded])
        gdb.execute("add-symbol-file {:s} {:s}".format(GefUtil.quote_gdb_argument(self.args.path), command))
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel_or_kpti_disabled
    def do_invoke(self, args):
        if not os.path.exists(args.path):
            self.quiet_err("Could not find {:s}".format(args.path))
            return

        kversion = Kernel.version()
        if kversion is None:
            self.quiet_err("Could not find Linux kernel")
            return
        if kversion < "3.0":
            self.quiet_err("Unsupported before v3.0")
            return

        self.kmod = Kernel.modules()

        # modules
        ret = self.kmod.initialize()
        if args.meta or not ret:
            for func, line in Kernel.export_meta(self, self.kmod.meta):
                func(line)
        if not ret:
            self.quiet_err("Failed to initialize")
            return

        # get module addrs
        self.module_addrs, meta = self.kmod.get_addrs()
        for func, line in Kernel.export_meta(self, meta):
            func(line)
        if self.module_addrs == []:
            self.quiet_err("Could not find any modules")
            return
        self.quiet_info("Num of modules: {:d}".format(len(self.module_addrs)))

        # module->sect_attrs
        requested = self.kmod.find(self.module_addrs, args.name)
        ret = self.kmod.initialize_sect_attrs(self.module_addrs, requested)
        if args.meta or not ret:
            for func, line in Kernel.export_meta(self, self.kmod.sect_attrs_meta):
                func(line)
        if not ret:
            self.quiet_err("Failed to initialize")
            return

        if args.meta:
            return

        # doit
        self.kmod_load()
        return



@register_command
class KtypesCommand(GenericCommand, BufferingOutput):
    """Display kernel type information from /sys/kernel/btf/vmlinux."""

    _cmdline_ = "ktypes"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _note_ = [
        "This command requires CONFIG_DEBUG_INFO_BTF=y.",
        "CONFIG_KALLSYMS_ALL=y is not required.",
    ]
    _note_ = "\n".join(_note_)

    def check_command(self):
        try:
            GefUtil.which("bpftool")
            if is_x86():
                GefUtil.which("gcc")
            elif is_arm64():
                GefUtil.which("aarch64-linux-gnu-gcc")
            elif is_arm32():
                GefUtil.which("arm-linux-gnueabihf-gcc")
        except FileNotFoundError as e:
            err("{}".format(e))
            return False
        return True

    def get_base_name(self):
        if not hasattr(runtime.CommandRegistry.instances["ksymaddr-remote"], "kernel_version"):
            gdb.execute("ksymaddr-remote --no-pager GEF_DUMMY_STRING", to_string=True)
            if not hasattr(runtime.CommandRegistry.instances["ksymaddr-remote"], "kernel_version"):
                err("Could not find kernel version")
                return None

        ks = runtime.CommandRegistry.instances["ksymaddr-remote"]
        h = hashlib.sha256(String.str2bytes(ks.version_string)).hexdigest()[-16:]
        major, minor, patch = ks.kernel_version
        base_name = os.path.join(GEF_TEMP_DIR, "ktypes-{:d}.{:d}.{:d}-{:s}".format(major, minor, patch, h))
        return base_name

    def get_btf_addr(self):
        start = Symbol.get_ksymaddr("__start_BTF")
        if start is None:
            return None
        end = Symbol.get_ksymaddr("__stop_BTF")
        return start, end - start

    def build_header_file(self):
        base_path = self.get_base_name()
        if base_path is None:
            return None

        raw_path = base_path + ".raw"
        header_path = base_path + ".h"

        # use cache
        if not self.args.rescan:
            if os.path.exists(header_path) and os.path.getsize(header_path) > 0:
                return header_path

        # get address of /sys/kernel/btf/vmlinux
        addr_size = self.get_btf_addr()
        if addr_size is None:
            err("Could not find /sys/kernel/btf/vmlinux")
            return None

        # read /sys/kernel/btf/vmlinux
        try:
            content = read_memory(*addr_size)
        except gdb.MemoryError:
            err("Memory read error")
            return None

        # save it
        open(raw_path, "wb").write(content)

        # raw -> vmlinux.h
        os.system("{!r} btf dump file {!r} format c > {!r}".format(GefUtil.which("bpftool"), raw_path, header_path))
        return header_path

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    def do_invoke(self, args):
        if not self.check_command():
            return

        header_path = self.build_header_file()
        if header_path is None:
            warn("This kernel may be CONFIG_DEBUG_INFO_BTF=n")
            return

        content = open(header_path, "r").read()

        self.out = []
        self.out.extend(content.splitlines())
        self.print_output(check_terminal_size=True)
        return


@register_command
class KtypesLoadCommand(KtypesCommand):
    """Load kernel type information from /sys/kernel/btf/vmlinux."""

    _cmdline_ = "ktypes-load"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"
    _aliases_ = ["kt-load"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    _syntax_ = parser.format_help()

    def get_compiler(self):
        try:
            if is_x86_64():
                return GefUtil.which("gcc"), []
            if is_x86_32():
                return GefUtil.which("gcc"), ["-m32"]
            if is_arm64():
                return GefUtil.which("aarch64-linux-gnu-gcc"), []
            if is_arm32():
                return GefUtil.which("arm-linux-gnueabihf-gcc"), []
            if is_riscv64():
                return GefUtil.which("riscv64-linux-gnu-gcc"), []
            if is_riscv32():
                try:
                    return GefUtil.which("riscv32-linux-gnu-gcc"), []
                except FileNotFoundError:
                    return GefUtil.which("riscv64-linux-gnu-gcc"), ["-march=rv32imac", "-mabi=ilp32"]
        except FileNotFoundError as e:
            err("{}".format(e))
        return None

    def check_command(self):
        return super().check_command() and self.get_compiler() is not None

    def build_obj_file(self, header_path):
        compiler = self.get_compiler()
        if compiler is None:
            return None
        gcc, opt = compiler
        with open(header_path, "rb") as file:
            content = file.read()
        options = [gcc] + opt + ["-std=c11", "-fms-extensions", "-g", "-O0", "-fno-eliminate-unused-debug-types", "-w", "-c"]
        h = hashlib.sha256(content + repr(options).encode()).hexdigest()
        obj_path = header_path[:-2] + "-" + h + ".o"

        # use cache
        if not self.args.rescan:
            if os.path.exists(obj_path) and os.path.getsize(obj_path) > 0:
                return obj_path

        with tempfile.TemporaryDirectory(dir=GEF_TEMP_DIR) as directory:
            source_path = os.path.join(directory, "vmlinux.c")
            temp_obj = os.path.join(directory, "vmlinux.o")
            with open(source_path, "wb") as file:
                file.write(content)
            cmd = options + [source_path, "-o", temp_obj]
            info(" ".join(shlex.quote(arg) for arg in cmd))
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True)
            if result.returncode != 0:
                err("Failed to compile kernel types: {:s}".format(result.stdout.strip()))
                return None
            elf = Elf.get_elf(temp_obj)
            if elf is None or not elf.has_debuginfo():
                err("Compiled object contains no debug information")
                return None
            os.replace(temp_obj, obj_path)
        return obj_path

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    def do_invoke(self, args):
        if not self.check_command():
            return

        header_path = self.build_header_file()
        if header_path is None:
            return

        obj_path = self.build_obj_file(header_path)
        if obj_path is None:
            err("Failed to build")
            return

        info(obj_path)
        gdb.execute("file {:s}".format(GefUtil.quote_gdb_argument(obj_path)), to_string=True)
        info("Kernel types are loaded successfully")
        return



@register_command
class KsymaddrRemoteCommand(GenericCommand, BufferingOutput):
    """Resolve kernel symbols from kallsyms table."""

    _cmdline_ = "ksymaddr-remote"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"
    _aliases_ = ["ks"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("keyword", metavar="KEYWORD", nargs="*", help="filter by specific symbol name.")
    parser.add_argument("-t", "--type", action="append", default=[], help="filter by symbol type.")
    parser.add_argument("-e", "--exact", action="store_true", help="use exact match.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-s", "--smart", action="store_true", help="filter __pfx_*, __ksymtab_*, etc.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("-V", "--vmlinux-file", metavar="FILE",
                       help="force use your vmlinux file which includes symbols.")
    group.add_argument("-M", "--system-map", metavar="FILE",
                       help="read and relocate symbols from a System.map file.")
    parser.add_argument("-I", "--ignore-loaded-vmlinux", action="store_true", help="force skip parsing loaded vmlinux.")
    parser.add_argument("-C", "--print-saved-config", action="store_true", help="print saved (cached) config contents.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} commit_creds prepare_kernel_cred  # OR search",
        "{0:s} --system-map /boot/System.map commit_creds",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "GEF caches offset information for parsing kallsyms to speed up this command.",
        "Each cache is used based on kernel version strings, so kernels of the same version",
        "share one cache even if the CONFIG is different. GEF checks the cached offsets",
        "against the running kernel and parses again when they do not match.",
        "To drop a cache by hand, rescan with `ks -rv` or use `gef reset-cache --hard`.",
        "`--system-map` and `--vmlinux-file` check the KASLR offset against the exception entry and linux_banner.",
        "With only one anchor, it warns that the kernel build could not be verified.",
        "Absolute symbols and symbols linked outside the kernel image are not relocated.",
    ]
    _note_ = "\n".join(_note_)

    def print_kallsyms(self, kallsyms, keywords, types, smart):
        if is_32bit():
            fmt = "{:#010x} {:s} {:s}"
        else:
            fmt = "{:#018x} {:s} {:s}"

        if types:
            types = [t.lower() for t in types]
            kallsyms = [entry for entry in kallsyms if entry[2].lower() in types]

        if smart:
            ignore_list = (
                "__pfx_", # prefix symbols for function padding
                "__kstrtab_",
                "__ksymtab_",
                "__kcrctab_",
                "__tpstrtab_", # tracepoint
                "__initcall__",
                "__traceiter_",
                "__tracepoint_",
                "__probestub_",
                "__already_done.",
                "__flags.",
                "__func__.",
                "__key.",
                "__mkey.",
                "__msg.",
                "__print_once.",
                "__quirk.",
                "__warned.",
                "__wkey.",
                "___done.",
                "___once_key.",
                "___tp_str.",
                "__compound_literal.",
                "__SCT__tp_func_",
                "__SCK__tp_func_",
                "__TRACE_SYSTEM_",
            )
            kallsyms = [entry for entry in kallsyms if not entry[1].startswith(ignore_list)]

        self.out = []
        if not keywords:
            for addr, symbol, typ in kallsyms:
                self.out.append(fmt.format(addr, typ, symbol))

        elif self.args.exact:
            for addr, symbol, typ in kallsyms:
                if symbol in keywords:
                    self.out.append(fmt.format(addr, typ, symbol))

        else:
            for addr, symbol, typ in kallsyms:
                text = fmt.format(addr, typ, symbol)
                for k in keywords:
                    if k in text: # not only symbol search, but also address search
                        self.out.append(text)
                        break
        return

    def print_saved_config(self):
        cfg_file_name = Cache.peek_cache_for(Ksym.Config.name)
        if cfg_file_name is not None:
            info("path: {:s}".format(cfg_file_name))
            if os.path.exists(cfg_file_name):
                gef_print(titlify("content (hexlified)"))
                config = configparser.ConfigParser()
                config.read(cfg_file_name)
                for param_name in config["parameters"]:
                    param_value = config["parameters"][param_name]
                    try:
                        param_value = int(param_value)
                        gef_print("{:s} = {:#x}".format(param_name, param_value))
                    except ValueError:
                        gef_print("{:s} = {:s}".format(param_name, param_value))
                return

        err("Could not find cached config (Run the `ksymaddr-remote` command at least once)")
        return

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    def do_invoke(self, args):
        if args.print_saved_config:
            self.print_saved_config()
            return

        if args.system_map is None:
            self.quiet_info("Wait for memory scan")

        ret = Ksym.get_kallsyms(
            rescan=args.rescan, vmlinux_file=args.vmlinux_file, system_map=args.system_map,
            ignore_loaded_vmlinux=args.ignore_loaded_vmlinux,
            verbose=args.verbose, quiet=args.quiet,
        )
        if ret is None:
            return
        kallsyms, _kallsyms_map = ret

        self.print_kallsyms(kallsyms, args.keyword, args.type, args.smart)
        self.print_output(check_terminal_size=True)
        return



@register_command
class VmlinuxToElfApplyCommand(GenericCommand):
    """Apply symbol from kallsyms in memory using vmlinux-to-elf."""

    _cmdline_ = "vmlinux-to-elf-apply"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true",
                        help="regenerate the ELF instead of reusing a matching symbol cache.")
    _syntax_ = parser.format_help()

    @staticmethod
    def dump_kernel_elf(rescan=False):
        """Dump the kernel from the memory, then apply vmlinux-to-elf to create symboled ELF."""
        # check
        try:
            vmlinux2elf = GefUtil.which("vmlinux-to-elf")
        except FileNotFoundError as e:
            err("{}".format(e))
            return None

        # resolve text_base, ro_base
        klayout = Kernel.layout()
        if None in (klayout.text_base, klayout.text_size, klayout.ro_base, klayout.ro_size):
            err("Failed to resolve")
            return None
        gef_print("kernel base:   {:#x}-{:#x} ({:#x} bytes)".format(klayout.text_base, klayout.text_end, klayout.text_size))
        gef_print("kernel rodata: {:#x}-{:#x} ({:#x} bytes)".format(klayout.ro_base, klayout.ro_end, klayout.ro_size))

        info("Start memory dump")
        # rodata size detection may be inaccurate on kernels with RWX attribute regions.
        # Since they tend to be very large, we put a size cap on the rodata to make it faster.
        if klayout.rwx:
            # The number 0x400000 has no basis.
            fixed_ro_base_size = min(0x40_0000, klayout.ro_size)
        else:
            fixed_ro_base_size = klayout.ro_size

        fd, dumped_mem_file = GefUtil.mkstemp(prefix="dump-memory-", suffix=".raw")
        os.close(fd)

        # dump text
        start = klayout.text_base
        end = start + klayout.text_size
        gef_print("Dumping .text area:   {:#x} - {:#x}".format(start, end))
        data = read_memory(start, end - start, safe=True)
        if data is None:
            err("Memory read error. Make sure the context is in supervisor mode / Ring-0")
            os.unlink(dumped_mem_file)
            return None
        with open(dumped_mem_file, "wb") as output:
            output.write(data)
        del data

        # dump sparse
        text_end = klayout.text_end
        unmapped_size = klayout.ro_base - text_end
        if unmapped_size:
            gef_print("Non-mapping area:     {:#x} - {:#x} (ZERO fill)".format(text_end, klayout.ro_base))
            with open(dumped_mem_file, "ab") as output:
                output.write(b"\0" * unmapped_size)

        # dump rodata
        start = klayout.ro_base
        end = start + fixed_ro_base_size
        gef_print("Dumping .rodata area: {:#x} - {:#x}".format(start, end))
        data = read_memory(start, end - start, safe=True)
        if data is None:
            err("Memory read error. Make sure the context is in supervisor mode / Ring-0")
            os.unlink(dumped_mem_file)
            return None
        with open(dumped_mem_file, "ab") as output:
            output.write(data)
        del data

        with open(dumped_mem_file, "rb") as source:
            digest = hashlib.sha256(source.read())
        digest.update("{:x}".format(klayout.text_base).encode())
        h = digest.hexdigest()
        saved_mem_file = os.path.join(GEF_TEMP_DIR, "dump-memory-{:s}.raw".format(h))
        symboled_vmlinux_file = os.path.join(GEF_TEMP_DIR, "dump-memory-{:s}.elf".format(h))
        os.replace(dumped_mem_file, saved_mem_file)
        dumped_mem_file = saved_mem_file
        gef_print("Dumped to {:s}".format(dumped_mem_file))
        if not rescan and os.path.exists(symboled_vmlinux_file) and os.path.getsize(symboled_vmlinux_file) > 0:
            info("A previously used file found, will be reused")
            return symboled_vmlinux_file
        if os.path.exists(symboled_vmlinux_file):
            os.unlink(symboled_vmlinux_file)

        # apply vmlinux-to-elf
        cmd = "{:s} {:s} {:s} --base-address={:#x}".format(
            shlex.quote(vmlinux2elf), shlex.quote(dumped_mem_file), shlex.quote(symboled_vmlinux_file), klayout.text_base,
        )
        warn("Execute `{:s}`".format(cmd))
        if GefUtil.os_system(cmd):
            if os.path.exists(symboled_vmlinux_file):
                os.unlink(symboled_vmlinux_file)
            err("vmlinux-to-elf failed")
            return None

        # Error
        if not os.path.exists(symboled_vmlinux_file) or os.path.getsize(symboled_vmlinux_file) == 0:
            return None

        # Success
        return symboled_vmlinux_file

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64"))
    @only_if_in_kernel
    def do_invoke(self, args):
        info("Wait for memory scan")

        text_base = Kernel.layout().text_base
        if text_base is None:
            err("Failed to resolve kbase")
            return

        symboled_vmlinux_file = self.dump_kernel_elf(args.rescan)
        if symboled_vmlinux_file is None:
            err("Failed to create kernel ELF")
            return

        # load symbol
        info("Adding symbol")
        # Prior to gdb 8.x, add-symbol-file command requires a .text address
        #   gdb 9.x: Usage: add-symbol-file FILE [-readnow | -readnever] [-o OFF] [ADDR] [-s SECT-NAME SECT-ADDR]...
        #   gdb 8.x: Usage: add-symbol-file FILE ADDR [-readnow | -readnever | -s SECT-NAME SECT-ADDR]...
        # But the created ELF has no .text, only a .kernel
        # Applying an empty symbol has no effect, so tentatively specify the same address as the .kernel.
        cmd = "add-symbol-file {:s} {:#x} -s .kernel {:#x}".format(
            GefUtil.quote_gdb_argument(symboled_vmlinux_file), text_base, text_base,
        )
        warn("Execute `{:s}`".format(cmd))
        gdb.execute(cmd)
        return



@register_command
class KsymaddrRemoteApplyCommand(GenericCommand):
    """Apply symbol from kallsyms in memory."""

    _cmdline_ = "ksymaddr-remote-apply"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"
    _aliases_ = ["ks-apply"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    def create_symboled_elf(self, sym_elf_path):
        # get .kernel range
        from gef.commands.debugging.other import AddSymbolTemporaryCommand
        text_base = Symbol.get_ksymaddr("_stext")
        if text_base is None:
            err("Failed to get kernel base (_stext)")
            return False
        res = gdb.execute("ksymaddr-remote --quiet --no-pager", to_string=True)
        text_end = int(res.splitlines()[-1].split()[0], 16)

        # make blank ELF
        text_base &= get_pagesize_mask_high()
        blank_elf = AddSymbolTemporaryCommand.create_blank_elf(text_base, text_end)
        if blank_elf is None:
            err("Failed to create blank ELF")
            return False

        # parse kernel symbol
        cmd_string_arr = []
        for line in res.splitlines():
            addr, typ, func_name = line.split()
            addr = int(addr, 16)

            if addr < text_base:
                # lower address is percpu-relative. It is meaningless to import the address, so it is skipped.
                continue

            if typ in ["T", "t", "W", None]:
                type_flag = "function"
            else:
                type_flag = "object"
            if typ and typ in "abcdefghijklmnopqrstuvwxyz":
                global_flag = "local"
            else:
                global_flag = "global"

            # higher address needs relative
            relative_addr = addr - text_base
            cmd_string_arr.append("--add-symbol")
            cmd_string_arr.append("{:s}=.text:{:#x},{:s},{:s}".format(func_name, relative_addr, global_flag, type_flag))

        self.quiet_info("{:d} entries will be added".format(len(cmd_string_arr) // 2))

        # embedding symbols
        objcopy = GefUtil.which(Config.get_gef_setting("gef.objcopy_command"))
        processed_count = 0
        for cmd_string_arr_sliced in slicer(cmd_string_arr, 10000 * 2):
            subprocess.check_output([objcopy] + cmd_string_arr_sliced + [blank_elf])
            processed_count += len(cmd_string_arr_sliced) // 2

            # debug print
            if processed_count and processed_count % 10000 == 0:
                self.quiet_info("{:d} entries were processed".format(processed_count))

        self.quiet_info("{:d} entries were processed".format(processed_count))
        os.rename(blank_elf, sym_elf_path)
        return True

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    @only_if_in_kernel
    def do_invoke(self, args):
        try:
            GefUtil.which(Config.get_gef_setting("gef.objcopy_command"))
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        self.quiet_info("Wait for memory scan")

        # resolve kversion for saved file name
        kversion = Kernel.kernel_version()
        h = hashlib.sha256(String.str2bytes(kversion.version_string)).hexdigest()[-16:]
        sym_elf_path = os.path.join(GEF_TEMP_DIR, "ks-apply-{:s}.elf".format(h))
        if (not args.rescan) and os.path.exists(sym_elf_path) and os.path.getsize(sym_elf_path) > 0:
            self.quiet_info("A previously used file found, will be reused")
        else:
            if os.path.exists(sym_elf_path):
                os.unlink(sym_elf_path)
            ret = self.create_symboled_elf(sym_elf_path)
            if not ret:
                return

        # add symbol to gdb
        text_base = Symbol.get_ksymaddr("_stext") & get_pagesize_mask_high()
        cmd = "add-symbol-file {:s} {:#x}".format(sym_elf_path, text_base)
        self.quiet_warn("Execute `{:s}`".format(cmd))
        gdb.execute(cmd)
        return
