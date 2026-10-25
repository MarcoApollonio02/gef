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
import struct
import subprocess

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

    def build_obj_file(self, header_path):
        source_path = header_path[:-2] + ".c"
        obj_path = source_path[:-2]

        # use cache
        if not self.args.rescan:
            if os.path.exists(obj_path) and os.path.getsize(obj_path) > 0:
                return obj_path

        # copy vmlinux.h to vmlinux.c
        open(source_path, "wb").write(open(header_path, "rb").read())

        try:
            if is_x86_64():
                gcc, opt = GefUtil.which("gcc"), ""
            elif is_x86_32():
                gcc, opt = GefUtil.which("gcc"), "-m32"
            elif is_arm64():
                gcc, opt = GefUtil.which("aarch64-linux-gnu-gcc"), ""
            elif is_arm32():
                gcc, opt = GefUtil.which("arm-linux-gnueabihf-gcc"), ""
        except FileNotFoundError as e:
            err("{}".format(e))
            return None

        # build with debug types
        cmd = "{!r} {:s} -std=c11 -g -O0 -fno-eliminate-unused-debug-types -w -c {!r} -o {!r}".format(
            gcc, opt, source_path, obj_path,
        )
        info(cmd)
        os.system(cmd)

        if not os.path.exists(obj_path):
            return None

        return obj_path

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

        obj_path = self.build_obj_file(header_path)
        if obj_path is None:
            err("Failed to build")
            return

        info(obj_path)
        gdb.execute("file {:s}".format(obj_path), to_string=True)
        info("Kernel types are loaded successfully")
        return


@register_command
class KsymaddrRemoteCommand(GenericCommand, BufferingOutput):
    """Resolve kernel symbols from kallsyms table."""
    # Thanks to https://github.com/marin-m/vmlinux-to-elf

    _cmdline_ = "ksymaddr-remote"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"
    _aliases_ = ["ks"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("keyword", metavar="KEYWORD", nargs="*", help="filter by specific symbol name.")
    parser.add_argument("-t", "--type", action="append", default=[], help="filter by symbol type.")
    parser.add_argument("-e", "--exact", action="store_true", help="use exact match.")
    parser.add_argument("-r", "--rescan", action="store_true", help="do not use cache.")
    parser.add_argument("-s", "--smart", action="store_true", help="filter __pfx_*, __ksymtab_*, etc.")
    parser.add_argument("--vmlinux-file", help="force use your vmlinux file which includes symbols.")
    parser.add_argument("-I", "--ignore-loaded-vmlinux", action="store_true", help="force skip parsing loaded vmlinux.")
    parser.add_argument("--print-saved-config", action="store_true", help="print saved (cached) config contents.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    parser.add_argument("-v", "--verbose", action="store_true", help="enable verbose mode.")
    parser.add_argument("-q", "--quiet", action="store_true", help="enable quiet mode.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s} commit_creds prepare_kernel_cred  # OR search",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        "GEF caches offset information for parsing kallsyms to speed up this command.",
        "Each cache is used based on kernel version strings.",
        "In other words, in cases where the kernel version is exactly the same and",
        "the CONFIG is slightly different, the offset will be applied incorrectly.",
        "In this case, rescan with `ks -rv` or clear the cache with `gef reset-cache --hard`.",
    ]
    _note_ = "\n".join(_note_)

    def __init__(self, *args, **kwargs):
        super().__init__()
        """
        # Do not use dict; There are cases where multiple symbols with the same name exist.
        # cat /proc/kallsyms |grep set_is_seen
        ffffffff812326e0 t set_is_seen
        ffffffff81d58900 t set_is_seen
        ffffffff81d5cab0 t set_is_seen
        #
        """
        self.kallsyms = []
        return

    def get_loaded_vmlinux_path(self):
        if self.args.ignore_loaded_vmlinux:
            return None

        # Check `nm` first for later use (in parse_vmlinux)
        try:
            GefUtil.which(Config.get_gef_setting("gef.nm_command"))
        except FileNotFoundError as e:
            self.quiet_err("{}".format(e))
            return None

        # check vmlinux
        for inf in gdb.inferiors():
            if not hasattr(inf, "progspace"):
                continue
            if not hasattr(inf.progspace, "filename"):
                continue

            filename = str(inf.progspace.filename)
            if not os.path.exists(filename):
                continue

            # Currently, the filename in vmlinux is hard-coded
            if "vmlinux" not in os.path.basename(filename).lower():
                continue

            # it has symbol?
            try:
                elf = Elf(filename)
                if elf.get_shdr(".symtab"):
                    return filename
            except Exception:
                continue
        return None

    def parse_vmlinux(self, filename):
        # read symbols
        try:
            nm = GefUtil.which(Config.get_gef_setting("gef.nm_command"))
        except FileNotFoundError as e:
            self.quiet_err("{}".format(e))
            return
        result = GefUtil.gef_execute_external([nm, filename], as_list=True)

        # distinctive addresses to use for rebasing
        if is_x86():
            target = [
                "asm_exc_divide_error", # 5.8~
                "divide_error", # 3.0 ~ 5.7
            ]
        elif is_arm64() or is_arm32():
            target = [
                "vectors", # 3.7~
            ]
        elif is_riscv64() or is_riscv32():
            target = [
                "handle_exception", # 4.19~
            ]
        else:
            raise

        # parse symbol
        tmp_kallsyms = []
        target_found = {}
        for line in result:
            try:
                addr, typ, name = line.split()
                addr = int(addr, 16)
                typ = typ.strip()
                name = name.strip()
            except ValueError:
                continue
            tmp_kallsyms.append([addr, name, typ])

            if name in target:
                target_found["handler"] = addr

        # rebase
        if target_found:
            text_base_hint = Kernel.get_kernel_base_hint()
            if text_base_hint:
                diff = text_base_hint - target_found["handler"]
                if diff & get_pagesize_mask_low() == 0:
                    self.kallsyms = []
                    for addr, name, typ in tmp_kallsyms:
                        # don't rebase per-cpu offset
                        if addr >= 0x4000_0000:
                            # This value is the lowest boundary between ARM32 kernel and userland.
                            addr += diff
                        self.kallsyms.append([addr, name, typ])
                    return

        # fail, use as is
        self.kallsyms = tmp_kallsyms
        return

    def get_token_table(self):
        # Parse symbol name tokens
        tokens = []
        position = self.offset_kallsyms_token_table
        for _ in range(256):
            token = ""
            while self.kernel_img[position]:
                token += chr(self.kernel_img[position])
                position += 1
            position += 1
            tokens.append(token)
        assert len(tokens) == 256
        return tokens

    def read_kallsyms(self):
        if self.kallsyms: # resolved already
            return

        tokens = self.get_token_table()
        symbol_names = []
        position = self.offset_kallsyms_names
        for _ in range(self.num_symbols):
            # read token length
            length = self.kernel_img[position]
            position += 1

            # check if big symbol (6.1~)
            if self.kernel_version >= (6, 1, 0):
                if length & 0x80:
                    low = length & 0x7f
                    high = self.kernel_img[position]
                    position += 1
                    length = (high << 7) | low

            # make symbol_name
            symbol_name = ""
            for _ in range(length):
                symbol_token_index = self.kernel_img[position]
                symbol_token = tokens[symbol_token_index]
                position += 1
                symbol_name += symbol_token
            symbol_names.append(symbol_name)

        for addr, name in zip(self.kernel_addresses, symbol_names):
            try:
                self.kallsyms.append([addr, name[1:], name[0]])
            except IndexError:
                pass
        return

    def print_kallsyms(self, keywords, types, smart):
        if is_32bit():
            fmt = "{:#010x} {:s} {:s}"
        else:
            fmt = "{:#018x} {:s} {:s}"

        if types:
            types = [t.lower() for t in types]
            kallsyms = [entry for entry in self.kallsyms if entry[2].lower() in types]
        else:
            kallsyms = self.kallsyms

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

    def get_kernel_version_triplet(self, version_number):
        major = int(version_number.split(".")[0])
        minor = int(version_number.split(".")[1])
        if len(version_number.split(".")) == 2:
            patch = 0
        else:
            patch = int(version_number.split(".")[2])
        return (major, minor, patch)

    def get_kernel_version(self):
        # don't use Kernel.kernel_version, since it refers ksymaddr-remote
        r = re.search(rb"Linux version (\d+\.[\d.]*\d)[ -~]+", self.kernel_img)
        if r is None:
            self.verbose_err("Could not find the kernel version")
            return False
        self.version_string = r.group(0)
        self.version_string_offset = r.span()[0]
        self.verbose_info("linux_banner: {:#x}".format(self.ro_base + self.version_string_offset))
        version_number = r.group(1).decode("ascii")
        self.kernel_version = self.get_kernel_version_triplet(version_number)

        # The important thing for parsing is whether it is 6.1.42 or later.
        # However, some distributions may have a patch version of 0.
        # e.g., debian 6.1.119-1 -> 6.1.0-28-amd64
        # In this case, special processing is required to find a different version string.
        if self.kernel_version[:2] == (6, 1):
            # e.g., Linux version 6.1.0-28-amd64 (debian-kernel@lists.debian.org) (gcc-12 (Debian 12.2.0-14) 12.2.0,
            # GNU ld (GNU Binutils for Debian) 2.40) #1 SMP PREEMPT_DYNAMIC Debian 6.1.119-1 (2024-11-22)
            r = re.findall(rb" 6\.1\.(\d+)", self.version_string)
            for patch_version in r:
                patch_version = int(patch_version)
                if patch_version >= 42:
                    self.kernel_version = (self.kernel_version[0], self.kernel_version[1], patch_version)
                    break
        return True

    def get_cfg_name(self):
        h = hashlib.sha256(String.str2bytes(self.version_string)).hexdigest()[-16:]
        major, minor, patch = self.kernel_version
        cfg_file_name = os.path.join(GEF_TEMP_DIR, "ksymaddr-remote-{:d}.{:d}.{:d}-{:s}.cfg".format(major, minor, patch, h))
        return cfg_file_name

    def save_config(self, param_name):
        cfg_file_name = self.get_cfg_name()
        config = configparser.ConfigParser()
        if os.path.exists(cfg_file_name):
            config.read(cfg_file_name)
        else:
            config["parameters"] = {}

        config["parameters"][param_name] = str(getattr(self, param_name))
        with open(cfg_file_name, "w") as cfg_file:
            config.write(cfg_file)
        return

    def get_saved_config(self, param_names):
        if self.args.rescan:
            return False

        cfg_file_name = self.get_cfg_name()
        if not os.path.exists(cfg_file_name):
            return False

        config = configparser.ConfigParser()
        config.read(cfg_file_name)
        for param_name in param_names:
            if param_name not in config["parameters"]:
                return False

        for param_name in param_names:
            param_value = int(config["parameters"][param_name])
            setattr(self, param_name, param_value)
        return True

    def print_saved_config(self):
        if hasattr(self, "version_string"):
            cfg_file_name = self.get_cfg_name()
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

    def find_kallsyms_token_table(self):
        ret = self.get_saved_config(["offset_kallsyms_token_table"])
        if ret:
            self.verbose_info("kallsyms_token_table: {:#x}".format(self.ro_base + self.offset_kallsyms_token_table))
            return True

        """
        [Search strategy]
        - kallsyms_token_table has unique sequences like "30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00".
        - We search for it from .rodata area, then search backwards for invalid characters to get the top.

        [Positional relationship]
        - ...
        - kallsyms_token_table
        - ...

        [Sample values for 64bit]
        gef> hexdump -n byte kallsyms_token_table
        0xffffffff8b2b51b0:    65 75 00 77 5f 00 61 64 64 00 64 5f 5f 66 75 6e    |  eu.w_.add.d__fun  |
        0xffffffff8b2b51c0:    63 5f 5f 00 74 70 5f 66 75 6e 63 00 33 32 00 6e    |  c__.tp_func.32.n  |
        0xffffffff8b2b51d0:    61 00 66 66 00 69 70 00 78 65 6e 00 70 72 00 73    |  a.ff.ip.xen.pr.s  |
        0xffffffff8b2b51e0:    65 74 00 63 70 75 00 49 44 00 65 64 00 53 43 00    |  et.cpu.ID.ed.SC.  |
        0xffffffff8b2b51f0:    66 72 65 00 76 65 5f 00 70 6f 00 78 5f 00 5f 73    |  fre.ve_.po.x_._s  |
        0xffffffff8b2b5200:    68 00 2e 31 00 62 6c 00 6d 65 6d 00 5f 72 65 67    |  h..1.bl.mem._reg  |
        0xffffffff8b2b5210:    00 74 5f 5f 00 6c 6f 63 6b 00 62 5f 00 72 5f 5f    |  .t__.lock.b_.r__  |
        0xffffffff8b2b5220:    6b 73 74 72 74 61 62 6e 73 00 66 75 6e 63 5f 5f    |  kstrtabns.func__  |
        0xffffffff8b2b5230:    00 69 6e 74 5f 00 72 65 73 00 74 72 61 63 65 00    |  .int_.res.trace.  |
        0xffffffff8b2b5240:    70 61 72 00 2e 30 00 64 65 76 65 6e 74 5f 00 6d    |  par..0.devent_.m  |
        0xffffffff8b2b5250:    75 00 61 63 70 69 5f 00 6d 70 00 73 74 61 00 64    |  u.acpi_.mp.sta.d  |
        0xffffffff8b2b5260:    65 62 75 67 00 5f 5f 5f 00 62 75 67 00 6f 75 00    |  ebug.___.bug.ou.  |
        0xffffffff8b2b5270:    5f 73 74 61 00 77 72 69 74 00 2e 00 67 72 6f 00    |  _sta.writ...gro.  |
        0xffffffff8b2b5280:    30 00 31 00 32 00 33 00 34 00 35 00 36 00 37 00    |  0.1.2.3.4.5.6.7.  | <- here unique seqs
        0xffffffff8b2b5290:    38 00 39 00 72 63 00 77 61 00 63 61 6c 00 75 70    |  8.9.rc.wa.cal.up  |
        0xffffffff8b2b52a0:    5f 00 45 5f 00 67 65 5f 00 6d 61 70 00 41 00 42    |  _.E_.ge_.map.A.B  |

        [Sample values for 32bit]
        gef> hexdump -n byte kallsyms_token_table
        0xc6e58efc:    54 52 41 43 45 5f 53 59 53 00 41 43 45 5f 53 59    |  TRACE_SYS.ACE_SY  |
        0xc6e58f0c:    53 00 5f 53 59 53 00 54 45 4d 00 41 43 45 00 69    |  S._SYS.TEM.ACE.i  |
        0xc6e58f1c:    67 00 70 6f 69 6e 74 5f 00 62 75 00 75 74 5f 00    |  g.point_.bu.ut_.  | # codespell:ignore
        0xc6e58f2c:    5f 53 59 00 54 52 00 5f 73 79 00 72 65 61 64 00    |  _SY.TR._sy.read.  |
        0xc6e58f3c:    66 5f 00 75 6c 00 62 6c 00 61 6c 6c 6f 63 00 74    |  f_.ul.bl.alloc.t  |
        0xc6e58f4c:    6c 00 63 6c 00 65 79 00 61 74 61 00 70 63 00 5f    |  l.cl.ey.ata.pc._  |
        0xc6e58f5c:    65 6e 00 76 65 72 00 54 45 00 64 74 72 61 63 65    |  en.ver.TE.dtrace  | # codespell:ignore
        0xc6e58f6c:    5f 65 76 65 6e 74 5f 00 61 70 00 61 74 65 00 74    |  _event_.ap.ate.t  |
        0xc6e58f7c:    6e 00 41 43 00 6d 73 00 72 61 77 5f 00 5f 63 6f    |  n.AC.ms.raw_._co  |
        0xc6e58f8c:    00 73 74 72 00 6d 6f 00 67 69 73 74 65 72 00 69    |  .str.mo.gister.i  |
        0xc6e58f9c:    70 00 63 6f 6e 00 67 69 73 00 69 6e 69 74 00 66    |  p.con.gis.init.f  |
        0xc6e58fac:    75 6e 63 00 65 5f 73 00 75 74 00 5f 73 68 00 70    |  unc.e_s.ut._sh.p  |
        0xc6e58fbc:    6f 00 61 6c 6c 00 2e 00 66 73 5f 00 30 00 31 00    |  o.all...fs_.0.1.  |
        0xc6e58fcc:    32 00 33 00 34 00 35 00 36 00 37 00 38 00 39 00    |  2.3.4.5.6.7.8.9.  | <- here unique seqs
        0xc6e58fdc:    6b 5f 00 5f 63 68 00 72 69 74 00 61 63 70 69 00    |  k_._ch.rit.acpi.  |
        0xc6e58fec:    5f 63 6f 6e 00 65 78 74 34 00 61 6d 00 41 00 42    |  _con.ext4.am.A.B  |
        """

        # first, search for unique bytes
        seq_to_find = b"0\x001\x002\x003\x004\x005\x006\x007\x008\x009\x00"
        seq_to_avoid = [b":\0", b"\0\0", b"\0\1", b"\0\2", b"ASCII\0"]
        target_pattern = seq_to_find + b"(?!" + b"|".join(seq_to_avoid) + b")"

        unique_bytes_offset = []
        for r in re.finditer(target_pattern, self.kernel_img):
            unique_bytes_offset.append(r.span()) # (start_pos, end_pos)

        if len(unique_bytes_offset) == 0:
            self.verbose_err("Could not find kallsyms_token_table (0 candidate)")
            return False

        if len(unique_bytes_offset) > 1:
            # strict check
            for i, offsets in enumerate(unique_bytes_offset.copy()):
                self.verbose_info("unique_bytes {:d}: {:#x}".format(i, self.ro_base + offsets[0]))
                follow = self.kernel_img[offsets[1]:offsets[1] + 1]
                if not follow.isalnum() and follow not in [b"_", b"."]:
                    unique_bytes_offset.remove(offsets)
            # re-check
            if len(unique_bytes_offset) == 0:
                self.verbose_err("Could not find kallsyms_token_table (0 candidate)")
                return False
            if len(unique_bytes_offset) > 1:
                self.verbose_err("Could not find kallsyms_token_table (multiple candidates)")
                return False

        position = unique_bytes_offset[0][0]
        self.verbose_info("unique_bytes: {:#x}".format(self.ro_base + position))

        # second, backward search for the top
        position -= 1
        if position < 0:
            self.verbose_err("Could not find kallsyms_token_table (failed to get top: before '0')")
            return False
        if self.kernel_img[position] != 0:
            self.verbose_err("Unexpected byte before '0' entry in kallsyms_token_table")
            return False

        num_tokens_back = ord('0') # 48
        max_token_len = 50

        # find the beginning of a kallsyms_token_table
        for _ in range(num_tokens_back):
            # find the beginning of a token
            for _ in range(max_token_len):
                position -= 1
                if position < 0:
                    self.verbose_err("Could not find kallsyms_token_table (out of range while walking tokens)")
                    return False

                b = self.kernel_img[position]
                if b == 0 or b > ord('z'):
                    break

            else:
                # max_token_len exceeded
                self.verbose_err("This structure is not a kallsyms_token_table (token too long)")
                return False

        position += 1
        position += -position % 4

        self.offset_kallsyms_token_table = position
        self.save_config("offset_kallsyms_token_table")
        self.verbose_info("kallsyms_token_table: {:#x}".format(self.ro_base + self.offset_kallsyms_token_table))
        return True

    def find_kallsyms_token_index(self):
        ret = self.get_saved_config(["offset_kallsyms_token_index"])
        if ret:
            self.verbose_info("kallsyms_token_index: {:#x}".format(self.ro_base + self.offset_kallsyms_token_index))
            return True

        """
        [Search strategy]
        - Find the index where the string appears in kallsyms_token_table.
        - Find where that index is arranged like a table.

        [Positional relationship]
        - ...
        - kallsyms_token_table
        - kallsyms_token_index
        - ...

        [Sample values for 64bit]
        gef> hexdump -n word kallsyms_token_index
        0xffffffff8b2b5540:    0x0000 0x0003 0x0006 0x000a 0x0014 0x001c 0x001f 0x0022    |  ..............".  |
        0xffffffff8b2b5550:    0x0025 0x0028 0x002c 0x002f 0x0033 0x0037 0x003a 0x003d    |  %.(.,./.3.7.:.=.  |
        0xffffffff8b2b5560:    0x0040 0x0044 0x0048 0x004b 0x004e 0x0052 0x0055 0x0058    |  @.D.H.K.N.R.U.X.  |
        0xffffffff8b2b5570:    0x005c 0x0061 0x0065 0x006a 0x006d 0x007a 0x0081 0x0086    |  ..a.e.j.m.z.....  |
        0xffffffff8b2b5580:    0x008a 0x0090 0x0094 0x0097 0x009f 0x00a2 0x00a8 0x00ab    |  ................  |
        0xffffffff8b2b5590:    0x00af 0x00b5 0x00b9 0x00bd 0x00c0 0x00c5 0x00ca 0x00cc    |  ................  |
        0xffffffff8b2b55a0:    0x00d0 0x00d2 0x00d4 0x00d6 0x00d8 0x00da 0x00dc 0x00de    |  ................  |
        0xffffffff8b2b55b0:    0x00e0 0x00e2 0x00e4 0x00e7 0x00ea 0x00ee 0x00f2 0x00f5    |  ................  |

        [Sample values for 32bit]
        gef> hexdump -n word kallsyms_token_index
        0xc6e59274:    0x0000 0x000a 0x0012 0x0017 0x001b 0x001f 0x0022 0x0029    |  ............".).  |
        0xc6e59284:    0x002c 0x0030 0x0034 0x0037 0x003b 0x0040 0x0043 0x0046    |  ,.0.4.7.;.@.C.F.  |
        0xc6e59294:    0x0049 0x004f 0x0052 0x0055 0x0058 0x005c 0x005f 0x0063    |  I.O.R.U.X..._.c.  |
        0xc6e592a4:    0x0067 0x006a 0x0078 0x007b 0x007f 0x0082 0x0085 0x0088    |  g.j.x.{.........  |
        0xc6e592b4:    0x008d 0x0091 0x0095 0x0098 0x009f 0x00a2 0x00a6 0x00aa    |  ................  |
        0xc6e592c4:    0x00af 0x00b4 0x00b8 0x00bb 0x00bf 0x00c2 0x00c6 0x00c8    |  ................  |
        0xc6e592d4:    0x00cc 0x00ce 0x00d0 0x00d2 0x00d4 0x00d6 0x00d8 0x00da    |  ................  |
        0xc6e592e4:    0x00dc 0x00de 0x00e0 0x00e3 0x00e7 0x00eb 0x00f0 0x00f5    |  ................  |
        """

        # create expected kallsyms_token_index byte sequqence
        position = self.offset_kallsyms_token_table
        seq_token_table_head = self.kernel_img[position:position + 256]

        token_offsets = [p16(0)]
        pos = 0
        while True:
            pos = seq_token_table_head.find(b"\0", pos + 1)
            if pos == -1:
                break
            token_offsets.append(p16(pos + 1))
        seq_to_find = b"".join(token_offsets)

        # search for it from memory
        position = self.kernel_img.find(seq_to_find, self.offset_kallsyms_token_table)
        if position == -1:
            self.verbose_err("Could not find kallsyms_token_index (0 candidate)")
            return False

        self.offset_kallsyms_token_index = position
        self.save_config("offset_kallsyms_token_index")
        self.verbose_info("kallsyms_token_index: {:#x}".format(self.ro_base + self.offset_kallsyms_token_index))
        return True

    def find_kallsyms_markers(self):
        # determines the size of table elements depended on kernel version.
        if self.kernel_version < (4, 20, 0):
            # kallsyms_markers is unsigned long[]
            self.kallsyms_markers_table_element_size = runtime.current_arch.ptrsize
        else:
            # kallsyms_markers is unsigned int[]
            self.kallsyms_markers_table_element_size = 4

        if self.kernel_version >= (6, 1, 42) and self.kernel_version < (6, 9, 0):
            ret = self.get_saved_config([
                "offset_kallsyms_token_markers",
                "offset_kallsyms_seqs_of_names",
            ])
            if ret:
                self.verbose_info("kallsyms_markers: {:#x}".format(self.ro_base + self.offset_kallsyms_markers))
                self.verbose_info("kallsyms_seqs_of_names: {:#x}".format(self.ro_base + self.offset_kallsyms_seqs_of_names))
                return True
        else:
            ret = self.get_saved_config([
                "offset_kallsyms_token_markers",
            ])
            if ret:
                self.verbose_info("kallsyms_markers: {:#x}".format(self.ro_base + self.offset_kallsyms_markers))
                return True

        """
        [Search strategy]
        - From kallsyms_token_table, search backwards for 0x00000000.
        - For kernel v6.1.42~v6.8, there is kallsyms_seqs_of_names between kallsyms_markers and kallsyms_token_table,
          so this should be skipped.

        [Positional relationship]
        ...
        - kallsyms_markers
        - kallsyms_seqs_of_names (v6.1.42~v6.8)
        - kallsyms_token_table
        - kallsyms_token_index
        ...
        - kallsyms_seqs_of_names (v6.9~)
        ...

        [Sample values for 64bit ~v6.1.41]
        gef> hexdump -n dword kallsyms_markers
        0xffffffff8b2b4b48:    0x00000000 0x00000ab0 0x000016d3 0x00002316    |  .............#..  | <- kallsyms_markers
        0xffffffff8b2b4b58:    0x00002f38 0x00003cf8 0x00004c4c 0x000059c8    |  8/...<..LL...Y..  |
        0xffffffff8b2b4b68:    0x0000664b 0x00007316 0x00008119 0x00008f2e    |  Kf...s..........  |
        0xffffffff8b2b4b78:    0x00009cc6 0x0000a9ff 0x0000b687 0x0000c20f    |  ................  |
        ...
        0xffffffff8b2b5180:    0x0013fa80 0x001404c6 0x00140f67 0x00141a29    |  ........g...)...  |
        0xffffffff8b2b5190:    0x0014240e 0x00142e25 0x00143a5f 0x0014442a    |  .$..%..._:..*D..  |
        0xffffffff8b2b51a0:    0x00144e55 0x001458d8 0x00146338 0x00000000    |  UN...X..8c......  |
        0xffffffff8b2b51b0:    0x77007565 0x6461005f 0x5f640064 0x6e75665f    |  eu.w_.add.d__fun  | <- kallsyms_token_table

        [Sample values for 64bit v6.1.42~]
        gef> hexdump -n dword kallsyms_markers
        0xffffffff8d5fcde0:    0x00000000 0x00000b55 0x000017bb 0x000024c3    |  ....U........$..  | <- kallsyms_markers
        0xffffffff8d5fcdf0:    0x000030c1 0x00003dca 0x00004983 0x000058aa    |  .0...=...I...X..  |
        0xffffffff8d5fce00:    0x00006785 0x0000760e 0x0000828d 0x00009160    |  .g...v......`...  |
        0xffffffff8d5fce10:    0x00009efa 0x0000ab20 0x0000b73a 0x0000c37d    |  .... ...:...}...  |
        ...
        0xffffffff8d5fd790:    0x00212755 0x002131b8 0x00213af8 0x00214558    |  U'!..1!..:!.XE!.  |
        0xffffffff8d5fd7a0: (*)0x01069d01 0x9d01019d 0x029d0100 0x02039d01    |  ................  | <- kallsyms_seqs_of_names (*)
        0xffffffff8d5fd7b0:    0xa400291c 0x10a50024 0x0154a500 0xaa0116aa    |  .)..$.....T.....  |
        0xffffffff8d5fd7c0:    0x87610214 0x01274902 0xb201cbaf 0xbbbc01c9    |  ..a..I'.........  |

        [Sample values for 32bit v6.1.42~]
        gef> hexdump -n dword kallsyms_markers
        0xc6e0dc98:    0x00000000 0x00000c61 0x0000188f 0x00002641    |  ....a.......A&..  | <- kallsyms_markers
        0xc6e0dca8:    0x00003492 0x000041a7 0x00004e6b 0x00005ace    |  .4...A..kN...Z..  |
        0xc6e0dcb8:    0x0000691b 0x00007703 0x00008411 0x00008fc1    |  .i...w..........  |
        0xc6e0dcc8:    0x00009c98 0x0000a8ea 0x0000b719 0x0000c4dd    |  ................  |
        ...
        0xc6e0e2c8:    0x0014f2fa 0x0014fbeb 0x00150653 0x00634401(*) |  ........S....Dc.  | <- kallsyms_seqs_of_names (*)
        0xc6e0e2d8:    0xd90030d9 0x8bd30032 0x0189d300 0x6a01e97f    |  .0..2..........j  |
        0xc6e0e2e8:    0x31d90063 0x0007e100 0xd600b7e1 0xd1d900cb    |  c..1............  |
        0xc6e0e2f8:    0x0083dd00 0xd90004e9 0x85ef00ab 0x00bfdb00    |  ................  |
        """

        # kallsyms_markers[0] is 0.
        seq_to_find = b"\0" * self.kallsyms_markers_table_element_size

        # ignore the 0 immediately above kallsyms_token_table.
        position = self.offset_kallsyms_token_table - 1
        if len(self.kernel_img) <= position:
            return False
        while position > 0 and self.kernel_img[position] == 0:
            position -= 1

        # aligned search for it from memory
        while position > 0:
            needle = self.kernel_img.rfind(seq_to_find, 0, position)
            if needle == -1:
                self.verbose_err("Could not find kallsyms_markers")
                return False
            # check alignment
            align_diff = needle % self.kallsyms_markers_table_element_size
            if align_diff == 0:
                position = needle
                break # ok
            else:
                position = needle + self.kallsyms_markers_table_element_size - align_diff
                # not aligned, so retry

        if self.kernel_version >= (6, 1, 42) and self.kernel_version < (6, 9, 0):
            # kallsyms_seqs_of_names was introduced in kernel 6.1.42
            # In this case, we may find kallsyms_seqs_of_names instead of kallsyms_markers,
            # so we should search back through memory again.
            #
            # kallsyms_markers        (1) we want to find this
            # kallsyms_seqs_of_names  (3) this may have been found, try the backward search again
            # kallsyms_token_table    (2) backward search from here
            # kallsyms_token_index
            #
            while position > 0:
                # the first some values of kallsyms_markers should be a small number.
                # if not, detected kallsyms_markers is incorrect and we'll go back further.
                first_10_elements = self.kernel_img[position + self.kallsyms_markers_table_element_size:]
                first_10_elements = first_10_elements[:self.kallsyms_markers_table_element_size * 10]
                first_10_elements = slice_unpack(first_10_elements, self.kallsyms_markers_table_element_size)
                if all((x & 0xfff_0000) == 0 for x in first_10_elements):
                    break

                needle = self.kernel_img.rfind(seq_to_find, 0, position)
                if needle == -1:
                    self.verbose_err("Could not find kallsyms_markers")
                    return False
                # check alignment
                align_diff = needle % self.kallsyms_markers_table_element_size
                if align_diff == 0:
                    position = needle
                else:
                    position = needle + self.kallsyms_markers_table_element_size - align_diff

        if position <= 0:
            self.verbose_err("Could not find kallsyms_markers")
            return False

        self.offset_kallsyms_markers = position
        self.save_config("offset_kallsyms_markers")
        self.verbose_info("kallsyms_markers: {:#x}".format(self.ro_base + self.offset_kallsyms_markers))

        if self.kernel_version >= (6, 1, 42) and self.kernel_version < (6, 9, 0):
            # locate kallsyms_seqs_of_names to get the table size of kallsyms_markers (used after).
            #
            # kallsyms_markers        (1) we found this
            # kallsyms_seqs_of_names  (2) to know the end of kallsyms_markers, we need to find this
            # kallsyms_token_table
            # kallsyms_token_index
            #
            position = self.offset_kallsyms_markers + self.kallsyms_markers_table_element_size
            # check MSB of the element of kallsyms_markers
            while self.kernel_img[position + (self.kallsyms_markers_table_element_size - 1)] == 0:
                a = u32(self.kernel_img[position - self.kallsyms_markers_table_element_size:position]) # prev
                b = u32(self.kernel_img[position:position + self.kallsyms_markers_table_element_size]) # current
                # kallsyms_markers are monotonically increasing.
                # and it doesn't increase very dramatically.
                if a > b or b - a > 0x10_0000:
                    break
                position += self.kallsyms_markers_table_element_size
            self.offset_kallsyms_seqs_of_names = position
            self.save_config("offset_kallsyms_seqs_of_names")
            self.verbose_info("kallsyms_seqs_of_names: {:#x}".format(self.ro_base + self.offset_kallsyms_seqs_of_names))

        return True

    def find_kallsyms_names(self):
        ret = self.get_saved_config(["offset_kallsyms_names"])
        if ret:
            return True

        """
        [Search strategy]
        - From kallsyms_markers, go back as far as we can definitively go back.
        - This address is not accurate.

        [Positional relationship]
        ...
        - kallsyms_names (this is not accurate address in this step)
        - kallsyms_markers
        - kallsyms_seqs_of_names (v6.1.42~v6.8)
        - kallsyms_token_table
        - kallsyms_token_index
        ...
        - kallsyms_seqs_of_names (v6.9~)
        ...

        [Sample values for 64bit]
        gef> hexdump -n qword kallsyms_names
        0xffffffff8b16e610:    0x0cf3ec0e78b6410a 0xf370ff4109fe61cb    |  .A.x.....a..A.p.  | <- kallsyms_names
        0xffffffff8b16e620:    0x0c410774722cbdeb 0xa8410df67ef4285f    |  ..,rt.A._(.~..A.  |
        0xffffffff8b16e630:    0x936bed62d8632c71 0x925f0c4107f67ef4    |  q,c.b.k..~..A._.  |
        0xffffffff8b16e640:    0xfb646741067772f1 0x706563a4410add86    |  .rw.Agd....A.cep  |
        ...
        0xffffffff8b2b4b20:    0x616bd977fc6d7364 0x738df5ff440e61f6    |  dsm.w.ka.a.D...s  |
        0xffffffff8b2b4b30:    0x6765625fbfe87263 0x63738df5ff440cf5    |  cr.._beg..D...sc  |
        0xffffffff8b2b4b40:    0x000064ee5fbfe872 0x00000ab000000000    |  r.._.d..........  | <- kallsyms_markers
        0xffffffff8b2b4b50:    0x00002316000016d3 0x00003cf800002f38    |  .....#..8/...<..  |

        [Sample values for 32bit]
        gef> hexdump -n qword kallsyms_names
        0xc6cbce58:    0x335fd57472fb5c08 0x54039974f9540432    |  ...rt._32.T.t..T  | <- kallsyms_names
        0xc6cbce68:    0x63ff72fb5c0799a6 0xd57472fb5c0a30a1    |  .....r.c.0...rt.  |
        0xc6cbce78:    0x177407b6f932335f 0xa0ca0aa1f3796669    |  _32...t.ify.....  |
        0xc6cbce88:    0xd7f49b2d63ecc37f 0x2d63ecc37fa0ca0a    |  ...c-.........c-  |
        ...
        0xc6e0dc78:    0x3a7262fe620d105f 0x10ff67ef796ccf65    |  _..b.br:e.ly.g..  |
        0xc6e0dc88:    0x62fe420964164203 0x0000ec6d699b6b72    |  .B.d.B.brk.im...  |
        0xc6e0dc98:    0x00000c6100000000 0x000026410000188f    |  ....a.......A&..  | <- kallsyms_markers
        0xc6e0dca8:    0x000041a700003492 0x00005ace00004e6b    |  .4...A..kN...Z..  |
        """

        # take the last element of kallsyms_marker
        if hasattr(self, "offset_kallsyms_seqs_of_names"): # maybe 6.1.42~6.8
            kallsyms_markers_end = self.offset_kallsyms_seqs_of_names
        else:
            kallsyms_markers_end = self.offset_kallsyms_token_table

        kallsyms_markers_data = self.kernel_img[self.offset_kallsyms_markers:kallsyms_markers_end]
        kallsyms_markers_entries = slice_unpack(kallsyms_markers_data, self.kallsyms_markers_table_element_size)
        kallsyms_markers_last_entry = list(filter(None, kallsyms_markers_entries))[-1] # filter 0, maybe padding

        # go back that number of bytes
        position = self.offset_kallsyms_markers
        position -= kallsyms_markers_last_entry
        position += -position % self.kallsyms_markers_table_element_size

        if position <= 0:
            self.verbose_err("Could not find kallsyms_names")
            return False

        # This value is provisional. It will be corrected in the next process (=find_kallsyms_num_syms).
        self.offset_kallsyms_names = position
        self.verbose_info("kallsyms_names: {:#x} (candidate)".format(self.ro_base + self.offset_kallsyms_names))
        return True

    def find_kallsyms_num_syms(self):
        ret = self.get_saved_config([
            "num_symbols",
            "offset_kallsyms_names",
            "offset_kallsyms_num_syms",
        ])
        if ret:
            self.verbose_info("num_symbols: {:#x}".format(self.num_symbols))
            self.verbose_info("kallsyms_names: {:#x}".format(self.ro_base + self.offset_kallsyms_names))
            self.verbose_info("kallsyms_num_syms: {:#x}".format(self.ro_base + self.offset_kallsyms_num_syms))
            return True

        """
        [Search strategy]
        - From candidate address of kallsyms_names, search backwards to the top of what can be correctly
          interpreted as kallsyms_names.

        [Positional relationship]
        ...
        - kallsyms_num_syms
        - kallsyms_names (to be fixed in this step)
        - kallsyms_markers
        - kallsyms_seqs_of_names (v6.1.42~v6.8)
        - kallsyms_token_table
        - kallsyms_token_index
        ...
        - kallsyms_seqs_of_names (v6.9~)
        ...

        [Sample values for 64bit]
        gef> hexdump -n qword kallsyms_num_syms
        0xffffffff8b16e608:    0x000000000001982b 0x0cf3ec0e78b6410a    |  +........A.x....  |
        0xffffffff8b16e618:    0xf370ff4109fe61cb 0x0c410774722cbdeb    |  .a..A.p...,rt.A.  |
        0xffffffff8b16e628:    0xa8410df67ef4285f 0x936bed62d8632c71    |  _(.~..A.q,c.b.k.  |
        0xffffffff8b16e638:    0x925f0c4107f67ef4 0xfb646741067772f1    |  .~..A._..rw.Agd.  |

        [Sample values for 32bit]
        gef> hexdump -n dword kallsyms_num_syms
        0xc6cbce54:    0x00018eb8 0x72fb5c08 0x335fd574 0xf9540432    |  .......rt._32.T.  |
        0xc6cbce64:    0x54039974 0x5c0799a6 0x63ff72fb 0x5c0a30a1    |  t..T.....r.c.0..  |
        0xc6cbce74:    0xd57472fb 0xf932335f 0x177407b6 0xf3796669    |  .rt._32...t.ify.  |
        """

        token_table = self.get_token_table()
        possible_symbol_types = "-?ABCDGINPRSTUVWabcdginprstuvw" # from `man nm`
        dp = []
        step = 4

        position = self.offset_kallsyms_names
        # kallsyms_names should be aligned.
        # This optimization is based on experience and is applied for now.
        position += -position % step

        while True:
            if position < 0:
                self.verbose_err("Could not find kallsyms_names")
                return False

            # Do some types of checks.
            # 1: check the token type is likely or not.
            token_index = self.kernel_img[position + 1]
            symbol_type = token_table[token_index][0]
            if symbol_type not in possible_symbol_types:
                position -= step
                continue

            # 2: check the table (kallsyms_names) entirely.
            # Each element of kallsyms_names consists of {number of tokens, tokens[number of tokens]}.
            # tokens[0][0] is symbol type.
            #
            # The following is an example of last elements of kallsyms_names.
            # gef> x/24xb 0xffffffffb46b4b48-0x10
            # 0xffffffffb46b4b38: 0xf5   0x0c*  0x44   0xff   0xf5   0x8d   0x73   0x63 (*: start of last valid elements)
            # 0xffffffffb46b4b40: 0x72   0xe8   0xbf   0x5f   0xee   0x64*  0x00** 0x00 (*: end of last valid elements, **: end marker)
            # 0xffffffffb46b4b48: 0x00*  0x00   0x00   0x00   0xb0   0x0a   0x00   0x00 (*: start of kallsyms_markers)
            #
            # 0x0c: number of tokens
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x44]
            # 'D' (= symbol type)
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xff]
            # '__'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xf5]
            # 'in'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x8d]
            # 'it_'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x73]
            # 's'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x63]
            # 'c'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x72]
            # 'r'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xe8]
            # 'at'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xbf]
            # 'ch'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x5f]
            # '_'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0xee]
            # 'en'
            # gef> pi GCI["ksymaddr-remote"].get_token_table()[0x64]
            # 'd'
            # (=`__init_scratch_end`)
            #
            # Finally, 0x00(**) is following, this is the marker that represents the end of kallsyms_names.
            # This can be interpreted that the size of element is 0.
            #
            # However, this 0x00 may not exist.
            # gef> x/16xb 0xffffffffadefc1d8-0x8
            # 0xffffffffadefc1d0: 0x12   0x65   0x05*  0xbf   0x65   0xaf   0x74   0xa5** (*/**: start/end of last valid elements)
            # 0xffffffffadefc1d8: 0x00*  0x00   0x00   0x00   0xb2   0x0b   0x00   0x00   (*: start of kallsyms_markers)
            # Even in this case, the first byte of kallsyms_markers is always 0, so we use it.
            #
            # Check that this structure is correct or not, using bottom-up DP.
            # dp[i] contains num_syms as interpreted from `kallsyms_makers - i` as the start of kallsyms_names.
            # dp[i] == -1 means invalid.
            range_start = position
            range_end = self.offset_kallsyms_markers
            range_end -= len(dp) # shortcut the already checked results.
            for pos in range(range_end, range_start - 1, -1):
                symbol_size = self.kernel_img[pos]
                is_big_symbol = False # default

                # check if big symbol (6.1~)
                if self.kernel_version >= (6, 1, 0):
                    if symbol_size & 0x80:
                        low = symbol_size & 0x7f
                        high = self.kernel_img[pos + 1]
                        symbol_size = (high << 7) | low
                        is_big_symbol = True

                # 0xffffffffb46b4b38: 0xf5     0x0c     0x44     0xff     0xf5     0x8d     0x73     0x63
                # 0xffffffffb46b4b40: 0x72     0xe8     0xbf     0x5f     0xee     0x64     0x00*    0x00*
                #                                                                           dp[2]=0  dp[1]=0
                # 0xffffffffb46b4b48: 0x00*    0x00     0x00     0x00     0xb0     0x0a     0x00     0x00
                #                     dp[0]=0
                if symbol_size == 0:
                    dp.append(0) # maybe it is a last entry
                    continue

                # 0xffffffffb46b4b38: 0xf5     0x0c     0x44     0xff     0xf5     0x8d     0x73     0x63
                # 0xffffffffb46b4b40: 0x72     0xe8     0xbf     0x5f     0xee     0x64*    0x00     0x00
                #                                                                  dp[3]=-1 dp[2]=0  dp[1]=0
                # 0xffffffffb46b4b48: 0x00*    0x00     0x00     0x00     0xb0     0x0a     0x00     0x00
                #                     dp[0]=0
                dp_len = len(dp)
                if is_big_symbol:
                    dp_len = len(dp) - 1
                if symbol_size >= dp_len:
                    dp.append(-1) # exceed the kallsyms_markers
                    continue

                # 0xffffffffb46b4b38: 0xf5     0x0c*    0x44     0xff     0xf5     0x8d     0x73     0x63
                #                              dp[f]=1  dp[e]=-1 dp[d]=-1 dp[c]=-1 dp[b]=-1 dp[a]=-1 dp[9]=-1
                # 0xffffffffb46b4b40: 0x72     0xe8     0xbf     0x5f     0xee     0x64     0x00**   0x00
                #                     dp[8]=-1 dp[7]=-1 dp[6]=-1 dp[5]=-1 dp[4]=-1 dp[3]=-1 dp[2]=0  dp[1]=0
                # 0xffffffffb46b4b48: 0x00*    0x00     0x00     0x00     0xb0     0x0a     0x00     0x00
                #                     dp[0]=0
                # when we see 0x0c(*), next element is 0x00(**).
                # In this case, here, len(dp) == 15 (dp[15] does not exist, but dp[14] exists).
                # dp[-(0xc + 1)] is dp[2]. dp[2] is 0, not -1, so dp[15] is valid. If dp[2] is -1, dp[15] is invalid.
                offset_of_next_element = -symbol_size - 1
                if is_big_symbol:
                    offset_of_next_element -= 1
                if dp[offset_of_next_element] == -1:
                    dp.append(-1)
                    continue
                # seems to be okay, append valid dp
                dp.append(dp[offset_of_next_element] + 1)

            num_symbols = dp[-1]
            if num_symbols < 256:
                # It is judged as NG because there are too few symbols.
                position -= step
                continue

            # 3: Find num_symbols from memory.
            if self.kallsyms_markers_table_element_size == 4:
                seq_to_find = p32(num_symbols)
            elif self.kallsyms_markers_table_element_size == 8:
                seq_to_find = p64(num_symbols)
            # Depending on the environment, there are many zero padding after seq_to_find (=kallsyms_num_syms).
            # This is probably because each variable is aligned in units of 256 bytes.
            MAX_ALIGNMENT = 256
            start = max(0, position - MAX_ALIGNMENT)
            needle = self.kernel_img.rfind(seq_to_find, start, position)
            if needle == -1:
                position -= step
                continue

            # it seems ok.
            self.offset_kallsyms_names = position
            self.offset_kallsyms_num_syms = needle
            break

        self.save_config("offset_kallsyms_names")
        self.save_config("offset_kallsyms_num_syms")
        self.num_symbols = num_symbols
        self.save_config("num_symbols")
        self.verbose_info("num_symbols: {:#x}".format(self.num_symbols))
        self.verbose_info("kallsyms_names: {:#x}".format(self.ro_base + self.offset_kallsyms_names))
        self.verbose_info("kallsyms_num_syms: {:#x}".format(self.ro_base + self.offset_kallsyms_num_syms))
        return True

    def find_kallsyms_offsets(self):
        """
        [Search strategy]
        - ~v6.3
          - From kallsyms_num_syms, go back by num_symbols element sizes.
          - num_symbols offsets are stored, so get them.
        - v6.4~
          - From kallsyms_token_index + 0x200, num_symbols offsets are stored, so get them.

        [Positional relationship]
        - ...
        - kallsyms_offsets (v4.6~v6.3, CONFIG_KALLSYMS_BASE_RELATIVE=y)
        - kallsyms_relative_base (v4.6~v6.3, CONFIG_KALLSYMS_BASE_RELATIVE=y)
        - kallsyms_num_syms
        - kallsyms_names
        - kallsyms_markers
        - kallsyms_seqs_of_names (v6.1.42~v6.8)
        - kallsyms_token_table
        - kallsyms_token_index
        - kallsyms_offsets (v6.4~, CONFIG_KALLSYMS_BASE_RELATIVE=y)
        - kallsyms_relative_base (v6.4~v6.19, CONFIG_KALLSYMS_BASE_RELATIVE=y)
        - kallsyms_seqs_of_names (v6.9~)
        - ...

        [Sample values for 64bit ~v6.3, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n (use positive offset)]
        gef> hexdump -n dword kallsyms_offsets
        0xffffffff8b108550:    0x00000000 0x00000000 0x00001000 0x00002000    |  ............. ..  |
        0xffffffff8b108560:    0x00006000 0x0000b000 0x0000c000 0x00018000    |  .`..............  |
        0xffffffff8b108570:    0x00019000 0x00019008 0x00019010 0x00019020    |  ............ ...  |
        0xffffffff8b108580:    0x00019420 0x00019440 0x00019448 0x00019450    |   ...@...H...P...  |

        [Sample values for 64bit ~v6.3, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y (use negative offset)]
        gef> hexdump -n dword kallsyms_offsets
        0xffffffffa72854b0:    0xffffffff 0xffffffff 0xffffffff 0xffffffbf    |  ................  |
        0xffffffffa72854c0:    0xffffffba 0xfffffeef 0xfffffdef 0xfffffddf    |  ................  |
        0xffffffffa72854d0:    0xfffffdcf 0xfffffa1f 0xfffff9cf 0xfffff9bf    |  ................  |
        0xffffffffa72854e0:    0xfffff99f 0xfffff8ff 0xfffff76f 0xfffff73f    |  ........o...?...  |

        [Sample values for 32bit ~v6.3, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n (use positive offset)]
        gef> hexdump -n dword kallsyms_offsets
        0xc6c59370:    0x00000000 0x00000000 0x00000000 0x00000070    |  ............p...  |
        0xc6c59380:    0x00000080 0x000001d8 0x000002e0 0x00000320    |  ............ ...  |
        0xc6c59390:    0x00000360 0x000003a8 0x000003e8 0x000004a8    |  `...............  |
        0xc6c593a0:    0x000005a8 0x0000066c 0x0000073c 0x000007ac    |  ....l...<.......  |

        [Sample values for 64bit v6.4~, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n (use positive offset)]
        gef> hexdump -n word kallsyms_token_index
        0xffffffff844fa178:    0x0000 0x0003 0x0006 0x000a 0x0010 0x0013 0x0016 0x0019    |  ................  |
        0xffffffff844fa188:    0x001d 0x0029 0x002d 0x0030 0x0034 0x0037 0x003b 0x003e    |  ..).-.0.4.7.;.>.  |
        0xffffffff844fa198:    0x0041 0x0056 0x005a 0x005e 0x0061 0x0064 0x0067 0x006a    |  A.V.Z.^.a.d.g.j.  |
        ...
        0xffffffff844fa358:    0x0386 0x0389 0x038c 0x038f 0x0392 0x0395 0x0398 0x039b    |  ................  |
        0xffffffff844fa368:    0x039e 0x03a1 0x03a5 0x03a8 0x03ab 0x03ae 0x03b1 0x03b4    |  ................  |
        gef> hexdump -n dword kallsyms_offset
        0xffffffff844fa378:    0x00000000 0x00000000 0x00001000 0x00002000    |  ............. ..  |
        0xffffffff844fa388:    0x00006000 0x0000b000 0x0000c000 0x00014000    |  .`...........@..  |
        ...
        0xffffffff8461e44c:    0xf89effff 0xf89dffff 0xf89d9fff 0xf89d9fff    |  ................  |
        0xffffffff8461e45c:    0x00000000 0x81000000 0xffffffff 0x02fa0e02    |  ................  |
        relative_base_address: 0xffffffff81000000

        [Sample values for 64bit v6.4~, CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y (use negative offset)]
        gef> hexdump -n word kallsyms_token_index
        0xffffffff86744a38:    0x0000 0x0004 0x000c 0x0010 0x0014 0x0017 0x001b 0x0020    |  .............. .  |
        0xffffffff86744a48:    0x002d 0x0034 0x0039 0x003d 0x0042 0x0045 0x0048 0x004b    |  -.4.9.=.B.E.H.K.  |
        0xffffffff86744a58:    0x004f 0x0053 0x005d 0x0060 0x0064 0x0067 0x006b 0x0072    |  O.S.].`.d.g.k.r.  |
        ...
        0xffffffff86744c18:    0x0338 0x033b 0x033e 0x0341 0x0349 0x034c 0x034f 0x0357    |  8.;.>.A.I.L.O.W.  |
        0xffffffff86744c28:    0x035a 0x035d 0x0360 0x0363 0x0369 0x036e 0x0372 0x0375    |  Z.].`.c.i.n.r.u.  |
        gef> hexdump -n dword kallsyms_offset
        0xffffffff86744c38:    0xffffffff 0xffffffff 0xffffffff 0xffffffaf    |  ................  |
        0xffffffff86744c48:    0xffffffaa 0xfffffe9f 0xfffffe8f 0xfffffd8f    |  ................  |
        ...
        0xffffffff8677ed5c:    0xff09237f 0xff09218f 0xff09217f 0xff0920a9    |  .#...!...!... ..  |
        0xffffffff8677ed6c:    0x00000000 0x85c00000 0xffffffff 0x00f0d800    |  ................  |
        relative_base_address: 0xffffffff85c00000
        """

        # const values
        if Endian.is_big_endian():
            endianness_marker = ">"
            endian_str = "big"
        else:
            endianness_marker = "<"
            endian_str = "little"
        offset_byte_size = 4
        address_byte_size = runtime.current_arch.ptrsize

        if self.kernel_version < (7, 0, 0):
            # get relative_base_address
            if self.kernel_version < (6, 4, 0):
                # ignore the 0 immediately above offset_kallsyms_num_syms.
                position = self.offset_kallsyms_num_syms
                while True:
                    previous_word = self.kernel_img[position - address_byte_size:position]
                    if previous_word != b"\0" * address_byte_size:
                        break
                    position -= address_byte_size

                # Go backward by num_symbols.
                position -= address_byte_size

                # read from kallsyms_relative_base
                relative_base_address = int.from_bytes(self.kernel_img[position:position + address_byte_size], endian_str)

                if relative_base_address and (relative_base_address & get_pagesize_mask_low()) == 0:
                    """
                    some environment has invalid address as relative_base_address.
                    so don't use the logic of is_valid_addr(relative_base_address).

                    gef> hexdump -n qword 0xffffafc5c2adb260-0x10 0x20
                    0xffffafc5c2adb250:    0xffffafc5c1750000 0x0000000000028193    |  ..u.............  |
                    0xffffafc5c2adb260:    0x6474107414bc5404 0x6c7463be6270d277    |  .T..t.tdw.pb.ctl  |
                    gef> x/16xg 0xffffafc5c1750000
                    0xffffafc5c1750000:     Cannot access memory at address 0xffffafc5c1750000
                    """
                    while True:
                        previous_word = self.kernel_img[position - offset_byte_size:position]
                        if previous_word != b"\0" * offset_byte_size:
                            break
                        position -= offset_byte_size
                    position -= self.num_symbols * offset_byte_size

            else: # kernel_version >= (6, 4):
                position = self.offset_kallsyms_token_index + 0x200
                position_relative_base = align(position + self.num_symbols * offset_byte_size, runtime.current_arch.ptrsize)
                relative_base_address_data = self.kernel_img[position_relative_base:position_relative_base + address_byte_size]
                if len(relative_base_address_data) == 0:
                    self.verbose_err("kernel_img is not long enough.")
                    return False
                relative_base_address = int.from_bytes(relative_base_address_data, endian_str)
                if not (relative_base_address and (relative_base_address & get_pagesize_mask_low()) == 0):
                    return True

            # Getting here means that the relative_address and position have been detected correctly.
            self.verbose_info("relative_base_address: {:#x}".format(relative_base_address))

            # Try to parse addresses or offsets.
            fmt = "{:s}{:d}i".format(endianness_marker, self.num_symbols) # signed int
            kallsyms_offsets_data = self.kernel_img[position:position + self.num_symbols * offset_byte_size]
            ksym_offsets = struct.unpack(fmt, kallsyms_offsets_data)

            # Check the ratio of the negative value
            number_of_negative_items = len([offset for offset in ksym_offsets if offset < 0])
            if number_of_negative_items / len(ksym_offsets) >= 0.5:
                # the case CONFIG_KALLSYMS_ABSOLUTE_PERCPU=y.
                kernel_addresses = []
                for offset in ksym_offsets:
                    if offset < 0:
                        x = relative_base_address - 1 - offset
                        kernel_addresses.append(x)
                    else:
                        kernel_addresses.append(offset)
            else:
                # the case CONFIG_KALLSYMS_ABSOLUTE_PERCPU=n.
                kernel_addresses = []
                for offset in ksym_offsets:
                    x = offset + relative_base_address
                    kernel_addresses.append(x)

            # Check the ratio of the null value.
            number_of_null_items = kernel_addresses.count(0)
            if number_of_null_items / len(kernel_addresses) >= 0.2:
                return True

        else: # kernel_version >= (7, 0):
            position = self.offset_kallsyms_token_index + 0x200

            # Try to parse addresses or offsets.
            fmt = "{:s}{:d}i".format(endianness_marker, self.num_symbols) # signed int
            kallsyms_offsets_data = self.kernel_img[position:position + self.num_symbols * offset_byte_size]
            ksym_offsets = struct.unpack(fmt, kallsyms_offsets_data)

            # 7.0+: offset_to_ptr style, no kallsyms_relative_base. CONFIG_KALLSYMS_ABSOLUTE_PERCPU is removed.
            kernel_addresses = []
            for i, offset in enumerate(ksym_offsets):
                element_va = self.ro_base + position + i * offset_byte_size
                kernel_addresses.append(element_va + offset)

        # It seems ok.
        self.offset_kallsyms_addresses_or_offsets = position
        self.kernel_addresses = kernel_addresses
        self.verbose_info("kallsyms_offsets: {:#x}".format(self.ro_base + self.offset_kallsyms_addresses_or_offsets))
        return True

    def find_kallsyms_addresses(self):
        """
        [Search strategy]
        - From kallsyms_num_syms, go back by num_symbols element sizes.
        - num_symbols addresses are stored, so get them.

        [Positional relationship]
        - ...
        - kallsyms_addresses (~v6.3, CONFIG_KALLSYMS_BASE_RELATIVE=n)
        - kallsyms_num_syms
        - kallsyms_names
        - kallsyms_markers
        - kallsyms_seqs_of_names (v6.1.42~v6.8)
        - kallsyms_token_table
        - kallsyms_token_index
        - kallsyms_addresses (v6.4~?, CONFIG_KALLSYMS_BASE_RELATIVE=n) # Unimplemented, as this pattern has not been observed yet.
        - kallsyms_seqs_of_names (v6.9~)
        - ...

        [Sample values for 64bit ~v6.3]
        gef> hexdump -n qword kallsyms_addresses
        0xffffffff81ae3cb8:    0x0000000000000000 0x0000000000000000    |  ................  |
        0xffffffff81ae3cc8:    0x0000000000004000 0x0000000000009000    |  .@..............  |
        ...
        0xffffffff81ae4588:    0xffffffff81000000 0xffffffff81000000    |  ................  |
        0xffffffff81ae4598:    0xffffffff81000110 0xffffffff810001a9    |  ................  |

        [Sample values for 32bit ~v6.3]
        gef> hexdump -n dword kallsyms_addresses
        0xc1940888:    0xc1000000 0xc1000000 0xc10000bc 0xc10000cc    |  ................  |
        0xc1940898:    0xc10000ed 0xc1000165 0xc10001e7 0xc1000239    |  ....e.......9...  |
        0xc19408a8:    0xc1000283 0xc10002c1 0xc10002d0 0xc1000302    |  ................  |
        0xc19408b8:    0xc1000328 0xc100032f 0xc1000338 0xc1000338    |  (.../...8...8...  |
        """

        # const values
        if Endian.is_big_endian():
            endianness_marker = ">"
        else:
            endianness_marker = "<"
        address_byte_size = runtime.current_arch.ptrsize

        # ignore the 0 immediately above offset_kallsyms_num_syms.
        position = self.offset_kallsyms_num_syms
        while True:
            previous_word = self.kernel_img[position - address_byte_size:position]
            if previous_word != b"\0" * address_byte_size:
                break
            position -= address_byte_size

        # Go backward by num_symbols.
        position -= self.num_symbols * address_byte_size

        # Try to parse addresses.
        if address_byte_size == 8:
            fmt = "{:s}{:d}Q".format(endianness_marker, self.num_symbols)
        else:
            fmt = "{:s}{:d}I".format(endianness_marker, self.num_symbols)
        kallsyms_addresses_data = self.kernel_img[position:position + self.num_symbols * address_byte_size]
        self.kernel_addresses = struct.unpack(fmt, kallsyms_addresses_data)
        self.offset_kallsyms_addresses_or_offsets = position
        self.verbose_info("kallsyms_addresses: {:#x}".format(self.ro_base + self.offset_kallsyms_addresses_or_offsets))
        return True

    def initialize(self):
        ret = self.get_kernel_version()
        if not ret:
            return False

        if self.args.rescan:
            cfg_file_name = self.get_cfg_name()
            if os.path.exists(cfg_file_name):
                os.remove(cfg_file_name)
        else:
            # the case of both kernel version string are same, but offset are different.
            current_version_string_offset = self.version_string_offset # keep current
            if self.get_saved_config(["version_string_offset"]): # load temporarily
                if self.version_string_offset != current_version_string_offset:
                    cfg_file_name = self.get_cfg_name()
                    os.remove(cfg_file_name)
                    self.version_string_offset = current_version_string_offset # set current again

        ret = self.find_kallsyms_token_table()
        if not ret:
            return False

        ret = self.find_kallsyms_token_index()
        if not ret:
            return False

        ret = self.find_kallsyms_markers()
        if not ret:
            return False

        ret = self.find_kallsyms_names()
        if not ret:
            return False

        ret = self.find_kallsyms_num_syms()
        if not ret:
            return False

        self.offset_kallsyms_addresses_or_offsets = None
        if self.kernel_version >= (4, 6):
            # On modern kernels, first check the case CONFIG_KALLSYMS_BASE_RELATIVE=y.
            ret = self.find_kallsyms_offsets()
            if not ret:
                return False

        if not self.offset_kallsyms_addresses_or_offsets:
            if self.kernel_version < (7, 0):
                # the case CONFIG_KALLSYMS_BASE_RELATIVE=n.
                self.find_kallsyms_addresses()

        self.save_config("version_string")
        self.save_config("version_string_offset")
        self.save_config("ro_size")
        return True

    def arm64_fast_path(self):
        if not is_in_kernel():
            self.quiet_info("Use slow path")
            return False

        # This path is more faster because it does not use pagewalk.
        # Instead of finding ro_base from pagewalk results, it finds ro_base by scanning the kernel version.
        # It is especially beneficial for ARM64, due to extensive pagetables and pagewalk take a long time.
        # It may work on other architectures but limited to ARM64 as others gain little.

        # First, search for the kernel version string from $pc.
        # It is located at around top of ro_base, and ro_base is aligned by 0x10000.
        current = (runtime.current_arch.pc & ~0xffff) + 0x10000 # Starting address to brute force ro_base
        step_size = 0x10000
        while True:
            try:
                # As kernel version string is near the top of ro_base, it is enough to check the first page.
                candidate_rodata = read_memory(current, get_pagesize())
            except gdb.MemoryError:
                # reached to the end of ro_base
                self.quiet_info("Use slow path")
                return False

            # '\n\0' is needed to avoid false positives in the dmesg buffer.
            r = re.search(rb"Linux version (\d+\.[\d.]*\d)[ -~]+\n\0", candidate_rodata)
            if r:
                # Found kernel version string
                version_string_address = current + r.span()[0]
                self.version_string = r.group(0)[:-2]
                version_number = r.group(1).decode("ascii")
                self.kernel_version = self.get_kernel_version_triplet(version_number)
                break
            current += step_size

        # We can make the hash from the kernel version string and load from saved config.
        # At this point, following two parameters are enough.
        ret = self.get_saved_config([
            "version_string_offset",
            "ro_size",
        ])
        if not ret:
            self.quiet_info("Use slow path")
            return False

        # Restore ro_base with considering kASLR.
        self.quiet_info("Use fast path")
        self.ro_base = version_string_address - self.version_string_offset
        self.verbose_info("ro_base: {:#x}-{:#x}".format(self.ro_base, self.ro_base + self.ro_size))

        # doit
        self.kernel_img = read_memory(self.ro_base, self.ro_size)
        ret = self.initialize()
        if not ret:
            self.quiet_info("Use slow path")
            return False

        self.read_kallsyms()
        return True

    def parse_kallsyms(self):
        if self.kallsyms:
            return True # use cache

        # Fast path when reattaching GDB after executing this command once (ARM64 only).
        if is_arm64():
            ret = self.arm64_fast_path()
            if ret:
                return True

        # Slow path
        try:
            kinfo = Kernel.get_kernel_layout()
            if kinfo.has_none:
                return False
        except gdb.MemoryError:
            self.quiet_err("Memory read error")
            return False

        if not kinfo.rwx:
            # On modern kernels, ro_size can be trusted, so it only tries to parse once.
            self.ro_base = kinfo.ro_base
            self.ro_size = kinfo.ro_size
            self.kernel_img = read_memory(self.ro_base, self.ro_size)
            self.verbose_info("ro_base: {:#x}-{:#x}".format(self.ro_base, self.ro_base + self.ro_size))
            ret = self.initialize()
            if not ret:
                return False
        else:
            # Older kernel that has the RWX attribute don't trust ro_size.
            # Very large values of ro_size can be detected.
            # It will take a long time to parse if you just use it.
            # Gradually increasing ro_size while searching can speed up several times.
            self.ro_base = kinfo.ro_base
            # This value is a heuristic threshold derived through testing across numerous kernel images.
            # Unless there is a compelling reason, do not modify it.
            base_size = 0x10_0000
            step = 0x10_0000
            for candidate_size in range(base_size, kinfo.ro_size, step):
                self.ro_size = candidate_size
                self.kernel_img = read_memory(self.ro_base, self.ro_size)
                self.verbose_info("ro_base: {:#x}-{:#x}".format(self.ro_base, self.ro_base + self.ro_size))
                ret = self.initialize()
                if ret:
                    # found
                    break
            else:
                # not found
                return False

        # here, we got all offsets to read kallsyms
        self.read_kallsyms()
        return True

    def parse_main(self):
        if self.kallsyms:
            return True

        # specified vmlinux parse
        if self.args.vmlinux_file:
            if not os.path.exists(self.args.vmlinux_file):
                self.quiet_err("Could not find vmlinux file")
                return False
            self.quiet_info("Parse from file: {!s}".format(self.args.vmlinux_file))
            self.parse_vmlinux(self.args.vmlinux_file)
            return True

        # loaded vmlinux parse
        loaded_vmlinux = self.get_loaded_vmlinux_path()
        if loaded_vmlinux:
            self.quiet_info("Parse from file: {!s}".format(loaded_vmlinux))
            self.parse_vmlinux(loaded_vmlinux)
            return True

        # normal parse
        self.quiet_info("Wait for memory scan")
        ret = self.parse_kallsyms()
        if ret:
            return True

        # failed, but if args.rescan was not specified originally
        if not self.args.rescan:
            self.quiet_info("Try to rescan (ignore cached config)")
            original_rescan = self.args.rescan
            self.args.rescan = True
            try:
                self.kallsyms = []
                ret = self.parse_kallsyms()
            finally:
                self.args.rescan = original_rescan
            if ret:
                return True

        self.quiet_err("Failed to parse")
        return False

    @parse_args
    @only_if_gdb_running
    @only_if_specific_gdb_mode(mode=("qemu-system", "vmware", "kgdb"))
    @only_if_specific_arch(arch=("x86_32", "x86_64", "ARM32", "ARM64", "RISCV32", "RISCV64"))
    def do_invoke(self, args):
        if args.print_saved_config:
            self.print_saved_config()
            return

        if self.args.rescan:
            self.kallsyms = []

        ret = self.parse_main()
        if not ret:
            return

        self.print_kallsyms(args.keyword, args.type, args.smart)
        self.print_output(check_terminal_size=True)
        return


@register_command
class VmlinuxToElfApplyCommand(GenericCommand):
    """Apply symbol from kallsyms in memory using vmlinux-to-elf."""

    _cmdline_ = "vmlinux-to-elf-apply"
    _category_ = "06-e. Qemu-system/KGDB Cooperation - Linux Symbol/Type"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--rescan", action="store_true",
                        help="force applying again. (default: reuse vmlinux-to-elf-dump-memory.elf if exists)")
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

        # resolve kversion for saved file name
        kversion = Kernel.kernel_version()
        h = hashlib.sha256(String.str2bytes(kversion.version_string)).hexdigest()[-16:]
        dumped_mem_file = os.path.join(GEF_TEMP_DIR, "dump-memory-{:s}.raw".format(h))
        symboled_vmlinux_file = os.path.join(GEF_TEMP_DIR, "dump-memory-{:s}.elf".format(h))

        # check if it can be reused
        if (not rescan) and os.path.exists(symboled_vmlinux_file) and os.path.getsize(symboled_vmlinux_file) > 0:
            info("A previously used file found, will be reused")
            return symboled_vmlinux_file

        # resolve text_base, ro_base
        kinfo = Kernel.get_kernel_layout()
        if None in (kinfo.text_base, kinfo.text_size, kinfo.ro_base, kinfo.ro_size):
            err("Failed to resolve")
            return None
        gef_print("kernel base:   {:#x}-{:#x} ({:#x} bytes)".format(kinfo.text_base, kinfo.text_end, kinfo.text_size))
        gef_print("kernel rodata: {:#x}-{:#x} ({:#x} bytes)".format(kinfo.ro_base, kinfo.ro_end, kinfo.ro_size))

        info("Start memory dump")
        # rodata size detection may be inaccurate on kernels with RWX attribute regions.
        # Since they tend to be very large, we put a size cap on the rodata to make it faster.
        if kinfo.rwx:
            # The number 0x400000 has no basis.
            fixed_ro_base_size = min(0x40_0000, kinfo.ro_size)
        else:
            fixed_ro_base_size = kinfo.ro_size

        # delete old file
        if os.path.exists(dumped_mem_file):
            gef_print("Delete old {:s}".format(dumped_mem_file))
            os.unlink(dumped_mem_file)
        if os.path.exists(symboled_vmlinux_file):
            gef_print("Delete old {:s}".format(symboled_vmlinux_file))
            os.unlink(symboled_vmlinux_file)

        # delete files related to old file
        for f in os.listdir(GEF_TEMP_DIR):
            if os.path.basename(dumped_mem_file) in f:
                remove_file = os.path.join(GEF_TEMP_DIR, f)
                gef_print("Delete old {:s}".format(remove_file))
                os.unlink(remove_file)
            if os.path.basename(symboled_vmlinux_file) in f:
                remove_file = os.path.join(GEF_TEMP_DIR, f)
                gef_print("Delete old {:s}".format(remove_file))
                os.unlink(remove_file)

        # dump text
        start = kinfo.text_base
        end = start + kinfo.text_size
        gef_print("Dumping .text area:   {:#x} - {:#x}".format(start, end))
        try:
            gdb.execute("dump memory {} {:#x} {:#x}".format(dumped_mem_file, start, end), to_string=True)
        except gdb.MemoryError:
            err("Memory read error. Make sure the context is in supervisor mode / Ring-0")
            return None

        # dump sparse
        text_end = kinfo.text_end
        unmapped_size = kinfo.ro_base - text_end
        if unmapped_size:
            gef_print("Non-mapping area:     {:#x} - {:#x} (ZERO fill)".format(text_end, kinfo.ro_base))
            open(dumped_mem_file, "a").write("\0" * unmapped_size)

        # dump rodata
        start = kinfo.ro_base
        end = start + fixed_ro_base_size
        gef_print("Dumping .rodata area: {:#x} - {:#x}".format(start, end))
        try:
            gdb.execute("append memory {} {:#x} {:#x}".format(dumped_mem_file, start, end), to_string=True)
        except gdb.MemoryError:
            err("Memory read error. Make sure the context is in supervisor mode / Ring-0")
            return None

        gef_print("Dumped to {:s}".format(dumped_mem_file))

        # apply vmlinux-to-elf
        cmd = "{!r} {!r} {!r} --base-address={:#x}".format(vmlinux2elf, dumped_mem_file, symboled_vmlinux_file, kinfo.text_base)
        warn("Execute `{:s}`".format(cmd))
        os.system(cmd)

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

        text_base = Kernel.get_kernel_base()
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
        cmd = "add-symbol-file {!r} {:#x} -s .kernel {:#x}".format(symboled_vmlinux_file, text_base, text_base)
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
