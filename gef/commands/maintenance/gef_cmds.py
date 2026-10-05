"""GEF maintenance commands (category 99) extracted from the monolithic gef.py.

Auto-discovered by gef.bootstrap via pkgutil.walk_packages.
"""
import argparse
import configparser
import datetime
import hashlib
import os
import re
import subprocess
import sys

import gdb

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    GefAlias,
    only_if_gdb_running,
    only_if_specific_arch,
    parse_args,
    register_command,
)
from gef.core import runtime
from gef.core.address import AddressUtil, Endian
from gef.core.arch_base import Architecture
from gef.core.cache import Cache
from gef.core.color import Color, err, gef_print, info, ok, titlify, warn
from gef.core.config import Config
from gef.core.events import EventHandler, EventHooking
from gef.core.process import (
    Pid,
    get_arch,
    is_64bit,
    is_alive,
    is_arm32,
    is_arm32_cortex_m,
    is_arm64,
    is_attach,
    is_container_attach,
    is_emulated32,
    is_in_kernel,
    is_in_secure,
    is_kdb,
    is_kgdb,
    is_kvm_enabled,
    is_normal_run,
    is_over_serial,
    is_pin,
    is_qiling,
    is_qemu_system,
    is_qemu_user,
    is_remote_debug,
    is_rr,
    is_smp_enabled,
    is_support_secure_world,
    is_vmware,
    is_wine,
    is_x86,
    set_arch,
)
from gef.core.qemu import QemuMonitor, is_supported_physmode
from gef.core.runtime import get_current_arch
from gef.core.strings import String
from gef.core.symbols import ModuleLoader
from gef.core.utils import GEF_FILEPATH, GEF_RC, GEF_TEMP_DIR, GefUtil


@register_command
class GefThemeCommand(GenericCommand, BufferingOutput):
    """Customize GEF appearance."""

    _cmdline_ = "theme"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("key", metavar="KEY", nargs="?", help="color theme key.")
    parser.add_argument("value", metavar="VALUE", nargs="*", help="color theme value.")
    parser.add_argument("-c", "--color-sample", action="store_true", help="print available name of colors.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    _example_ = [
        "{0:s}                         # show all theme settings",
        "{0:s} address_code            # show specified theme setting",
        "{0:s} address_code bold cyan  # set new theme",
    ]
    _example_ = "\n".join(_example_).format(_cmdline_)

    _note_ = [
        'GDB 17 do not allow multiple color specifications (such as "bold red"). This bug had fixed in GDB 18.',
    ]
    _note_ = "\n".join(_note_)

    def __init__(self, *args, **kwargs):
        super().__init__()
        self.add_setting("context_title_line", "cyan", "Color of the borders in context window")
        self.add_setting("context_title_message", "cyan", "Color of the title in context window")
        self.add_setting("default_title_line", "cyan", "Default color of borders")
        self.add_setting("default_title_message", "cyan", "Default color of title")
        self.add_setting("table_heading", "bold blue", "Color of the column headings to tables (e.g., vmmap)")
        self.add_setting("context_code_past", "bright_black", "Color to display past code")
        self.add_setting("context_code_future", "", "Color to display future code")
        self.add_setting("disassemble_address", "", "Color of address when disassembling")
        self.add_setting("disassemble_address_highlight", "bold green", "Color of address when disassembling (=$pc)")
        self.add_setting("disassemble_opcode", "white", "Color of location when disassembling")
        self.add_setting("disassemble_opcode_highlight", "bold white", "Color of location when disassembling (=$pc)")
        self.add_setting("disassemble_mnemonic_normal", "yellow", "Color of normal mnemonic when disassembling")
        self.add_setting("disassemble_mnemonic_normal_highlight", "bold bright_yellow",
                         "Color of normal mnemonic when disassembling (=$pc)")
        self.add_setting("disassemble_mnemonic_branch", "bold bright_yellow", "Color of branch mnemonic when disassembling")
        self.add_setting("disassemble_mnemonic_branch_highlight", "bold bright_yellow",
                         "Color of branch mnemonic when disassembling (=$pc)")
        self.add_setting("disassemble_operands_normal", "cyan", "Color of normal operands when disassembling")
        self.add_setting("disassemble_operands_normal_highlight", "bold cyan",
                         "Color of normal operands when disassembling (=$pc)")
        self.add_setting("disassemble_operands_const", "bright_blue", "Color of const operands when disassembling")
        self.add_setting("disassemble_operands_const_highlight", "bold bright_blue",
                         "Color of const operands when disassembling (=$pc)")
        self.add_setting("disassemble_operands_symbol", "white", "Color of symbol operands when disassembling)")
        self.add_setting("disassemble_operands_symbol_highlight", "bold white",
                         "Color of symbol operands when disassembling (=$pc)")
        self.add_setting("dereference_string", "yellow", "Color of dereferenced string")
        self.add_setting("dereference_base_address", "cyan", "Color of dereferenced address")
        self.add_setting("dereference_register_value", "bold blue", "Color of dereferenced register")
        self.add_setting("registers_register_name", "blue", "Color of the register name in the register window")
        self.add_setting("registers_value_changed", "bold red", "Color of the changed register in the register window")
        self.add_setting("address_stack", "magenta", "Color to use when a stack address is found")
        self.add_setting("address_heap", "bright_blue", "Color to use when a heap address is found")
        self.add_setting("address_code", "red", "Color to use when a code address is found")
        self.add_setting("address_writable", "green", "Color to use when a writable address is found")
        self.add_setting("address_readonly", "white", "Color to use when a read-only address is found")
        self.add_setting("address_rwx", "underline", "Color to use when a RWX address is found")
        self.add_setting("address_valid_but_none", "bright_black", "Color to use when a --- address is found")
        self.add_setting("source_current_line", "bold green", "Color to use for the current code line in the source window")
        self.add_setting("heap_arena_label", "bold cyan underline", "Color of the arena label used heap")
        self.add_setting("heap_chunk_label", "bold cyan underline", "Color of the chunk label used heap")
        self.add_setting("heap_label_active", "bold green underline", "Color of the (active) label used heap")
        self.add_setting("heap_label_inactive", "bold red underline", "Color of the (inactive) label used heap")
        self.add_setting("heap_chunk_address_used", "bright_black", "Color of the chunk address used heap")
        self.add_setting("heap_chunk_address_freed", "bold yellow", "Color of the freed chunk address used heap")
        self.add_setting("heap_chunk_used", "bright_black", "Color of the used chunk used heap")
        self.add_setting("heap_chunk_freed", "yellow", "Color of the freed chunk used heap")
        self.add_setting("heap_chunk_size", "bold magenta", "Color of the size used heap")
        self.add_setting("heap_chunk_flag_prev_inuse", "bold red", "Color of the prev_in_use flag used heap")
        self.add_setting("heap_chunk_flag_non_main_arena", "bold yellow", "Color of the non_main_arena flag used heap")
        self.add_setting("heap_chunk_flag_is_mmapped", "bold blue", "Color of the is_mmapped flag used heap")
        self.add_setting("heap_freelist_hint", "bold blue", "Color of the freelist hint used heap")
        self.add_setting("heap_page_address", "bold", "Color of the page address used heap")
        self.add_setting("heap_management_address", "bright_blue", "Color of the management address used heap")
        self.add_setting("heap_slab_address", "lilac", "Color of the slab management address used heap")
        self.add_setting("heap_corrupted_msg", "bold red", "Color of the corrupted message used heap")
        return

    def show_all_config(self):
        self.out.append(titlify("settings"))

        settings = []
        for x in Config.__gef_config__:
            if x.startswith("theme."):
                settings.append(x.split(".", 1)[1])

        for setting in sorted(settings):
            value = Config.get_gef_setting("theme.{:s}".format(setting))
            if value:
                value = Color.colorify(value, value)
                self.out.append("{:40s}: {:s}".format(setting, value))
            else:
                self.out.append("{:40s}: {:s}".format(setting, "None"))
        return

    def show_color_sample(self):

        def list_all_color_sample(mod):
            i = 0
            line = ""
            for k, v in Color.colors.items():
                if k.endswith("_off") or k == "normal":
                    continue
                line += ("{}{:20s}{}  ".format(mod + v, k, Color.colors["normal"]))

                if k in ["blink", "cyan", "bright_white", "_black"]: # group terminators
                    self.out.append(line)
                    line = ""
                    i = 0
                    continue

                if i % 5 == 4:
                    self.out.append(line)
                    line = ""
                i += 1

        self.out.append(titlify("defined colors"))
        list_all_color_sample("")

        self.out.append(titlify("defined colors (bold)"))
        list_all_color_sample(Color.colors["bold"])

        self.out.append(titlify("defined colors (highlight)"))
        list_all_color_sample(Color.colors["highlight"])
        return

    @parse_args
    def do_invoke(self, args):
        self.out = []

        # show all
        if args.key is None:
            self.show_all_config()
            if args.color_sample:
                self.show_color_sample()
            else:
                self.out.append("* use --color-sample to see available color name")
            self.print_output(check_terminal_size=True)
            return

        # show one
        key = "theme.{:s}".format(args.key)
        if key not in Config.__gef_config__:
            err("Invalid key")
            return
        if args.value == []:
            value = Config.get_gef_setting(key)
            value = Color.colorify(value, value)
            gef_print("{:40s}: {:s}".format(args.key, value))
            return

        # set
        val = [x for x in args.value if x in Color.colors]
        gdb.execute("gef config theme.{:s} {!r}".format(args.key, " ".join(val)))
        return


@register_command
class HistoryCommand(GenericCommand, BufferingOutput):
    """Show gdb command history easily."""

    _cmdline_ = "history"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def get_history(self):
        history = {}
        line_idx = 0
        prev_ret = None
        while True:
            ret = gdb.execute("show commands {:d}".format(line_idx), to_string=True)
            for line in ret.splitlines():
                line_idx = int(line.split()[0])
                if line_idx in history:
                    continue
                history[line_idx] = line

            if prev_ret == ret:
                break
            prev_ret = ret
        return list(history.values())

    @parse_args
    def do_invoke(self, args):
        self.out = self.get_history()
        self.print_output(skip_color=True)
        return


@register_command
class GefCommand(GenericCommand):
    """The base command of GEF maintenance."""

    _cmdline_ = "gef"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    subparsers = parser.add_subparsers(title="command")
    subparsers.add_parser("missing")
    subparsers.add_parser("config")
    subparsers.add_parser("save")
    subparsers.add_parser("restore")
    subparsers.add_parser("reload")
    subparsers.add_parser("reset-breakpoint")
    subparsers.add_parser("reset-cache")
    subparsers.add_parser("arch-list")
    subparsers.add_parser("raise-exception")
    subparsers.add_parser("pyobj-list")
    subparsers.add_parser("avail-comm-list")
    subparsers.add_parser("set-arch")
    subparsers.add_parser("status")
    subparsers.add_parser("version")
    subparsers.add_parser("check-update")
    subparsers.add_parser("tmux-setup")
    subparsers.add_parser("dump-commands")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(prefix=True)
        self.add_setting("follow_child", False, "Automatically set GDB to follow child when forking")
        self.add_setting("disable_color", False, "Disable all colors in GEF")
        self.add_setting("always_no_pager", False, "Always disable pager in gef_print()")
        self.add_setting("pager_min_lines", 11, "Show pager only if output is longer than this value")
        self.add_setting("keep_pager_result", False, "Leaves temporary files in gef_print()")
        self.add_setting("less_option", "-Rf -j.5", "LESS command option used in gef_print()")
        # binutils for cross-arch
        self.add_setting("nm_command", "nm", "nm command (executable name or path)")
        self.add_setting("objcopy_command", "objcopy", "objcopy command (executable name or path)")
        self.add_setting("objdump_command", "objdump", "objdump command (executable name or path)")
        self.add_setting("readelf_command", "readelf", "readelf command (executable name or path)")
        self.add_setting("cppfilt_command", "c++filt", "c++filt command (executable name or path)")
        # workarounds
        self.add_setting("readline_compat", False, "Workaround for readline SOH/ETX issue (SEGV)")
        self.add_setting("read_memory_work_around_for_aarch64_secure_memory", False,
                         "Workaround for AArch64 secure memory read_memory failures")
        self.add_setting("physmap_base_for_read_physmem_kgdb_work_around", 0,
                         "Use this address as physmap_base to read physmem if read_physmem is slow in KGDB")
        # other
        self.add_setting("kgdb_force", False, "Force-enable KGDB mode (for agent-proxy)")
        self.add_setting("kgdb_system_registers", False, "Whether KGDB provides access to system registers")
        return

    @parse_args
    def do_invoke(self, args):
        gdb.execute("gef help") # for frequent use
        return


@register_command
class GefHelpCommand(GenericCommand, BufferingOutput):
    """Display GEF command list."""

    _cmdline_ = "gef help"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def generate_help(self):
        """Generate builtin commands documentation."""
        # get maxlen of cmdline
        maxlen = max(len(x) for x in runtime.CommandRegistry.instances.keys())

        # docs of each command
        docs = []
        for cmdline, instance in runtime.CommandRegistry.instances.items():
            # category
            category = getattr(instance, "_category_", "Uncategorized")

            # document
            doc = getattr(instance.__class__, "__doc__", "").lstrip()
            doc = [Color.greenify(x) for x in doc.splitlines()]
            # Adjust the position assuming there are multiple lines
            doc = ("\n{:<{:d}s}  ".format("", maxlen)).join(doc).rstrip()

            # alias
            if hasattr(instance._aliases_, "__iter__"):
                if not instance._aliases_:
                    aliases = ""
                elif isinstance(instance._aliases_, str):
                    aliases = " (alias: {:s})".format(instance._aliases_)
                else:
                    aliases = " (alias: {:s})".format(", ".join(instance._aliases_))
            else:
                aliases = ""

            msg = "  {:<{:d}s} -- {:s}{:s}".format(cmdline, maxlen, doc, aliases)
            docs.append([category, msg])

        docs = sorted(docs)

        def get_major_category(x):
            if x is None:
                return None
            return x.split(". ")[1].split(" - ")[0]

        # merging
        output = []
        old_category = None
        for category, msg in docs:
            # separator
            draw_separator = False
            if get_major_category(old_category) != get_major_category(category):
                draw_separator = True
            if draw_separator:
                separator = titlify(get_major_category(category))
                output.append(separator)

            # headings
            if old_category != category:
                category_headings = "[{:s}]".format(Color.colorify(category, "bold yellow"))
                output.append(category_headings)

            old_category = category
            output.append(msg)

        return output

    @parse_args
    def do_invoke(self, args):
        self.out = []
        self.out.append(titlify("GEF - GDB Enhanced Features"))
        self.out.extend(self.generate_help())
        self.print_output()
        return


@register_command
class GefConfigCommand(GenericCommand):
    """Display or change GEF configuration."""

    _cmdline_ = "gef config"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("setting_name", metavar="SETTING_NAME", nargs="?", help="setting name.")
    parser.add_argument("setting_value", metavar="SETTING_VALUE", nargs="?", help="setting value.")
    parser.add_argument("-s", "--show-only-changes", action="store_true", help="show only changed settings.")
    _syntax_ = parser.format_help()

    def __init__(self):
        super().__init__(complete="use_user_complete")
        return

    def print_setting(self, config_name, with_description=False, show_only_changes=False):
        """Print a GEF configuration setting, with optional description and original value,
        highlighting changes."""
        res = Config.__gef_config__.get(config_name)
        res_orig = Config.__gef_config_orig__.get(config_name)

        # something is wrong
        if not res or not res_orig:
            return

        string_color = Config.get_gef_setting("theme.dereference_string")
        misc_color = Config.get_gef_setting("theme.dereference_base_address")

        value, type_, desc = res
        value_orig, _, _ = res_orig

        setting = Color.colorify(config_name, "green")
        type_name = type_.__name__
        if type_name == "str":
            value = '"{:s}"'.format(Color.colorify(value, string_color))
            value_orig = '"{:s}"'.format(Color.colorify(value_orig, string_color))
        else:
            value = Color.colorify(value, misc_color)
            value_orig = Color.colorify(value_orig, misc_color)

        if show_only_changes:
            if value != value_orig:
                gef_print("{:s} ({:s}) = {:s}   (orig: {:s})".format(setting, type_name, value, value_orig))
            # do not print the description
            return

        gef_print("{:s} ({:s}) = {:s}".format(setting, type_name, value))
        if with_description:
            if value != value_orig:
                gef_print("")
                gef_print(Color.colorify("Original value:", "bold underline"))
                gef_print("{:s} ({:s}) = {:s}".format(setting, type_name, value_orig))
            gef_print("")
            gef_print(Color.colorify("Description:", "bold underline"))
            gef_print("{:s}".format(desc))
        return

    def set_setting(self, config_name, config_value):
        """Set a GEF configuration value, validating type and command, and updating the cache."""
        if "." not in config_name:
            err("Invalid command format")
            return

        loaded_cmdlines = [x.replace(" ", "_").replace("-", "_") for x in runtime.CommandRegistry.instances.keys()]
        command_name = config_name.split(".", 1)[0]
        if command_name not in loaded_cmdlines:
            err("Unknown command '{:s}'".format(command_name))
            return

        type_ = Config.__gef_config__.get(config_name, [None, None, None])[1]
        if type_ is None:
            err("Failed to get '{:s}' config setting".format(config_name))
            return

        try:
            if type_ is bool:
                if config_value.upper() in ("TRUE", "T", "1"):
                    newval = True
                else:
                    newval = False
            else:
                newval = type_(config_value)
        except Exception:
            err("{} expects type '{}'".format(config_name, type_.__name__))
            return

        Config.__gef_config__[config_name][0] = newval
        Cache.reset_gef_caches(all=True)
        return

    def complete(self, text, word): # noqa
        """Provide tab-completion suggestions for GEF config settings based on user input."""
        settings = sorted(Config.__gef_config__)

        if text.strip() in settings:
            # already matched
            return []

        if text == "":
            # no prefix: example: `gef config TAB`
            return [s for s in settings if ((word is None) or (s and word in s))]

        if "." not in text:
            # if looking for possible prefix
            return [s for s in settings if s.startswith(text.strip())]

        # finally, look for possible values for given prefix
        return [s.split(".", 1)[1] for s in settings if s and s.startswith(text.strip())]

    @parse_args
    def do_invoke(self, args):
        # list all configs
        if (args.setting_name, args.setting_value) == (None, None):
            gef_print(titlify("GEF configuration settings"))
            for name in sorted(Config.__gef_config__):
                self.print_setting(name, show_only_changes=args.show_only_changes)
            return

        # show name-matched config(s)
        if args.setting_name and args.setting_value is None:
            names = [x for x in Config.__gef_config__.keys() if x.startswith(args.setting_name)]
            if not names:
                return
            if len(names) == 1 or (args.setting_name in Config.__gef_config__): # uniquely identified or exact match
                gef_print(titlify("GEF configuration setting: {:s}".format(names[0])))
                self.print_setting(names[0], with_description=True, show_only_changes=args.show_only_changes)
            else:
                gef_print(titlify("GEF configuration settings matching '{:s}'".format(args.setting_name)))
                for name in names:
                    self.print_setting(name, show_only_changes=args.show_only_changes)
            return

        # set config value
        self.set_setting(args.setting_name, args.setting_value)
        return


@register_command
class GefSaveCommand(GenericCommand):
    """Save the current settings to '~/.gef.rc'."""

    _cmdline_ = "gef save"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    @parse_args
    def do_invoke(self, args):
        cfg = configparser.RawConfigParser()
        old_sect = None

        # save the configuration
        for key in sorted(Config.__gef_config__):
            sect, optname = key.split(".", 1)
            value = Config.__gef_config__.get(key, None)
            value = value[0] if value else None

            if old_sect != sect:
                cfg.add_section(sect)
                old_sect = sect

            cfg.set(sect, optname, value)

        # save the aliases
        cfg.add_section("user-defined-aliases")
        cfg.add_section("user-defined-aliases.repeat")
        for alias in runtime.alias_instances.values():
            # check pre-defined alias or not
            if alias._command_ in runtime.CommandRegistry.instances:
                instance = runtime.CommandRegistry.instances[alias._command_]
                if alias._alias_ in instance._aliases_:
                    continue

            cfg.set("user-defined-aliases", alias._alias_, alias._command_)
            cfg.set("user-defined-aliases.repeat", alias._alias_, str(alias._repeat_))

        with open(GEF_RC, "w") as fd:
            cfg.write(fd)

        self.quiet_ok("Configuration saved to '{:s}'".format(GEF_RC))
        return


@register_command
class GefRestoreCommand(GenericCommand):
    """Load settings from '~/.gef.rc'."""

    _cmdline_ = "gef restore"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-q", "--quiet", action="store_true", help="quiet execution.")
    _syntax_ = parser.format_help()

    @parse_args
    def do_invoke(self, args):
        if not os.access(GEF_RC, os.R_OK):
            self.quiet_info("Could not find {:s}, GEF uses default settings".format(GEF_RC))
            return

        cfg = configparser.ConfigParser()
        cfg.read(GEF_RC)

        for section in cfg.sections():
            if section == "user-defined-aliases.repeat":
                continue

            if section == "user-defined-aliases":
                # load the aliases
                for key in cfg.options(section):
                    repeat = cfg.get("user-defined-aliases.repeat", key)
                    GefAlias(key, cfg.get("user-defined-aliases", key), force_repeat=repeat)
                continue

            # load the other options
            for optname in cfg.options(section):
                # warn unused setting
                key = "{:s}.{:s}".format(section, optname)
                if key not in Config.__gef_config__:
                    err("Config '{:s}' is no longer in use, skipping...".format(Color.boldify(key)))
                    continue

                # restore type
                Type = Config.__gef_config__.get(key)[1]
                new_value = cfg.get(section, optname)
                try:
                    if Type is bool:
                        if new_value == "True":
                            new_value = True
                        elif new_value == "False":
                            new_value = False
                        else:
                            raise ValueError
                    else:
                        new_value = Type(new_value)
                except ValueError:
                    err("Config '{:s}' has bad value, skipping...".format(Color.boldify(key)))
                    continue

                # set
                Config.__gef_config__[key][0] = new_value

        # ensure that the temporary directory always exists
        abspath = os.path.expanduser(GEF_TEMP_DIR)
        abspath = os.path.realpath(abspath)
        if not os.path.isdir(abspath):
            os.makedirs(abspath, mode=0o755, exist_ok=True)

        self.quiet_ok("Configuration from '{:s}' restored".format(Color.colorify(GEF_RC, "bold blue")))
        return


@register_command
class GefMissingCommand(GenericCommand):
    """Display the GEF commands that could not be loaded with the reason."""

    _cmdline_ = "gef missing"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    _note_ = [
        "This command only detects commands that could not be loaded when GEF started.",
        "To speed up startup, some commands lazy load required modules and dependencies.",
        "These command cannot be detected.",
    ]
    _note_ = "\n".join(_note_)

    @parse_args
    def do_invoke(self, args):
        missing_commands = runtime.missing_modules.keys()
        if not missing_commands:
            ok("No missing command")
            return
        for missing_command in missing_commands:
            reason = runtime.missing_modules[missing_command]
            warn("Command `{}` is missing, reason  ->  {}".format(missing_command, reason))
        return


@register_command
class GefReloadCommand(GenericCommand):
    """Reload the GEF."""

    _cmdline_ = "gef reload"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    def do_invoke(self, args):
        info("Check syntax {:s}".format(GEF_FILEPATH))

        try:
            pythonbin = GefUtil.which("python3")
        except FileNotFoundError as e:
            err("{}, failed to reload".format(e))
            return

        try:
            subprocess.check_output([pythonbin, GEF_FILEPATH])
        except subprocess.CalledProcessError:
            err("Reload aborted")
            return

        EventHooking.gef_on_continue_unhook(EventHandler.continue_handler)
        EventHooking.gef_on_stop_unhook(EventHandler.hook_stop_handler)
        EventHooking.gef_on_new_unhook(EventHandler.new_objfile_handler)
        EventHooking.gef_on_exit_unhook(EventHandler.exit_handler)
        EventHooking.gef_on_memchanged_unhook(EventHandler.memchanged_handler)
        EventHooking.gef_on_regchanged_unhook(EventHandler.regchanged_handler)
        Cache.reset_gef_caches(all=True)

        info("Reload {:s}".format(GEF_FILEPATH))
        s = gdb.execute("source {:s}".format(GEF_FILEPATH), to_string=True)
        for line in s.splitlines():
            if ".gnu_debugaltlink" in line:
                continue
            if "No debugging symbols" in line:
                continue
            gef_print(line)

        if runtime.current_arch is None:
            set_arch(get_arch())

        if not (is_qemu_user() or is_pin()):
            gdb.execute("define c\ncontinue\nend")

        Cache.reset_gef_caches(all=True)
        return


@register_command
class GefResetCacheCommand(GenericCommand):
    """Reset all caches (both Cache.cache_until_next and Cache.cache_this_session)."""

    _cmdline_ = "gef reset-cache"
    _category_ = "99. GEF Maintenance Command"
    _aliases_ = ["reset-cache"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--hard", action="store_true", help="also delete under {:s}.".format(GEF_TEMP_DIR))
    _syntax_ = parser.format_help()

    @parse_args
    def do_invoke(self, args):
        Cache.reset_gef_caches(all=True)

        if args.hard:
            GefUtil.rmdir(GEF_TEMP_DIR, verbose=True, keep_root=True)
        return


@register_command
class GefResetBreakpointsCommand(GenericCommand):
    """Show and reset all breakpoints (include internal breakpoints)."""

    _cmdline_ = "gef reset-breakpoint"
    _category_ = "99. GEF Maintenance Command"
    _aliases_ = ["reset-breakpoint"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-c", "--commit", action="store_true", help="actually perform delete.")
    _syntax_ = parser.format_help()

    def get_breakpoint(self, b):
        if hasattr(b, "locations"): # gdb 13.1~
            for bl in b.locations:
                if bl and bl.address is not None:
                    return bl.address
        else: # for old gdb
            if b.location and b.location.startswith("*"):
                pos = b.location.lstrip("*")
                try:
                    return int(pos, 16)
                except ValueError:
                    pass
        return None

    @parse_args
    def do_invoke(self, args):
        breakpoints = gdb.breakpoints()
        n = len(breakpoints)

        for bp in breakpoints:
            bp_str = repr(bp)
            bp_addr = self.get_breakpoint(bp)
            if args.commit:
                bp.delete()
                if bp_addr is not None:
                    gef_print("Delete successfully: {:s} (@{:#x})".format(bp_str, bp_addr))
                else:
                    gef_print("Delete successfully: {:s}".format(bp_str))
            else:
                if bp_addr is not None:
                    info("Breakpoint is found: {:s} (@{:#x})".format(bp_str, bp_addr))
                else:
                    info("Breakpoint is found: {:s}".format(bp_str))

        if not args.commit and n > 0:
            warn('This dry run mode skips deleting breakpoint; add "--commit" to proceed')
        return


@register_command
class GefArchListCommand(GenericCommand, BufferingOutput):
    """Display defined architecture information."""

    _cmdline_ = "gef arch-list"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def dump_arch_info(self, arch):
        """Display detailed architecture information, including bit length, endianness,
        registers, and feature support."""
        if arch.arch == "HPPA" and arch.mode == "64":
            # Currently, HPPA-64 is unsupported.
            # A definition for displaying syscalls is provided, but it is provisional.
            return

        # title
        if arch.arch == "ARM":
            arch_name = "ARM (ARM/THUMB)"
        elif arch.arch == arch.mode:
            arch_name = arch.arch
        else:
            arch_name = "{:s} {:s}".format(arch.arch, arch.mode)
        self.out.append(titlify(arch_name))

        # settings
        self.out.append("{:30s}  ->  {!s}".format("bit length", arch.bit_length))
        self.out.append("{:30s}  ->  {!s}".format("endianness", arch.endianness))

        if arch.arch == "ARM":
            inst_len = "ARM:4 / THUMB:2or4"
        elif arch.instruction_length is None:
            inst_len = "variable length"
        else:
            inst_len = str(arch.instruction_length)
        self.out.append("{:30s}  ->  {!s}".format("instruction length", inst_len))

        if arch.return_register is None:
            ret_regs = "different for each system call"
        else:
            ret_regs = str(arch.return_register)
        self.out.append("{:30s}  ->  {!s}".format("return register", ret_regs))

        fparams = ", ".join(arch.function_parameters)
        if len(arch.function_parameters) == 1:
            fparams += " (passing via stack)"
        self.out.append("{:30s}  ->  {!s}".format("function parameters", fparams))

        self.out.append("{:30s}  ->  {!s}".format("syscall register", arch.syscall_register))

        if arch.syscall_parameters is None:
            sparams = "different for each system call"
        else:
            sparams = ", ".join(arch.syscall_parameters)
        self.out.append("{:30s}  ->  {!s}".format("syscall parameters", sparams))

        self.out.append("{:30s}  ->  {!s}".format("Has a call/jump delay slot", arch.has_delay_slot))
        self.out.append("{:30s}  ->  {!s}".format("Has a syscall delay slot", arch.has_syscall_delay_slot))
        self.out.append("{:30s}  ->  {!s}".format("Has a ret delay slot", arch.has_ret_delay_slot))
        self.out.append("{:30s}  ->  {!s}".format("Stack grow down", arch.stack_grow_down))
        self.out.append("{:30s}  ->  {!s}".format("Thread Local Storage support", arch.tls_supported))
        self.out.append("{:30s}  ->  {!s}".format("keystone support", arch.keystone_support))
        self.out.append("{:30s}  ->  {!s}".format("capstone support", arch.capstone_support))
        self.out.append("{:30s}  ->  {!s}".format("unicorn support", arch.unicorn_support))
        return

    def listup_arch_info(self):
        queue = Architecture.__subclasses__()
        while queue:
            cls = queue.pop(0)
            self.dump_arch_info(cls())
            queue = cls.__subclasses__() + queue
        return

    @parse_args
    def do_invoke(self, args):
        self.out = []
        self.listup_arch_info()
        self.print_output()
        return


@register_command
class GefRaiseExceptionCommand(GenericCommand):
    """Raise an exception for development."""

    _cmdline_ = "gef raise-exception"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    def do_invoke(self, args):
        raise RuntimeError("Test exception")


@register_command
class GefPyObjListCommand(GenericCommand, BufferingOutput):
    """Display defined global python object."""

    _cmdline_ = "gef pyobj-list"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def listup_pyobject(self):
        skip_name_list = [
            "__name__",
            "__loader__",
            "__doc__",
            "__spec__",
            "__package__",
            "__annotations__",
            "__warningregistry__",
            "GdbRemoveReadlineFinder",
        ]

        skip_type_list = [
            type(re.compile("")), # regex object
            type(sys), # module
        ]

        function_type = type(lambda x:x)
        class_type = type(GefCommand)

        arch_list = []
        queue = Architecture.__subclasses__()
        while queue:
            cls = queue.pop(0)
            arch_list.append(cls)
            queue = cls.__subclasses__() + queue

        global_configs = []
        classes = []
        command_classes = []
        bp_classes = []
        arch_classes = []
        arch_determinations = []
        gdb_mode_determinations = []
        decorators = []
        syscall_defines = []
        gef_print_wrappers = []
        read_write_mems = []
        others = []

        for gobj in dir(sys.modules["__main__"]): # for global object
            # skip specific
            if gobj in skip_name_list:
                continue

            obj = getattr(sys.modules["__main__"], gobj)
            t = type(obj)

            # skip specific type
            if t in skip_type_list:
                continue

            # classify
            if gobj.startswith("__") and t is not function_type:
                global_configs.append("{!s} {!s}".format(t, gobj))
            elif gobj in ["current_arch"]:
                t = type(get_current_arch())
                global_configs.append("{!s} {!s}".format(t, gobj))
            elif gobj.upper() == gobj and t is not class_type:
                global_configs.append("{!s} {!s}".format(t, gobj))
            elif t is class_type:
                if gobj.endswith("Command"):
                    command_classes.append("{!s} {!s}".format(t, gobj))
                elif gobj.endswith("Breakpoint") or gobj.endswith("Watchpoint"):
                    bp_classes.append("{!s} {!s}".format(t, gobj))
                elif obj in arch_list:
                    arch_classes.append("{!s} {!s}".format(t, gobj))
                else:
                    classes.append("{!s} {!s}".format(t, gobj))
            elif obj.__doc__ and obj.__doc__.startswith("Architecture determination function"):
                arch_determinations.append("{!s} {!s}".format(t, gobj))
            elif obj.__doc__ and obj.__doc__.startswith("GDB mode determination function"):
                gdb_mode_determinations.append("{!s} {!s}".format(t, gobj))
            elif obj.__doc__ and obj.__doc__.startswith("Decorator"):
                decorators.append("{!s} {!s}".format(t, gobj))
            elif gobj.endswith(("syscall_tbl", "syscall_list")) or gobj.startswith("syscall_defs"):
                syscall_defines.append("{!s} {!s}".format(t, gobj))
            elif obj.__doc__ and obj.__doc__.startswith("The wrapper of gef_print"):
                gef_print_wrappers.append("{!s} {!s}".format(t, gobj))
            elif re.match(r"(read|write)_.*(memory|physmem).*", gobj):
                read_write_mems.append("{!s} {!s}".format(t, gobj))
            else:
                others.append("{!s} {!s}".format(t, gobj))

        self.out.append(titlify("GEF global configs"))
        self.out.extend(sorted(global_configs))
        self.out.append(titlify("Command classes"))
        self.out.extend(sorted(command_classes))
        self.out.append(titlify("Breakpoint classes"))
        self.out.extend(sorted(bp_classes))
        self.out.append(titlify("Architecture classes"))
        self.out.extend(sorted(arch_classes))
        self.out.append(titlify("Architecture determination function"))
        self.out.extend(sorted(arch_determinations))
        self.out.append(titlify("GDB mode determination function"))
        self.out.extend(sorted(gdb_mode_determinations))
        self.out.append(titlify("Classes"))
        self.out.extend(sorted(classes))
        self.out.append(titlify("Syscall defines"))
        self.out.extend(sorted(syscall_defines))
        self.out.append(titlify("Decorators"))
        self.out.extend(sorted(decorators))
        self.out.append(titlify("gef_print wrapper"))
        self.out.extend(sorted(gef_print_wrappers))
        self.out.append(titlify("read/write memory functions"))
        self.out.extend(sorted(read_write_mems))
        self.out.append(titlify("Other functions"))
        self.out.extend(sorted(others))
        return

    @parse_args
    def do_invoke(self, args):
        self.out = []
        self.listup_pyobject()
        self.print_output()
        return


@register_command
class GefAvailableCommandListCommand(GenericCommand, BufferingOutput):
    """Display a list of commands available for the current architecture and gdb execution mode."""

    _cmdline_ = "gef avail-comm-list"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-s", "--sort", action="store_true", help="sort by command name.")
    parser.add_argument("-a", "--only-available", action="store_true", help="show only available commands.")
    parser.add_argument("-u", "--only-unavailable", action="store_true", help="show only unavailable commands.")
    parser.add_argument("-n", "--no-pager", action="store_true", help="do not use the pager.")
    _syntax_ = parser.format_help()

    def check_require_arch_set(self, decorators):
        for line in decorators:
            if "@require_arch_set" in line:
                return runtime.current_arch is None
        return False

    def check_include_mode(self, decorators):
        for line in decorators:
            if "@only_if_specific_gdb_mode" in line:
                if is_pin():
                    return '"pin"' in line
                if is_qemu_system():
                    return '"qemu-system"' in line
                if is_qemu_user():
                    return '"qemu-user"' in line
                if is_vmware():
                    return '"vmware"' in line
                if is_qiling():
                    return '"qiling"' in line
                if is_rr():
                    return '"rr"' in line
                if is_wine():
                    return '"wine"' in line
                if is_kgdb():
                    return '"kgdb"' in line
                return False
        return True

    def check_exclude_mode(self, decorators):
        for line in decorators:
            if "@exclude_specific_gdb_mode" in line:
                if is_pin():
                    return '"pin"' in line
                if is_qemu_system():
                    return '"qemu-system"' in line
                if is_qemu_user():
                    return '"qemu-user"' in line
                if is_vmware():
                    return '"vmware"' in line
                if is_qiling():
                    return '"qiling"' in line
                if is_rr():
                    return '"rr"' in line
                if is_wine():
                    return '"wine"' in line
                if is_kgdb():
                    return '"kgdb"' in line
                return False
        return False

    def get_arch_name(self):
        s = GefUtil.get_source(only_if_specific_arch).replace("\n", "")
        r = re.search(r"dic = (\{.*\})", s)
        dic = eval(r.group(1))

        for arch, func in dic.items():
            if func():
                return '"{:s}"'.format(arch)
        return None

    def check_include_arch(self, decorators, arch_name):
        for line in decorators:
            if "@only_if_specific_arch" in line:
                return str(arch_name) in line
        return True

    def check_exclude_arch(self, decorators, arch_name):
        for line in decorators:
            if "@exclude_specific_arch" in line:
                return str(arch_name) in line
        return False

    def check_load_package(self, decorators, dec_name, import_name):
        for line in decorators:
            if dec_name in line:
                try:
                    readline = sys.modules.get("readline", None)
                    sys.modules["readline"] = None
                    __import__(import_name)
                    sys.modules["readline"] = readline
                except ImportError:
                    return False
                return True
        return True

    def add_out(self, cmdline, avail, msg=""):
        if self.args.only_available and not avail:
            return
        if self.args.only_unavailable and avail:
            return
        if avail:
            self.out.append("{:<34s}: {:s}".format(
                cmdline, Color.colorify("Available", "bold green"),
            ))
        else:
            self.out.append("{:<34s}: {:s} ({:s})".format(
                cmdline, Color.colorify("Unavailable", "bold red"), msg,
            ))
        return

    def listup_avail_comms(self):
        arch_name = self.get_arch_name()
        for cmdline, instance in runtime.CommandRegistry.instances.items():
            s = GefUtil.get_source(instance.do_invoke)
            decorators = [line for line in s.splitlines() if line.lstrip().startswith("@")]
            if self.check_require_arch_set(decorators):
                self.add_out(cmdline, False, "current_arch is None")
                continue
            if not self.check_include_arch(decorators, arch_name):
                self.add_out(cmdline, False, "Unsupported arch")
                continue
            if self.check_exclude_arch(decorators, arch_name):
                self.add_out(cmdline, False, "Unsupported arch")
                continue
            if not self.check_include_mode(decorators):
                self.add_out(cmdline, False, "Unsupported gdb mode")
                continue
            if self.check_exclude_mode(decorators):
                self.add_out(cmdline, False, "Unsupported gdb mode")
                continue
            if not self.check_load_package(decorators, "@ModuleLoader.load_capstone", "capstone"):
                self.add_out(cmdline, False, "capstone package is unavailable")
                continue
            if not self.check_load_package(decorators, "@ModuleLoader.load_unicorn", "unicorn"):
                self.add_out(cmdline, False, "unicorn package is unavailable")
                continue
            if not self.check_load_package(decorators, "@ModuleLoader.load_keystone", "keystone"):
                self.add_out(cmdline, False, "keystone-engine package is unavailable")
                continue
            if not self.check_load_package(decorators, "@ModuleLoader.load_ropper", "ropper"):
                self.add_out(cmdline, False, "ropper package is unavailable")
                continue
            if not self.check_load_package(decorators, "@ModuleLoader.load_binwalk", "binwalk"):
                self.add_out(cmdline, False, "binwalk package is unavailable")
                continue
            if not self.check_load_package(decorators, "@ModuleLoader.load_crccheck", "crccheck"):
                self.add_out(cmdline, False, "crccheck package is unavailable")
                continue
            if not self.check_load_package(decorators, "@ModuleLoader.load_codext", "codext"):
                self.add_out(cmdline, False, "codext package is unavailable")
                continue
            if not self.check_load_package(decorators, "@ModuleLoader.load_angr", "angr"):
                self.add_out(cmdline, False, "angr package is unavailable")
                continue
            self.add_out(cmdline, True)
        return

    @parse_args
    @only_if_gdb_running
    def do_invoke(self, args):
        self.out = []
        self.listup_avail_comms()
        if args.sort:
            self.out = sorted(self.out)
        self.print_output(check_terminal_size=True)
        return


@register_command
class GefDumpCommandsCommand(GenericCommand):
    """Dump GEF command documentation as Markdown."""

    _cmdline_ = "gef dump-commands"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("output", metavar="OUTPUT", nargs="?", default="COMMANDS.md",
                        help="output file path. (default: %(default)s)")
    _syntax_ = parser.format_help()

    def normalize_text(self, value):
        """Normalize a value for Markdown output."""
        if value is None:
            return ""

        text = str(value).strip()
        return text

    def make_code_block(self, value, lang="text"):
        """Render a fenced Markdown code block."""
        text = self.normalize_text(value)
        if not text:
            return ""

        fence = "```"
        while fence in text:
            fence += "`"

        return "{:s}{:s}\n{:s}\n{:s}".format(fence, lang, text, fence)

    def make_inline_code(self, value):
        """Render inline Markdown code."""
        text = self.normalize_text(value)
        if not text:
            return ""

        return "`{:s}`".format(text.replace("`", "\\`"))

    def get_aliases(self, instance):
        """Return aliases as a normalized list."""
        aliases = getattr(instance, "_aliases_", [])

        if aliases is None:
            return []

        if isinstance(aliases, str):
            if aliases:
                return [aliases]
            return []

        if hasattr(aliases, "__iter__"):
            return [str(alias) for alias in aliases]

        return [str(aliases)]

    def get_summary(self, instance):
        summary = getattr(instance.__class__, "__doc__", "")
        return self.normalize_text(summary)

    def syntax_for_dump(self, instance):
        """Render the command syntax with an effectively infinite width."""
        parser = getattr(instance, "parser", None)
        if parser is None:
            return getattr(instance, "_syntax_", None)

        old_formatter = parser.formatter_class
        parser.formatter_class = lambda prog: argparse.HelpFormatter(prog, width=10**7)
        try:
            return parser.format_help()
        finally:
            parser.formatter_class = old_formatter

    def render_command(self, command_name, instance):
        """Render a single command as Markdown."""
        syntax = self.syntax_for_dump(instance)
        example = getattr(instance, "_example_", None)
        note = getattr(instance, "_note_", None)
        aliases = self.get_aliases(instance)
        summary = self.get_summary(instance)

        lines = []
        lines.append("## {:s}".format(command_name))
        lines.append("")

        if summary:
            lines.append(summary)
            lines.append("")

        if aliases:
            rendered_aliases = ", ".join(self.make_inline_code(alias) for alias in aliases)
            lines.append("- Alias: {:s}".format(rendered_aliases))

        lines.append("")

        if syntax:
            lines.append("### Syntax")
            lines.append("")
            lines.append(self.make_code_block(syntax, "text"))
            lines.append("")

        if example:
            lines.append("### Examples")
            lines.append("")
            lines.append(self.make_code_block(example, "gdb"))
            lines.append("")

        if note:
            lines.append("### Notes")
            lines.append("")
            lines.append(self.make_code_block(note, "text"))
            lines.append("")

        return "\n".join(lines).rstrip()

    def render_commands(self):
        """Render all registered GEF commands as Markdown."""
        lines = []
        lines.append("# GEF Commands")
        lines.append("")

        commands = []
        categories = set()
        for command_name, instance in runtime.CommandRegistry.instances.items():
            if not getattr(instance, "_cmdline_", None):
                continue
            category = instance._category_
            categories.add(category)
            commands.append((category, command_name, instance))
        commands = sorted(commands, key=lambda item: (item[0], item[1]))

        lines.append("## Table of contents")
        lines.append("")
        for cat_orig in sorted(categories):
            cat = cat_orig[::]
            cat = cat.replace(" ", "-")
            cat = cat.replace("/", "")
            cat = cat.replace(".", "")
            cat = cat.lower()
            lines.append("- [{:s}](#{:s})".format(cat_orig, cat))
        lines.append("")

        prev_category = None
        for category, command_name, instance in commands:
            if category != prev_category:
                lines.append("# {:s}".format(category))
                prev_category = category
            lines.append(self.render_command(command_name, instance))
            lines.append("")

        return "\n".join(lines).rstrip() + "\n"

    @parse_args
    def do_invoke(self, args):
        output = self.render_commands()
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(output)
        return


@register_command
class GefSetArchCommand(GenericCommand):
    """Set a specific architecture to gef."""

    _cmdline_ = "gef set-arch"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("arch", metavar="ARCH", nargs="?", help="target architecture.")
    group.add_argument("-l", "--list", action="store_true", help="show supported architecture words.")
    _syntax_ = parser.format_help()

    def arch_listup(self):
        fmt = "{:12s} {:s}"
        legend = ["Arch", "Available names (Case insensitive)"]
        gef_print(GefUtil.make_legend(fmt.format(*legend)))

        queue = Architecture.__subclasses__()
        while queue:
            cls = queue.pop(0)
            queue = cls.__subclasses__() + queue

            arch = Color.boldify("{:12s}".format(cls.__name__))
            words = ", ".join(filter(lambda x: isinstance(x, str), cls.load_condition))
            gef_print("{:s} {:s}".format(arch, words))
        return

    @parse_args
    def do_invoke(self, args):
        if args.list:
            self.arch_listup()
            return

        try:
            set_arch(args.arch)
            info("set_arch({:s}) is successfully".format(args.arch))
            Cache.reset_gef_caches(all=True)
        except OSError:
            err("set_arch({:s}) is failed".format(args.arch))
        return


@register_command
class GefStatusCommand(GenericCommand):
    """Display current gef status."""

    _cmdline_ = "gef status"
    _category_ = "99. GEF Maintenance Command"
    _aliases_ = ["arch-info"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    def do_invoke(self, args):
        gef_print(titlify("GDB/ELF settings"))
        show_arch = gdb.execute("show architecture", to_string=True).rstrip()
        gef_print("{:30s}  ->  {:s}".format("show architecture", show_arch))
        if is_64bit():
            bit_str = "64-bit"
        else:
            bit_str = "32-bit"
        if Endian.is_big_endian():
            endian_str = "big"
        else:
            endian_str = "little"
        gef_print("{:30s}  ->  {:s}".format("bit", bit_str))
        gef_print("{:30s}  ->  {:s}".format("endian", endian_str))

        gef_print(titlify("GDB mode"))
        gef_print("{:30s}  ->  {!s}".format("is_normal_run()", is_normal_run()))
        gef_print("{:30s}  ->  {!s}".format("is_attach()", is_attach()))
        gef_print("{:30s}  ->  {!s}".format("is_remote_debug()", is_remote_debug()))
        gef_print("{:30s}  ->  {!s}".format("is_container_attach()", is_container_attach()))
        gef_print("{:30s}  ->  {!s}".format("is_qemu_system()", is_qemu_system()))
        gef_print("{:30s}  ->  {!s}".format("is_qemu_user()", is_qemu_user()))
        gef_print("{:30s}  ->  {!s}".format("is_pin()", is_pin()))
        gef_print("{:30s}  ->  {!s}".format("is_over_serial()", is_over_serial()))
        kgdb_forced = " (forced)" if Config.get_gef_setting("gef.kgdb_force") is True else ""
        gef_print("{:30s}  ->  {!s}{:s}".format("is_kgdb()", is_kgdb(), kgdb_forced))
        gef_print("{:30s}  ->  {!s}".format("is_kdb()", is_kdb()))
        gef_print("{:30s}  ->  {!s}".format("is_qiling()", is_qiling()))
        gef_print("{:30s}  ->  {!s}".format("is_vmware()", is_vmware()))
        gef_print("{:30s}  ->  {!s}".format("is_in_kernel()", is_in_kernel()))
        gef_print("{:30s}  ->  {!s}".format("is_in_secure()", is_in_secure()))
        gef_print("{:30s}  ->  {!s}".format("is_rr()", is_rr()))
        gef_print("{:30s}  ->  {!s}".format("is_wine()", is_wine()))

        gef_print(titlify("Others"))
        gef_print("{:30s}  ->  {!s}".format("is_alive()", is_alive()))
        gef_print("{:30s}  ->  {!s}".format("is_kvm_enabled()", is_kvm_enabled()))
        gef_print("{:30s}  ->  {!s}".format("is_smp_enabled()", is_smp_enabled()))
        gef_print("{:30s}  ->  {!s}".format("is_support_secure_world()", is_support_secure_world()))
        gef_print("{:30s}  ->  {!s}".format("is_supported_physmode()", is_supported_physmode()))
        if is_supported_physmode():
            gef_print("{:30s}  ->  {!s}".format("get_current_mmu_mode()", QemuMonitor.get_current_mmu_mode()))

        gef_print(titlify("GEF architecture information"))
        if runtime.current_arch is None:
            gef_print("{:30s}  ->  None".format("current_arch"))
            gef_print("{:30s}  ->  {!s}".format("ptrsize", AddressUtil.ptr_width()))
            return
        gef_print("{:30s}  ->  {!s}".format("current_arch.arch", runtime.current_arch.arch))
        gef_print("{:30s}  ->  {!s}".format("current_arch.mode", runtime.current_arch.mode))
        if is_arm32() or is_arm32_cortex_m():
            gef_print("{:30s}  ->  {!s}".format("current_arch.is_cortex_m()", runtime.current_arch.is_cortex_m()))
        gef_print("{:30s}  ->  {!s}".format("current_arch.ptrsize", runtime.current_arch.ptrsize))

        if runtime.current_arch.instruction_length is None:
            inst_len = "variable length"
        else:
            inst_len = str(runtime.current_arch.instruction_length)
        gef_print("{:30s}  ->  {!s}".format("instruction length", inst_len))

        if runtime.current_arch.return_register is None:
            ret_regs = "different for each system call"
        else:
            ret_regs = str(runtime.current_arch.return_register)
        gef_print("{:30s}  ->  {!s}".format("return register", ret_regs))

        fparams = ", ".join(runtime.current_arch.function_parameters)
        if len(runtime.current_arch.function_parameters) == 1:
            fparams += " (passing via stack)"
        gef_print("{:30s}  ->  {!s}".format("function parameters", fparams))

        gef_print("{:30s}  ->  {!s}".format("syscall register", runtime.current_arch.syscall_register))

        if runtime.current_arch.syscall_parameters is None:
            sparams = "different for each system call"
        else:
            sparams = ", ".join(runtime.current_arch.syscall_parameters)
        gef_print("{:30s}  ->  {!s}".format("syscall parameters", sparams))

        if is_x86() or is_arm32() or is_arm64():
            gef_print("{:30s}  ->  {!s}".format("32bit-emulated (compat mode)", is_emulated32()))
        gef_print("{:30s}  ->  {!s}".format("Has a call/jump delay slot", runtime.current_arch.has_delay_slot))
        gef_print("{:30s}  ->  {!s}".format("Has a syscall delay slot", runtime.current_arch.has_syscall_delay_slot))
        gef_print("{:30s}  ->  {!s}".format("Has a ret delay slot", runtime.current_arch.has_ret_delay_slot))
        gef_print("{:30s}  ->  {!s}".format("Stack grow down", runtime.current_arch.stack_grow_down))
        gef_print("{:30s}  ->  {!s}".format("Thread Local Storage support", runtime.current_arch.tls_supported))
        gef_print("{:30s}  ->  {!s}".format("keystone support", runtime.current_arch.keystone_support))
        gef_print("{:30s}  ->  {!s}".format("capstone support", runtime.current_arch.capstone_support))
        gef_print("{:30s}  ->  {!s}".format("unicorn support", runtime.current_arch.unicorn_support))
        return


@register_command
class GefVersionCommand(GenericCommand):
    """Display GEF version info."""

    _cmdline_ = "gef version"
    _category_ = "99. GEF Maintenance Command"
    _aliases_ = ["version"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("--compact", action="store_true", help="show compact style.")
    _syntax_ = parser.format_help()

    def os_version(self):
        try:
            lsb_release_command = GefUtil.which("lsb_release")
            res = GefUtil.gef_execute_external([lsb_release_command, "-d"], as_list=True)
            for line in res:
                if line.startswith("Description:"):
                    return line.split(":")[1].strip()
        except FileNotFoundError:
            pass

        if os.path.exists("/etc/issue.net"):
            content = open("/etc/issue.net").read().strip()
            if content:
                return content

        if os.path.exists("/etc/issue"):
            content = open("/etc/issue").read().strip()
            content = content.replace(" \\n \\l", "")
            if content:
                return content

        if os.path.exists("/etc/os-release"):
            content = open("/etc/os-release").read()
            for line in content.splitlines():
                r = re.search(r'PRETTY_NAME="(.+)"', line)
                if r:
                    return r.group(1)

        return "Not found"

    def kernel_version_from_uname(self):
        try:
            uname_command = GefUtil.which("uname")
            res = GefUtil.gef_execute_external([uname_command, "-a"], as_list=True)
            return res[0]
        except FileNotFoundError:
            return "Not found"

    def kernel_version_from_proc(self):
        try:
            return open("/proc/version").read().strip()
        except FileNotFoundError:
            return "Not found"

    def system_libc_version(self):
        res = GefUtil.gef_execute_external(["cat", "/proc/self/maps"], as_list=True)
        libc_targets = ("libc-2.", "libc.so.6", "libuClibc-")
        for line in res:
            if not any(kw in line for kw in libc_targets):
                continue
            path = line.split()[-1]
            if not os.path.exists(path):
                continue
            data = open(path, "rb").read()
            pos = re.search(b"(GNU C Library|uClibc-ng release) [\x20-\x7e]*", data)
            if pos:
                return String.bytes2str(pos.group(0))
        return "Not found"

    def qemu_system_version(self):
        return gdb.execute("monitor info version", to_string=True).strip()

    def qemu_user_version(self):
        pid = Pid.get_pid()
        try:
            res = GefUtil.gef_execute_external(["/proc/{:d}/exe".format(pid), "--version"], as_list=True)
            return res[0].strip()
        except (IndexError, FileNotFoundError):
            return "Not recognized"

    def gef_version(self):
        gef_hash = hashlib.sha1(open(GEF_FILEPATH, "rb").read()).hexdigest()
        dt = datetime.datetime.fromtimestamp(os.stat(GEF_FILEPATH).st_mtime)
        return "Last modified: {} SHA1: {}".format(dt.strftime("%Y-%m-%d %H:%M:%S"), gef_hash)

    def gdb_version(self):
        try:
            return gdb.VERSION # GDB >= 8.1 (or earlier?)
        except AttributeError:
            return gdb.execute("show version", to_string=True).split("\n")[0]

    def python_version(self):
        return sys.version.replace("\n", " ")

    def capstone_version(self):

        @ModuleLoader.load_capstone
        def _capstone_version():
            capstone = sys.modules["capstone"]
            return ".".join(map(str, capstone.cs_version()))

        try:
            return _capstone_version()
        except (KeyError, ImportWarning):
            return "Not found"

    def keystone_version(self):

        @ModuleLoader.load_keystone
        def _keystone_version():
            keystone = sys.modules["keystone"]
            return ".".join(map(str, keystone.ks_version()))

        try:
            return _keystone_version()
        except (KeyError, ImportWarning):
            return "Not found"

    def unicorn_version(self):

        @ModuleLoader.load_unicorn
        def _unicorn_version():
            unicorn = sys.modules["unicorn"]
            return unicorn.__version__

        try:
            return _unicorn_version()
        except (KeyError, ImportWarning):
            return "Not found"

    def ropper_version(self):

        @ModuleLoader.load_ropper
        def _ropper_version():
            ropper = sys.modules["ropper"]
            return ".".join(map(str, ropper.VERSION))

        try:
            return _ropper_version()
        except (KeyError, ImportWarning, AttributeError):
            return "Not found"

    def angr_version(self):

        @ModuleLoader.load_angr
        def _angr_version():
            angr = sys.modules["angr"]
            return angr.__version__

        try:
            return _angr_version()
        except (KeyError, ImportWarning, AttributeError):
            return "Not found"

    def gcc_version(self):
        try:
            gcc_command = GefUtil.which("gcc")
        except FileNotFoundError:
            return "Not found"
        res = GefUtil.gef_execute_external([gcc_command, "--version"], as_list=True)
        return res[0]

    def readelf_version(self):
        try:
            readelf_command = GefUtil.which(Config.get_gef_setting("gef.readelf_command"))
        except FileNotFoundError:
            return "Not found"
        res = GefUtil.gef_execute_external([readelf_command, "-v"], as_list=True)
        return res[0]

    def objdump_version(self):
        try:
            objdump_command = GefUtil.which(Config.get_gef_setting("gef.objdump_command"))
        except FileNotFoundError:
            return "Not found"
        res = GefUtil.gef_execute_external([objdump_command, "-v"], as_list=True)
        return res[0]

    def seccomp_tools_version(self):
        try:
            seccomp_tools_command = GefUtil.which("seccomp-tools")
        except FileNotFoundError:
            return "Not found"
        res = GefUtil.gef_execute_external([seccomp_tools_command, "--version"], as_list=True)
        return res[0]

    def ceccomp_version(self):
        try:
            ceccomp_command = GefUtil.which("ceccomp")
        except FileNotFoundError:
            return "Not found"
        res = GefUtil.gef_execute_external([ceccomp_command, "version"], as_list=True)
        return res[0]

    def one_gadget_version(self):
        try:
            one_gadget_command = GefUtil.which("one_gadget")
        except FileNotFoundError:
            return "Not found"
        res = GefUtil.gef_execute_external([one_gadget_command, "--version"], as_list=True)
        return res[0]

    def rp_version(self):
        try:
            rp_lin_command = GefUtil.which("rp-lin")
        except FileNotFoundError:
            return "Not found"
        res = GefUtil.gef_execute_external([rp_lin_command, "--version", "--file", "a"], as_list=True)
        if "You are currently using " in res[0]:
            return res[0].replace("You are currently using ", "")
        return "Not found"

    def show_compact_info(self):
        gef_print("gdb:     {:s}".format(self.gdb_version()))
        gef_print("python:  {:s}".format(self.python_version()))
        gef_print("OS:      {:s}".format(self.os_version()))
        gef_print("kernel:  {:s}".format(self.kernel_version_from_uname()))
        if is_qemu_system():
            gef_print("qemu:    {:s}".format(self.qemu_system_version()))
        return

    def show_full_info(self):
        gef_print(titlify("versions"))
        gef_print("OS:                     {:s}".format(self.os_version()))
        gef_print("kernel (uname -a):      {:s}".format(self.kernel_version_from_uname()))
        gef_print("kernel (/proc/version): {:s}".format(self.kernel_version_from_proc()))
        gef_print("System libc:            {:s}".format(self.system_libc_version()))
        if is_qemu_system():
            gef_print("qemu:                   {:s}".format(self.qemu_system_version()))
        if is_qemu_user():
            gef_print("qemu:                   {:s}".format(self.qemu_user_version()))
        gef_print("GEF:                    {:s}".format(self.gef_version()))
        gef_print("gdb:                    {:s}".format(self.gdb_version()))
        gef_print("python:                 {:s}".format(self.python_version()))
        gef_print("capstone:               {:s}".format(self.capstone_version()))
        gef_print("keystone:               {:s}".format(self.keystone_version()))
        gef_print("unicorn:                {:s}".format(self.unicorn_version()))
        gef_print("ropper:                 {:s}".format(self.ropper_version()))
        gef_print("angr:                   {:s}".format(self.angr_version()))
        gef_print("gcc:                    {:s}".format(self.gcc_version()))
        gef_print("readelf:                {:s}".format(self.readelf_version()))
        gef_print("objdump:                {:s}".format(self.objdump_version()))
        gef_print("seccomp-tools:          {:s}".format(self.seccomp_tools_version()))
        gef_print("ceccomp:                {:s}".format(self.ceccomp_version()))
        gef_print("one_gadget:             {:s}".format(self.one_gadget_version()))
        gef_print("rp:                     {:s}".format(self.rp_version()))

        gef_print(titlify("gdb build config"))
        gdb.execute("show configuration")
        return

    @parse_args
    def do_invoke(self, args):
        if args.compact:
            self.show_compact_info()
        else:
            self.show_full_info()
        return


@register_command
class GefCheckUpdateCommand(GenericCommand):
    """Check for gef updates."""

    _cmdline_ = "gef check-update"
    _category_ = "99. GEF Maintenance Command"

    parser = argparse.ArgumentParser(prog=_cmdline_)
    _syntax_ = parser.format_help()

    @parse_args
    def do_invoke(self, args):
        from gef.core.update import check_update
        status = check_update()
        if status == "no-update":
            info("No update")
        elif status == "update":
            info("Update found, try `python3 {:s} --upgrade`".format(GEF_FILEPATH))
        elif status == "unknown":
            info("[-] No recorded install hash; cannot compare (run --upgrade to establish one)")
        else:
            err("[-] Failed to get remote gef information")
        return


@register_command
class GefTmuxSetupCommand(GenericCommand):
    """Setup a comfortable tmux environment."""

    _cmdline_ = "gef tmux-setup"
    _category_ = "99. GEF Maintenance Command"
    _aliases_ = ["tmux-setup"]

    parser = argparse.ArgumentParser(prog=_cmdline_)
    parser.add_argument("-r", "--reset", action="store_true", help="reset all panes.")
    _syntax_ = parser.format_help()

    _note_ = [
        "- `screen` is no longer supported.",
        "",
        "- `tmux` settings are predefined and cannot be customized in this command.",
        "- If you want to customize it, edit `tmux_setup.py` and run `source /path/to/tmux_setup.py`.",
        "- It can be found in https://github.com/bata24/gef/blob/dev/dev/tmux/tmux_setup.py.",
        "",
        "- There is experimental support for `zellij` using a similar script.",
        "- Try starting `zellij-wrapper.py` in your shell (before starting `zellij` and `gdb`).",
        "- It can be found in https://github.com/bata24/gef/blob/dev/dev/zellij/zellij-wrapper.py.",
    ]
    _note_ = "\n".join(_note_)

    @staticmethod
    def get_redirect_configs():
        configs = [
            "context.redirect",
            "context_args.redirect",
            "context_code.redirect",
            "context_extra.redirect",
            "context_legend.redirect",
            "context_mem_access.redirect",
            "context_mem_watch.redirect",
            "context_regs.redirect",
            "context_source.redirect",
            "context_stack.redirect",
            "context_threads.redirect",
            "context_trace.redirect",
        ]
        return configs

    @staticmethod
    def get_tty_gef_used():
        """Return a set of TTYs currently used by GEF for tmux redirection."""
        tty_gef_used = [Config.get_gef_setting(c) for c in GefTmuxSetupCommand.get_redirect_configs()]
        tty_gef_used = [x for x in tty_gef_used if x] # filter ""
        return set(tty_gef_used)

    @staticmethod
    def reset_panes():
        """Reset tmux panes used by GEF, killing relevant panes and clearing related configurations."""
        # list panes
        tmux = GefUtil.which("tmux")
        res = subprocess.check_output([
            tmux, "list-panes", "-F#{pane_active}:#{pane_id}:#{pane_tty}"
        ]).decode("utf-8").strip()

        # kill panes
        tty_gef_used = GefTmuxSetupCommand.get_tty_gef_used()
        for line in res.splitlines():
            pane_active, pane_id, pane_tty = line.split(":")
            if pane_active == "1":
                continue
            if pane_tty not in tty_gef_used:
                continue
            subprocess.run([tmux, "kill-pane", "-t", pane_id])

        # reset config
        for config in GefTmuxSetupCommand.get_redirect_configs():
            gdb.execute('gef config {:s} ""'.format(config))

        # remove destructor
        import atexit
        try:
            atexit.unregister(GefTmuxSetupCommand.reset_panes)
        except Exception:
            pass
        return

    def tmux_setup(self):
        """Prepare the tmux environment by vertically splitting and redirect context output."""
        # reset previous settings
        tmux = GefUtil.which("tmux")
        if self.get_tty_gef_used():
            warn("Since it is already split, discard previous screen")
            GefTmuxSetupCommand.reset_panes()

        # split
        ok("tmux session found, splitting window...")
        pane_id, pane_tty = subprocess.check_output([
            tmux, "splitw", "-h", "-F#{pane_id}:#{pane_tty}", "-P",
        ]).decode("utf-8").strip().split(":")

        # add destructor
        import atexit
        atexit.register(GefTmuxSetupCommand.reset_panes)

        # clear the screen and let it wait for input forever
        gdb.execute(f"!'{tmux}' send-keys -t {pane_id} 'clear ; cat' C-m")
        gdb.execute(f"!'{tmux}' select-pane -L")

        ok(f"Setting `context.redirect` to '{pane_tty}'...")
        gdb.execute(f"gef config context.redirect {pane_tty}")

        Cache.reset_gef_caches(all=True)
        return

    @parse_args
    def do_invoke(self, args):
        try:
            GefUtil.which("tmux")
        except FileNotFoundError as e:
            err("{}".format(e))
            return

        if args.reset:
            GefTmuxSetupCommand.reset_panes()
            return

        if os.getenv("TMUX"):
            self.tmux_setup()
            return

        warn("Not in a tmux session")
        return


