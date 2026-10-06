"""GEF register access (Layer 1).

`get_register` reads a register through gdb (with fallbacks for qemu-system,
vmware and kgdb targets); `to_unsigned_long` casts a gdb.Value to unsigned long.

References to `process` helpers and to command classes (Phase 2) are
late-imported inside `get_register`, because those modules do not exist yet.
"""
import gdb
import re

from gef.core.address import AddressUtil
from gef.core.memory import u128


def to_unsigned_long(v):
    """Cast a gdb.Value to unsigned long."""
    mask = AddressUtil.get_vmem_end_mask()
    return int(v.cast(gdb.Value(mask).type)) & mask


# Don't use cache.
# This is because there is a command that performs step execution internally.
def get_register(regname, use_mbed_exec=False, use_monitor=False):
    """Return a register's value."""

    from gef.core.process import is_arm32, is_arm64, is_hppa32, is_hppa64, is_kgdb, is_qemu_system, is_vmware, is_x86, is_x86_64

    if regname[0] in ["%", "@"]:
        regname = "$" + regname[1:]

    if regname[0] != "$":
        regname = "$" + regname

    try:
        value = gdb.parse_and_eval(regname)
        if value.type.code == gdb.TYPE_CODE_INT:
            return to_unsigned_long(value)
        elif value.type.name == "vec128":
            if hasattr(value, "bytes"):
                return u128(value.bytes)
            else:
                return eval(str(value["uint128"]))
        else:
            return int(value)
    except gdb.error:
        if (is_hppa32() or is_hppa64()) and regname == "$r0":
            return 0
        try:
            value = gdb.selected_frame().read_register(regname[1:])
            return int(value)
        except (gdb.error, ValueError):
            pass

    if use_mbed_exec and is_qemu_system() and is_arm32():
        # Note that attempting to read a non-existent register will jump to an Undefined exception
        try:
            r = gdb.execute("read-system-register-for-qemu-arm {:s}".format(regname), to_string=True)
            if r:
                return int(r.split("=")[1], 16)
        except gdb.error:
            pass

    if use_monitor and is_qemu_system() and is_x86():
        regname = regname.lstrip("$").upper()
        res = gdb.execute("monitor info registers", to_string=True)
        r = re.search(r"{:s}=(\S+)".format(regname), res)
        if r:
            return int(r.group(1), 16)

    if use_monitor and is_vmware() and is_x86_64():
        regname = regname.lstrip("$")
        res = gdb.execute("monitor r {:s}".format(regname), to_string=True)
        r = re.search(r"{:s}=(\S+)".format(regname), res)
        if r:
            return int(r.group(1), 16)

    if use_mbed_exec and is_kgdb() and (is_x86_64() or is_arm64()):
        from gef.commands.kernel.register import ReadSystemRegisterForKgdbCommand

        if ReadSystemRegisterForKgdbCommand.is_supported_reg(regname):
            try:
                r = gdb.execute("read-system-register-for-kgdb {:s}".format(regname), to_string=True)
                if r:
                    return int(r.split("=")[1], 16)
            except gdb.error:
                pass

    return None

