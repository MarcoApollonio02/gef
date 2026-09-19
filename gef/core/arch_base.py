"""Abstract base class for all architectures supported by GEF."""

import abc

import gdb

from gef.core import runtime
from gef.core.address import AddressUtil
from gef.core.color import Color
from gef.core.registers import get_register


class Architecture:
    """Generic metaclass for the architecture supported by GEF."""

    __metaclass__ = abc.ABCMeta

    # base properties

    @property
    @abc.abstractmethod
    def arch(self):
        pass

    @property
    @abc.abstractmethod
    def mode(self):
        pass

    @property
    @abc.abstractmethod
    def load_condition(self):
        pass

    # register properties

    @property
    @abc.abstractmethod
    def all_registers(self):
        pass

    @property
    @abc.abstractmethod
    def alias_registers(self):
        pass

    @property
    @abc.abstractmethod
    def special_registers(self):
        pass

    @property
    @abc.abstractmethod
    def flag_register(self):
        pass

    @property
    @abc.abstractmethod
    def flags_table(self):
        pass

    @property
    @abc.abstractmethod
    def return_register(self):
        pass

    @property
    @abc.abstractmethod
    def function_parameters(self):
        pass

    @property
    @abc.abstractmethod
    def syscall_register(self):
        pass

    @property
    @abc.abstractmethod
    def syscall_parameters(self):
        pass

    # architecture properties

    @property
    @abc.abstractmethod
    def bit_length(self):
        pass

    @property
    @abc.abstractmethod
    def endianness(self):
        pass

    @property
    @abc.abstractmethod
    def instruction_length(self):
        pass

    @property
    @abc.abstractmethod
    def has_delay_slot(self):
        pass

    @property
    @abc.abstractmethod
    def has_syscall_delay_slot(self):
        pass

    @property
    @abc.abstractmethod
    def has_ret_delay_slot(self):
        pass

    @property
    @abc.abstractmethod
    def stack_grow_down(self):
        pass

    @property
    @abc.abstractmethod
    def tls_supported(self):
        pass

    # module properties

    @property
    @abc.abstractmethod
    def keystone_support(self):
        pass

    @property
    @abc.abstractmethod
    def capstone_support(self):
        pass

    @property
    @abc.abstractmethod
    def unicorn_support(self):
        pass

    # instruction properties

    @property
    @abc.abstractmethod
    def nop_insn(self):
        pass

    @property
    @abc.abstractmethod
    def infloop_insn(self):
        pass

    @property
    @abc.abstractmethod
    def trap_insn(self):
        pass

    @property
    @abc.abstractmethod
    def ret_insn(self):
        pass

    @property
    @abc.abstractmethod
    def syscall_insn(self):
        pass

    # instruction methods

    @abc.abstractmethod
    def is_syscall(self, insn):
        pass

    @abc.abstractmethod
    def is_call(self, insn):
        pass

    @abc.abstractmethod
    def is_jump(self, insn):
        pass

    @abc.abstractmethod
    def is_ret(self, insn):
        pass

    @abc.abstractmethod
    def is_conditional_branch(self, insn):
        pass

    @abc.abstractmethod
    def is_branch_taken(self, insn):
        pass

    # register methods

    @abc.abstractmethod
    def flag_register_to_human(self, val=None):
        pass

    @abc.abstractmethod
    def get_ra(self, insn, frame):
        pass

    @abc.abstractmethod
    def get_tls(self):
        pass

    @abc.abstractmethod
    def decode_cookie(self, value, cookie):
        pass

    @abc.abstractmethod
    def encode_cookie(self, value, cookie):
        pass

    @property
    def pc(self):
        return get_register("$pc")

    @property
    def sp(self):
        return get_register("$sp")

    @property
    def ptrsize(self):
        return AddressUtil.get_memory_alignment()

    def get_ith_parameter(self, i, in_func=True):
        if i < len(self.function_parameters):
            reg = self.function_parameters[i]
            val = get_register(reg)
            key = reg
            return key, val
        else:
            from gef.core.memory import read_int_from_memory
            i -= len(self.function_parameters)
            sp = runtime.current_arch.sp
            sz = runtime.current_arch.ptrsize
            loc = sp + (i * sz)
            val = read_int_from_memory(loc)
            key = "[sp + {:#x}]".format(i * sz)
            return key, val

    def get_aliased_registers(self):
        # use cache
        if hasattr(self, "aliased_registers"):
            return self.aliased_registers

        # {"$zero":"$zero/$x0", ...}
        self.aliased_registers = {}
        for reg in self.all_registers:
            if self.alias_registers and reg in self.alias_registers:
                reg_str = "{:s}/{:s}".format(reg, self.alias_registers[reg])
            else:
                reg_str = reg
            self.aliased_registers[reg] = reg_str
        return self.aliased_registers

    def get_aliased_registers_name_max(self):
        # use cache
        if hasattr(self, "aliased_registers_max_len"):
            return self.aliased_registers_max_len

        # max(len("$zero/$x0"), ...)
        maxlen = max([len(v) for v in self.get_aliased_registers().values() if v != self.flag_register])
        self.aliased_registers_max_len = maxlen
        return self.aliased_registers_max_len

    def get_registers_name_max(self):
        # use cache
        if hasattr(self, "registers_max_len"):
            return self.registers_max_len

        # max(len("$x0"), ...)
        maxlen = max([len(v) for v in self.all_registers if v != self.flag_register])
        self.registers_max_len = maxlen
        return self.registers_max_len

    @staticmethod
    def flags_to_human(reg_value, value_table):
        """Return a human readable string showing the flag states."""
        flags = []
        for i in value_table:
            if reg_value & (1 << i):
                flag_str = Color.boldify(value_table[i].upper())
            else:
                flag_str = value_table[i].lower()
            flags.append(flag_str)
        return "{:#x} [{}]".format(reg_value, " ".join(flags))
