"""gef.commands — command framework public surface.

The command *base* infrastructure is re-exported here. Concrete command
implementations live in the category subpackages and are auto-discovered by
gef.bootstrap.
"""

from gef.commands.base import (
    BufferingOutput,
    GenericCommand,
    exclude_specific_arch,
    exclude_specific_gdb_mode,
    only_if_events_supported,
    only_if_gdb_running,
    only_if_gdb_target_local,
    only_if_in_kernel,
    only_if_in_kernel_or_kpti_disabled,
    only_if_kvm_disabled,
    only_if_smp_disabled,
    only_if_specific_arch,
    only_if_specific_gdb_mode,
    parse_args,
    register_command,
    register_priority_command,
    require_arch_set,
    switch_to_intel_syntax,
    timeout,
)

__all__ = [
    "BufferingOutput",
    "GenericCommand",
    "exclude_specific_arch",
    "exclude_specific_gdb_mode",
    "only_if_events_supported",
    "only_if_gdb_running",
    "only_if_gdb_target_local",
    "only_if_in_kernel",
    "only_if_in_kernel_or_kpti_disabled",
    "only_if_kvm_disabled",
    "only_if_smp_disabled",
    "only_if_specific_arch",
    "only_if_specific_gdb_mode",
    "parse_args",
    "register_command",
    "register_priority_command",
    "require_arch_set",
    "switch_to_intel_syntax",
    "timeout",
]
