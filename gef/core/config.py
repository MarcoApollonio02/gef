"""GEF configuration (Layer 0). Holds __gef_config__ / __gef_config_orig__.

These are class attributes mutated in place (dict assignment), so importing
the class by name is safe across modules.
"""
from gef.core.cache import Cache


class Config:
    """Manage gef configurations. Most configs are tied to specific commands.
    They are defined in the form `command_name.config_name`.
    Internally it is stored as a triple (value, type, description)."""

    __gef_config__ = {} # keep gef configs
    __gef_config_orig__ = {} # for debugging

    @staticmethod
    @Cache.cache_until_next
    def get_gef_setting(name):
        """Read global gef settings. Return None if not found."""
        setting = Config.__gef_config__.get(name, None)
        if setting is None:
            return None # A valid config can never return None, but False, 0 or ""
        return setting[0]

    @staticmethod
    def set_gef_setting(name, value, _type=None, _desc=None):
        """Set global gef settings.
        Raise ValueError if `name` doesn't exist and `type` and `desc` are not provided."""
        Cache.reset_gef_caches()

        if name not in Config.__gef_config__:
            # create new setting
            if _type is None or _desc is None:
                raise ValueError("Setting '{}' is undefined, need to provide type and description".format(name))
            Config.__gef_config__[name] = [_type(value), _type, _desc]
            return

        # set existing setting
        func = Config.__gef_config__[name][1]
        Config.__gef_config__[name][0] = func(value)
        return
