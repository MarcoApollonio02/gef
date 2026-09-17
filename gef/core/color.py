"""GEF coloring and output (Layer 0).

Color: ANSI coloring. gef_print/ok/err/warn/info/titlify: output wrappers.
gef_print applies highlight_text (core.highlight) before printing.
"""
import os
import re

from gef.core.config import Config
from gef.core.highlight import highlight_text


def gef_print(x="", less=False, redirect=None, skip_color=False, *args, **kwargs):
    """Wrapper around print(), with pager, redirecting and coloring."""
    if not skip_color:
        x = highlight_text(x)

    if redirect:
        with open(redirect, "w") as f:
            print(x, *args, **kwargs, file=f)
        return

    if less:
        from gef.core.utils import GefUtil
        try:
            less = GefUtil.which("less")
        except FileNotFoundError:
            less = False

    if not less:
        # if x is blank, print a blank line.
        print(x, *args, **kwargs)
        return

    # use pager but x is blank
    if not x:
        return

    always_no_pager = Config.get_gef_setting("gef.always_no_pager")
    if always_no_pager:
        print(x, *args, **kwargs)
        return

    pager_min_lines = Config.get_gef_setting("gef.pager_min_lines")
    if len(x.splitlines()) < pager_min_lines:
        print(x, *args, **kwargs)
        return

    # write to file and less
    if isinstance(x, bytes):
        tmp_fd, tmp_path = GefUtil.mkstemp(prefix="gef_print", suffix=".txt")
        os.fdopen(tmp_fd, "wb").write(x)
    else:
        try:
            # this is faster than converting to bytes and then writing.
            tmp_fd, tmp_path = GefUtil.mkstemp(prefix="gef_print", suffix=".txt")
            os.fdopen(tmp_fd, "w").write(x)
        except Exception:
            # fallback if a write error occurs
            # tmp_fd is closed at this point, so delete it and reopen it
            os.unlink(tmp_path)
            tmp_fd, tmp_path = GefUtil.mkstemp(prefix="gef_print", suffix=".txt")
            from gef.core.strings import String
            os.fdopen(tmp_fd, "wb").write(String.str2bytes(x))

    # less
    less_option = Config.get_gef_setting("gef.less_option")
    os.system("{!r} {:s} {!r}".format(less, less_option, tmp_path))

    # cleanup
    keep_pager_result = Config.get_gef_setting("gef.keep_pager_result")
    if keep_pager_result:
        print("result saved at {:s}".format(tmp_path))
    else:
        os.unlink(tmp_path)
    return


def titlify(text, color=None, msg_color=None, horizontal_line="-"):
    """Print a centered title."""
    from gef.core.utils import GefUtil
    cols = GefUtil.get_terminal_size()[1]
    if color is None:
        color = Config.get_gef_setting("theme.default_title_line")
    if msg_color is None:
        msg_color = Config.get_gef_setting("theme.default_title_message")

    msg = []
    if text:
        nb = (cols - len(text) - 2) // 2
        msg.append(Color.colorify("{} ".format(horizontal_line * nb), color))
        msg.append(Color.colorify(text, msg_color))
        msg.append(Color.colorify(" {}".format(horizontal_line * nb), color))
    else:
        msg.append(Color.colorify("{}".format(horizontal_line * cols), color))
    return "".join(msg)


def err(msg, redirect=""):
    """The wrapper of gef_print for error level message."""
    gef_print("{} {}".format(Color.colorify("[!]", "bold red"), msg), redirect=redirect)
    return


def warn(msg, redirect=""):
    """The wrapper of gef_print for warning level message."""
    gef_print("{} {}".format(Color.colorify("[*]", "bold yellow"), msg), redirect=redirect)
    return


def ok(msg, redirect=""):
    """The wrapper of gef_print for ok level message."""
    gef_print("{} {}".format(Color.colorify("[+]", "bold green"), msg), redirect=redirect)
    return


def info(msg, redirect=""):
    """The wrapper of gef_print for information level message."""
    gef_print("{} {}".format(Color.colorify("[+]", "bold blue"), msg), redirect=redirect)
    return
class Color:
    """Used to colorify terminal output."""

    # https://en.wikipedia.org/wiki/ANSI_escape_code
    colors = {
        "normal"               : "\033[0m",

        "bold"                 : "\033[1m",
        "bold_off"             : "\033[21m",
        "highlight"            : "\033[2m",
        "highlight_off"        : "\033[22m",
        "italic"               : "\033[3m",
        "italic_off"           : "\033[23m",
        "underline"            : "\033[4m",
        "underline_off"        : "\033[24m",
        "blink"                : "\033[5m",
        "blink_off"            : "\033[25m",

        "black"                : "\033[30m",
        "red"                  : "\033[31m",
        "green"                : "\033[32m",
        "yellow"               : "\033[33m",
        "blue"                 : "\033[34m",
        "magenta"              : "\033[35m",
        "cyan"                 : "\033[36m",

        "bright_black"         : "\033[90m",
        "bright_red"           : "\033[91m",
        "bright_green"         : "\033[92m",
        "bright_yellow"        : "\033[93m",
        "bright_blue"          : "\033[94m",
        "bright_magenta"       : "\033[95m",
        "bright_cyan"          : "\033[96m",
        "bright_white"         : "\033[97m",

        "coral_red"            : "\033[38;2;239;133;125m",
        "sunshine_yellow"      : "\033[38;2;255;237;171m",
        "ice_green"            : "\033[38;2;163;214;204m",
        "wistaria"             : "\033[38;2;141;147;200m",
        "pink_almond"          : "\033[38;2;227;172;174m",
        "poppy_red"            : "\033[38;2;234;85;80m",
        "cream_yellow"         : "\033[38;2;255;243;184m",
        "turquoise_green"      : "\033[38;2;0;148;122m",
        "blue_lavender"        : "\033[38;2;164;168;212m",
        "rose_dust"            : "\033[38;2;230;192;192m",
        "_red"                 : "\033[38;2;234;85;80m",
        "naples_yellow"        : "\033[38;2;253;211;92m",
        "sea_green"            : "\033[38;2;0;172;151m",
        "pannsy"               : "\033[38;2;77;67;152m",
        "white"                : "\033[38;2;255;255;255m",
        "tomato_red"           : "\033[38;2;234;85;73m",
        "topaz"                : "\033[38;2;233;188;0m",
        "peppermint_green"     : "\033[38;2;0;172;154m",
        "violet"               : "\033[38;2;90;68;152m",
        "snow_white"           : "\033[38;2;250;253;255m",
        "vermilion"            : "\033[38;2;234;85;58m",
        "chrome_yellow"        : "\033[38;2;252;200;0m",
        "peacock_green"        : "\033[38;2;0;164;151m",
        "heliotrope"           : "\033[38;2;144;121;182m",
        "pink_white"           : "\033[38;2;254;249;251m",
        "scarlet"              : "\033[38;2;234;85;50m",
        "cream"                : "\033[38;2;227;215;163m",
        "nile_blue"            : "\033[38;2;44;180;173m",
        "deep_royal_purple"    : "\033[38;2;71;38;110m",
        "milky_white"          : "\033[38;2;255;255;249m",
        "carrot_orange"        : "\033[38;2;237;109;53m",
        "straw"                : "\033[38;2;236;224;147m",
        "saxe_blue"            : "\033[38;2;65;139;137m",
        "grape"                : "\033[38;2;86;37;110m",
        "amber_white"          : "\033[38;2;255;249;245m",
        "chinese_red"          : "\033[38;2;237;109;70m",
        "jasmine_yellow"       : "\033[38;2;237;222;123m",
        "slate_green"          : "\033[38;2;60;113;112m",
        "mauve"                : "\033[38;2;145;93;163m",
        "lavender_ice"         : "\033[38;2;247;246;251m",
        "terracotta"           : "\033[38;2;189;104;86m",
        "antique_gold"         : "\033[38;2;193;171;5m",
        "teal_green"           : "\033[38;2;0;106;108m",
        "iris"                 : "\033[38;2;199;165;204m",
        "pearl_white"          : "\033[38;2;247;246;245m",
        "cocoa_brown"          : "\033[38;2;152;96;94m",
        "olive"                : "\033[38;2;114;100;12m",
        "aqua_green"           : "\033[38;2;136;191;191m",
        "lilac"                : "\033[38;2;209;186;218m",
        "ivory"                : "\033[38;2;248;244;230m",
        "mahogany"             : "\033[38;2;107;63;49m",
        "olive_drab"           : "\033[38;2;102;90;26m",
        "aquamarine"           : "\033[38;2;103;181;183m",
        "lavender"             : "\033[38;2;202;184;217m",
        "powder_pink"          : "\033[38;2;245;236;244m",
        "chocolate"            : "\033[38;2;108;53;36m",
        "jaune_brillant"       : "\033[38;2;255;220;0m",
        "peacock_blue"         : "\033[38;2;0;158;159m",
        "crocus"               : "\033[38;2;183;159;203m",
        "silver_white"         : "\033[38;2;239;239;239m",
        "marron"               : "\033[38;2;106;25;23m",
        "_yellow"              : "\033[38;2;255;220;0m",
        "turquoise"            : "\033[38;2;0;155;159m",
        "lavender_mauve"       : "\033[38;2;166;136;189m",
        "frosty_gray"          : "\033[38;2;232;236;233m",
        "sepia"                : "\033[38;2;98;45;24m",
        "citrus"               : "\033[38;2;237;220;68m",
        "capri_blue"           : "\033[38;2;0;163;167m",
        "purple"               : "\033[38;2;155;114;176m",
        "silver_pink"          : "\033[38;2;238;234;236m",
        "coffee"               : "\033[38;2;123;85;68m",
        "limelight"            : "\033[38;2;255;247;153m",
        "cambridge_blue"       : "\033[38;2;37;183;192m",
        "royal_purple"         : "\033[38;2;127;17;132m",
        "beige_cameo"          : "\033[38;2;238;233;230m",
        "brown"                : "\033[38;2;143;101;82m",
        "canary_yellow"        : "\033[38;2;255;244;98m",
        "turquoise_blue"       : "\033[38;2;0;175;204m",
        "raisin"               : "\033[38;2;107;57;95m",
        "ecru"                 : "\033[38;2;238;231;224m",
        "burnt_sienna"         : "\033[38;2;187;85;53m",
        "mimosa"               : "\033[38;2;255;244;98m",
        "horizon_blue"         : "\033[38;2;130;205;221m",
        "plum"                 : "\033[38;2;108;36;99m",
        "pink_beige"           : "\033[38;2;237;228;225m",
        "amber_rose"           : "\033[38;2;230;191;178m",
        "lemon_yellow"         : "\033[38;2;255;243;82m",
        "summer_shower"        : "\033[38;2;161;216;226m",
        "raspberry"            : "\033[38;2;132;26;117m",
        "frosty_white"         : "\033[38;2;230;234;230m",
        "beige_rose"           : "\033[38;2;232;211;202m",
        "melon_yellow"         : "\033[38;2;224;222;148m",
        "_horizon_blue"        : "\033[38;2;161;216;230m",
        "framboise"            : "\033[38;2;154;13;124m",
        "oyster_white"         : "\033[38;2;234;232;225m",
        "salmon_pink"          : "\033[38;2;243;166;140m",
        "chartreuse_yellow"    : "\033[38;2;227;229;72m",
        "cerulean_blue"        : "\033[38;2;0;141;183m",
        "dahlia_purple"        : "\033[38;2;165;0;130m",
        "wisteria_mist"        : "\033[38;2;211;214;221m",
        "sahara"               : "\033[38;2;226;150;118m",
        "lime_yellow"          : "\033[38;2;234;238;162m",
        "duck_blue"            : "\033[38;2;0;113;153m",
        "orchid_purple"        : "\033[38;2;175;0;130m",
        "cloud"                : "\033[38;2;212;217;223m",
        "ash_rose"             : "\033[38;2;230;191;171m",
        "lime_green"           : "\033[38;2;230;235;148m",
        "marine_blue"          : "\033[38;2;0;104;136m",
        "raspberry_red"        : "\033[38;2;159;22;106m",
        "moon_gray"            : "\033[38;2;212;217;220m",
        "shell_pink"           : "\033[38;2;251;218;200m",
        "chartreuse_green"     : "\033[38;2;217;227;103m",
        "madonna_blue"         : "\033[38;2;0;96;141m",
        "orchid"               : "\033[38;2;217;170;205m",
        "china_clay"           : "\033[38;2;212;220;211m",
        "baby_pink"            : "\033[38;2;253;237;228m",
        "lettuce_green"        : "\033[38;2;209;222;76m",
        "egyptian_blue"        : "\033[38;2;0;115;168m",
        "lilla"                : "\033[38;2;224;181;211m",
        "sand_beige"           : "\033[38;2;220;214;210m",
        "nail_pink"            : "\033[38;2;252;228;214m",
        "olive_green"          : "\033[38;2;95;101;39m",
        "baby_blue"            : "\033[38;2;187;226;241m",
        "rose_tendre"          : "\033[38;2;230;175;207m",
        "orchid_mist"          : "\033[38;2;211;211;216m",
        "raw_sienna"           : "\033[38;2;225;123;52m",
        "moss_green"           : "\033[38;2;119;126;65m",
        "sky_blue"             : "\033[38;2;160;216;239m",
        "orchid_pink"          : "\033[38;2;218;129;178m",
        "reed_gray"            : "\033[38;2;212;217;214m",
        "caramel"              : "\033[38;2;188;97;30m",
        "grass_green"          : "\033[38;2;123;141;66m",
        "shadow_blue"          : "\033[38;2;113;155;173m",
        "cyclamen_pink"        : "\033[38;2;208;79;151m",
        "sky_gray"             : "\033[38;2;203;208;211m",
        "sunset"               : "\033[38;2;246;180;131m",
        "spring_green"         : "\033[38;2;156;187;28m",
        "_cyan"                : "\033[38;2;0;161;233m",
        "_magenta"             : "\033[38;2;228;0;127m",
        "lavender_gray"        : "\033[38;2;188;186;206m",
        "cinnamon"             : "\033[38;2;190;143;104m",
        "leaf_green"           : "\033[38;2;159;194;77m",
        "yacht_blue"           : "\033[38;2;64;158;204m",
        "bougainvillaea"       : "\033[38;2;230;47;139m",
        "silver"               : "\033[38;2;201;202;202m",
        "tan"                  : "\033[38;2;191;120;62m",
        "white_lily"           : "\033[38;2;240;246;218m",
        "chalk_blue"           : "\033[38;2;104;169;207m",
        "ruby"                 : "\033[38;2;199;0;103m",
        "pearl_gray"           : "\033[38;2;201;201;196m",
        "champagne"            : "\033[38;2;233;218;203m",
        "asparagus_green"      : "\033[38;2;219;235;196m",
        "pigeon_blue"          : "\033[38;2;136;181;211m",
        "claret"               : "\033[38;2;148;31;87m",
        "sand_gray"            : "\033[38;2;201;201;194m",
        "peach"                : "\033[38;2;251;216;181m",
        "citron_green"         : "\033[38;2;97;142;52m",
        "smoke_blue"           : "\033[38;2;164;193;215m",
        "azalee"               : "\033[38;2;216;52;115m",
        "marble_gray"          : "\033[38;2;192;197;194m",
        "cafe_au_lait"         : "\033[38;2;148;108;69m",
        "meadow_green"         : "\033[38;2;101;171;49m",
        "frosty_blue"          : "\033[38;2;187;219;243m",
        "cosmos"               : "\033[38;2;220;107;154m",
        "opal_gray"            : "\033[38;2;191;190;197m",
        "orange"               : "\033[38;2;238;120;0m",
        "apple_green"          : "\033[38;2;167;210;141m",
        "bleu_acide"           : "\033[38;2;0;110;176m",
        "lotus_pink"           : "\033[38;2;222;130;167m",
        "french_gray"          : "\033[38;2;141;160;182m",
        "apricot"              : "\033[38;2;247;185;119m",
        "ivy_green"            : "\033[38;2;87;138;61m",
        "cobalt_blue"          : "\033[38;2;0;104;183m",
        "old_orchid"           : "\033[38;2;227;173;193m",
        "mist"                 : "\033[38;2;180;174;177m",
        "amber"                : "\033[38;2;194;137;75m",
        "spinach_green"        : "\033[38;2;65;112;56m",
        "sapphire_blue"        : "\033[38;2;0;104;183m",
        "rose_mist"            : "\033[38;2;222;190;204m",
        "ash_blond"            : "\033[38;2;181;181;174m",
        "bronze"               : "\033[38;2;172;107;37m",
        "cactus"               : "\033[38;2;56;125;57m",
        "spectrum_blue"        : "\033[38;2;0;117;194m",
        "rose_dragee"          : "\033[38;2;229;193;205m",
        "fog"                  : "\033[38;2;171;177;181m",
        "vanilla"              : "\033[38;2;232;197;156m",
        "sky_green"            : "\033[38;2;190;224;194m",
        "_blue"                : "\033[38;2;0;117;194m",
        "cherry_pink"          : "\033[38;2;235;110;160m",
        "beige_gray"           : "\033[38;2;180;173;169m",
        "cork"                 : "\033[38;2;196;154;106m",
        "spearmint"            : "\033[38;2;121;192;110m",
        "zenith_blue"          : "\033[38;2;68;150;211m",
        "opera"                : "\033[38;2;233;83;136m",
        "silver_gray"          : "\033[38;2;175;175;176m",
        "burnt_umber"          : "\033[38;2;111;84;54m",
        "mint_green"           : "\033[38;2;137;201;151m",
        "heavenly_blue"        : "\033[38;2;104;164;217m",
        "rose_red"             : "\033[38;2;234;97;142m",
        "storm_gray"           : "\033[38;2;170;170;176m",
        "raw_umber"            : "\033[38;2;134;102;41m",
        "parrot_green"         : "\033[38;2;55;163;74m",
        "orchid_gray"          : "\033[38;2;188;199;215m",
        "old_lilac"            : "\033[38;2;176;119;140m",
        "green_fog"            : "\033[38;2;171;177;173m",
        "flesh"                : "\033[38;2;250;208;158m",
        "summer_green"         : "\033[38;2;0;153;68m",
        "powder_blue"          : "\033[38;2;188;205;219m",
        "cocoa"                : "\033[38;2;110;74;85m",
        "ash_gray"             : "\033[38;2;159;160;158m",
        "golden_yellow"        : "\033[38;2;246;174;84m",
        "opal_green"           : "\033[38;2;190;224;206m",
        "light_blue"           : "\033[38;2;178;203;228m",
        "wine_red"             : "\033[38;2;179;62;92m",
        "rose_gray"            : "\033[38;2;157;142;135m",
        "mandarin_orange"      : "\033[38;2;243;152;29m",
        "spray_green"          : "\033[38;2;164;213;189m",
        "_baby_blue"           : "\033[38;2;162;194;230m",
        "garnet"               : "\033[38;2;148;35;67m",
        "elephant_skin"        : "\033[38;2;159;159;152m",
        "marigold"             : "\033[38;2;243;152;0m",
        "bottle_green"         : "\033[38;2;0;77;37m",
        "day_dream"            : "\033[38;2;163;185;224m",
        "cochineal_red"        : "\033[38;2;200;44;85m",
        "battleship_gray"      : "\033[38;2;137;137;137m",
        "ecru_beige"           : "\033[38;2;246;229;204m",
        "cobalt_green"         : "\033[38;2;60;179;122m",
        "salvia_blue"          : "\033[38;2;148;173;218m",
        "strawberry"           : "\033[38;2;231;53;98m",
        "stone_gray"           : "\033[38;2;137;136;128m",
        "oyster"               : "\033[38;2;234;225;207m",
        "evergreen"            : "\033[38;2;0;152;79m",
        "hyacinth_blue"        : "\033[38;2;122;153;207m",
        "ruby_red"             : "\033[38;2;231;53;98m",
        "moss_gray"            : "\033[38;2;126;131;127m",
        "ochre"                : "\033[38;2;186;139;64m",
        "malachite_green"      : "\033[38;2;0;152;84m",
        "hyacinth"             : "\033[38;2;108;155;210m",
        "carmine"              : "\033[38;2;215;0;53m",
        "dove_gray"            : "\033[38;2;125;123;131m",
        "khaki"                : "\033[38;2;197;160;90m",
        "_green"               : "\033[38;2;0;169;96m",
        "midnight_blue"        : "\033[38;2;0;30;67m",
        "signal_red"           : "\033[38;2;232;56;61m",
        "gray"                 : "\033[38;2;125;125;125m",
        "buff"                 : "\033[38;2;202;172;113m",
        "emerald_green"        : "\033[38;2;0;169;104m",
        "navy_blue"            : "\033[38;2;32;47;85m",
        "burgundy"             : "\033[38;2;108;39;53m",
        "steel_gray"           : "\033[38;2;115;109;113m",
        "saffron_yellow"       : "\033[38;2;250;197;89m",
        "forest_green"         : "\033[38;2;40;140;102m",
        "prussian_blue"        : "\033[38;2;25;47;96m",
        "bordeaux"             : "\033[38;2;108;39;45m",
        "ivy_gray"             : "\033[38;2;102;108;103m",
        "pumpkin"              : "\033[38;2;229;163;35m",
        "viridian"             : "\033[38;2;0;136;90m",
        "iron_blue"            : "\033[38;2;25;47;96m",
        "camellia"             : "\033[38;2;218;83;110m",
        "slate_gray"           : "\033[38;2;98;96;99m",
        "yellow_ocher"         : "\033[38;2;196;151;47m",
        "holly_green"          : "\033[38;2;0;105;72m",
        "indigo"               : "\033[38;2;4;60;120m",
        "rose"                 : "\033[38;2;233;84;100m",
        "graphite"             : "\033[38;2;89;78;82m",
        "blond"                : "\033[38;2;242;213;138m",
        "billiard_green"       : "\033[38;2;0;92;66m",
        "ink_blue"             : "\033[38;2;0;63;142m",
        "rose_pink"            : "\033[38;2;241;156;167m",
        "charcoal_gray"        : "\033[38;2;78;69;74m",
        "beige"                : "\033[38;2;238;220;179m",
        "chrome_green"         : "\033[38;2;0;83;63m",
        "oriental_blue"        : "\033[38;2;38;73;157m",
        "pink"                 : "\033[38;2;245;178;178m",
        "taupe"                : "\033[38;2;80;73;70m",
        "biscuit"              : "\033[38;2;234;215;164m",
        "antique_green"        : "\033[38;2;84;145;127m",
        "ultramarine_blue"     : "\033[38;2;71;83;162m",
        "flamingo_pink"        : "\033[38;2;245;178;172m",
        "lamp_black"           : "\033[38;2;36;20;14m",
        "leghorn"              : "\033[38;2;255;233;169m",
        "water_green"          : "\033[38;2;165;201;193m",
        "ultramarine"          : "\033[38;2;67;77;162m",
        "old_rose"             : "\033[38;2;226;147;153m",
        "_black"               : "\033[38;2;0;0;0m",

        "__black"              : "\033[38;2;0;0;0m",
        "aliceblue"            : "\033[38;2;240;248;255m",
        "darkcyan"             : "\033[38;2;0;139;139m",
        "lightyellow"          : "\033[38;2;255;255;224m",
        "coral"                : "\033[38;2;255;127;80m",
        "dimgray"              : "\033[38;2;105;105;105m",
        "_lavender"            : "\033[38;2;230;230;250m",
        "teal"                 : "\033[38;2;0;128;128m",
        "lightgoldenrodyellow" : "\033[38;2;250;250;210m",
        "tomato"               : "\033[38;2;255;99;71m",
        "_gray"                : "\033[38;2;128;128;128m",
        "lightsteelblue"       : "\033[38;2;176;196;222m",
        "darkslategray"        : "\033[38;2;47;79;79m",
        "lemonchiffon"         : "\033[38;2;255;250;205m",
        "orangered"            : "\033[38;2;255;69;0m",
        "darkgray"             : "\033[38;2;169;169;169m",
        "lightslategray"       : "\033[38;2;119;136;153m",
        "darkgreen"            : "\033[38;2;0;100;0m",
        "wheat"                : "\033[38;2;245;222;179m",
        "__red"                : "\033[38;2;255;0;0m",
        "_silver"              : "\033[38;2;192;192;192m",
        "slategray"            : "\033[38;2;112;128;144m",
        "__green"              : "\033[38;2;0;128;0m",
        "burlywood"            : "\033[38;2;222;184;135m",
        "crimson"              : "\033[38;2;220;20;60m",
        "lightgray"            : "\033[38;2;211;211;211m",
        "steelblue"            : "\033[38;2;70;130;180m",
        "forestgreen"          : "\033[38;2;34;139;34m",
        "_tan"                 : "\033[38;2;210;180;140m",
        "mediumvioletred"      : "\033[38;2;199;21;133m",
        "gainsboro"            : "\033[38;2;220;220;220m",
        "royalblue"            : "\033[38;2;65;105;225m",
        "seagreen"             : "\033[38;2;46;139;87m",
        "_khaki"               : "\033[38;2;240;230;140m",
        "deeppink"             : "\033[38;2;255;20;147m",
        "whitesmoke"           : "\033[38;2;245;245;245m",
        "midnightblue"         : "\033[38;2;25;25;112m",
        "mediumseagreen"       : "\033[38;2;60;179;113m",
        "__yellow"             : "\033[38;2;255;255;0m",
        "hotpink"              : "\033[38;2;255;105;180m",
        "__white"              : "\033[38;2;255;255;255m",
        "navy"                 : "\033[38;2;0;0;128m",
        "mediumaquamarine"     : "\033[38;2;102;205;170m",
        "gold"                 : "\033[38;2;255;215;0m",
        "palevioletred"        : "\033[38;2;219;112;147m",
        "snow"                 : "\033[38;2;255;250;250m",
        "darkblue"             : "\033[38;2;0;0;139m",
        "darkseagreen"         : "\033[38;2;143;188;143m",
        "_orange"              : "\033[38;2;255;165;0m",
        "_pink"                : "\033[38;2;255;192;203m",
        "ghostwhite"           : "\033[38;2;248;248;255m",
        "mediumblue"           : "\033[38;2;0;0;205m",
        "_aquamarine"          : "\033[38;2;127;255;212m",
        "sandybrown"           : "\033[38;2;244;164;96m",
        "lightpink"            : "\033[38;2;255;182;193m",
        "floralwhite"          : "\033[38;2;255;250;240m",
        "__blue"               : "\033[38;2;0;0;255m",
        "palegreen"            : "\033[38;2;152;251;152m",
        "darkorange"           : "\033[38;2;255;140;0m",
        "thistle"              : "\033[38;2;216;191;216m",
        "linen"                : "\033[38;2;250;240;230m",
        "dodgerblue"           : "\033[38;2;30;144;255m",
        "lightgreen"           : "\033[38;2;144;238;144m",
        "goldenrod"            : "\033[38;2;218;165;32m",
        "__magenta"            : "\033[38;2;255;0;255m",
        "antiquewhite"         : "\033[38;2;250;235;215m",
        "cornflowerblue"       : "\033[38;2;100;149;237m",
        "springgreen"          : "\033[38;2;0;255;127m",
        "peru"                 : "\033[38;2;205;133;63m",
        "fuchsia"              : "\033[38;2;255;0;255m",
        "papayawhip"           : "\033[38;2;255;239;213m",
        "deepskyblue"          : "\033[38;2;0;191;255m",
        "mediumspringgreen"    : "\033[38;2;0;250;154m",
        "darkgoldenrod"        : "\033[38;2;184;134;11m",
        "_violet"              : "\033[38;2;238;130;238m",
        "blanchedalmond"       : "\033[38;2;255;235;205m",
        "lightskyblue"         : "\033[38;2;135;206;250m",
        "lawngreen"            : "\033[38;2;124;252;0m",
        "_chocolate"           : "\033[38;2;210;105;30m",
        "_plum"                : "\033[38;2;221;160;221m",
        "bisque"               : "\033[38;2;255;228;196m",
        "skyblue"              : "\033[38;2;135;206;235m",
        "chartreuse"           : "\033[38;2;127;255;0m",
        "sienna"               : "\033[38;2;160;82;45m",
        "_orchid"              : "\033[38;2;218;112;214m",
        "moccasin"             : "\033[38;2;255;228;181m",
        "lightblue"            : "\033[38;2;173;216;230m",
        "greenyellow"          : "\033[38;2;173;255;47m",
        "saddlebrown"          : "\033[38;2;139;69;19m",
        "mediumorchid"         : "\033[38;2;186;85;211m",
        "navajowhite"          : "\033[38;2;255;222;173m",
        "powderblue"           : "\033[38;2;176;224;230m",
        "lime"                 : "\033[38;2;0;255;0m",
        "maroon"               : "\033[38;2;128;0;0m",
        "darkorchid"           : "\033[38;2;153;50;204m",
        "peachpuff"            : "\033[38;2;255;218;185m",
        "paleturquoise"        : "\033[38;2;175;238;238m",
        "limegreen"            : "\033[38;2;50;205;50m",
        "darkred"              : "\033[38;2;139;0;0m",
        "darkviolet"           : "\033[38;2;148;0;211m",
        "mistyrose"            : "\033[38;2;255;228;225m",
        "lightcyan"            : "\033[38;2;224;255;255m",
        "yellowgreen"          : "\033[38;2;154;205;50m",
        "_brown"               : "\033[38;2;165;42;42m",
        "darkmagenta"          : "\033[38;2;139;0;139m",
        "lavenderblush"        : "\033[38;2;255;240;245m",
        "__cyan"               : "\033[38;2;0;255;255m",
        "darkolivegreen"       : "\033[38;2;85;107;47m",
        "firebrick"            : "\033[38;2;178;34;34m",
        "_purple"              : "\033[38;2;128;0;128m",
        "seashell"             : "\033[38;2;255;245;238m",
        "aqua"                 : "\033[38;2;0;255;255m",
        "olivedrab"            : "\033[38;2;107;142;35m",
        "indianred"            : "\033[38;2;205;92;92m",
        "_indigo"              : "\033[38;2;75;0;130m",
        "oldlace"              : "\033[38;2;253;245;230m",
        "_turquoise"           : "\033[38;2;64;224;208m",
        "_olive"               : "\033[38;2;128;128;0m",
        "rosybrown"            : "\033[38;2;188;143;143m",
        "darkslateblue"        : "\033[38;2;72;61;139m",
        "_ivory"               : "\033[38;2;255;255;240m",
        "mediumturquoise"      : "\033[38;2;72;209;204m",
        "darkkhaki"            : "\033[38;2;189;183;107m",
        "darksalmon"           : "\033[38;2;233;150;122m",
        "blueviolet"           : "\033[38;2;138;43;226m",
        "honeydew"             : "\033[38;2;240;255;240m",
        "darkturquoise"        : "\033[38;2;0;206;209m",
        "palegoldenrod"        : "\033[38;2;238;232;170m",
        "lightcoral"           : "\033[38;2;240;128;128m",
        "mediumpurple"         : "\033[38;2;147;112;219m",
        "mintcream"            : "\033[38;2;245;255;250m",
        "lightseagreen"        : "\033[38;2;32;178;170m",
        "cornsilk"             : "\033[38;2;255;248;220m",
        "salmon"               : "\033[38;2;250;128;114m",
        "slateblue"            : "\033[38;2;106;90;205m",
        "azure"                : "\033[38;2;240;255;255m",
        "cadetblue"            : "\033[38;2;95;158;160m",
        "_beige"               : "\033[38;2;245;245;220m",
        "lightsalmon"          : "\033[38;2;255;160;122m",
        "mediumslateblue"      : "\033[38;2;123;104;238m",
    }

    @staticmethod
    def boldify(msg):
        return Color.colorify(msg, "bold")

    @staticmethod
    def grayify(msg):
        return Color.colorify(msg, "bright_black")

    @staticmethod
    def redify(msg):
        return Color.colorify(msg, "red")

    @staticmethod
    def greenify(msg):
        return Color.colorify(msg, "green")

    @staticmethod
    def yellowify(msg):
        return Color.colorify(msg, "yellow")

    @staticmethod
    def blueify(msg):
        return Color.colorify(msg, "blue")

    @staticmethod
    def cyanify(msg):
        return Color.colorify(msg, "cyan")

    NO_COLOR = None

    @staticmethod
    def disable_color():
        if Config.get_gef_setting("gef.disable_color") is True:
            return True
        if Color.NO_COLOR is None:
            if os.environ.get("NO_COLOR", None):
                Color.NO_COLOR = True
            else:
                Color.NO_COLOR = False
        if Color.NO_COLOR:
            return True
        return False

    @staticmethod
    def colorify(text, attrs):
        """Color text according to the given attributes."""
        if Color.disable_color():
            return str(text)

        colors = Color.colors
        escapes = [colors[attr] for attr in attrs.split() if attr in colors]
        if len(escapes) == 0:
            return str(text)

        out = "".join(escapes) + str(text) + colors["normal"]
        return out

    @staticmethod
    def colorify_hex(value, attrs):
        text = "{:#x}".format(value)
        return Color.colorify(text, attrs)

    @staticmethod
    def remove_color(text):
        return re.sub(r"\x1B\[([0-9]{1,2}(;[0-9]{1,3})*)?m", "", text)


