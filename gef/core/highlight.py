"""Text-highlight logic (Layer 0).

Extracted from HighlightCommand so gef_print (core.color) can apply highlights
without depending on the commands layer (which would invert the layering).
HighlightCommand (in gef.commands, Phase 2) delegates to highlight_text here.
"""
import re

from gef.core.config import Config


highlight_table = {}


def highlight_text(text):
    """Highlight text using highlight_table { match -> color } settings.

    If RegEx is enabled it will create a match group around all items in the
    highlight_table and wrap the specified color in the highlight_table
    around those matches.

    If RegEx is disabled, split by ANSI codes and 'colorify' each match found
    within the specified string."""
    from gef.core.color import Color

    if not highlight_table:
        return text

    if Config.get_gef_setting("highlight.regex"):
        for match, color in highlight_table.items():
            text = re.sub("(" + match + ")", Color.colorify("\\1", color), text)
        return text

    ansiSplit = re.split(r"(\033\[[\d;]*m)", text)
    for match, color in highlight_table.items():
        for index, val in enumerate(ansiSplit):
            found = val.find(match)
            if found > -1:
                ansiSplit[index] = val.replace(match, Color.colorify(match, color))
                break
        text = "".join(ansiSplit)
        ansiSplit = re.split(r"(\033\[[\d;]*m)", text)
    return "".join(ansiSplit)
