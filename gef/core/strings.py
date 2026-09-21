"""String utility helpers (Layer 1).

`String` is a `@staticmethod` collection of pure-Python byte/string
manipulation helpers (hex-digit tables, str/bytes/bit conversions, Morse
codec). It has no gdb or GEF dependencies.
"""


class String:
    """A collection of utility functions that are related to strings."""

    STRING_ASCII_LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
    STRING_ASCII_UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    STRING_ASCII_LETTERS = STRING_ASCII_LOWERCASE + STRING_ASCII_UPPERCASE
    STRING_DIGITS = "0123456789"
    STRING_HEXDIGITS = "0123456789abcdefABCDEF"
    STRING_PUNCTUATION = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"
    STRING_WHITESPACE = " \t\n\r\x0b\x0c"
    STRING_PRINTABLE = STRING_DIGITS + STRING_ASCII_LETTERS + STRING_PUNCTUATION + STRING_WHITESPACE
    MORSE_CODE_DICT = {
        b".-"     : b"A",
        b"-..."   : b"B",
        b"-.-."   : b"C",
        b"-.."    : b"D",
        b"."      : b"E",
        b"..-."   : b"F",
        b"--."    : b"G",
        b"...."   : b"H",
        b".."     : b"I",
        b".---"   : b"J",
        b"-.-"    : b"K",
        b".-.."   : b"L",
        b"--"     : b"M",
        b"-."     : b"N",
        b"---"    : b"O",
        b".--."   : b"P",
        b"--.-"   : b"Q",
        b".-."    : b"R",
        b"..."    : b"S",
        b"-"      : b"T",
        b"..-"    : b"U",
        b"...-"   : b"V",
        b".--"    : b"W",
        b"-..-"   : b"X",
        b"-.--"   : b"Y",
        b"--.."   : b"Z",
        b".----"  : b"1",
        b"..---"  : b"2",
        b"...--"  : b"3",
        b"....-"  : b"4",
        b"....."  : b"5",
        b"-...."  : b"6",
        b"--..."  : b"7",
        b"---.."  : b"8",
        b"----."  : b"9",
        b"-----"  : b"0",
        b"--..--" : b",",
        b".-.-.-" : b".",
        b"..--.." : b"?",
        b"-..-."  : b"/",
        b"-....-" : b"-",
        b"-.--."  : b"(",
        b"-.--.-" : b")",
    }

    @staticmethod
    def str2bytes(x):
        """Helper function for str -> bytes."""
        if isinstance(x, bytes):
            return x
        if isinstance(x, str):
            try:
                return bytes(ord(xx) for xx in x)
            except ValueError:
                # If str is UTF-8 multi-byte string, raise an error.
                # e.g., `pi String.str2bytes(b"\xc5\x82".decode("utf-8"))`
                # In that case, you should simply encode it as UTF-8.
                return x.encode("utf-8")
        raise

    @staticmethod
    def bytes2str(x):
        """Helper function for bytes -> str."""
        if isinstance(x, str):
            return x
        if isinstance(x, bytes):
            return "".join(chr(xx) for xx in x)
        raise

    @staticmethod # noqa
    def bits2bytes(a, endian="big"):
        """Helper function for bits -> bytes."""
        if isinstance(a, str):
            a = String.str2bytes(a)
        if isinstance(a, bytes):
            a = a.replace(b"0", b"\x00")
            a = a.replace(b"1", b"\x01")
        if not isinstance(a, list):
            a = list(a)
        assert set(a) <= {0x0, 0x1}

        out = []

        if endian == "little":
            s = i = 0
            for x in a:
                s += x << i
                i += 1
                if i == 8:
                    out.append(s)
                    s = i = 0
            if i > 0:
                out.append(s)
        else:
            s = i = 0
            for x in a:
                s += s + x
                i += 1
                if i == 8:
                    out.append(s)
                    s = i = 0
            if i > 0:
                s = s << (8 - i)
                out.append(s)
        return bytes(out)

    @staticmethod # noqa
    def bytes2bits(a, endian="big"):
        """Helper function for bytes -> bits."""
        if isinstance(a, str):
            a = String.str2bytes(a)

        out = []

        if endian == "little":
            for x in a:
                for i in range(8):
                    b = (x >> i) & 1
                    out.append(b)
        else:
            for x in a:
                for i in range(8):
                    b = (x >> (7 - i)) & 1
                    out.append(b)
        return out

    @staticmethod
    def morse_decode(a):
        """Decode a bytes or string sequence from Morse code to text."""
        if isinstance(a, str):
            a = String.str2bytes(a)

        decoded = b""
        for elem in a.split():
            decoded += String.MORSE_CODE_DICT.get(elem, elem)
        return decoded

    @staticmethod
    def morse_encode(a):
        """Encode a bytes or string sequence from text to Morse code."""
        if isinstance(a, str):
            a = String.str2bytes(a)

        MORSE_CODE_REVERSE_DICT = {v: k for k, v in String.MORSE_CODE_DICT.items()}

        encoded = b""
        for elem in a:
            elem = bytes([elem])
            encoded += MORSE_CODE_REVERSE_DICT.get(elem.upper(), elem)
            encoded += b" "
        return encoded[:-1]

    @staticmethod
    def is_hex(pattern):
        """Return whether provided string is a hexadecimal value."""
        if not pattern.startswith("0x") and not pattern.startswith("0X"):
            return False
        return len(pattern) % 2 == 0 and all(c in String.STRING_HEXDIGITS for c in pattern[2:])
