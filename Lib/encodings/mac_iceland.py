""" Python Character Mapping Codec mac_iceland generated from 'MAPPINGS/VENDORS/APPLE/ICELAND.TXT' with gencodec.py.

"""#"

import codecs

### Codec APIs

class Codec(codecs.Codec):

    def encode(self,input,errors='strict'):
        return codecs.charmap_encode(input,errors,encoding_map)

    def decode(self,input,errors='strict'):
        return codecs.charmap_decode(input,errors,decoding_table)

class IncrementalEncoder(codecs.IncrementalEncoder):
    def encode(self, input, final=False):
        return codecs.charmap_encode(input,self.errors,encoding_map)[0]

class IncrementalDecoder(codecs.IncrementalDecoder):
    def decode(self, input, final=False):
        return codecs.charmap_decode(input,self.errors,decoding_table)[0]

class StreamWriter(Codec,codecs.StreamWriter):
    pass

class StreamReader(Codec,codecs.StreamReader):
    pass

### encodings module API

def getregentry():
    return codecs.CodecInfo(
        name='mac-iceland',
        encode=Codec().encode,
        decode=Codec().decode,
        incrementalencoder=IncrementalEncoder,
        incrementaldecoder=IncrementalDecoder,
        streamreader=StreamReader,
        streamwriter=StreamWriter,
    )


### Decoding Table

decoding_table = (
    u'\x00'     #  0x00 -> CONTROL CHARACTER
    u'\x01'     #  0x01 -> CONTROL CHARACTER
    u'\x02'     #  0x02 -> CONTROL CHARACTER
    u'\x03'     #  0x03 -> CONTROL CHARACTER
    u'\x04'     #  0x04 -> CONTROL CHARACTER
    u'\x05'     #  0x05 -> CONTROL CHARACTER
    u'\x06'     #  0x06 -> CONTROL CHARACTER
    u'\x07'     #  0x07 -> CONTROL CHARACTER
    u'\x08'     #  0x08 -> CONTROL CHARACTER
    u'\t'       #  0x09 -> CONTROL CHARACTER
    u'\n'       #  0x0A -> CONTROL CHARACTER
    u'\x0b'     #  0x0B -> CONTROL CHARACTER
    u'\x0c'     #  0x0C -> CONTROL CHARACTER
    u'\r'       #  0x0D -> CONTROL CHARACTER
    u'\x0e'     #  0x0E -> CONTROL CHARACTER
    u'\x0f'     #  0x0F -> CONTROL CHARACTER
    u'\x10'     #  0x10 -> CONTROL CHARACTER
    u'\x11'     #  0x11 -> CONTROL CHARACTER
    u'\x12'     #  0x12 -> CONTROL CHARACTER
    u'\x13'     #  0x13 -> CONTROL CHARACTER
    u'\x14'     #  0x14 -> CONTROL CHARACTER
    u'\x15'     #  0x15 -> CONTROL CHARACTER
    u'\x16'     #  0x16 -> CONTROL CHARACTER
    u'\x17'     #  0x17 -> CONTROL CHARACTER
    u'\x18'     #  0x18 -> CONTROL CHARACTER
    u'\x19'     #  0x19 -> CONTROL CHARACTER
    u'\x1a'     #  0x1A -> CONTROL CHARACTER
    u'\x1b'     #  0x1B -> CONTROL CHARACTER
    u'\x1c'     #  0x1C -> CONTROL CHARACTER
    u'\x1d'     #  0x1D -> CONTROL CHARACTER
    u'\x1e'     #  0x1E -> CONTROL CHARACTER
    u'\x1f'     #  0x1F -> CONTROL CHARACTER
    u' '        #  0x20 -> SPACE
    u'!'        #  0x21 -> EXCLAMATION MARK
    u'"'        #  0x22 -> QUOTATION MARK
    u'#'        #  0x23 -> NUMBER SIGN
    u'$'        #  0x24 -> DOLLAR SIGN
    u'%'        #  0x25 -> PERCENT SIGN
    u'&'        #  0x26 -> AMPERSAND
    u"'"        #  0x27 -> APOSTROPHE
    u'('        #  0x28 -> LEFT PARENTHESIS
    u')'        #  0x29 -> RIGHT PARENTHESIS
    u'*'        #  0x2A -> ASTERISK
    u'+'        #  0x2B -> PLUS SIGN
    u','        #  0x2C -> COMMA
    u'-'        #  0x2D -> HYPHEN-MINUS
    u'.'        #  0x2E -> FULL STOP
    u'/'        #  0x2F -> SOLIDUS
    u'0'        #  0x30 -> DIGIT ZERO
    u'1'        #  0x31 -> DIGIT ONE
    u'2'        #  0x32 -> DIGIT TWO
    u'3'        #  0x33 -> DIGIT THREE
    u'4'        #  0x34 -> DIGIT FOUR
    u'5'        #  0x35 -> DIGIT FIVE
    u'6'        #  0x36 -> DIGIT SIX
    u'7'        #  0x37 -> DIGIT SEVEN
    u'8'        #  0x38 -> DIGIT EIGHT
    u'9'        #  0x39 -> DIGIT NINE
    u':'        #  0x3A -> COLON
    u';'        #  0x3B -> SEMICOLON
    u'<'        #  0x3C -> LESS-THAN SIGN
    u'='        #  0x3D -> EQUALS SIGN
    u'>'        #  0x3E -> GREATER-THAN SIGN
    u'?'        #  0x3F -> QUESTION MARK
    u'@'        #  0x40 -> COMMERCIAL AT
    u'A'        #  0x41 -> LATIN CAPITAL LETTER A
    u'B'        #  0x42 -> LATIN CAPITAL LETTER B
    u'C'        #  0x43 -> LATIN CAPITAL LETTER C
    u'D'        #  0x44 -> LATIN CAPITAL LETTER D
    u'E'        #  0x45 -> LATIN CAPITAL LETTER E
    u'F'        #  0x46 -> LATIN CAPITAL LETTER F
    u'G'        #  0x47 -> LATIN CAPITAL LETTER G
    u'H'        #  0x48 -> LATIN CAPITAL LETTER H
    u'I'        #  0x49 -> LATIN CAPITAL LETTER I
    u'J'        #  0x4A -> LATIN CAPITAL LETTER J
    u'K'        #  0x4B -> LATIN CAPITAL LETTER K
    u'L'        #  0x4C -> LATIN CAPITAL LETTER L
    u'M'        #  0x4D -> LATIN CAPITAL LETTER M
    u'N'        #  0x4E -> LATIN CAPITAL LETTER N
    u'O'        #  0x4F -> LATIN CAPITAL LETTER O
    u'P'        #  0x50 -> LATIN CAPITAL LETTER P
    u'Q'        #  0x51 -> LATIN CAPITAL LETTER Q
    u'R'        #  0x52 -> LATIN CAPITAL LETTER R
    u'S'        #  0x53 -> LATIN CAPITAL LETTER S
    u'T'        #  0x54 -> LATIN CAPITAL LETTER T
    u'U'        #  0x55 -> LATIN CAPITAL LETTER U
    u'V'        #  0x56 -> LATIN CAPITAL LETTER V
    u'W'        #  0x57 -> LATIN CAPITAL LETTER W
    u'X'        #  0x58 -> LATIN CAPITAL LETTER X
    u'Y'        #  0x59 -> LATIN CAPITAL LETTER Y
    u'Z'        #  0x5A -> LATIN CAPITAL LETTER Z
    u'['        #  0x5B -> LEFT SQUARE BRACKET
    u'\\'       #  0x5C -> REVERSE SOLIDUS
    u']'        #  0x5D -> RIGHT SQUARE BRACKET
    u'^'        #  0x5E -> CIRCUMFLEX ACCENT
    u'_'        #  0x5F -> LOW LINE
    u'`'        #  0x60 -> GRAVE ACCENT
    u'a'        #  0x61 -> LATIN SMALL LETTER A
    u'b'        #  0x62 -> LATIN SMALL LETTER B
    u'c'        #  0x63 -> LATIN SMALL LETTER C
    u'd'        #  0x64 -> LATIN SMALL LETTER D
    u'e'        #  0x65 -> LATIN SMALL LETTER E
    u'f'        #  0x66 -> LATIN SMALL LETTER F
    u'g'        #  0x67 -> LATIN SMALL LETTER G
    u'h'        #  0x68 -> LATIN SMALL LETTER H
    u'i'        #  0x69 -> LATIN SMALL LETTER I
    u'j'        #  0x6A -> LATIN SMALL LETTER J
    u'k'        #  0x6B -> LATIN SMALL LETTER K
    u'l'        #  0x6C -> LATIN SMALL LETTER L
    u'm'        #  0x6D -> LATIN SMALL LETTER M
    u'n'        #  0x6E -> LATIN SMALL LETTER N
    u'o'        #  0x6F -> LATIN SMALL LETTER O
    u'p'        #  0x70 -> LATIN SMALL LETTER P
    u'q'        #  0x71 -> LATIN SMALL LETTER Q
    u'r'        #  0x72 -> LATIN SMALL LETTER R
    u's'        #  0x73 -> LATIN SMALL LETTER S
    u't'        #  0x74 -> LATIN SMALL LETTER T
    u'u'        #  0x75 -> LATIN SMALL LETTER U
    u'v'        #  0x76 -> LATIN SMALL LETTER V
    u'w'        #  0x77 -> LATIN SMALL LETTER W
    u'x'        #  0x78 -> LATIN SMALL LETTER X
    u'y'        #  0x79 -> LATIN SMALL LETTER Y
    u'z'        #  0x7A -> LATIN SMALL LETTER Z
    u'{'        #  0x7B -> LEFT CURLY BRACKET
    u'|'        #  0x7C -> VERTICAL LINE
    u'}'        #  0x7D -> RIGHT CURLY BRACKET
    u'~'        #  0x7E -> TILDE
    u'\x7f'     #  0x7F -> CONTROL CHARACTER
    u'\xc4'     #  0x80 -> LATIN CAPITAL LETTER A WITH DIAERESIS
    u'\xc5'     #  0x81 -> LATIN CAPITAL LETTER A WITH RING ABOVE
    u'\xc7'     #  0x82 -> LATIN CAPITAL LETTER C WITH CEDILLA
    u'\xc9'     #  0x83 -> LATIN CAPITAL LETTER E WITH ACUTE
    u'\xd1'     #  0x84 -> LATIN CAPITAL LETTER N WITH TILDE
    u'\xd6'     #  0x85 -> LATIN CAPITAL LETTER O WITH DIAERESIS
    u'\xdc'     #  0x86 -> LATIN CAPITAL LETTER U WITH DIAERESIS
    u'\xe1'     #  0x87 -> LATIN SMALL LETTER A WITH ACUTE
    u'\xe0'     #  0x88 -> LATIN SMALL LETTER A WITH GRAVE
    u'\xe2'     #  0x89 -> LATIN SMALL LETTER A WITH CIRCUMFLEX
    u'\xe4'     #  0x8A -> LATIN SMALL LETTER A WITH DIAERESIS
    u'\xe3'     #  0x8B -> LATIN SMALL LETTER A WITH TILDE
    u'\xe5'     #  0x8C -> LATIN SMALL LETTER A WITH RING ABOVE
    u'\xe7'     #  0x8D -> LATIN SMALL LETTER C WITH CEDILLA
    u'\xe9'     #  0x8E -> LATIN SMALL LETTER E WITH ACUTE
    u'\xe8'     #  0x8F -> LATIN SMALL LETTER E WITH GRAVE
    u'\xea'     #  0x90 -> LATIN SMALL LETTER E WITH CIRCUMFLEX
    u'\xeb'     #  0x91 -> LATIN SMALL LETTER E WITH DIAERESIS
    u'\xed'     #  0x92 -> LATIN SMALL LETTER I WITH ACUTE
    u'\xec'     #  0x93 -> LATIN SMALL LETTER I WITH GRAVE
    u'\xee'     #  0x94 -> LATIN SMALL LETTER I WITH CIRCUMFLEX
    u'\xef'     #  0x95 -> LATIN SMALL LETTER I WITH DIAERESIS
    u'\xf1'     #  0x96 -> LATIN SMALL LETTER N WITH TILDE
    u'\xf3'     #  0x97 -> LATIN SMALL LETTER O WITH ACUTE
    u'\xf2'     #  0x98 -> LATIN SMALL LETTER O WITH GRAVE
    u'\xf4'     #  0x99 -> LATIN SMALL LETTER O WITH CIRCUMFLEX
    u'\xf6'     #  0x9A -> LATIN SMALL LETTER O WITH DIAERESIS
    u'\xf5'     #  0x9B -> LATIN SMALL LETTER O WITH TILDE
    u'\xfa'     #  0x9C -> LATIN SMALL LETTER U WITH ACUTE
    u'\xf9'     #  0x9D -> LATIN SMALL LETTER U WITH GRAVE
    u'\xfb'     #  0x9E -> LATIN SMALL LETTER U WITH CIRCUMFLEX
    u'\xfc'     #  0x9F -> LATIN SMALL LETTER U WITH DIAERESIS
    u'\xdd'     #  0xA0 -> LATIN CAPITAL LETTER Y WITH ACUTE
    u'\xb0'     #  0xA1 -> DEGREE SIGN
    u'\xa2'     #  0xA2 -> CENT SIGN
    u'\xa3'     #  0xA3 -> POUND SIGN
    u'\xa7'     #  0xA4 -> SECTION SIGN
    u'\u2022'   #  0xA5 -> BULLET
    u'\xb6'     #  0xA6 -> PILCROW SIGN
    u'\xdf'     #  0xA7 -> LATIN SMALL LETTER SHARP S
    u'\xae'     #  0xA8 -> REGISTERED SIGN
    u'\xa9'     #  0xA9 -> COPYRIGHT SIGN
    u'\u2122'   #  0xAA -> TRADE MARK SIGN
    u'\xb4'     #  0xAB -> ACUTE ACCENT
    u'\xa8'     #  0xAC -> DIAERESIS
    u'\u2260'   #  0xAD -> NOT EQUAL TO
    u'\xc6'     #  0xAE -> LATIN CAPITAL LETTER AE
    u'\xd8'     #  0xAF -> LATIN CAPITAL LETTER O WITH STROKE
    u'\u221e'   #  0xB0 -> INFINITY
    u'\xb1'     #  0xB1 -> PLUS-MINUS SIGN
    u'\u2264'   #  0xB2 -> LESS-THAN OR EQUAL TO
    u'\u2265'   #  0xB3 -> GREATER-THAN OR EQUAL TO
    u'\xa5'     #  0xB4 -> YEN SIGN
    u'\xb5'     #  0xB5 -> MICRO SIGN
    u'\u2202'   #  0xB6 -> PARTIAL DIFFERENTIAL
    u'\u2211'   #  0xB7 -> N-ARY SUMMATION
    u'\u220f'   #  0xB8 -> N-ARY PRODUCT
    u'\u03c0'   #  0xB9 -> GREEK SMALL LETTER PI
    u'\u222b'   #  0xBA -> INTEGRAL
    u'\xaa'     #  0xBB -> FEMININE ORDINAL INDICATOR
    u'\xba'     #  0xBC -> MASCULINE ORDINAL INDICATOR
    u'\u03a9'   #  0xBD -> GREEK CAPITAL LETTER OMEGA
    u'\xe6'     #  0xBE -> LATIN SMALL LETTER AE
    u'\xf8'     #  0xBF -> LATIN SMALL LETTER O WITH STROKE
    u'\xbf'     #  0xC0 -> INVERTED QUESTION MARK
    u'\xa1'     #  0xC1 -> INVERTED EXCLAMATION MARK
    u'\xac'     #  0xC2 -> NOT SIGN
    u'\u221a'   #  0xC3 -> SQUARE ROOT
    u'\u0192'   #  0xC4 -> LATIN SMALL LETTER F WITH HOOK
    u'\u2248'   #  0xC5 -> ALMOST EQUAL TO
    u'\u2206'   #  0xC6 -> INCREMENT
    u'\xab'     #  0xC7 -> LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
    u'\xbb'     #  0xC8 -> RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
    u'\u2026'   #  0xC9 -> HORIZONTAL ELLIPSIS
    u'\xa0'     #  0xCA -> NO-BREAK SPACE
    u'\xc0'     #  0xCB -> LATIN CAPITAL LETTER A WITH GRAVE
    u'\xc3'     #  0xCC -> LATIN CAPITAL LETTER A WITH TILDE
    u'\xd5'     #  0xCD -> LATIN CAPITAL LETTER O WITH TILDE
    u'\u0152'   #  0xCE -> LATIN CAPITAL LIGATURE OE
    u'\u0153'   #  0xCF -> LATIN SMALL LIGATURE OE
    u'\u2013'   #  0xD0 -> EN DASH
    u'\u2014'   #  0xD1 -> EM DASH
    u'\u201c'   #  0xD2 -> LEFT DOUBLE QUOTATION MARK
    u'\u201d'   #  0xD3 -> RIGHT DOUBLE QUOTATION MARK
    u'\u2018'   #  0xD4 -> LEFT SINGLE QUOTATION MARK
    u'\u2019'   #  0xD5 -> RIGHT SINGLE QUOTATION MARK
    u'\xf7'     #  0xD6 -> DIVISION SIGN
    u'\u25ca'   #  0xD7 -> LOZENGE
    u'\xff'     #  0xD8 -> LATIN SMALL LETTER Y WITH DIAERESIS
    u'\u0178'   #  0xD9 -> LATIN CAPITAL LETTER Y WITH DIAERESIS
    u'\u2044'   #  0xDA -> FRACTION SLASH
    u'\u20ac'   #  0xDB -> EURO SIGN
    u'\xd0'     #  0xDC -> LATIN CAPITAL LETTER ETH
    u'\xf0'     #  0xDD -> LATIN SMALL LETTER ETH
    u'\xde'     #  0xDE -> LATIN CAPITAL LETTER THORN
    u'\xfe'     #  0xDF -> LATIN SMALL LETTER THORN
    u'\xfd'     #  0xE0 -> LATIN SMALL LETTER Y WITH ACUTE
    u'\xb7'     #  0xE1 -> MIDDLE DOT
    u'\u201a'   #  0xE2 -> SINGLE LOW-9 QUOTATION MARK
    u'\u201e'   #  0xE3 -> DOUBLE LOW-9 QUOTATION MARK
    u'\u2030'   #  0xE4 -> PER MILLE SIGN
    u'\xc2'     #  0xE5 -> LATIN CAPITAL LETTER A WITH CIRCUMFLEX
    u'\xca'     #  0xE6 -> LATIN CAPITAL LETTER E WITH CIRCUMFLEX
    u'\xc1'     #  0xE7 -> LATIN CAPITAL LETTER A WITH ACUTE
    u'\xcb'     #  0xE8 -> LATIN CAPITAL LETTER E WITH DIAERESIS
    u'\xc8'     #  0xE9 -> LATIN CAPITAL LETTER E WITH GRAVE
    u'\xcd'     #  0xEA -> LATIN CAPITAL LETTER I WITH ACUTE
    u'\xce'     #  0xEB -> LATIN CAPITAL LETTER I WITH CIRCUMFLEX
    u'\xcf'     #  0xEC -> LATIN CAPITAL LETTER I WITH DIAERESIS
    u'\xcc'     #  0xED -> LATIN CAPITAL LETTER I WITH GRAVE
    u'\xd3'     #  0xEE -> LATIN CAPITAL LETTER O WITH ACUTE
    u'\xd4'     #  0xEF -> LATIN CAPITAL LETTER O WITH CIRCUMFLEX
    u'\uf8ff'   #  0xF0 -> Apple logo
    u'\xd2'     #  0xF1 -> LATIN CAPITAL LETTER O WITH GRAVE
    u'\xda'     #  0xF2 -> LATIN CAPITAL LETTER U WITH ACUTE
    u'\xdb'     #  0xF3 -> LATIN CAPITAL LETTER U WITH CIRCUMFLEX
    u'\xd9'     #  0xF4 -> LATIN CAPITAL LETTER U WITH GRAVE
    u'\u0131'   #  0xF5 -> LATIN SMALL LETTER DOTLESS I
    u'\u02c6'   #  0xF6 -> MODIFIER LETTER CIRCUMFLEX ACCENT
    u'\u02dc'   #  0xF7 -> SMALL TILDE
    u'\xaf'     #  0xF8 -> MACRON
    u'\u02d8'   #  0xF9 -> BREVE
    u'\u02d9'   #  0xFA -> DOT ABOVE
    u'\u02da'   #  0xFB -> RING ABOVE
    u'\xb8'     #  0xFC -> CEDILLA
    u'\u02dd'   #  0xFD -> DOUBLE ACUTE ACCENT
    u'\u02db'   #  0xFE -> OGONEK
    u'\u02c7'   #  0xFF -> CARON
)

### Encoding Map

encoding_map = {
    0x0000: 0x00,       #  CONTROL CHARACTER
    0x0001: 0x01,       #  CONTROL CHARACTER
    0x0002: 0x02,       #  CONTROL CHARACTER
    0x0003: 0x03,       #  CONTROL CHARACTER
    0x0004: 0x04,       #  CONTROL CHARACTER
    0x0005: 0x05,       #  CONTROL CHARACTER
    0x0006: 0x06,       #  CONTROL CHARACTER
    0x0007: 0x07,       #  CONTROL CHARACTER
    0x0008: 0x08,       #  CONTROL CHARACTER
    0x0009: 0x09,       #  CONTROL CHARACTER
    0x000A: 0x0A,       #  CONTROL CHARACTER
    0x000B: 0x0B,       #  CONTROL CHARACTER
    0x000C: 0x0C,       #  CONTROL CHARACTER
    0x000D: 0x0D,       #  CONTROL CHARACTER
    0x000E: 0x0E,       #  CONTROL CHARACTER
    0x000F: 0x0F,       #  CONTROL CHARACTER
    0x0010: 0x10,       #  CONTROL CHARACTER
    0x0011: 0x11,       #  CONTROL CHARACTER
    0x0012: 0x12,       #  CONTROL CHARACTER
    0x0013: 0x13,       #  CONTROL CHARACTER
    0x0014: 0x14,       #  CONTROL CHARACTER
    0x0015: 0x15,       #  CONTROL CHARACTER
    0x0016: 0x16,       #  CONTROL CHARACTER
    0x0017: 0x17,       #  CONTROL CHARACTER
    0x0018: 0x18,       #  CONTROL CHARACTER
    0x0019: 0x19,       #  CONTROL CHARACTER
    0x001A: 0x1A,       #  CONTROL CHARACTER
    0x001B: 0x1B,       #  CONTROL CHARACTER
    0x001C: 0x1C,       #  CONTROL CHARACTER
    0x001D: 0x1D,       #  CONTROL CHARACTER
    0x001E: 0x1E,       #  CONTROL CHARACTER
    0x001F: 0x1F,       #  CONTROL CHARACTER
    0x0020: 0x20,       #  SPACE
    0x0021: 0x21,       #  EXCLAMATION MARK
    0x0022: 0x22,       #  QUOTATION MARK
    0x0023: 0x23,       #  NUMBER SIGN
    0x0024: 0x24,       #  DOLLAR SIGN
    0x0025: 0x25,       #  PERCENT SIGN
    0x0026: 0x26,       #  AMPERSAND
    0x0027: 0x27,       #  APOSTROPHE
    0x0028: 0x28,       #  LEFT PARENTHESIS
    0x0029: 0x29,       #  RIGHT PARENTHESIS
    0x002A: 0x2A,       #  ASTERISK
    0x002B: 0x2B,       #  PLUS SIGN
    0x002C: 0x2C,       #  COMMA
    0x002D: 0x2D,       #  HYPHEN-MINUS
    0x002E: 0x2E,       #  FULL STOP
    0x002F: 0x2F,       #  SOLIDUS
    0x0030: 0x30,       #  DIGIT ZERO
    0x0031: 0x31,       #  DIGIT ONE
    0x0032: 0x32,       #  DIGIT TWO
    0x0033: 0x33,       #  DIGIT THREE
    0x0034: 0x34,       #  DIGIT FOUR
    0x0035: 0x35,       #  DIGIT FIVE
    0x0036: 0x36,       #  DIGIT SIX
    0x0037: 0x37,       #  DIGIT SEVEN
    0x0038: 0x38,       #  DIGIT EIGHT
    0x0039: 0x39,       #  DIGIT NINE
    0x003A: 0x3A,       #  COLON
    0x003B: 0x3B,       #  SEMICOLON
    0x003C: 0x3C,       #  LESS-THAN SIGN
    0x003D: 0x3D,       #  EQUALS SIGN
    0x003E: 0x3E,       #  GREATER-THAN SIGN
    0x003F: 0x3F,       #  QUESTION MARK
    0x0040: 0x40,       #  COMMERCIAL AT
    0x0041: 0x41,       #  LATIN CAPITAL LETTER A
    0x0042: 0x42,       #  LATIN CAPITAL LETTER B
    0x0043: 0x43,       #  LATIN CAPITAL LETTER C
    0x0044: 0x44,       #  LATIN CAPITAL LETTER D
    0x0045: 0x45,       #  LATIN CAPITAL LETTER E
    0x0046: 0x46,       #  LATIN CAPITAL LETTER F
    0x0047: 0x47,       #  LATIN CAPITAL LETTER G
    0x0048: 0x48,       #  LATIN CAPITAL LETTER H
    0x0049: 0x49,       #  LATIN CAPITAL LETTER I
    0x004A: 0x4A,       #  LATIN CAPITAL LETTER J
    0x004B: 0x4B,       #  LATIN CAPITAL LETTER K
    0x004C: 0x4C,       #  LATIN CAPITAL LETTER L
    0x004D: 0x4D,       #  LATIN CAPITAL LETTER M
    0x004E: 0x4E,       #  LATIN CAPITAL LETTER N
    0x004F: 0x4F,       #  LATIN CAPITAL LETTER O
    0x0050: 0x50,       #  LATIN CAPITAL LETTER P
    0x0051: 0x51,       #  LATIN CAPITAL LETTER Q
    0x0052: 0x52,       #  LATIN CAPITAL LETTER R
    0x0053: 0x53,       #  LATIN CAPITAL LETTER S
    0x0054: 0x54,       #  LATIN CAPITAL LETTER T
    0x0055: 0x55,       #  LATIN CAPITAL LETTER U
    0x0056: 0x56,       #  LATIN CAPITAL LETTER V
    0x0057: 0x57,       #  LATIN CAPITAL LETTER W
    0x0058: 0x58,       #  LATIN CAPITAL LETTER X
    0x0059: 0x59,       #  LATIN CAPITAL LETTER Y
    0x005A: 0x5A,       #  LATIN CAPITAL LETTER Z
    0x005B: 0x5B,       #  LEFT SQUARE BRACKET
    0x005C: 0x5C,       #  REVERSE SOLIDUS
    0x005D: 0x5D,       #  RIGHT SQUARE BRACKET
    0x005E: 0x5E,       #  CIRCUMFLEX ACCENT
    0x005F: 0x5F,       #  LOW LINE
    0x0060: 0x60,       #  GRAVE ACCENT
    0x0061: 0x61,       #  LATIN SMALL LETTER A
    0x0062: 0x62,       #  LATIN SMALL LETTER B
    0x0063: 0x63,       #  LATIN SMALL LETTER C
    0x0064: 0x64,       #  LATIN SMALL LETTER D
    0x0065: 0x65,       #  LATIN SMALL LETTER E
    0x0066: 0x66,       #  LATIN SMALL LETTER F
    0x0067: 0x67,       #  LATIN SMALL LETTER G
    0x0068: 0x68,       #  LATIN SMALL LETTER H
    0x0069: 0x69,       #  LATIN SMALL LETTER I
    0x006A: 0x6A,       #  LATIN SMALL LETTER J
    0x006B: 0x6B,       #  LATIN SMALL LETTER K
    0x006C: 0x6C,       #  LATIN SMALL LETTER L
    0x006D: 0x6D,       #  LATIN SMALL LETTER M
    0x006E: 0x6E,       #  LATIN SMALL LETTER N
    0x006F: 0x6F,       #  LATIN SMALL LETTER O
    0x0070: 0x70,       #  LATIN SMALL LETTER P
    0x0071: 0x71,       #  LATIN SMALL LETTER Q
    0x0072: 0x72,       #  LATIN SMALL LETTER R
    0x0073: 0x73,       #  LATIN SMALL LETTER S
    0x0074: 0x74,       #  LATIN SMALL LETTER T
    0x0075: 0x75,       #  LATIN SMALL LETTER U
    0x0076: 0x76,       #  LATIN SMALL LETTER V
    0x0077: 0x77,       #  LATIN SMALL LETTER W
    0x0078: 0x78,       #  LATIN SMALL LETTER X
    0x0079: 0x79,       #  LATIN SMALL LETTER Y
    0x007A: 0x7A,       #  LATIN SMALL LETTER Z
    0x007B: 0x7B,       #  LEFT CURLY BRACKET
    0x007C: 0x7C,       #  VERTICAL LINE
    0x007D: 0x7D,       #  RIGHT CURLY BRACKET
    0x007E: 0x7E,       #  TILDE
    0x007F: 0x7F,       #  CONTROL CHARACTER
    0x00A0: 0xCA,       #  NO-BREAK SPACE
    0x00A1: 0xC1,       #  INVERTED EXCLAMATION MARK
    0x00A2: 0xA2,       #  CENT SIGN
    0x00A3: 0xA3,       #  POUND SIGN
    0x00A5: 0xB4,       #  YEN SIGN
    0x00A7: 0xA4,       #  SECTION SIGN
    0x00A8: 0xAC,       #  DIAERESIS
    0x00A9: 0xA9,       #  COPYRIGHT SIGN
    0x00AA: 0xBB,       #  FEMININE ORDINAL INDICATOR
    0x00AB: 0xC7,       #  LEFT-POINTING DOUBLE ANGLE QUOTATION MARK
    0x00AC: 0xC2,       #  NOT SIGN
    0x00AE: 0xA8,       #  REGISTERED SIGN
    0x00AF: 0xF8,       #  MACRON
    0x00B0: 0xA1,       #  DEGREE SIGN
    0x00B1: 0xB1,       #  PLUS-MINUS SIGN
    0x00B4: 0xAB,       #  ACUTE ACCENT
    0x00B5: 0xB5,       #  MICRO SIGN
    0x00B6: 0xA6,       #  PILCROW SIGN
    0x00B7: 0xE1,       #  MIDDLE DOT
    0x00B8: 0xFC,       #  CEDILLA
    0x00BA: 0xBC,       #  MASCULINE ORDINAL INDICATOR
    0x00BB: 0xC8,       #  RIGHT-POINTING DOUBLE ANGLE QUOTATION MARK
    0x00BF: 0xC0,       #  INVERTED QUESTION MARK
    0x00C0: 0xCB,       #  LATIN CAPITAL LETTER A WITH GRAVE
    0x00C1: 0xE7,       #  LATIN CAPITAL LETTER A WITH ACUTE
    0x00C2: 0xE5,       #  LATIN CAPITAL LETTER A WITH CIRCUMFLEX
    0x00C3: 0xCC,       #  LATIN CAPITAL LETTER A WITH TILDE
    0x00C4: 0x80,       #  LATIN CAPITAL LETTER A WITH DIAERESIS
    0x00C5: 0x81,       #  LATIN CAPITAL LETTER A WITH RING ABOVE
    0x00C6: 0xAE,       #  LATIN CAPITAL LETTER AE
    0x00C7: 0x82,       #  LATIN CAPITAL LETTER C WITH CEDILLA
    0x00C8: 0xE9,       #  LATIN CAPITAL LETTER E WITH GRAVE
    0x00C9: 0x83,       #  LATIN CAPITAL LETTER E WITH ACUTE
    0x00CA: 0xE6,       #  LATIN CAPITAL LETTER E WITH CIRCUMFLEX
    0x00CB: 0xE8,       #  LATIN CAPITAL LETTER E WITH DIAERESIS
    0x00CC: 0xED,       #  LATIN CAPITAL LETTER I WITH GRAVE
    0x00CD: 0xEA,       #  LATIN CAPITAL LETTER I WITH ACUTE
    0x00CE: 0xEB,       #  LATIN CAPITAL LETTER I WITH CIRCUMFLEX
    0x00CF: 0xEC,       #  LATIN CAPITAL LETTER I WITH DIAERESIS
    0x00D0: 0xDC,       #  LATIN CAPITAL LETTER ETH
    0x00D1: 0x84,       #  LATIN CAPITAL LETTER N WITH TILDE
    0x00D2: 0xF1,       #  LATIN CAPITAL LETTER O WITH GRAVE
    0x00D3: 0xEE,       #  LATIN CAPITAL LETTER O WITH ACUTE
    0x00D4: 0xEF,       #  LATIN CAPITAL LETTER O WITH CIRCUMFLEX
    0x00D5: 0xCD,       #  LATIN CAPITAL LETTER O WITH TILDE
    0x00D6: 0x85,       #  LATIN CAPITAL LETTER O WITH DIAERESIS
    0x00D8: 0xAF,       #  LATIN CAPITAL LETTER O WITH STROKE
    0x00D9: 0xF4,       #  LATIN CAPITAL LETTER U WITH GRAVE
    0x00DA: 0xF2,       #  LATIN CAPITAL LETTER U WITH ACUTE
    0x00DB: 0xF3,       #  LATIN CAPITAL LETTER U WITH CIRCUMFLEX
    0x00DC: 0x86,       #  LATIN CAPITAL LETTER U WITH DIAERESIS
    0x00DD: 0xA0,       #  LATIN CAPITAL LETTER Y WITH ACUTE
    0x00DE: 0xDE,       #  LATIN CAPITAL LETTER THORN
    0x00DF: 0xA7,       #  LATIN SMALL LETTER SHARP S
    0x00E0: 0x88,       #  LATIN SMALL LETTER A WITH GRAVE
    0x00E1: 0x87,       #  LATIN SMALL LETTER A WITH ACUTE
    0x00E2: 0x89,       #  LATIN SMALL LETTER A WITH CIRCUMFLEX
    0x00E3: 0x8B,       #  LATIN SMALL LETTER A WITH TILDE
    0x00E4: 0x8A,       #  LATIN SMALL LETTER A WITH DIAERESIS
    0x00E5: 0x8C,       #  LATIN SMALL LETTER A WITH RING ABOVE
    0x00E6: 0xBE,       #  LATIN SMALL LETTER AE
    0x00E7: 0x8D,       #  LATIN SMALL LETTER C WITH CEDILLA
    0x00E8: 0x8F,       #  LATIN SMALL LETTER E WITH GRAVE
    0x00E9: 0x8E,       #  LATIN SMALL LETTER E WITH ACUTE
    0x00EA: 0x90,       #  LATIN SMALL LETTER E WITH CIRCUMFLEX
    0x00EB: 0x91,       #  LATIN SMALL LETTER E WITH DIAERESIS
    0x00EC: 0x93,       #  LATIN SMALL LETTER I WITH GRAVE
    0x00ED: 0x92,       #  LATIN SMALL LETTER I WITH ACUTE
    0x00EE: 0x94,       #  LATIN SMALL LETTER I WITH CIRCUMFLEX
    0x00EF: 0x95,       #  LATIN SMALL LETTER I WITH DIAERESIS
    0x00F0: 0xDD,       #  LATIN SMALL LETTER ETH
    0x00F1: 0x96,       #  LATIN SMALL LETTER N WITH TILDE
    0x00F2: 0x98,       #  LATIN SMALL LETTER O WITH GRAVE
    0x00F3: 0x97,       #  LATIN SMALL LETTER O WITH ACUTE
    0x00F4: 0x99,       #  LATIN SMALL LETTER O WITH CIRCUMFLEX
    0x00F5: 0x9B,       #  LATIN SMALL LETTER O WITH TILDE
    0x00F6: 0x9A,       #  LATIN SMALL LETTER O WITH DIAERESIS
    0x00F7: 0xD6,       #  DIVISION SIGN
    0x00F8: 0xBF,       #  LATIN SMALL LETTER O WITH STROKE
    0x00F9: 0x9D,       #  LATIN SMALL LETTER U WITH GRAVE
    0x00FA: 0x9C,       #  LATIN SMALL LETTER U WITH ACUTE
    0x00FB: 0x9E,       #  LATIN SMALL LETTER U WITH CIRCUMFLEX
    0x00FC: 0x9F,       #  LATIN SMALL LETTER U WITH DIAERESIS
    0x00FD: 0xE0,       #  LATIN SMALL LETTER Y WITH ACUTE
    0x00FE: 0xDF,       #  LATIN SMALL LETTER THORN
    0x00FF: 0xD8,       #  LATIN SMALL LETTER Y WITH DIAERESIS
    0x0131: 0xF5,       #  LATIN SMALL LETTER DOTLESS I
    0x0152: 0xCE,       #  LATIN CAPITAL LIGATURE OE
    0x0153: 0xCF,       #  LATIN SMALL LIGATURE OE
    0x0178: 0xD9,       #  LATIN CAPITAL LETTER Y WITH DIAERESIS
    0x0192: 0xC4,       #  LATIN SMALL LETTER F WITH HOOK
    0x02C6: 0xF6,       #  MODIFIER LETTER CIRCUMFLEX ACCENT
    0x02C7: 0xFF,       #  CARON
    0x02D8: 0xF9,       #  BREVE
    0x02D9: 0xFA,       #  DOT ABOVE
    0x02DA: 0xFB,       #  RING ABOVE
    0x02DB: 0xFE,       #  OGONEK
    0x02DC: 0xF7,       #  SMALL TILDE
    0x02DD: 0xFD,       #  DOUBLE ACUTE ACCENT
    0x03A9: 0xBD,       #  GREEK CAPITAL LETTER OMEGA
    0x03C0: 0xB9,       #  GREEK SMALL LETTER PI
    0x2013: 0xD0,       #  EN DASH
    0x2014: 0xD1,       #  EM DASH
    0x2018: 0xD4,       #  LEFT SINGLE QUOTATION MARK
    0x2019: 0xD5,       #  RIGHT SINGLE QUOTATION MARK
    0x201A: 0xE2,       #  SINGLE LOW-9 QUOTATION MARK
    0x201C: 0xD2,       #  LEFT DOUBLE QUOTATION MARK
    0x201D: 0xD3,       #  RIGHT DOUBLE QUOTATION MARK
    0x201E: 0xE3,       #  DOUBLE LOW-9 QUOTATION MARK
    0x2022: 0xA5,       #  BULLET
    0x2026: 0xC9,       #  HORIZONTAL ELLIPSIS
    0x2030: 0xE4,       #  PER MILLE SIGN
    0x2044: 0xDA,       #  FRACTION SLASH
    0x20AC: 0xDB,       #  EURO SIGN
    0x2122: 0xAA,       #  TRADE MARK SIGN
    0x2202: 0xB6,       #  PARTIAL DIFFERENTIAL
    0x2206: 0xC6,       #  INCREMENT
    0x220F: 0xB8,       #  N-ARY PRODUCT
    0x2211: 0xB7,       #  N-ARY SUMMATION
    0x221A: 0xC3,       #  SQUARE ROOT
    0x221E: 0xB0,       #  INFINITY
    0x222B: 0xBA,       #  INTEGRAL
    0x2248: 0xC5,       #  ALMOST EQUAL TO
    0x2260: 0xAD,       #  NOT EQUAL TO
    0x2264: 0xB2,       #  LESS-THAN OR EQUAL TO
    0x2265: 0xB3,       #  GREATER-THAN OR EQUAL TO
    0x25CA: 0xD7,       #  LOZENGE
    0xF8FF: 0xF0,       #  Apple logo
}
