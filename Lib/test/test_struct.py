from test_support import TestFailed, verbose, verify
import struct
## import pdb

def simple_err(func, *args):
    try:
        apply(func, args)
    except struct.error:
        pass
    else:
        raise TestFailed, "%s%s did not raise struct.error" % (
            func.__name__, args)
##      pdb.set_trace()

def any_err(func, *args):
    try:
        apply(func, args)
    except (struct.error, OverflowError, TypeError):
        pass
    else:
        raise TestFailed, "%s%s did not raise error" % (
            func.__name__, args)
##      pdb.set_trace()

simple_err(struct.calcsize, 'Z')

sz = struct.calcsize('i')
if sz * 3 != struct.calcsize('iii'):
    raise TestFailed, 'inconsistent sizes'

fmt = 'cbxxxxxxhhhhiillffd'
fmt3 = '3c3b18x12h6i6l6f3d'
sz = struct.calcsize(fmt)
sz3 = struct.calcsize(fmt3)
if sz * 3 != sz3:
    raise TestFailed, 'inconsistent sizes (3*%s -> 3*%d = %d, %s -> %d)' % (
        `fmt`, sz, 3*sz, `fmt3`, sz3)

simple_err(struct.pack, 'iii', 3)
simple_err(struct.pack, 'i', 3, 3, 3)
simple_err(struct.pack, 'i', 'foo')
simple_err(struct.unpack, 'd', 'flap')
s = struct.pack('ii', 1, 2)
simple_err(struct.unpack, 'iii', s)
simple_err(struct.unpack, 'i', s)

c = 'a'
b = 1
h = 255
i = 65535
l = 65536
f = 3.1415
d = 3.1415

for prefix in ('', '@', '<', '>', '=', '!'):
    for format in ('xcbhilfd', 'xcBHILfd'):
        format = prefix + format
        if verbose:
            print "trying:", format
        s = struct.pack(format, c, b, h, i, l, f, d)
        cp, bp, hp, ip, lp, fp, dp = struct.unpack(format, s)
        if (cp != c or bp != b or hp != h or ip != i or lp != l or
            int(100 * fp) != int(100 * f) or int(100 * dp) != int(100 * d)):
            # ^^^ calculate only to two decimal places
            raise TestFailed, "unpack/pack not transitive (%s, %s)" % (
                str(format), str((cp, bp, hp, ip, lp, fp, dp)))

# Test some of the new features in detail

# (format, argument, big-endian result, little-endian result, asymmetric)
tests = [
    ('c', 'a', 'a', 'a', 0),
    ('xc', 'a', '\0a', '\0a', 0),
    ('cx', 'a', 'a\0', 'a\0', 0),
    ('s', 'a', 'a', 'a', 0),
    ('0s', 'helloworld', '', '', 1),
    ('1s', 'helloworld', 'h', 'h', 1),
    ('9s', 'helloworld', 'helloworl', 'helloworl', 1),
    ('10s', 'helloworld', 'helloworld', 'helloworld', 0),
    ('11s', 'helloworld', 'helloworld\0', 'helloworld\0', 1),
    ('20s', 'helloworld', 'helloworld'+10*'\0', 'helloworld'+10*'\0', 1),
    ('b', 7, '\7', '\7', 0),
    ('b', -7, '\371', '\371', 0),
    ('B', 7, '\7', '\7', 0),
    ('B', 249, '\371', '\371', 0),
    ('h', 700, '\002\274', '\274\002', 0),
    ('h', -700, '\375D', 'D\375', 0),
    ('H', 700, '\002\274', '\274\002', 0),
    ('H', 0x10000-700, '\375D', 'D\375', 0),
    ('i', 70000000, '\004,\035\200', '\200\035,\004', 0),
    ('i', -70000000, '\373\323\342\200', '\200\342\323\373', 0),
    ('I', 70000000L, '\004,\035\200', '\200\035,\004', 0),
    ('I', 0x100000000L-70000000, '\373\323\342\200', '\200\342\323\373', 0),
    ('l', 70000000, '\004,\035\200', '\200\035,\004', 0),
    ('l', -70000000, '\373\323\342\200', '\200\342\323\373', 0),
    ('L', 70000000L, '\004,\035\200', '\200\035,\004', 0),
    ('L', 0x100000000L-70000000, '\373\323\342\200', '\200\342\323\373', 0),
    ('f', 2.0, '@\000\000\000', '\000\000\000@', 0),
    ('d', 2.0, '@\000\000\000\000\000\000\000',
               '\000\000\000\000\000\000\000@', 0),
    ('f', -2.0, '\300\000\000\000', '\000\000\000\300', 0),
    ('d', -2.0, '\300\000\000\000\000\000\000\000',
               '\000\000\000\000\000\000\000\300', 0),
]

isbigendian = struct.pack('=i', 1)[0] == chr(0)

for fmt, arg, big, lil, asy in tests:
    if verbose:
        print `fmt`, `arg`, `big`, `lil`
    for (xfmt, exp) in [('>'+fmt, big), ('!'+fmt, big), ('<'+fmt, lil),
                        ('='+fmt, isbigendian and big or lil)]:
        res = struct.pack(xfmt, arg)
        if res != exp:
            raise TestFailed, "pack(%s, %s) -> %s # expected %s" % (
                `fmt`, `arg`, `res`, `exp`)
        n = struct.calcsize(xfmt)
        if n != len(res):
            raise TestFailed, "calcsize(%s) -> %d # expected %d" % (
                `xfmt`, n, len(res))
        rev = struct.unpack(xfmt, res)[0]
        if rev != arg and not asy:
            raise TestFailed, "unpack(%s, %s) -> (%s,) # expected (%s,)" % (
                `fmt`, `res`, `rev`, `arg`)

###########################################################################
# q/Q tests.

has_native_qQ = 1
try:
    struct.pack("q", 5)
except struct.error:
    has_native_qQ = 0

if verbose:
    print "Platform has native q/Q?", has_native_qQ and "Yes." or "No."

any_err(struct.pack, "Q", -1)   # can't pack -1 as unsigned regardless
simple_err(struct.pack, "q", "a")  # can't pack string as 'q' regardless
simple_err(struct.pack, "Q", "a")  # ditto, but 'Q'

def string_reverse(s):
    chars = list(s)
    chars.reverse()
    return "".join(chars)

def bigendian_to_native(value):
    if isbigendian:
        return value
    else:
        return string_reverse(value)

def test_native_qQ():
    bytes = struct.calcsize('q')
    # The expected values here are in big-endian format, primarily because
    # I'm on a little-endian machine and so this is the clearest way (for
    # me) to force the code to get exercised.
    for format, input, expected in (
            ('q', -1, '\xff' * bytes),
            ('q', 0, '\x00' * bytes),
            ('Q', 0, '\x00' * bytes),
            ('q', 1L, '\x00' * (bytes-1) + '\x01'),
            ('Q', (1L << (8*bytes))-1, '\xff' * bytes),
            ('q', (1L << (8*bytes-1))-1, '\x7f' + '\xff' * (bytes - 1))):
        got = struct.pack(format, input)
        native_expected = bigendian_to_native(expected)
        verify(got == native_expected,
               "%r-pack of %r gave %r, not %r" %
                    (format, input, got, native_expected))
        retrieved = struct.unpack(format, got)[0]
        verify(retrieved == input,
               "%r-unpack of %r gave %r, not %r" %
                    (format, got, retrieved, input))

if has_native_qQ:
    test_native_qQ()

# Standard q/Q (8 bytes; should work on all platforms).

MIN_Q, MAX_Q = 0, 2L**64 - 1
MIN_q, MAX_q = -(2L**63), 2L**63 - 1

import binascii
def test_one_qQ(x, pack=struct.pack,
                   unpack=struct.unpack,
                   unhexlify=binascii.unhexlify):
    if verbose:
        print "trying std q/Q on", x, "==", hex(x)

    # Try 'q'.
    if MIN_q <= x <= MAX_q:
        # Try '>q'.
        expected = long(x)
        if x < 0:
            expected += 1L << 64
            assert expected > 0
        expected = hex(expected)[2:-1] # chop "0x" and trailing 'L'
        if len(expected) & 1:
            expected = "0" + expected
        expected = unhexlify(expected)
        expected = "\x00" * (8 - len(expected)) + expected

        # >q pack work?
        got = pack(">q", x)
        verify(got == expected,
               "'>q'-pack of %r gave %r, not %r" %
                (x, got, expected))

        # >q unpack work?
        retrieved = unpack(">q", got)[0]
        verify(x == retrieved,
               "'>q'-unpack of %r gave %r, not %r" %
                (got, retrieved, x))

        # Adding any byte should cause a "too big" error.
        any_err(unpack, ">q", '\x01' + got)

        # Try '<q'.
        expected = string_reverse(expected)

        # <q pack work?
        got = pack("<q", x)
        verify(got == expected,
               "'<q'-pack of %r gave %r, not %r" %
                (x, got, expected))

        # <q unpack work?
        retrieved = unpack("<q", got)[0]
        verify(x == retrieved,
               "'<q'-unpack of %r gave %r, not %r" %
                (got, retrieved, x))

        # Adding any byte should cause a "too big" error.
        any_err(unpack, "<q", '\x01' + got)

    else:
        # x is out of q's range -- verify pack realizes that.
        any_err(pack, '>q', x)
        any_err(pack, '<q', x)

    # Much the same for 'Q'.
    if MIN_Q <= x <= MAX_Q:
        # Try '>Q'.
        expected = long(x)
        expected = hex(expected)[2:-1] # chop "0x" and trailing 'L'
        if len(expected) & 1:
            expected = "0" + expected
        expected = unhexlify(expected)
        expected = "\x00" * (8 - len(expected)) + expected

        # >Q pack work?
        got = pack(">Q", x)
        verify(got == expected,
               "'>Q'-pack of %r gave %r, not %r" %
                (x, got, expected))

        # >Q unpack work?
        retrieved = unpack(">Q", got)[0]
        verify(x == retrieved,
               "'>Q'-unpack of %r gave %r, not %r" %
                (got, retrieved, x))

        # Adding any byte should cause a "too big" error.
        any_err(unpack, ">Q", '\x01' + got)

        # Try '<Q'.
        expected = string_reverse(expected)

        # <Q pack work?
        got = pack("<Q", x)
        verify(got == expected,
               "'<Q'-pack of %r gave %r, not %r" %
                (x, got, expected))

        # <Q unpack work?
        retrieved = unpack("<Q", got)[0]
        verify(x == retrieved,
               "'<Q'-unpack of %r gave %r, not %r" %
                (got, retrieved, x))

        # Adding any byte should cause a "too big" error.
        any_err(unpack, "<Q", '\x01' + got)

    else:
        # x is out of Q's range -- verify pack realizes that.
        any_err(pack, '>Q', x)
        any_err(pack, '<Q', x)

def test_std_qQ():
    from random import randrange

    # Create all interesting powers of 2.
    values = []
    for exp in range(70):
        values.append(1L << exp)

    # Add some random 64-bit values.
    for i in range(50):
        val = 0L
        for j in range(8):
            val = (val << 8) | randrange(256)
        values.append(val)

    # Try all those, and their negations, and +-1 from them.  Note
    # that this tests all power-of-2 boundaries in range, and a few out
    # of range, plus +-(2**n +- 1).
    for base in values:
        for val in -base, base:
            for incr in -1, 0, 1:
                x = val + incr
                try:
                    x = int(x)
                except OverflowError:
                    pass
                test_one_qQ(x)

test_std_qQ()
