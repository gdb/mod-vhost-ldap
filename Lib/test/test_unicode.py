""" Test script for the Unicode implementation.

Written by Marc-Andre Lemburg (mal@lemburg.com).

(c) Copyright CNRI, All Rights Reserved. NO WARRANTY.

"""
from test_support import verbose
import sys

def test(method, input, output, *args):
    if verbose:
        print '%s.%s%s =? %s... ' % (repr(input), method, args, output),
    try:
        f = getattr(input, method)
        value = apply(f, args)
    except:
        value = sys.exc_type
        exc = sys.exc_info()
    else:
        exc = None
    if value != output:
        if verbose:
            print 'no'
        print '*',f, `input`, `output`, `value`
        if exc:
            print '  value == %s: %s' % (exc[:2])
    else:
        if verbose:
            print 'yes'

test('capitalize', u' hello ', u' hello ')
test('capitalize', u'hello ', u'Hello ')

test('title', u' hello ', u' Hello ')
test('title', u'hello ', u'Hello ')
test('title', u"fOrMaT thIs aS titLe String", u'Format This As Title String')
test('title', u"fOrMaT,thIs-aS*titLe;String", u'Format,This-As*Title;String')
test('title', u"getInt", u'Getint')

test('find', u'abcdefghiabc', 0, u'abc')
test('find', u'abcdefghiabc', 9, u'abc', 1)
test('find', u'abcdefghiabc', -1, u'def', 4)

test('rfind', u'abcdefghiabc', 9, u'abc')

test('lower', u'HeLLo', u'hello')
test('lower', u'hello', u'hello')

test('upper', u'HeLLo', u'HELLO')
test('upper', u'HELLO', u'HELLO')

if 0:
    transtable = '\000\001\002\003\004\005\006\007\010\011\012\013\014\015\016\017\020\021\022\023\024\025\026\027\030\031\032\033\034\035\036\037 !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`xyzdefghijklmnopqrstuvwxyz{|}~\177\200\201\202\203\204\205\206\207\210\211\212\213\214\215\216\217\220\221\222\223\224\225\226\227\230\231\232\233\234\235\236\237\240\241\242\243\244\245\246\247\250\251\252\253\254\255\256\257\260\261\262\263\264\265\266\267\270\271\272\273\274\275\276\277\300\301\302\303\304\305\306\307\310\311\312\313\314\315\316\317\320\321\322\323\324\325\326\327\330\331\332\333\334\335\336\337\340\341\342\343\344\345\346\347\350\351\352\353\354\355\356\357\360\361\362\363\364\365\366\367\370\371\372\373\374\375\376\377'

    test('maketrans', u'abc', transtable, u'xyz')
    test('maketrans', u'abc', ValueError, u'xyzq')

test('split', u'this is the split function',
     [u'this', u'is', u'the', u'split', u'function'])
test('split', u'a|b|c|d', [u'a', u'b', u'c', u'd'], u'|')
test('split', u'a|b|c|d', [u'a', u'b', u'c|d'], u'|', 2)
test('split', u'a b c d', [u'a', u'b c d'], None, 1)
test('split', u'a b c d', [u'a', u'b', u'c d'], None, 2)
test('split', u'a b c d', [u'a', u'b', u'c', u'd'], None, 3)
test('split', u'a b c d', [u'a', u'b', u'c', u'd'], None, 4)
test('split', u'a b c d', [u'a b c d'], None, 0)
test('split', u'a  b  c  d', [u'a', u'b', u'c  d'], None, 2)
test('split', u'a b c d ', [u'a', u'b', u'c', u'd'])

# join now works with any sequence type
class Sequence:
    def __init__(self): self.seq = 'wxyz'
    def __len__(self): return len(self.seq)
    def __getitem__(self, i): return self.seq[i]

test('join', u' ', u'a b c d', [u'a', u'b', u'c', u'd'])
test('join', u'', u'abcd', (u'a', u'b', u'c', u'd'))
test('join', u' ', u'w x y z', Sequence())
test('join', u' ', TypeError, 7)

class BadSeq(Sequence):
    def __init__(self): self.seq = [7, u'hello', 123L]

test('join', u' ', TypeError, BadSeq())

result = u''
for i in range(10):
    if i > 0:
        result = result + u':'
    result = result + u'x'*10
test('join', u':', result, [u'x' * 10] * 10)
test('join', u':', result, (u'x' * 10,) * 10)

test('strip', u'   hello   ', u'hello')
test('lstrip', u'   hello   ', u'hello   ')
test('rstrip', u'   hello   ', u'   hello')
test('strip', u'hello', u'hello')

test('swapcase', u'HeLLo cOmpUteRs', u'hEllO CoMPuTErS')

if 0:
    test('translate', u'xyzabcdef', u'xyzxyz', transtable, u'def')

    table = string.maketrans('a', u'A')
    test('translate', u'abc', u'Abc', table)
    test('translate', u'xyz', u'xyz', table)

test('replace', u'one!two!three!', u'one@two!three!', u'!', u'@', 1)
test('replace', u'one!two!three!', u'onetwothree', '!', '')
test('replace', u'one!two!three!', u'one@two@three!', u'!', u'@', 2)
test('replace', u'one!two!three!', u'one@two@three@', u'!', u'@', 3)
test('replace', u'one!two!three!', u'one@two@three@', u'!', u'@', 4)
test('replace', u'one!two!three!', u'one!two!three!', u'!', u'@', 0)
test('replace', u'one!two!three!', u'one@two@three@', u'!', u'@')
test('replace', u'one!two!three!', u'one!two!three!', u'x', u'@')
test('replace', u'one!two!three!', u'one!two!three!', u'x', u'@', 2)

test('startswith', u'hello', 1, u'he')
test('startswith', u'hello', 1, u'hello')
test('startswith', u'hello', 0, u'hello world')
test('startswith', u'hello', 1, u'')
test('startswith', u'hello', 0, u'ello')
test('startswith', u'hello', 1, u'ello', 1)
test('startswith', u'hello', 1, u'o', 4)
test('startswith', u'hello', 0, u'o', 5)
test('startswith', u'hello', 1, u'', 5)
test('startswith', u'hello', 0, u'lo', 6)
test('startswith', u'helloworld', 1, u'lowo', 3)
test('startswith', u'helloworld', 1, u'lowo', 3, 7)
test('startswith', u'helloworld', 0, u'lowo', 3, 6)

test('endswith', u'hello', 1, u'lo')
test('endswith', u'hello', 0, u'he')
test('endswith', u'hello', 1, u'')
test('endswith', u'hello', 0, u'hello world')
test('endswith', u'helloworld', 0, u'worl')
test('endswith', u'helloworld', 1, u'worl', 3, 9)
test('endswith', u'helloworld', 1, u'world', 3, 12)
test('endswith', u'helloworld', 1, u'lowo', 1, 7)
test('endswith', u'helloworld', 1, u'lowo', 2, 7)
test('endswith', u'helloworld', 1, u'lowo', 3, 7)
test('endswith', u'helloworld', 0, u'lowo', 4, 7)
test('endswith', u'helloworld', 0, u'lowo', 3, 8)
test('endswith', u'ab', 0, u'ab', 0, 1)
test('endswith', u'ab', 0, u'ab', 0, 0)

test('expandtabs', u'abc\rab\tdef\ng\thi', u'abc\rab      def\ng       hi')
test('expandtabs', u'abc\rab\tdef\ng\thi', u'abc\rab      def\ng       hi', 8)
test('expandtabs', u'abc\rab\tdef\ng\thi', u'abc\rab  def\ng   hi', 4)
test('expandtabs', u'abc\r\nab\tdef\ng\thi', u'abc\r\nab  def\ng   hi', 4)

if 0:
    test('capwords', u'abc def ghi', u'Abc Def Ghi')
    test('capwords', u'abc\tdef\nghi', u'Abc Def Ghi')
    test('capwords', u'abc\t   def  \nghi', u'Abc Def Ghi')

# Comparisons:
print 'Testing Unicode comparisons...',
assert u'abc' == 'abc'
assert 'abc' == u'abc'
assert u'abc' == u'abc'
assert u'abcd' > 'abc'
assert 'abcd' > u'abc'
assert u'abcd' > u'abc'
assert u'abc' < 'abcd'
assert 'abc' < u'abcd'
assert u'abc' < u'abcd'
print 'done.'

test('ljust', u'abc',  u'abc       ', 10)
test('rjust', u'abc',  u'       abc', 10)
test('center', u'abc', u'   abc    ', 10)
test('ljust', u'abc',  u'abc   ', 6)
test('rjust', u'abc',  u'   abc', 6)
test('center', u'abc', u' abc  ', 6)
test('ljust', u'abc', u'abc', 2)
test('rjust', u'abc', u'abc', 2)
test('center', u'abc', u'abc', 2)

test('islower', u'a', 1)
test('islower', u'A', 0)
test('islower', u'\n', 0)
test('islower', u'\u1FFc', 0)
test('islower', u'abc', 1)
test('islower', u'aBc', 0)
test('islower', u'abc\n', 1)

test('isupper', u'a', 0)
test('isupper', u'A', 1)
test('isupper', u'\n', 0)
test('isupper', u'\u1FFc', 0)
test('isupper', u'ABC', 1)
test('isupper', u'AbC', 0)
test('isupper', u'ABC\n', 1)

test('istitle', u'a', 0)
test('istitle', u'A', 1)
test('istitle', u'\n', 0)
test('istitle', u'\u1FFc', 1)
test('istitle', u'A Titlecased Line', 1)
test('istitle', u'A\nTitlecased Line', 1)
test('istitle', u'A Titlecased, Line', 1)
test('istitle', u'Greek \u1FFcitlecases ...', 1)
test('istitle', u'Not a capitalized String', 0)
test('istitle', u'Not\ta Titlecase String', 0)
test('istitle', u'Not--a Titlecase String', 0)

test('splitlines', u"abc\ndef\n\rghi", [u'abc', u'def', u'', u'ghi'])
test('splitlines', u"abc\ndef\n\r\nghi", [u'abc', u'def', u'', u'ghi'])
test('splitlines', u"abc\ndef\r\nghi", [u'abc', u'def', u'ghi'])
test('splitlines', u"abc\ndef\r\nghi\n", [u'abc', u'def', u'ghi'])
test('splitlines', u"abc\ndef\r\nghi\n\r", [u'abc', u'def', u'ghi', u''])
test('splitlines', u"\nabc\ndef\r\nghi\n\r", [u'', u'abc', u'def', u'ghi', u''])
test('splitlines', u"\nabc\ndef\r\nghi\n\r", [u'', u'abc\012def\015\012ghi\012\015'], 1)
test('splitlines', u"\nabc\ndef\r\nghi\n\r", [u'', u'abc', u'def\015\012ghi\012\015'], 2)

test('translate', u"abababc", u'bbbc', {ord('a'):None})
test('translate', u"abababc", u'iiic', {ord('a'):None, ord('b'):ord('i')})
test('translate', u"abababc", u'iiix', {ord('a'):None, ord('b'):ord('i'), ord('c'):u'x'})

# Contains:
print 'Testing Unicode contains method...',
assert ('a' in 'abdb') == 1
assert ('a' in 'bdab') == 1
assert ('a' in 'bdaba') == 1
assert ('a' in 'bdba') == 1
assert ('a' in u'bdba') == 1
assert (u'a' in u'bdba') == 1
assert (u'a' in u'bdb') == 0
assert (u'a' in 'bdb') == 0
assert (u'a' in 'bdba') == 1
print 'done.'

# Formatting:
print 'Testing Unicode formatting strings...',
assert u"%s, %s" % (u"abc", "abc") == u'abc, abc'
assert u"%s, %s, %i, %f, %5.2f" % (u"abc", "abc", 1, 2, 3) == u'abc, abc, 1, 2.000000,  3.00'
assert u"%s, %s, %i, %f, %5.2f" % (u"abc", "abc", 1, -2, 3) == u'abc, abc, 1, -2.000000,  3.00'
assert u"%s, %s, %i, %f, %5.2f" % (u"abc", "abc", -1, -2, 3.5) == u'abc, abc, -1, -2.000000,  3.50'
assert u"%s, %s, %i, %f, %5.2f" % (u"abc", "abc", -1, -2, 3.57) == u'abc, abc, -1, -2.000000,  3.57'
assert u"%s, %s, %i, %f, %5.2f" % (u"abc", "abc", -1, -2, 1003.57) == u'abc, abc, -1, -2.000000, 1003.57'
assert u"%c" % (u"abc",) == u'a'
assert u"%c" % ("abc",) == u'a'
assert u"%c" % (34,) == u'"'
assert u"%c" % (36,) == u'$'
assert u"%r, %r" % (u"abc", "abc") == u"u'abc', 'abc'"
assert u"%(x)s, %(y)s" % {'x':u"abc", 'y':"def"} == u'abc, def'
assert u"%(x)s, %(�)s" % {'x':u"abc", u'�'.encode('utf-8'):"def"} == u'abc, def'
print 'done.'

# Test builtin codecs
print 'Testing builtin codecs...',

assert unicode('hello','ascii') == u'hello'
assert unicode('hello','utf-8') == u'hello'
assert unicode('hello','utf8') == u'hello'
assert unicode('hello','latin-1') == u'hello'

assert u'hello'.encode('ascii') == 'hello'
assert u'hello'.encode('utf-8') == 'hello'
assert u'hello'.encode('utf8') == 'hello'
assert u'hello'.encode('utf-16-le') == 'h\000e\000l\000l\000o\000'
assert u'hello'.encode('utf-16-be') == '\000h\000e\000l\000l\000o'
assert u'hello'.encode('latin-1') == 'hello'

u = u''.join(map(unichr, range(1024)))
for encoding in ('utf-8', 'utf-16', 'utf-16-le', 'utf-16-be',
                 'raw_unicode_escape', 'unicode_escape', 'unicode_internal'):
    assert unicode(u.encode(encoding),encoding) == u

u = u''.join(map(unichr, range(256)))
for encoding in ('latin-1',):
    assert unicode(u.encode(encoding),encoding) == u

u = u''.join(map(unichr, range(128)))
for encoding in ('ascii',):
    assert unicode(u.encode(encoding),encoding) == u

print 'done.'
