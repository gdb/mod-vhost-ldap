import sys
sys.path = ['.'] + sys.path

from test.test_support import verbose, run_suite
import re
import sys, os, traceback

# Misc tests from Tim Peters' re.doc

import unittest

class ReTests(unittest.TestCase):
    def test_search_star_plus(self):
        self.assertEqual(re.search('x*', 'axx').span(0), (0, 0))
        self.assertEqual(re.search('x*', 'axx').span(), (0, 0))
        self.assertEqual(re.search('x+', 'axx').span(0), (1, 3))
        self.assertEqual(re.search('x+', 'axx').span(), (1, 3))
        self.assertEqual(re.search('x', 'aaa') is None, True)
        self.assertEqual(re.match('a*', 'xxx').span(0), (0, 0))
        self.assertEqual(re.match('a*', 'xxx').span(), (0, 0))
        self.assertEqual(re.match('x*', 'xxxa').span(0), (0, 3))
        self.assertEqual(re.match('x*', 'xxxa').span(), (0, 3))
        self.assertEqual(re.match('a+', 'xxx') is None, True)

    def bump_num(self, matchobj):
        int_value = int(matchobj.group(0))
        return str(int_value + 1)

    def test_basic_re_sub(self):
        self.assertEqual(re.sub("(?i)b+", "x", "bbbb BBBB"), 'x x')
        self.assertEqual(re.sub(r'\d+', self.bump_num, '08.2 -2 23x99y'),
                         '9.3 -3 24x100y')
        self.assertEqual(re.sub(r'\d+', self.bump_num, '08.2 -2 23x99y', 3),
                         '9.3 -3 23x99y')

        self.assertEqual(re.sub('.', lambda m: r"\n", 'x'), '\\n')
        self.assertEqual(re.sub('.', r"\n", 'x'), '\n')

        s = r"\1\1"
        self.assertEqual(re.sub('(.)', s, 'x'), 'xx')
        self.assertEqual(re.sub('(.)', re.escape(s), 'x'), s)
        self.assertEqual(re.sub('(.)', lambda m: s, 'x'), s)

        self.assertEqual(re.sub('(?P<a>x)', '\g<a>\g<a>', 'xx'), 'xxxx')
        self.assertEqual(re.sub('(?P<a>x)', '\g<a>\g<1>', 'xx'), 'xxxx')
        self.assertEqual(re.sub('(?P<unk>x)', '\g<unk>\g<unk>', 'xx'), 'xxxx')
        self.assertEqual(re.sub('(?P<unk>x)', '\g<1>\g<1>', 'xx'), 'xxxx')

        self.assertEqual(re.sub('a',r'\t\n\v\r\f\a\b\B\Z\a\A\w\W\s\S\d\D','a'),
                         '\t\n\v\r\f\a\b\\B\\Z\a\\A\\w\\W\\s\\S\\d\\D')
        self.assertEqual(re.sub('a', '\t\n\v\r\f\a', 'a'), '\t\n\v\r\f\a')
        self.assertEqual(re.sub('a', '\t\n\v\r\f\a', 'a'),
                         (chr(9)+chr(10)+chr(11)+chr(13)+chr(12)+chr(7)))

        self.assertEqual(re.sub('^\s*', 'X', 'test'), 'Xtest')

    def test_escaped_re_sub(self):
        # Test for sub() on escaped characters, see SF bug #449000
        self.assertEqual(re.sub(r'\r\n', r'\n', 'abc\r\ndef\r\n'),
                         'abc\ndef\n')
        self.assertEqual(re.sub('\r\n', r'\n', 'abc\r\ndef\r\n'),
                         'abc\ndef\n')
        self.assertEqual(re.sub(r'\r\n', '\n', 'abc\r\ndef\r\n'),
                         'abc\ndef\n')
        self.assertEqual(re.sub('\r\n', '\n', 'abc\r\ndef\r\n'),
                         'abc\ndef\n')

    def test_qualified_re_sub(self):
        self.assertEqual(re.sub('a', 'b', 'aaaaa'), 'bbbbb')
        self.assertEqual(re.sub('a', 'b', 'aaaaa', 1), 'baaaa')

    def test_symbolic_refs(self):
        self.assertRaises(re.error, re.sub, '(?P<a>x)', '\g<a', 'xx')
        self.assertRaises(re.error, re.sub, '(?P<a>x)', '\g<', 'xx')
        self.assertRaises(re.error, re.sub, '(?P<a>x)', '\g', 'xx')
        self.assertRaises(re.error, re.sub, '(?P<a>x)', '\g<a a>', 'xx')
        self.assertRaises(re.error, re.sub, '(?P<a>x)', '\g<1a1>', 'xx')
        self.assertRaises(IndexError, re.sub, '(?P<a>x)', '\g<ab>', 'xx')
        self.assertRaises(re.error, re.sub, '(?P<a>x)|(?P<b>y)', '\g<b>', 'xx')
        self.assertRaises(re.error, re.sub, '(?P<a>x)|(?P<b>y)', '\\2', 'xx')

    def test_re_subn(self):
        self.assertEqual(re.subn("(?i)b+", "x", "bbbb BBBB"), ('x x', 2))
        self.assertEqual(re.subn("b+", "x", "bbbb BBBB"), ('x BBBB', 1))
        self.assertEqual(re.subn("b+", "x", "xyz"), ('xyz', 0))
        self.assertEqual(re.subn("b*", "x", "xyz"), ('xxxyxzx', 4))
        self.assertEqual(re.subn("b*", "x", "xyz", 2), ('xxxyz', 2))

    def test_re_split(self):
        self.assertEqual(re.split(":", ":a:b::c"), ['', 'a', 'b', '', 'c'])
        self.assertEqual(re.split(":*", ":a:b::c"), ['', 'a', 'b', 'c'])
        self.assertEqual(re.split("(:*)", ":a:b::c"),
                         ['', ':', 'a', ':', 'b', '::', 'c'])
        self.assertEqual(re.split("(?::*)", ":a:b::c"), ['', 'a', 'b', 'c'])
        self.assertEqual(re.split("(:)*", ":a:b::c"),
                         ['', ':', 'a', ':', 'b', ':', 'c'])
        self.assertEqual(re.split("([b:]+)", ":a:b::c"),
                         ['', ':', 'a', ':b::', 'c'])
        self.assertEqual(re.split("(b)|(:+)", ":a:b::c"),
                         ['', None, ':', 'a', None, ':', '', 'b', None, '',
                          None, '::', 'c'])
        self.assertEqual(re.split("(?:b)|(?::+)", ":a:b::c"),
                         ['', 'a', '', '', 'c'])

    def test_qualified_re_split(self):
        self.assertEqual(re.split(":", ":a:b::c", 2), ['', 'a', 'b::c'])
        self.assertEqual(re.split(':', 'a:b:c:d', 2), ['a', 'b', 'c:d'])
        self.assertEqual(re.split("(:)", ":a:b::c", 2),
                         ['', ':', 'a', ':', 'b::c'])
        self.assertEqual(re.split("(:*)", ":a:b::c", 2),
                         ['', ':', 'a', ':', 'b::c'])

    def test_re_findall(self):
        self.assertEqual(re.findall(":+", "abc"), [])
        self.assertEqual(re.findall(":+", "a:b::c:::d"), [":", "::", ":::"])
        self.assertEqual(re.findall("(:+)", "a:b::c:::d"), [":", "::", ":::"])
        self.assertEqual(re.findall("(:)(:*)", "a:b::c:::d"), [(":", ""),
                                                               (":", ":"),
                                                               (":", "::")])

    def test_re_match(self):
        # No groups at all
        m = re.match('a', 'a')
        self.assertEqual(m.groups(), ())
        # A single group
        m = re.match('(a)', 'a')
        self.assertEqual(m.groups(), ('a',))

        pat = re.compile('((a)|(b))(c)?')
        self.assertEqual(pat.match('a').groups(), ('a', 'a', None, None))
        self.assertEqual(pat.match('b').groups(), ('b', None, 'b', None))
        self.assertEqual(pat.match('ac').groups(), ('a', 'a', None, 'c'))
        self.assertEqual(pat.match('bc').groups(), ('b', None, 'b', 'c'))
        self.assertEqual(pat.match('bc').groups(""), ('b', "", 'b', 'c'))

        # A single group
        m = re.match('(a)', 'a')
        self.assertEqual(m.group(0), 'a')
        self.assertEqual(m.group(0), 'a')
        self.assertEqual(m.group(1), 'a')
        self.assertEqual(m.group(1, 1), ('a', 'a'))

        pat = re.compile('(?:(?P<a1>a)|(?P<b2>b))(?P<c3>c)?')
        self.assertEqual(pat.match('a').group(1, 2, 3), ('a', None, None))
        self.assertEqual(pat.match('b').group('a1', 'b2', 'c3'),
                         (None, 'b', None))
        self.assertEqual(pat.match('ac').group(1, 'b2', 3), ('a', None, 'c'))

    def test_re_escape(self):
        p=""
        for i in range(0, 256):
            p = p + chr(i)
            self.assertEqual(re.match(re.escape(chr(i)), chr(i)) is not None,
                             True)
            self.assertEqual(re.match(re.escape(chr(i)), chr(i)).span(), (0,1))

        pat=re.compile( re.escape(p) )
        self.assertEqual(pat.match(p) is not None, True)
        self.assertEqual(pat.match(p).span(), (0,256))

    def test_pickling(self):
        import pickle
        oldpat = re.compile('a(?:b|(c|e){1,2}?|d)+?(.)')
        s = pickle.dumps(oldpat)
        newpat = pickle.loads(s)
        self.assertEqual(oldpat, newpat)

    def test_constants(self):
        self.assertEqual(re.I, re.IGNORECASE)
        self.assertEqual(re.L, re.LOCALE)
        self.assertEqual(re.M, re.MULTILINE)
        self.assertEqual(re.S, re.DOTALL)
        self.assertEqual(re.X, re.VERBOSE)

    def test_flags(self):
        for flags in [re.I, re.M, re.X, re.S, re.L]:
            r = re.compile('^pattern$', flags)

    def test_limitations(self):
        # Try nasty case that overflows the straightforward recursive
        # implementation of repeated groups.
        try:
            re.match('(x)*', 50000*'x')
        except RuntimeError, v:
            self.assertEqual(str(v), "maximum recursion limit exceeded")
        else:
            self.fail("re.match('(x)*', 50000*'x') should have failed")

    def test_sre_character_literals(self):
        for i in [0, 8, 16, 32, 64, 127, 128, 255]:
            self.assertNotEqual(re.match(r"\%03o" % i, chr(i)), None)
            self.assertNotEqual(re.match(r"\%03o0" % i, chr(i)+"0"), None)
            self.assertNotEqual(re.match(r"\%03o8" % i, chr(i)+"8"), None)
            self.assertNotEqual(re.match(r"\x%02x" % i, chr(i)), None)
            self.assertNotEqual(re.match(r"\x%02x0" % i, chr(i)+"0"), None)
            self.assertNotEqual(re.match(r"\x%02xz" % i, chr(i)+"z"), None)
        self.assertRaises(re.error, re.match, "\911", "")

    def test_bug_113254(self):
        self.assertEqual(re.match(r'(a)|(b)', 'b').start(1), -1)
        self.assertEqual(re.match(r'(a)|(b)', 'b').end(1), -1)
        self.assertEqual(re.match(r'(a)|(b)', 'b').span(1), (-1, -1))

def run_re_tests():
    from test.re_tests import benchmarks, tests, SUCCEED, FAIL, SYNTAX_ERROR
    if verbose:
        print 'Running re_tests test suite'
    else:
        # To save time, only run the first and last 10 tests
        #tests = tests[:10] + tests[-10:]
        pass

    for t in tests:
        sys.stdout.flush()
        pattern = s = outcome = repl = expected = None
        if len(t) == 5:
            pattern, s, outcome, repl, expected = t
        elif len(t) == 3:
            pattern, s, outcome = t
        else:
            raise ValueError, ('Test tuples should have 3 or 5 fields', t)

        try:
            obj = re.compile(pattern)
        except re.error:
            if outcome == SYNTAX_ERROR: pass  # Expected a syntax error
            else:
                print '=== Syntax error:', t
        except KeyboardInterrupt: raise KeyboardInterrupt
        except:
            print '*** Unexpected error ***', t
            if verbose:
                traceback.print_exc(file=sys.stdout)
        else:
            try:
                result = obj.search(s)
            except re.error, msg:
                print '=== Unexpected exception', t, repr(msg)
            if outcome == SYNTAX_ERROR:
                # This should have been a syntax error; forget it.
                pass
            elif outcome == FAIL:
                if result is None: pass   # No match, as expected
                else: print '=== Succeeded incorrectly', t
            elif outcome == SUCCEED:
                if result is not None:
                    # Matched, as expected, so now we compute the
                    # result string and compare it to our expected result.
                    start, end = result.span(0)
                    vardict={'found': result.group(0),
                             'groups': result.group(),
                             'flags': result.re.flags}
                    for i in range(1, 100):
                        try:
                            gi = result.group(i)
                            # Special hack because else the string concat fails:
                            if gi is None:
                                gi = "None"
                        except IndexError:
                            gi = "Error"
                        vardict['g%d' % i] = gi
                    for i in result.re.groupindex.keys():
                        try:
                            gi = result.group(i)
                            if gi is None:
                                gi = "None"
                        except IndexError:
                            gi = "Error"
                        vardict[i] = gi
                    repl = eval(repl, vardict)
                    if repl != expected:
                        print '=== grouping error', t,
                        print repr(repl) + ' should be ' + repr(expected)
                else:
                    print '=== Failed incorrectly', t

                # Try the match on a unicode string, and check that it
                # still succeeds.
                try:
                    result = obj.search(unicode(s, "latin-1"))
                    if result is None:
                        print '=== Fails on unicode match', t
                except NameError:
                    continue # 1.5.2
                except TypeError:
                    continue # unicode test case

                # Try the match on a unicode pattern, and check that it
                # still succeeds.
                obj=re.compile(unicode(pattern, "latin-1"))
                result = obj.search(s)
                if result is None:
                    print '=== Fails on unicode pattern match', t

                # Try the match with the search area limited to the extent
                # of the match and see if it still succeeds.  \B will
                # break (because it won't match at the end or start of a
                # string), so we'll ignore patterns that feature it.

                if pattern[:2] != '\\B' and pattern[-2:] != '\\B' \
                               and result is not None:
                    obj = re.compile(pattern)
                    result = obj.search(s, result.start(0), result.end(0) + 1)
                    if result is None:
                        print '=== Failed on range-limited match', t

                # Try the match with IGNORECASE enabled, and check that it
                # still succeeds.
                obj = re.compile(pattern, re.IGNORECASE)
                result = obj.search(s)
                if result is None:
                    print '=== Fails on case-insensitive match', t

                # Try the match with LOCALE enabled, and check that it
                # still succeeds.
                obj = re.compile(pattern, re.LOCALE)
                result = obj.search(s)
                if result is None:
                    print '=== Fails on locale-sensitive match', t

                # Try the match with UNICODE locale enabled, and check
                # that it still succeeds.
                obj = re.compile(pattern, re.UNICODE)
                result = obj.search(s)
                if result is None:
                    print '=== Fails on unicode-sensitive match', t

def test_main():
    run_re_tests()
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(ReTests))
    run_suite(suite)

if __name__ == "__main__":
    test_main()
