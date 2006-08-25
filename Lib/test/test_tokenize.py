"""Tests for the tokenize module.

The tests were originally written in the old Python style, where the
test output was compared to a golden file.  This docstring represents
the first steps towards rewriting the entire test as a doctest.

The tests can be really simple.  Given a small fragment of source
code, print out a table with the tokens.  The ENDMARK is omitted for
brevity.

>>> dump_tokens("1 + 1")
NUMBER      '1'           (1, 0) (1, 1)
OP          '+'           (1, 2) (1, 3)
NUMBER      '1'           (1, 4) (1, 5)

A comment generates a token here, unlike in the parser module.  The
comment token is followed by an NL or a NEWLINE token, depending on
whether the line contains the completion of a statement.

>>> dump_tokens("if False:\\n"
...             "    # NL\\n"
...             "    True = False # NEWLINE\\n")
NAME        'if'          (1, 0) (1, 2)
NAME        'False'       (1, 3) (1, 8)
OP          ':'           (1, 8) (1, 9)
NEWLINE     '\\n'          (1, 9) (1, 10)
COMMENT     '# NL'        (2, 4) (2, 8)
NL          '\\n'          (2, 8) (2, 9)
INDENT      '    '        (3, 0) (3, 4)
NAME        'True'        (3, 4) (3, 8)
OP          '='           (3, 9) (3, 10)
NAME        'False'       (3, 11) (3, 16)
COMMENT     '# NEWLINE'   (3, 17) (3, 26)
NEWLINE     '\\n'          (3, 26) (3, 27)
DEDENT      ''            (4, 0) (4, 0)


There will be a bunch more tests of specific source patterns.

The tokenize module also defines an untokenize function that should
regenerate the original program text from the tokens.

There are some standard formatting practices that are easy to get right.

>>> roundtrip("if x == 1:\\n"
...           "    print x\\n")
if x == 1:
    print x

Some people use different formatting conventions, which makes
untokenize a little trickier.  Note that this test involves trailing
whitespace after the colon.  You can't see it, but it's there!

>>> roundtrip("if   x  ==  1  :  \\n"
...           "  print x\\n")
if   x  ==  1  :
  print x

Comments need to go in the right place.

>>> roundtrip("if x == 1:\\n"
...           "    # A comment by itself.\\n"
...           "    print x  # Comment here, too.\\n"
...           "    # Another comment.\\n"
...           "after_if = True\\n")
if x == 1:
    # A comment by itself.
    print x  # Comment here, too.
    # Another comment.
after_if = True

>>> roundtrip("if (x  # The comments need to go in the right place\\n"
...           "    == 1):\\n"
...           "    print 'x == 1'\\n")
if (x  # The comments need to go in the right place
    == 1):
    print 'x == 1'

"""

import os, glob, random
from cStringIO import StringIO
from test.test_support import (verbose, findfile, is_resource_enabled,
                               TestFailed)
from tokenize import (tokenize, generate_tokens, untokenize, tok_name,
                      ENDMARKER, NUMBER, NAME, OP, STRING, COMMENT)

# Test roundtrip for `untokenize`.  `f` is a file path.  The source code in f
# is tokenized, converted back to source code via tokenize.untokenize(),
# and tokenized again from the latter.  The test fails if the second
# tokenization doesn't match the first.
def test_roundtrip(f):
    ## print 'Testing:', f
    fobj = open(f)
    try:
        fulltok = list(generate_tokens(fobj.readline))
    finally:
        fobj.close()

    t1 = [tok[:2] for tok in fulltok]
    newtext = untokenize(t1)
    readline = iter(newtext.splitlines(1)).next
    t2 = [tok[:2] for tok in generate_tokens(readline)]
    if t1 != t2:
        raise TestFailed("untokenize() roundtrip failed for %r" % f)

def dump_tokens(s):
    """Print out the tokens in s in a table format.

    The ENDMARKER is omitted.
    """
    f = StringIO(s)
    for type, token, start, end, line in generate_tokens(f.readline):
        if type == ENDMARKER:
            break
        type = tok_name[type]
        print "%(type)-10.10s  %(token)-13.13r %(start)s %(end)s" % locals()

def roundtrip(s):
    f = StringIO(s)
    source = untokenize(generate_tokens(f.readline))
    print source,

# This is an example from the docs, set up as a doctest.
def decistmt(s):
    """Substitute Decimals for floats in a string of statements.

    >>> from decimal import Decimal
    >>> s = 'print +21.3e-5*-.1234/81.7'
    >>> decistmt(s)
    "print +Decimal ('21.3e-5')*-Decimal ('.1234')/Decimal ('81.7')"

    The format of the exponent is inherited from the platform C library.
    Known cases are "e-007" (Windows) and "e-07" (not Windows).  Since
    we're only showing 12 digits, and the 13th isn't close to 5, the
    rest of the output should be platform-independent.

    >>> exec(s) #doctest: +ELLIPSIS
    -3.21716034272e-0...7

    Output from calculations with Decimal should be identical across all
    platforms.

    >>> exec(decistmt(s))
    -3.217160342717258261933904529E-7
    """

    result = []
    g = generate_tokens(StringIO(s).readline)   # tokenize the string
    for toknum, tokval, _, _, _  in g:
        if toknum == NUMBER and '.' in tokval:  # replace NUMBER tokens
            result.extend([
                (NAME, 'Decimal'),
                (OP, '('),
                (STRING, repr(tokval)),
                (OP, ')')
            ])
        else:
            result.append((toknum, tokval))
    return untokenize(result)

def test_main():
    if verbose:
        print 'starting...'

    # This displays the tokenization of tokenize_tests.py to stdout, and
    # regrtest.py checks that this equals the expected output (in the
    # test/output/ directory).
    f = open(findfile('tokenize_tests' + os.extsep + 'txt'))
    tokenize(f.readline)
    f.close()

    # Now run test_roundtrip() over tokenize_test.py too, and over all
    # (if the "compiler" resource is enabled) or a small random sample (if
    # "compiler" is not enabled) of the test*.py files.
    f = findfile('tokenize_tests' + os.extsep + 'txt')
    test_roundtrip(f)

    testdir = os.path.dirname(f) or os.curdir
    testfiles = glob.glob(testdir + os.sep + 'test*.py')
    if not is_resource_enabled('compiler'):
        testfiles = random.sample(testfiles, 10)

    for f in testfiles:
        test_roundtrip(f)

    # Test detecton of IndentationError.
    sampleBadText = """\
def foo():
    bar
  baz
"""

    try:
        for tok in generate_tokens(StringIO(sampleBadText).readline):
            pass
    except IndentationError:
        pass
    else:
        raise TestFailed("Did not detect IndentationError:")

    # Run the doctests in this module.
    from test import test_tokenize  # i.e., this module
    from test.test_support import run_doctest
    run_doctest(test_tokenize, verbose)

    if verbose:
        print 'finished'

if __name__ == "__main__":
    test_main()
