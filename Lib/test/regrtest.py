#! /usr/bin/env python

"""Regression test.

This will find all modules whose name is "test_*" in the test
directory, and run them.  Various command line options provide
additional facilities.

Command line options:

-v: verbose -- run tests in verbose mode with output to stdout
-q: quiet -- don't print anything except if a test fails
-g: generate -- write the output file for a test instead of comparing it
-x: exclude -- arguments are tests to *exclude*

If non-option arguments are present, they are names for tests to run,
unless -x is given, in which case they are names for tests not to run.
If no test names are given, all tests are run.

-v is incompatible with -g and does not compare test output files.
"""

import sys
import string
import os
import getopt
import traceback

import test_support

def main():
    try:
	opts, args = getopt.getopt(sys.argv[1:], 'vgqx')
    except getopt.error, msg:
	print msg
	print __doc__
	return 2
    verbose = 0
    quiet = 0
    generate = 0
    exclude = 0
    for o, a in opts:
	if o == '-v': verbose = verbose+1
	if o == '-q': quiet = 1; verbose = 0
	if o == '-g': generate = 1
	if o == '-x': exclude = 1
    if generate and verbose:
	print "-g and -v don't go together!"
	return 2
    good = []
    bad = []
    skipped = []
    for i in range(len(args)):
	# Strip trailing ".py" from arguments
	if args[i][-3:] == '.py':
	    args[i] = args[i][:-3]
    if exclude:
	nottests[:0] = args
	args = []
    tests = args or findtests()
    test_support.verbose = verbose	# Tell tests to be moderately quiet
    for test in tests:
	if not quiet:
	    print test
	ok = runtest(test, generate, verbose)
	if ok > 0:
	    good.append(test)
	elif ok == 0:
	    bad.append(test)
	else:
	    if not quiet:
		print "test", test,
		print "skipped -- an optional feature could not be imported"
	    skipped.append(test)
    if good and not quiet:
	if not bad and not skipped and len(good) > 1:
	    print "All",
	print count(len(good), "test"), "OK."
    if bad:
	print count(len(bad), "test"), "failed:",
	print string.join(bad)
    if skipped and not quiet:
	print count(len(skipped), "test"), "skipped:",
	print string.join(skipped)
    return len(bad) > 0

stdtests = [
    'test_grammar',
    'test_opcodes',
    'test_operations',
    'test_builtin',
    'test_exceptions',
    'test_types',
   ]

nottests = [
    'test_support',
    'test_b1',
    'test_b2',
    ]

def findtests():
    """Return a list of all applicable test modules."""
    testdir = findtestdir()
    names = os.listdir(testdir)
    tests = []
    for name in names:
	if name[:5] == "test_" and name[-3:] == ".py":
	    modname = name[:-3]
	    if modname not in stdtests and modname not in nottests:
		tests.append(modname)
    tests.sort()
    return stdtests + tests

def runtest(test, generate, verbose):
    test_support.unload(test)
    testdir = findtestdir()
    outputdir = os.path.join(testdir, "output")
    outputfile = os.path.join(outputdir, test)
    try:
	if generate:
	    cfp = open(outputfile, "w")
	elif verbose:
	    cfp = sys.stdout
	else:
	    cfp = Compare(outputfile)
    except IOError:
	cfp = None
	print "Warning: can't open", outputfile
    try:
	save_stdout = sys.stdout
	try:
	    if cfp:
		sys.stdout = cfp
		print test		# Output file starts with test name
	    __import__(test)
	finally:
	    sys.stdout = save_stdout
    except ImportError, msg:
	return -1
    except test_support.TestFailed, msg:
	print "test", test, "failed --", msg
	return 0
    except:
	print "test", test, "crashed --", sys.exc_type, ":", sys.exc_value
	if verbose:
	    traceback.print_exc(file=sys.stdout)
	return 0
    else:
	return 1

def findtestdir():
    if __name__ == '__main__':
	file = sys.argv[0]
    else:
	file = __file__
    testdir = os.path.dirname(file) or os.curdir
    return testdir

def count(n, word):
    if n == 1:
	return "%d %s" % (n, word)
    else:
	return "%d %ss" % (n, word)

class Compare:

    def __init__(self, filename):
	self.fp = open(filename, 'r')

    def write(self, data):
	expected = self.fp.read(len(data))
	if data <> expected:
	    raise test_support.TestFailed, \
		    'Writing: '+`data`+', expected: '+`expected`

    def flush(self):
	pass

    def close(self):
	leftover = self.fp.read()
	if leftover:
	    raise test_support.TestFailed, 'Unread: '+`leftover`
	self.fp.close()

    def isatty(self):
	return 0

if __name__ == '__main__':
    sys.exit(main())
