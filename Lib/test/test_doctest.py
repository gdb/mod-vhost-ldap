"""
Test script for doctest.
"""

from test import test_support
import doctest
import warnings

######################################################################
## Sample Objects (used by test cases)
######################################################################

def sample_func(v):
    """
    Blah blah

    >>> print sample_func(22)
    44

    Yee ha!
    """
    return v+v

class SampleClass:
    """
    >>> print 1
    1
    """
    def __init__(self, val):
        """
        >>> print SampleClass(12).get()
        12
        """
        self.val = val

    def double(self):
        """
        >>> print SampleClass(12).double().get()
        24
        """
        return SampleClass(self.val + self.val)

    def get(self):
        """
        >>> print SampleClass(-5).get()
        -5
        """
        return self.val

    def a_staticmethod(v):
        """
        >>> print SampleClass.a_staticmethod(10)
        11
        """
        return v+1
    a_staticmethod = staticmethod(a_staticmethod)

    def a_classmethod(cls, v):
        """
        >>> print SampleClass.a_classmethod(10)
        12
        >>> print SampleClass(0).a_classmethod(10)
        12
        """
        return v+2
    a_classmethod = classmethod(a_classmethod)

    a_property = property(get, doc="""
        >>> print SampleClass(22).a_property
        22
        """)

    class NestedClass:
        """
        >>> x = SampleClass.NestedClass(5)
        >>> y = x.square()
        >>> print y.get()
        25
        """
        def __init__(self, val=0):
            """
            >>> print SampleClass.NestedClass().get()
            0
            """
            self.val = val
        def square(self):
            return SampleClass.NestedClass(self.val*self.val)
        def get(self):
            return self.val

class SampleNewStyleClass(object):
    r"""
    >>> print '1\n2\n3'
    1
    2
    3
    """
    def __init__(self, val):
        """
        >>> print SampleNewStyleClass(12).get()
        12
        """
        self.val = val

    def double(self):
        """
        >>> print SampleNewStyleClass(12).double().get()
        24
        """
        return SampleNewStyleClass(self.val + self.val)

    def get(self):
        """
        >>> print SampleNewStyleClass(-5).get()
        -5
        """
        return self.val

######################################################################
## Test Cases
######################################################################

def test_Example(): r"""
Unit tests for the `Example` class.

Example is a simple container class that holds:
  - `source`: A source string.
  - `want`: An expected output string.
  - `exc_msg`: An expected exception message string (or None if no
    exception is expected).
  - `lineno`: A line number (within the docstring).
  - `indent`: The example's indentation in the input string.
  - `options`: An option dictionary, mapping option flags to True or
    False.

These attributes are set by the constructor.  `source` and `want` are
required; the other attributes all have default values:

    >>> example = doctest.Example('print 1', '1\n')
    >>> (example.source, example.want, example.exc_msg,
    ...  example.lineno, example.indent, example.options)
    ('print 1\n', '1\n', None, 0, 0, {})

The first three attributes (`source`, `want`, and `exc_msg`) may be
specified positionally; the remaining arguments should be specified as
keyword arguments:

    >>> exc_msg = 'IndexError: pop from an empty list'
    >>> example = doctest.Example('[].pop()', '', exc_msg,
    ...                           lineno=5, indent=4,
    ...                           options={doctest.ELLIPSIS: True})
    >>> (example.source, example.want, example.exc_msg,
    ...  example.lineno, example.indent, example.options)
    ('[].pop()\n', '', 'IndexError: pop from an empty list\n', 5, 4, {8: True})

The constructor normalizes the `source` string to end in a newline:

    Source spans a single line: no terminating newline.
    >>> e = doctest.Example('print 1', '1\n')
    >>> e.source, e.want
    ('print 1\n', '1\n')

    >>> e = doctest.Example('print 1\n', '1\n')
    >>> e.source, e.want
    ('print 1\n', '1\n')

    Source spans multiple lines: require terminating newline.
    >>> e = doctest.Example('print 1;\nprint 2\n', '1\n2\n')
    >>> e.source, e.want
    ('print 1;\nprint 2\n', '1\n2\n')

    >>> e = doctest.Example('print 1;\nprint 2', '1\n2\n')
    >>> e.source, e.want
    ('print 1;\nprint 2\n', '1\n2\n')

    Empty source string (which should never appear in real examples)
    >>> e = doctest.Example('', '')
    >>> e.source, e.want
    ('\n', '')

The constructor normalizes the `want` string to end in a newline,
unless it's the empty string:

    >>> e = doctest.Example('print 1', '1\n')
    >>> e.source, e.want
    ('print 1\n', '1\n')

    >>> e = doctest.Example('print 1', '1')
    >>> e.source, e.want
    ('print 1\n', '1\n')

    >>> e = doctest.Example('print', '')
    >>> e.source, e.want
    ('print\n', '')

The constructor normalizes the `exc_msg` string to end in a newline,
unless it's `None`:

    Message spans one line
    >>> exc_msg = 'IndexError: pop from an empty list'
    >>> e = doctest.Example('[].pop()', '', exc_msg)
    >>> e.exc_msg
    'IndexError: pop from an empty list\n'

    >>> exc_msg = 'IndexError: pop from an empty list\n'
    >>> e = doctest.Example('[].pop()', '', exc_msg)
    >>> e.exc_msg
    'IndexError: pop from an empty list\n'

    Message spans multiple lines
    >>> exc_msg = 'ValueError: 1\n  2'
    >>> e = doctest.Example('raise ValueError("1\n  2")', '', exc_msg)
    >>> e.exc_msg
    'ValueError: 1\n  2\n'

    >>> exc_msg = 'ValueError: 1\n  2\n'
    >>> e = doctest.Example('raise ValueError("1\n  2")', '', exc_msg)
    >>> e.exc_msg
    'ValueError: 1\n  2\n'

    Empty (but non-None) exception message (which should never appear
    in real examples)
    >>> exc_msg = ''
    >>> e = doctest.Example('raise X()', '', exc_msg)
    >>> e.exc_msg
    '\n'
"""

def test_DocTest(): r"""
Unit tests for the `DocTest` class.

DocTest is a collection of examples, extracted from a docstring, along
with information about where the docstring comes from (a name,
filename, and line number).  The docstring is parsed by the `DocTest`
constructor:

    >>> docstring = '''
    ...     >>> print 12
    ...     12
    ...
    ... Non-example text.
    ...
    ...     >>> print 'another\example'
    ...     another
    ...     example
    ... '''
    >>> globs = {} # globals to run the test in.
    >>> parser = doctest.DocTestParser()
    >>> test = parser.get_doctest(docstring, globs, 'some_test',
    ...                           'some_file', 20)
    >>> print test
    <DocTest some_test from some_file:20 (2 examples)>
    >>> len(test.examples)
    2
    >>> e1, e2 = test.examples
    >>> (e1.source, e1.want, e1.lineno)
    ('print 12\n', '12\n', 1)
    >>> (e2.source, e2.want, e2.lineno)
    ("print 'another\\example'\n", 'another\nexample\n', 6)

Source information (name, filename, and line number) is available as
attributes on the doctest object:

    >>> (test.name, test.filename, test.lineno)
    ('some_test', 'some_file', 20)

The line number of an example within its containing file is found by
adding the line number of the example and the line number of its
containing test:

    >>> test.lineno + e1.lineno
    21
    >>> test.lineno + e2.lineno
    26

If the docstring contains inconsistant leading whitespace in the
expected output of an example, then `DocTest` will raise a ValueError:

    >>> docstring = r'''
    ...       >>> print 'bad\nindentation'
    ...       bad
    ...     indentation
    ...     '''
    >>> parser.get_doctest(docstring, globs, 'some_test', 'filename', 0)
    Traceback (most recent call last):
    ValueError: line 4 of the docstring for some_test has inconsistent leading whitespace: '    indentation'

If the docstring contains inconsistent leading whitespace on
continuation lines, then `DocTest` will raise a ValueError:

    >>> docstring = r'''
    ...       >>> print ('bad indentation',
    ...     ...          2)
    ...       ('bad', 'indentation')
    ...     '''
    >>> parser.get_doctest(docstring, globs, 'some_test', 'filename', 0)
    Traceback (most recent call last):
    ValueError: line 2 of the docstring for some_test has inconsistent leading whitespace: '    ...          2)'

If there's no blank space after a PS1 prompt ('>>>'), then `DocTest`
will raise a ValueError:

    >>> docstring = '>>>print 1\n1'
    >>> parser.get_doctest(docstring, globs, 'some_test', 'filename', 0)
    Traceback (most recent call last):
    ValueError: line 1 of the docstring for some_test lacks blank after >>>: '>>>print 1'

If there's no blank space after a PS2 prompt ('...'), then `DocTest`
will raise a ValueError:

    >>> docstring = '>>> if 1:\n...print 1\n1'
    >>> parser.get_doctest(docstring, globs, 'some_test', 'filename', 0)
    Traceback (most recent call last):
    ValueError: line 2 of the docstring for some_test lacks blank after ...: '...print 1'

"""

def test_DocTestFinder(): r"""
Unit tests for the `DocTestFinder` class.

DocTestFinder is used to extract DocTests from an object's docstring
and the docstrings of its contained objects.  It can be used with
modules, functions, classes, methods, staticmethods, classmethods, and
properties.

Finding Tests in Functions
~~~~~~~~~~~~~~~~~~~~~~~~~~
For a function whose docstring contains examples, DocTestFinder.find()
will return a single test (for that function's docstring):

    >>> finder = doctest.DocTestFinder()

We'll simulate a __file__ attr that ends in pyc:

    >>> import test.test_doctest
    >>> old = test.test_doctest.__file__
    >>> test.test_doctest.__file__ = 'test_doctest.pyc'

    >>> tests = finder.find(sample_func)

    >>> print tests  # doctest: +ELLIPSIS
    [<DocTest sample_func from ...:13 (1 example)>]

The exact name depends on how test_doctest was invoked, so allow for
leading path components.

    >>> tests[0].filename # doctest: +ELLIPSIS
    '...test_doctest.py'

    >>> test.test_doctest.__file__ = old


    >>> e = tests[0].examples[0]
    >>> (e.source, e.want, e.lineno)
    ('print sample_func(22)\n', '44\n', 3)

If an object has no docstring, then a test is not created for it:

    >>> def no_docstring(v):
    ...     pass
    >>> finder.find(no_docstring)
    []

If the function has a docstring with no examples, then a test with no
examples is returned.  (This lets `DocTestRunner` collect statistics
about which functions have no tests -- but is that useful?  And should
an empty test also be created when there's no docstring?)

    >>> def no_examples(v):
    ...     ''' no doctest examples '''
    >>> finder.find(no_examples)
    [<DocTest no_examples from None:1 (no examples)>]

Finding Tests in Classes
~~~~~~~~~~~~~~~~~~~~~~~~
For a class, DocTestFinder will create a test for the class's
docstring, and will recursively explore its contents, including
methods, classmethods, staticmethods, properties, and nested classes.

    >>> finder = doctest.DocTestFinder()
    >>> tests = finder.find(SampleClass)
    >>> tests.sort()
    >>> for t in tests:
    ...     print '%2s  %s' % (len(t.examples), t.name)
     1  SampleClass
     3  SampleClass.NestedClass
     1  SampleClass.NestedClass.__init__
     1  SampleClass.__init__
     2  SampleClass.a_classmethod
     1  SampleClass.a_property
     1  SampleClass.a_staticmethod
     1  SampleClass.double
     1  SampleClass.get

New-style classes are also supported:

    >>> tests = finder.find(SampleNewStyleClass)
    >>> tests.sort()
    >>> for t in tests:
    ...     print '%2s  %s' % (len(t.examples), t.name)
     1  SampleNewStyleClass
     1  SampleNewStyleClass.__init__
     1  SampleNewStyleClass.double
     1  SampleNewStyleClass.get

Finding Tests in Modules
~~~~~~~~~~~~~~~~~~~~~~~~
For a module, DocTestFinder will create a test for the class's
docstring, and will recursively explore its contents, including
functions, classes, and the `__test__` dictionary, if it exists:

    >>> # A module
    >>> import new
    >>> m = new.module('some_module')
    >>> def triple(val):
    ...     '''
    ...     >>> print tripple(11)
    ...     33
    ...     '''
    ...     return val*3
    >>> m.__dict__.update({
    ...     'sample_func': sample_func,
    ...     'SampleClass': SampleClass,
    ...     '__doc__': '''
    ...         Module docstring.
    ...             >>> print 'module'
    ...             module
    ...         ''',
    ...     '__test__': {
    ...         'd': '>>> print 6\n6\n>>> print 7\n7\n',
    ...         'c': triple}})

    >>> finder = doctest.DocTestFinder()
    >>> # Use module=test.test_doctest, to prevent doctest from
    >>> # ignoring the objects since they weren't defined in m.
    >>> import test.test_doctest
    >>> tests = finder.find(m, module=test.test_doctest)
    >>> tests.sort()
    >>> for t in tests:
    ...     print '%2s  %s' % (len(t.examples), t.name)
     1  some_module
     1  some_module.SampleClass
     3  some_module.SampleClass.NestedClass
     1  some_module.SampleClass.NestedClass.__init__
     1  some_module.SampleClass.__init__
     2  some_module.SampleClass.a_classmethod
     1  some_module.SampleClass.a_property
     1  some_module.SampleClass.a_staticmethod
     1  some_module.SampleClass.double
     1  some_module.SampleClass.get
     1  some_module.c
     2  some_module.d
     1  some_module.sample_func

Duplicate Removal
~~~~~~~~~~~~~~~~~
If a single object is listed twice (under different names), then tests
will only be generated for it once:

    >>> from test import doctest_aliases
    >>> tests = finder.find(doctest_aliases)
    >>> tests.sort()
    >>> print len(tests)
    2
    >>> print tests[0].name
    test.doctest_aliases.TwoNames

    TwoNames.f and TwoNames.g are bound to the same object.
    We can't guess which will be found in doctest's traversal of
    TwoNames.__dict__ first, so we have to allow for either.

    >>> tests[1].name.split('.')[-1] in ['f', 'g']
    True

Filter Functions
~~~~~~~~~~~~~~~~
A filter function can be used to restrict which objects get examined,
but this is temporary, undocumented internal support for testmod's
deprecated isprivate gimmick.

    >>> def namefilter(prefix, base):
    ...     return base.startswith('a_')
    >>> tests = doctest.DocTestFinder(_namefilter=namefilter).find(SampleClass)
    >>> tests.sort()
    >>> for t in tests:
    ...     print '%2s  %s' % (len(t.examples), t.name)
     1  SampleClass
     3  SampleClass.NestedClass
     1  SampleClass.NestedClass.__init__
     1  SampleClass.__init__
     1  SampleClass.double
     1  SampleClass.get

If a given object is filtered out, then none of the objects that it
contains will be added either:

    >>> def namefilter(prefix, base):
    ...     return base == 'NestedClass'
    >>> tests = doctest.DocTestFinder(_namefilter=namefilter).find(SampleClass)
    >>> tests.sort()
    >>> for t in tests:
    ...     print '%2s  %s' % (len(t.examples), t.name)
     1  SampleClass
     1  SampleClass.__init__
     2  SampleClass.a_classmethod
     1  SampleClass.a_property
     1  SampleClass.a_staticmethod
     1  SampleClass.double
     1  SampleClass.get

The filter function apply to contained objects, and *not* to the
object explicitly passed to DocTestFinder:

    >>> def namefilter(prefix, base):
    ...     return base == 'SampleClass'
    >>> tests = doctest.DocTestFinder(_namefilter=namefilter).find(SampleClass)
    >>> len(tests)
    9

Turning off Recursion
~~~~~~~~~~~~~~~~~~~~~
DocTestFinder can be told not to look for tests in contained objects
using the `recurse` flag:

    >>> tests = doctest.DocTestFinder(recurse=False).find(SampleClass)
    >>> tests.sort()
    >>> for t in tests:
    ...     print '%2s  %s' % (len(t.examples), t.name)
     1  SampleClass

Line numbers
~~~~~~~~~~~~
DocTestFinder finds the line number of each example:

    >>> def f(x):
    ...     '''
    ...     >>> x = 12
    ...
    ...     some text
    ...
    ...     >>> # examples are not created for comments & bare prompts.
    ...     >>>
    ...     ...
    ...
    ...     >>> for x in range(10):
    ...     ...     print x,
    ...     0 1 2 3 4 5 6 7 8 9
    ...     >>> x/2
    ...     6
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> [e.lineno for e in test.examples]
    [1, 9, 12]
"""

class test_DocTestRunner:
    def basics(): r"""
Unit tests for the `DocTestRunner` class.

DocTestRunner is used to run DocTest test cases, and to accumulate
statistics.  Here's a simple DocTest case we can use:

    >>> def f(x):
    ...     '''
    ...     >>> x = 12
    ...     >>> print x
    ...     12
    ...     >>> x/2
    ...     6
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]

The main DocTestRunner interface is the `run` method, which runs a
given DocTest case in a given namespace (globs).  It returns a tuple
`(f,t)`, where `f` is the number of failed tests and `t` is the number
of tried tests.

    >>> doctest.DocTestRunner(verbose=False).run(test)
    (0, 3)

If any example produces incorrect output, then the test runner reports
the failure and proceeds to the next example:

    >>> def f(x):
    ...     '''
    ...     >>> x = 12
    ...     >>> print x
    ...     14
    ...     >>> x/2
    ...     6
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=True).run(test)
    Trying:
        x = 12
    Expecting nothing
    ok
    Trying:
        print x
    Expecting:
        14
    **********************************************************************
    Line 3, in f
    Failed example:
        print x
    Expected:
        14
    Got:
        12
    Trying:
        x/2
    Expecting:
        6
    ok
    (1, 3)
"""
    def verbose_flag(): r"""
The `verbose` flag makes the test runner generate more detailed
output:

    >>> def f(x):
    ...     '''
    ...     >>> x = 12
    ...     >>> print x
    ...     12
    ...     >>> x/2
    ...     6
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]

    >>> doctest.DocTestRunner(verbose=True).run(test)
    Trying:
        x = 12
    Expecting nothing
    ok
    Trying:
        print x
    Expecting:
        12
    ok
    Trying:
        x/2
    Expecting:
        6
    ok
    (0, 3)

If the `verbose` flag is unspecified, then the output will be verbose
iff `-v` appears in sys.argv:

    >>> # Save the real sys.argv list.
    >>> old_argv = sys.argv

    >>> # If -v does not appear in sys.argv, then output isn't verbose.
    >>> sys.argv = ['test']
    >>> doctest.DocTestRunner().run(test)
    (0, 3)

    >>> # If -v does appear in sys.argv, then output is verbose.
    >>> sys.argv = ['test', '-v']
    >>> doctest.DocTestRunner().run(test)
    Trying:
        x = 12
    Expecting nothing
    ok
    Trying:
        print x
    Expecting:
        12
    ok
    Trying:
        x/2
    Expecting:
        6
    ok
    (0, 3)

    >>> # Restore sys.argv
    >>> sys.argv = old_argv

In the remaining examples, the test runner's verbosity will be
explicitly set, to ensure that the test behavior is consistent.
    """
    def exceptions(): r"""
Tests of `DocTestRunner`'s exception handling.

An expected exception is specified with a traceback message.  The
lines between the first line and the type/value may be omitted or
replaced with any other string:

    >>> def f(x):
    ...     '''
    ...     >>> x = 12
    ...     >>> print x/0
    ...     Traceback (most recent call last):
    ...     ZeroDivisionError: integer division or modulo by zero
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    (0, 2)

An example may not generate output before it raises an exception; if
it does, then the traceback message will not be recognized as
signaling an expected exception, so the example will be reported as an
unexpected exception:

    >>> def f(x):
    ...     '''
    ...     >>> x = 12
    ...     >>> print 'pre-exception output', x/0
    ...     pre-exception output
    ...     Traceback (most recent call last):
    ...     ZeroDivisionError: integer division or modulo by zero
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    ... # doctest: +ELLIPSIS
    **********************************************************************
    Line 3, in f
    Failed example:
        print 'pre-exception output', x/0
    Exception raised:
        ...
        ZeroDivisionError: integer division or modulo by zero
    (1, 2)

Exception messages may contain newlines:

    >>> def f(x):
    ...     r'''
    ...     >>> raise ValueError, 'multi\nline\nmessage'
    ...     Traceback (most recent call last):
    ...     ValueError: multi
    ...     line
    ...     message
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    (0, 1)

If an exception is expected, but an exception with the wrong type or
message is raised, then it is reported as a failure:

    >>> def f(x):
    ...     r'''
    ...     >>> raise ValueError, 'message'
    ...     Traceback (most recent call last):
    ...     ValueError: wrong message
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    ... # doctest: +ELLIPSIS
    **********************************************************************
    Line 2, in f
    Failed example:
        raise ValueError, 'message'
    Expected:
        Traceback (most recent call last):
        ValueError: wrong message
    Got:
        Traceback (most recent call last):
        ...
        ValueError: message
    (1, 1)

If an exception is raised but not expected, then it is reported as an
unexpected exception:

    >>> def f(x):
    ...     r'''
    ...     >>> 1/0
    ...     0
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    ... # doctest: +ELLIPSIS
    **********************************************************************
    Line 2, in f
    Failed example:
        1/0
    Exception raised:
        Traceback (most recent call last):
        ...
        ZeroDivisionError: integer division or modulo by zero
    (1, 1)
"""
    def optionflags(): r"""
Tests of `DocTestRunner`'s option flag handling.

Several option flags can be used to customize the behavior of the test
runner.  These are defined as module constants in doctest, and passed
to the DocTestRunner constructor (multiple constants should be or-ed
together).

The DONT_ACCEPT_TRUE_FOR_1 flag disables matches between True/False
and 1/0:

    >>> def f(x):
    ...     '>>> True\n1\n'

    >>> # Without the flag:
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    (0, 1)

    >>> # With the flag:
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> flags = doctest.DONT_ACCEPT_TRUE_FOR_1
    >>> doctest.DocTestRunner(verbose=False, optionflags=flags).run(test)
    **********************************************************************
    Line 1, in f
    Failed example:
        True
    Expected:
        1
    Got:
        True
    (1, 1)

The DONT_ACCEPT_BLANKLINE flag disables the match between blank lines
and the '<BLANKLINE>' marker:

    >>> def f(x):
    ...     '>>> print "a\\n\\nb"\na\n<BLANKLINE>\nb\n'

    >>> # Without the flag:
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    (0, 1)

    >>> # With the flag:
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> flags = doctest.DONT_ACCEPT_BLANKLINE
    >>> doctest.DocTestRunner(verbose=False, optionflags=flags).run(test)
    **********************************************************************
    Line 1, in f
    Failed example:
        print "a\n\nb"
    Expected:
        a
        <BLANKLINE>
        b
    Got:
        a
    <BLANKLINE>
        b
    (1, 1)

The NORMALIZE_WHITESPACE flag causes all sequences of whitespace to be
treated as equal:

    >>> def f(x):
    ...     '>>> print 1, 2, 3\n  1   2\n 3'

    >>> # Without the flag:
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    **********************************************************************
    Line 1, in f
    Failed example:
        print 1, 2, 3
    Expected:
          1   2
         3
    Got:
        1 2 3
    (1, 1)

    >>> # With the flag:
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> flags = doctest.NORMALIZE_WHITESPACE
    >>> doctest.DocTestRunner(verbose=False, optionflags=flags).run(test)
    (0, 1)

    An example from the docs:
    >>> print range(20) #doctest: +NORMALIZE_WHITESPACE
    [0,   1,  2,  3,  4,  5,  6,  7,  8,  9,
    10,  11, 12, 13, 14, 15, 16, 17, 18, 19]

The ELLIPSIS flag causes ellipsis marker ("...") in the expected
output to match any substring in the actual output:

    >>> def f(x):
    ...     '>>> print range(15)\n[0, 1, 2, ..., 14]\n'

    >>> # Without the flag:
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    **********************************************************************
    Line 1, in f
    Failed example:
        print range(15)
    Expected:
        [0, 1, 2, ..., 14]
    Got:
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
    (1, 1)

    >>> # With the flag:
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> flags = doctest.ELLIPSIS
    >>> doctest.DocTestRunner(verbose=False, optionflags=flags).run(test)
    (0, 1)

    ... also matches nothing:

    >>> for i in range(100):
    ...     print i**2, #doctest: +ELLIPSIS
    0 1...4...9 16 ... 36 49 64 ... 9801

    ... can be surprising; e.g., this test passes:

    >>> for i in range(21): #doctest: +ELLIPSIS
    ...     print i,
    0 1 2 ...1...2...0

    Examples from the docs:

    >>> print range(20) # doctest:+ELLIPSIS
    [0, 1, ..., 18, 19]

    >>> print range(20) # doctest: +ELLIPSIS
    ...                 # doctest: +NORMALIZE_WHITESPACE
    [0,    1, ...,   18,    19]

The UNIFIED_DIFF flag causes failures that involve multi-line expected
and actual outputs to be displayed using a unified diff:

    >>> def f(x):
    ...     r'''
    ...     >>> print '\n'.join('abcdefg')
    ...     a
    ...     B
    ...     c
    ...     d
    ...     f
    ...     g
    ...     h
    ...     '''

    >>> # Without the flag:
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    **********************************************************************
    Line 2, in f
    Failed example:
        print '\n'.join('abcdefg')
    Expected:
        a
        B
        c
        d
        f
        g
        h
    Got:
        a
        b
        c
        d
        e
        f
        g
    (1, 1)

    >>> # With the flag:
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> flags = doctest.UNIFIED_DIFF
    >>> doctest.DocTestRunner(verbose=False, optionflags=flags).run(test)
    **********************************************************************
    Line 2, in f
    Failed example:
        print '\n'.join('abcdefg')
    Differences (unified diff):
        --- Expected
        +++ Got
        @@ -1,8 +1,8 @@
         a
        -B
        +b
         c
         d
        +e
         f
         g
        -h
    <BLANKLINE>
    (1, 1)

The CONTEXT_DIFF flag causes failures that involve multi-line expected
and actual outputs to be displayed using a context diff:

    >>> # Reuse f() from the UNIFIED_DIFF example, above.
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> flags = doctest.CONTEXT_DIFF
    >>> doctest.DocTestRunner(verbose=False, optionflags=flags).run(test)
    **********************************************************************
    Line 2, in f
    Failed example:
        print '\n'.join('abcdefg')
    Differences (context diff):
        *** Expected
        --- Got
        ***************
        *** 1,8 ****
          a
        ! B
          c
          d
          f
          g
        - h
    <BLANKLINE>
        --- 1,8 ----
          a
        ! b
          c
          d
        + e
          f
          g
    <BLANKLINE>
    (1, 1)


The NDIFF_DIFF flag causes failures to use the difflib.Differ algorithm
used by the popular ndiff.py utility.  This does intraline difference
marking, as well as interline differences.

    >>> def f(x):
    ...     r'''
    ...     >>> print "a b  c d e f g h i   j k l m"
    ...     a b c d e f g h i j k 1 m
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> flags = doctest.NDIFF_DIFF
    >>> doctest.DocTestRunner(verbose=False, optionflags=flags).run(test)
    **********************************************************************
    Line 2, in f
    Failed example:
        print "a b  c d e f g h i   j k l m"
    Differences (ndiff with -expected +actual):
        - a b c d e f g h i j k 1 m
        ?                       ^
        + a b  c d e f g h i   j k l m
        ?     +              ++    ^
    <BLANKLINE>
    (1, 1)
    """

    def option_directives(): r"""
Tests of `DocTestRunner`'s option directive mechanism.

Option directives can be used to turn option flags on or off for a
single example.  To turn an option on for an example, follow that
example with a comment of the form ``# doctest: +OPTION``:

    >>> def f(x): r'''
    ...     >>> print range(10)       # should fail: no ellipsis
    ...     [0, 1, ..., 9]
    ...
    ...     >>> print range(10)       # doctest: +ELLIPSIS
    ...     [0, 1, ..., 9]
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    **********************************************************************
    Line 2, in f
    Failed example:
        print range(10)       # should fail: no ellipsis
    Expected:
        [0, 1, ..., 9]
    Got:
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    (1, 2)

To turn an option off for an example, follow that example with a
comment of the form ``# doctest: -OPTION``:

    >>> def f(x): r'''
    ...     >>> print range(10)
    ...     [0, 1, ..., 9]
    ...
    ...     >>> # should fail: no ellipsis
    ...     >>> print range(10)       # doctest: -ELLIPSIS
    ...     [0, 1, ..., 9]
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False,
    ...                       optionflags=doctest.ELLIPSIS).run(test)
    **********************************************************************
    Line 6, in f
    Failed example:
        print range(10)       # doctest: -ELLIPSIS
    Expected:
        [0, 1, ..., 9]
    Got:
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    (1, 2)

Option directives affect only the example that they appear with; they
do not change the options for surrounding examples:

    >>> def f(x): r'''
    ...     >>> print range(10)       # Should fail: no ellipsis
    ...     [0, 1, ..., 9]
    ...
    ...     >>> print range(10)       # doctest: +ELLIPSIS
    ...     [0, 1, ..., 9]
    ...
    ...     >>> print range(10)       # Should fail: no ellipsis
    ...     [0, 1, ..., 9]
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    **********************************************************************
    Line 2, in f
    Failed example:
        print range(10)       # Should fail: no ellipsis
    Expected:
        [0, 1, ..., 9]
    Got:
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    **********************************************************************
    Line 8, in f
    Failed example:
        print range(10)       # Should fail: no ellipsis
    Expected:
        [0, 1, ..., 9]
    Got:
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    (2, 3)

Multiple options may be modified by a single option directive.  They
may be separated by whitespace, commas, or both:

    >>> def f(x): r'''
    ...     >>> print range(10)       # Should fail
    ...     [0, 1,  ...,   9]
    ...     >>> print range(10)       # Should succeed
    ...     ... # doctest: +ELLIPSIS +NORMALIZE_WHITESPACE
    ...     [0, 1,  ...,   9]
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    **********************************************************************
    Line 2, in f
    Failed example:
        print range(10)       # Should fail
    Expected:
        [0, 1,  ...,   9]
    Got:
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    (1, 2)

    >>> def f(x): r'''
    ...     >>> print range(10)       # Should fail
    ...     [0, 1,  ...,   9]
    ...     >>> print range(10)       # Should succeed
    ...     ... # doctest: +ELLIPSIS,+NORMALIZE_WHITESPACE
    ...     [0, 1,  ...,   9]
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    **********************************************************************
    Line 2, in f
    Failed example:
        print range(10)       # Should fail
    Expected:
        [0, 1,  ...,   9]
    Got:
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    (1, 2)

    >>> def f(x): r'''
    ...     >>> print range(10)       # Should fail
    ...     [0, 1,  ...,   9]
    ...     >>> print range(10)       # Should succeed
    ...     ... # doctest: +ELLIPSIS, +NORMALIZE_WHITESPACE
    ...     [0, 1,  ...,   9]
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    **********************************************************************
    Line 2, in f
    Failed example:
        print range(10)       # Should fail
    Expected:
        [0, 1,  ...,   9]
    Got:
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
    (1, 2)

The option directive may be put on the line following the source, as
long as a continuation prompt is used:

    >>> def f(x): r'''
    ...     >>> print range(10)
    ...     ... # doctest: +ELLIPSIS
    ...     [0, 1, ..., 9]
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    (0, 1)

For examples with multi-line source, the option directive may appear
at the end of any line:

    >>> def f(x): r'''
    ...     >>> for x in range(10): # doctest: +ELLIPSIS
    ...     ...     print x,
    ...     0 1 2 ... 9
    ...
    ...     >>> for x in range(10):
    ...     ...     print x,        # doctest: +ELLIPSIS
    ...     0 1 2 ... 9
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    (0, 2)

If more than one line of an example with multi-line source has an
option directive, then they are combined:

    >>> def f(x): r'''
    ...     Should fail (option directive not on the last line):
    ...         >>> for x in range(10): # doctest: +ELLIPSIS
    ...         ...     print x,        # doctest: +NORMALIZE_WHITESPACE
    ...         0  1    2...9
    ...     '''
    >>> test = doctest.DocTestFinder().find(f)[0]
    >>> doctest.DocTestRunner(verbose=False).run(test)
    (0, 1)

It is an error to have a comment of the form ``# doctest:`` that is
*not* followed by words of the form ``+OPTION`` or ``-OPTION``, where
``OPTION`` is an option that has been registered with
`register_option`:

    >>> # Error: Option not registered
    >>> s = '>>> print 12   #doctest: +BADOPTION'
    >>> test = doctest.DocTestParser().get_doctest(s, {}, 's', 's.py', 0)
    Traceback (most recent call last):
    ValueError: line 1 of the doctest for s has an invalid option: '+BADOPTION'

    >>> # Error: No + or - prefix
    >>> s = '>>> print 12   #doctest: ELLIPSIS'
    >>> test = doctest.DocTestParser().get_doctest(s, {}, 's', 's.py', 0)
    Traceback (most recent call last):
    ValueError: line 1 of the doctest for s has an invalid option: 'ELLIPSIS'

It is an error to use an option directive on a line that contains no
source:

    >>> s = '>>> # doctest: +ELLIPSIS'
    >>> test = doctest.DocTestParser().get_doctest(s, {}, 's', 's.py', 0)
    Traceback (most recent call last):
    ValueError: line 0 of the doctest for s has an option directive on a line with no example: '# doctest: +ELLIPSIS'
"""

def test_testsource(): r"""
Unit tests for `testsource()`.

The testsource() function takes a module and a name, finds the (first)
test with that name in that module, and converts it to a script. The
example code is converted to regular Python code.  The surrounding
words and expected output are converted to comments:

    >>> import test.test_doctest
    >>> name = 'test.test_doctest.sample_func'
    >>> print doctest.testsource(test.test_doctest, name)
    # Blah blah
    #
    print sample_func(22)
    # Expected:
    ## 44
    #
    # Yee ha!

    >>> name = 'test.test_doctest.SampleNewStyleClass'
    >>> print doctest.testsource(test.test_doctest, name)
    print '1\n2\n3'
    # Expected:
    ## 1
    ## 2
    ## 3

    >>> name = 'test.test_doctest.SampleClass.a_classmethod'
    >>> print doctest.testsource(test.test_doctest, name)
    print SampleClass.a_classmethod(10)
    # Expected:
    ## 12
    print SampleClass(0).a_classmethod(10)
    # Expected:
    ## 12
"""

def test_debug(): r"""

Create a docstring that we want to debug:

    >>> s = '''
    ...     >>> x = 12
    ...     >>> print x
    ...     12
    ...     '''

Create some fake stdin input, to feed to the debugger:

    >>> import tempfile
    >>> fake_stdin = tempfile.TemporaryFile(mode='w+')
    >>> fake_stdin.write('\n'.join(['next', 'print x', 'continue', '']))
    >>> fake_stdin.seek(0)
    >>> real_stdin = sys.stdin
    >>> sys.stdin = fake_stdin

Run the debugger on the docstring, and then restore sys.stdin.

    >>> try:
    ...     doctest.debug_src(s)
    ... finally:
    ...      sys.stdin = real_stdin
    ...      fake_stdin.close()
    ... # doctest: +NORMALIZE_WHITESPACE
    > <string>(1)?()
    (Pdb) 12
    --Return--
    > <string>(1)?()->None
    (Pdb) 12
    (Pdb)

"""

def test_pdb_set_trace():
    r"""Using pdb.set_trace from a doctest

    You can use pdb.set_trace from a doctest.  To do so, you must
    retrieve the set_trace function from the pdb module at the time
    you use it.  The doctest module changes sys.stdout so that it can
    capture program output.  It also temporarily replaces pdb.set_trace
    with a version that restores stdout.  This is necessary for you to
    see debugger output.

      >>> doc = '''
      ... >>> x = 42
      ... >>> import pdb; pdb.set_trace()
      ... '''
      >>> parser = doctest.DocTestParser()
      >>> test = parser.get_doctest(doc, {}, "foo", "foo.py", 0)
      >>> runner = doctest.DocTestRunner(verbose=False)

    To demonstrate this, we'll create a fake standard input that
    captures our debugger input:

      >>> import tempfile
      >>> fake_stdin = tempfile.TemporaryFile(mode='w+')
      >>> fake_stdin.write('\n'.join([
      ...    'up',       # up out of pdb.set_trace
      ...    'up',       # up again to get out of our wrapper
      ...    'print x',  # print data defined by the example
      ...    'continue', # stop debugging
      ...    '']))
      >>> fake_stdin.seek(0)
      >>> real_stdin = sys.stdin
      >>> sys.stdin = fake_stdin

      >>> runner.run(test) # doctest: +ELLIPSIS
      --Return--
      > ...set_trace()->None
      -> Pdb().set_trace()
      (Pdb) > ...set_trace()
      -> real_pdb_set_trace()
      (Pdb) > <string>(1)?()
      (Pdb) 42
      (Pdb) (0, 2)

      >>> sys.stdin = real_stdin
      >>> fake_stdin.close()

      You can also put pdb.set_trace in a function called from a test:

      >>> def calls_set_trace():
      ...    y=2
      ...    import pdb; pdb.set_trace()

      >>> doc = '''
      ... >>> x=1
      ... >>> calls_set_trace()
      ... '''
      >>> test = parser.get_doctest(doc, globals(), "foo", "foo.py", 0)
      >>> fake_stdin = tempfile.TemporaryFile(mode='w+')
      >>> fake_stdin.write('\n'.join([
      ...    'up',       # up out of pdb.set_trace
      ...    'up',       # up again to get out of our wrapper
      ...    'print y',  # print data defined in the function
      ...    'up',       # out of function
      ...    'print x',  # print data defined by the example
      ...    'continue', # stop debugging
      ...    '']))
      >>> fake_stdin.seek(0)
      >>> real_stdin = sys.stdin
      >>> sys.stdin = fake_stdin

      >>> runner.run(test) # doctest: +ELLIPSIS
      --Return--
      > ...set_trace()->None
      -> Pdb().set_trace()
      (Pdb) ...set_trace()
      -> real_pdb_set_trace()
      (Pdb) > <string>(3)calls_set_trace()
      (Pdb) 2
      (Pdb) > <string>(1)?()
      (Pdb) 1
      (Pdb) (0, 2)
      """

def test_DocTestSuite():
    """DocTestSuite creates a unittest test suite from a doctest.

       We create a Suite by providing a module.  A module can be provided
       by passing a module object:

         >>> import unittest
         >>> import test.sample_doctest
         >>> suite = doctest.DocTestSuite(test.sample_doctest)
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=9 errors=0 failures=4>

       We can also supply the module by name:

         >>> suite = doctest.DocTestSuite('test.sample_doctest')
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=9 errors=0 failures=4>

       We can use the current module:

         >>> suite = test.sample_doctest.test_suite()
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=9 errors=0 failures=4>

       We can supply global variables.  If we pass globs, they will be
       used instead of the module globals.  Here we'll pass an empty
       globals, triggering an extra error:

         >>> suite = doctest.DocTestSuite('test.sample_doctest', globs={})
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=9 errors=0 failures=5>

       Alternatively, we can provide extra globals.  Here we'll make an
       error go away by providing an extra global variable:

         >>> suite = doctest.DocTestSuite('test.sample_doctest',
         ...                              extraglobs={'y': 1})
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=9 errors=0 failures=3>

       You can pass option flags.  Here we'll cause an extra error
       by disabling the blank-line feature:

         >>> suite = doctest.DocTestSuite('test.sample_doctest',
         ...                      optionflags=doctest.DONT_ACCEPT_BLANKLINE)
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=9 errors=0 failures=5>

       You can supply setUp and tearDown functions:

         >>> def setUp():
         ...     import test.test_doctest
         ...     test.test_doctest.sillySetup = True

         >>> def tearDown():
         ...     import test.test_doctest
         ...     del test.test_doctest.sillySetup

       Here, we installed a silly variable that the test expects:

         >>> suite = doctest.DocTestSuite('test.sample_doctest',
         ...      setUp=setUp, tearDown=tearDown)
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=9 errors=0 failures=3>

       But the tearDown restores sanity:

         >>> import test.test_doctest
         >>> test.test_doctest.sillySetup
         Traceback (most recent call last):
         ...
         AttributeError: 'module' object has no attribute 'sillySetup'

       Finally, you can provide an alternate test finder.  Here we'll
       use a custom test_finder to to run just the test named bar.
       However, the test in the module docstring, and the two tests
       in the module __test__ dict, aren't filtered, so we actually
       run three tests besides bar's.  The filtering mechanisms are
       poorly conceived, and will go away someday.

         >>> finder = doctest.DocTestFinder(
         ...    _namefilter=lambda prefix, base: base!='bar')
         >>> suite = doctest.DocTestSuite('test.sample_doctest',
         ...                              test_finder=finder)
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=4 errors=0 failures=1>
       """

def test_DocFileSuite():
    """We can test tests found in text files using a DocFileSuite.

       We create a suite by providing the names of one or more text
       files that include examples:

         >>> import unittest
         >>> suite = doctest.DocFileSuite('test_doctest.txt',
         ...                              'test_doctest2.txt')
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=2 errors=0 failures=2>

       The test files are looked for in the directory containing the
       calling module.  A package keyword argument can be provided to
       specify a different relative location.

         >>> import unittest
         >>> suite = doctest.DocFileSuite('test_doctest.txt',
         ...                              'test_doctest2.txt',
         ...                              package='test')
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=2 errors=0 failures=2>

       Note that '/' should be used as a path separator.  It will be
       converted to a native separator at run time:


         >>> suite = doctest.DocFileSuite('../test/test_doctest.txt')
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=1 errors=0 failures=1>

       You can specify initial global variables:

         >>> suite = doctest.DocFileSuite('test_doctest.txt',
         ...                              'test_doctest2.txt',
         ...                              globs={'favorite_color': 'blue'})
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=2 errors=0 failures=1>

       In this case, we supplied a missing favorite color. You can
       provide doctest options:

         >>> suite = doctest.DocFileSuite('test_doctest.txt',
         ...                              'test_doctest2.txt',
         ...                         optionflags=doctest.DONT_ACCEPT_BLANKLINE,
         ...                              globs={'favorite_color': 'blue'})
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=2 errors=0 failures=2>

       And, you can provide setUp and tearDown functions:

       You can supply setUp and teatDoen functions:

         >>> def setUp():
         ...     import test.test_doctest
         ...     test.test_doctest.sillySetup = True

         >>> def tearDown():
         ...     import test.test_doctest
         ...     del test.test_doctest.sillySetup

       Here, we installed a silly variable that the test expects:

         >>> suite = doctest.DocFileSuite('test_doctest.txt',
         ...                              'test_doctest2.txt',
         ...                              setUp=setUp, tearDown=tearDown)
         >>> suite.run(unittest.TestResult())
         <unittest.TestResult run=2 errors=0 failures=1>

       But the tearDown restores sanity:

         >>> import test.test_doctest
         >>> test.test_doctest.sillySetup
         Traceback (most recent call last):
         ...
         AttributeError: 'module' object has no attribute 'sillySetup'

    """

def test_trailing_space_in_test():
    """
    Trailing spaces in expected output are significant:

      >>> x, y = 'foo', ''
      >>> print x, y
      foo \n
    """

# old_test1, ... used to live in doctest.py, but cluttered it.  Note
# that these use the deprecated doctest.Tester, so should go away (or
# be rewritten) someday.

# Ignore all warnings about the use of class Tester in this module.
# Note that the name of this module may differ depending on how it's
# imported, so the use of __name__ is important.
warnings.filterwarnings("ignore", "class Tester", DeprecationWarning,
                        __name__, 0)

def old_test1(): r"""
>>> from doctest import Tester
>>> t = Tester(globs={'x': 42}, verbose=0)
>>> t.runstring(r'''
...      >>> x = x * 2
...      >>> print x
...      42
... ''', 'XYZ')
**********************************************************************
Line 3, in XYZ
Failed example:
    print x
Expected:
    42
Got:
    84
(1, 2)
>>> t.runstring(">>> x = x * 2\n>>> print x\n84\n", 'example2')
(0, 2)
>>> t.summarize()
**********************************************************************
1 items had failures:
   1 of   2 in XYZ
***Test Failed*** 1 failures.
(1, 4)
>>> t.summarize(verbose=1)
1 items passed all tests:
   2 tests in example2
**********************************************************************
1 items had failures:
   1 of   2 in XYZ
4 tests in 2 items.
3 passed and 1 failed.
***Test Failed*** 1 failures.
(1, 4)
"""

def old_test2(): r"""
        >>> from doctest import Tester
        >>> t = Tester(globs={}, verbose=1)
        >>> test = r'''
        ...    # just an example
        ...    >>> x = 1 + 2
        ...    >>> x
        ...    3
        ... '''
        >>> t.runstring(test, "Example")
        Running string Example
        Trying:
            x = 1 + 2
        Expecting nothing
        ok
        Trying:
            x
        Expecting:
            3
        ok
        0 of 2 examples failed in string Example
        (0, 2)
"""

def old_test3(): r"""
        >>> from doctest import Tester
        >>> t = Tester(globs={}, verbose=0)
        >>> def _f():
        ...     '''Trivial docstring example.
        ...     >>> assert 2 == 2
        ...     '''
        ...     return 32
        ...
        >>> t.rundoc(_f)  # expect 0 failures in 1 example
        (0, 1)
"""

def old_test4(): """
        >>> import new
        >>> m1 = new.module('_m1')
        >>> m2 = new.module('_m2')
        >>> test_data = \"""
        ... def _f():
        ...     '''>>> assert 1 == 1
        ...     '''
        ... def g():
        ...    '''>>> assert 2 != 1
        ...    '''
        ... class H:
        ...    '''>>> assert 2 > 1
        ...    '''
        ...    def bar(self):
        ...        '''>>> assert 1 < 2
        ...        '''
        ... \"""
        >>> exec test_data in m1.__dict__
        >>> exec test_data in m2.__dict__
        >>> m1.__dict__.update({"f2": m2._f, "g2": m2.g, "h2": m2.H})

        Tests that objects outside m1 are excluded:

        >>> from doctest import Tester
        >>> t = Tester(globs={}, verbose=0)
        >>> t.rundict(m1.__dict__, "rundict_test", m1)  # f2 and g2 and h2 skipped
        (0, 4)

        Once more, not excluding stuff outside m1:

        >>> t = Tester(globs={}, verbose=0)
        >>> t.rundict(m1.__dict__, "rundict_test_pvt")  # None are skipped.
        (0, 8)

        The exclusion of objects from outside the designated module is
        meant to be invoked automagically by testmod.

        >>> doctest.testmod(m1, verbose=False)
        (0, 4)
"""

######################################################################
## Main
######################################################################

def test_main():
    # Check the doctest cases in doctest itself:
    test_support.run_doctest(doctest, verbosity=True)
    # Check the doctest cases defined here:
    from test import test_doctest
    test_support.run_doctest(test_doctest, verbosity=True)

import trace, sys, re, StringIO
def test_coverage(coverdir):
    tracer = trace.Trace(ignoredirs=[sys.prefix, sys.exec_prefix,],
                         trace=0, count=1)
    tracer.run('reload(doctest); test_main()')
    r = tracer.results()
    print 'Writing coverage results...'
    r.write_results(show_missing=True, summary=True,
                    coverdir=coverdir)

if __name__ == '__main__':
    if '-c' in sys.argv:
        test_coverage('/tmp/doctest.cover')
    else:
        test_main()
