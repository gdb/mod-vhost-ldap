"""Loading unittests."""

import os
import sys
import types

from fnmatch import fnmatch

from . import case, suite


def _CmpToKey(mycmp):
    'Convert a cmp= function into a key= function'
    class K(object):
        def __init__(self, obj):
            self.obj = obj
        def __lt__(self, other):
            return mycmp(self.obj, other.obj) == -1
    return K


class TestLoader(object):
    """
    This class is responsible for loading tests according to various criteria
    and returning them wrapped in a TestSuite
    """
    testMethodPrefix = 'test'
    sortTestMethodsUsing = cmp
    suiteClass = suite.TestSuite
    _top_level_dir = None

    def loadTestsFromTestCase(self, testCaseClass):
        """Return a suite of all tests cases contained in testCaseClass"""
        if issubclass(testCaseClass, suite.TestSuite):
            raise TypeError("Test cases should not be derived from TestSuite." \
                                " Maybe you meant to derive from TestCase?")
        testCaseNames = self.getTestCaseNames(testCaseClass)
        if not testCaseNames and hasattr(testCaseClass, 'runTest'):
            testCaseNames = ['runTest']
        loaded_suite = self.suiteClass(map(testCaseClass, testCaseNames))
        return loaded_suite

    def loadTestsFromModule(self, module, use_load_tests=True):
        """Return a suite of all tests cases contained in the given module"""
        tests = []
        for name in dir(module):
            obj = getattr(module, name)
            if isinstance(obj, type) and issubclass(obj, case.TestCase):
                tests.append(self.loadTestsFromTestCase(obj))

        load_tests = getattr(module, 'load_tests', None)
        if use_load_tests and load_tests is not None:
            return load_tests(self, tests, None)
        return self.suiteClass(tests)

    def loadTestsFromName(self, name, module=None):
        """Return a suite of all tests cases given a string specifier.

        The name may resolve either to a module, a test case class, a
        test method within a test case class, or a callable object which
        returns a TestCase or TestSuite instance.

        The method optionally resolves the names relative to a given module.
        """
        parts = name.split('.')
        if module is None:
            parts_copy = parts[:]
            while parts_copy:
                try:
                    module = __import__('.'.join(parts_copy))
                    break
                except ImportError:
                    del parts_copy[-1]
                    if not parts_copy:
                        raise
            parts = parts[1:]
        obj = module
        for part in parts:
            parent, obj = obj, getattr(obj, part)

        if isinstance(obj, types.ModuleType):
            return self.loadTestsFromModule(obj)
        elif isinstance(obj, type) and issubclass(obj, case.TestCase):
            return self.loadTestsFromTestCase(obj)
        elif (isinstance(obj, types.UnboundMethodType) and
              isinstance(parent, type) and
              issubclass(parent, case.TestCase)):
            return suite.TestSuite([parent(obj.__name__)])
        elif isinstance(obj, suite.TestSuite):
            return obj
        elif hasattr(obj, '__call__'):
            test = obj()
            if isinstance(test, suite.TestSuite):
                return test
            elif isinstance(test, case.TestCase):
                return suite.TestSuite([test])
            else:
                raise TypeError("calling %s returned %s, not a test" %
                                (obj, test))
        else:
            raise TypeError("don't know how to make test from: %s" % obj)

    def loadTestsFromNames(self, names, module=None):
        """Return a suite of all tests cases found using the given sequence
        of string specifiers. See 'loadTestsFromName()'.
        """
        suites = [self.loadTestsFromName(name, module) for name in names]
        return self.suiteClass(suites)

    def getTestCaseNames(self, testCaseClass):
        """Return a sorted sequence of method names found within testCaseClass
        """
        def isTestMethod(attrname, testCaseClass=testCaseClass,
                         prefix=self.testMethodPrefix):
            return attrname.startswith(prefix) and \
                hasattr(getattr(testCaseClass, attrname), '__call__')
        testFnNames = filter(isTestMethod, dir(testCaseClass))
        if self.sortTestMethodsUsing:
            testFnNames.sort(key=_CmpToKey(self.sortTestMethodsUsing))
        return testFnNames

    def discover(self, start_dir, pattern='test*.py', top_level_dir=None):
        """Find and return all test modules from the specified start
        directory, recursing into subdirectories to find them. Only test files
        that match the pattern will be loaded. (Using shell style pattern
        matching.)

        All test modules must be importable from the top level of the project.
        If the start directory is not the top level directory then the top
        level directory must be specified separately.

        If a test package name (directory with '__init__.py') matches the
        pattern then the package will be checked for a 'load_tests' function. If
        this exists then it will be called with loader, tests, pattern.

        If load_tests exists then discovery does  *not* recurse into the package,
        load_tests is responsible for loading all tests in the package.

        The pattern is deliberately not stored as a loader attribute so that
        packages can continue discovery themselves. top_level_dir is stored so
        load_tests does not need to pass this argument in to loader.discover().
        """
        if top_level_dir is None and self._top_level_dir is not None:
            # make top_level_dir optional if called from load_tests in a package
            top_level_dir = self._top_level_dir
        elif top_level_dir is None:
            top_level_dir = start_dir

        top_level_dir = os.path.abspath(os.path.normpath(top_level_dir))
        start_dir = os.path.abspath(os.path.normpath(start_dir))

        if not top_level_dir in sys.path:
            # all test modules must be importable from the top level directory
            sys.path.append(top_level_dir)
        self._top_level_dir = top_level_dir

        if start_dir != top_level_dir and not os.path.isfile(os.path.join(start_dir, '__init__.py')):
            # what about __init__.pyc or pyo (etc)
            raise ImportError('Start directory is not importable: %r' % start_dir)

        tests = list(self._find_tests(start_dir, pattern))
        return self.suiteClass(tests)


    def _get_module_from_path(self, path):
        """Load a module from a path relative to the top-level directory
        of a project. Used by discovery."""
        path = os.path.splitext(os.path.normpath(path))[0]

        relpath = os.path.relpath(path, self._top_level_dir)
        assert not os.path.isabs(relpath), "Path must be within the project"
        assert not relpath.startswith('..'), "Path must be within the project"

        name = relpath.replace(os.path.sep, '.')
        __import__(name)
        return sys.modules[name]

    def _find_tests(self, start_dir, pattern):
        """Used by discovery. Yields test suites it loads."""
        paths = os.listdir(start_dir)

        for path in paths:
            full_path = os.path.join(start_dir, path)
            # what about __init__.pyc or pyo (etc)
            # we would need to avoid loading the same tests multiple times
            # from '.py', '.pyc' *and* '.pyo'
            if os.path.isfile(full_path) and path.lower().endswith('.py'):
                if fnmatch(path, pattern):
                    # if the test file matches, load it
                    module = self._get_module_from_path(full_path)
                    yield self.loadTestsFromModule(module)
            elif os.path.isdir(full_path):
                if not os.path.isfile(os.path.join(full_path, '__init__.py')):
                    continue

                load_tests = None
                tests = None
                if fnmatch(path, pattern):
                    # only check load_tests if the package directory itself matches the filter
                    package = self._get_module_from_path(full_path)
                    load_tests = getattr(package, 'load_tests', None)
                    tests = self.loadTestsFromModule(package, use_load_tests=False)

                if load_tests is None:
                    if tests is not None:
                        # tests loaded from package file
                        yield tests
                    # recurse into the package
                    for test in self._find_tests(full_path, pattern):
                        yield test
                else:
                    yield load_tests(self, tests, pattern)

defaultTestLoader = TestLoader()


def _makeLoader(prefix, sortUsing, suiteClass=None):
    loader = TestLoader()
    loader.sortTestMethodsUsing = sortUsing
    loader.testMethodPrefix = prefix
    if suiteClass:
        loader.suiteClass = suiteClass
    return loader

def getTestCaseNames(testCaseClass, prefix, sortUsing=cmp):
    return _makeLoader(prefix, sortUsing).getTestCaseNames(testCaseClass)

def makeSuite(testCaseClass, prefix='test', sortUsing=cmp,
              suiteClass=suite.TestSuite):
    return _makeLoader(prefix, sortUsing, suiteClass).loadTestsFromTestCase(testCaseClass)

def findTestCases(module, prefix='test', sortUsing=cmp,
                  suiteClass=suite.TestSuite):
    return _makeLoader(prefix, sortUsing, suiteClass).loadTestsFromModule(module)
