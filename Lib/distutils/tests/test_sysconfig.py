"""Tests for distutils.dist."""

from distutils import sysconfig
from distutils.ccompiler import get_default_compiler

import os
import unittest

from test.test_support import TESTFN

class SysconfigTestCase(unittest.TestCase):

    def setUp(self):
        self.old_AR = os.environ.get('AR')

    def tearDown(self):
        if self.old_AR is not None:
            os.environ['AR'] = self.old_AR

    def test_get_config_h_filename(self):
        config_h = sysconfig.get_config_h_filename()
        self.assert_(os.path.isfile(config_h), config_h)

    def test_get_python_lib(self):
        lib_dir = sysconfig.get_python_lib()
        # XXX doesn't work on Linux when Python was never installed before
        #self.assert_(os.path.isdir(lib_dir), lib_dir)
        # test for pythonxx.lib?

    def test_get_python_inc(self):
        inc_dir = sysconfig.get_python_inc()
        # This is not much of a test.  We make sure Python.h exists
        # in the directory returned by get_python_inc() but we don't know
        # it is the correct file.
        self.assert_(os.path.isdir(inc_dir), inc_dir)
        python_h = os.path.join(inc_dir, "Python.h")
        self.assert_(os.path.isfile(python_h), python_h)

    def test_get_config_vars(self):
        cvars = sysconfig.get_config_vars()
        self.assert_(isinstance(cvars, dict))
        self.assert_(cvars)

    def test_customize_compiler(self):

        # not testing if default compiler is not unix
        if get_default_compiler() != 'unix':
            return

        os.environ['AR'] = 'xxx'

        # make sure AR gets caught
        class compiler:
            compiler_type = 'unix'

            def set_executables(self, **kw):
                self.exes = kw

        comp = compiler()
        sysconfig.customize_compiler(comp)
        self.assertEquals(comp.exes['archiver'], 'xxx')


def test_suite():
    suite = unittest.TestSuite()
    suite.addTest(unittest.makeSuite(SysconfigTestCase))
    return suite
