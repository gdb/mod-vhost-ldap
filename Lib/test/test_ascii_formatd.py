# PyOS_ascii_formatd is deprecated and not called from anywhere in
#  Python itself. So this module is the only place it gets tested.
# Test that it works, and test that it's deprecated.

import unittest
from test.test_support import (check_warnings, run_unittest,
                               cpython_only, import_module)


class FormatDeprecationTests(unittest.TestCase):

    @cpython_only
    def test_format_deprecation(self):
        # skip if _ctypes is not available
        import_module('_ctypes')
        # delay importing ctypes until we know we're in CPython
        from ctypes import (pythonapi, create_string_buffer, sizeof, byref,
                            c_double)
        PyOS_ascii_formatd = pythonapi.PyOS_ascii_formatd
        buf = create_string_buffer(' ' * 100)

        with check_warnings(('PyOS_ascii_formatd is deprecated',
                             DeprecationWarning)):
            PyOS_ascii_formatd(byref(buf), sizeof(buf), '%+.10f',
                               c_double(10.0))
            self.assertEqual(buf.value, '+10.0000000000')


class FormatTests(unittest.TestCase):
    # ensure that, for the restricted set of format codes,
    # %-formatting returns the same values os PyOS_ascii_formatd
    @cpython_only
    def test_format(self):
        # delay importing ctypes until we know we're in CPython
        from ctypes import (pythonapi, create_string_buffer, sizeof, byref,
                            c_double)
        PyOS_ascii_formatd = pythonapi.PyOS_ascii_formatd
        buf = create_string_buffer(' ' * 100)

        tests = [
            ('%f', 100.0),
            ('%g', 100.0),
            ('%#g', 100.0),
            ('%#.2g', 100.0),
            ('%#.2g', 123.4567),
            ('%#.2g', 1.234567e200),
            ('%e', 1.234567e200),
            ('%e', 1.234),
            ('%+e', 1.234),
            ('%-e', 1.234),
            ]

        with check_warnings(('PyOS_ascii_formatd is deprecated',
                             DeprecationWarning)):
            for format, val in tests:
                PyOS_ascii_formatd(byref(buf), sizeof(buf), format,
                                   c_double(val))
                self.assertEqual(buf.value, format % val)


def test_main():
    run_unittest(FormatDeprecationTests, FormatTests)

if __name__ == '__main__':
    test_main()
