import unittest
from test import test_support


import os, resource

# This test is checking a few specific problem spots with the resource module.

class ResourceTest(unittest.TestCase):
    def test_fsize_ismax(self):
       
        try:
            (cur, max) = resource.getrlimit(resource.RLIMIT_FSIZE)
        except AttributeError:
            pass
        else:
            # RLIMIT_FSIZE should be RLIM_INFINITY, which will be a really big
            # number on a platform with large file support.  On these platforms,
            # we need to test that the get/setrlimit functions properly convert
            # the number to a C long long and that the conversion doesn't raise
            # an error.
            self.assertEqual(resource.RLIM_INFINITY, max)
            resource.setrlimit(resource.RLIMIT_FSIZE, (cur, max))

    def test_fsize_enforced(self):
        try:
            (cur, max) = resource.getrlimit(resource.RLIMIT_FSIZE)
        except AttributeError:
            pass
        else:
            # Check to see what happens when the RLIMIT_FSIZE is small.  Some
            # versions of Python were terminated by an uncaught SIGXFSZ, but
            # pythonrun.c has been fixed to ignore that exception.  If so, the
            # write() should return EFBIG when the limit is exceeded.
            
            # At least one platform has an unlimited RLIMIT_FSIZE and attempts
            # to change it raise ValueError instead.
            try:
                try:
                    resource.setrlimit(resource.RLIMIT_FSIZE, (1024, max))
                    limit_set = True
                except ValueError:
                    limit_set = False
                f = open(test_support.TESTFN, "wb")
                f.write("X" * 1024)
                try:
                    f.write("Y")
                    f.flush()
                except IOError:
                    if not limit_set:
                        raise
                f.close()
                os.unlink(test_support.TESTFN)
            finally:
                resource.setrlimit(resource.RLIMIT_FSIZE, (cur, max))

    def test_fsize_toobig(self):
        # Be sure that setrlimit is checking for really large values
        too_big = 10L**50
        try:
            (cur, max) = resource.getrlimit(resource.RLIMIT_FSIZE)
        except AttributeError:
            pass
        else:
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (too_big, max))
            except (OverflowError, ValueError):
                pass
            try:
                resource.setrlimit(resource.RLIMIT_FSIZE, (max, too_big))
            except (OverflowError, ValueError):
                pass

def test_main(verbose=None):
    test_support.run_unittest(ResourceTest)

if __name__ == "__main__":
    test_main()
