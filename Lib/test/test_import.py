from test_support import TESTFN, TestFailed

import os
import random
import sys

# Brief digression to test that import is case-sensitive:  if we got this
# far, we know for sure that "random" exists.
try:
    import RAnDoM
except ImportError:
    pass
else:
    raise TestFailed("import of RAnDoM should have failed (case mismatch)")

# Another brief digression to test the accuracy of manifest float constants.
import double_const  # don't blink -- that *was* the test

def test_with_extension(ext): # ext normally ".py"; perhaps ".pyw"
    source = TESTFN + ext
    pyo = TESTFN + ".pyo"
    if sys.platform.startswith('java'):
        pyc = TESTFN + "$py.class"
    else:
        pyc = TESTFN + ".pyc"

    f = open(source, "w")
    print >> f, "# This tests Python's ability to import a", ext, "file."
    a = random.randrange(1000)
    b = random.randrange(1000)
    print >> f, "a =", a
    print >> f, "b =", b
    f.close()

    try:
        try:
            mod = __import__(TESTFN)
        except ImportError, err:
            raise ValueError("import from %s failed: %s" % (ext, err))

        if mod.a != a or mod.b != b:
            print a, "!=", mod.a
            print b, "!=", mod.b
            raise ValueError("module loaded (%s) but contents invalid" % mod)
    finally:
        os.unlink(source)

    try:
        try:
            reload(mod)
        except ImportError, err:
            raise ValueError("import from .pyc/.pyo failed: %s" % err)
    finally:
        try:
            os.unlink(pyc)
        except os.error:
            pass
        try:
            os.unlink(pyo)
        except os.error:
            pass
        del sys.modules[TESTFN]

sys.path.insert(0, os.curdir)
try:
    test_with_extension(".py")
    if sys.platform.startswith("win"):
        for ext in ".PY", ".Py", ".pY", ".pyw", ".PYW", ".pYw":
            test_with_extension(ext)
finally:
    del sys.path[0]

def touch(path):
    fp = open(path, 'w')
    fp.close()

# test imports of packages with really long names, but specifically that their
# reprs include the full name
try:
    longname = 'areallylongpackageandmodulenametotestreprtruncation'
    os.mkdir(longname)
    touch(os.path.join(longname, '__init__.py'))
    os.mkdir(os.path.join(longname, longname))
    touch(os.path.join(longname, longname, '__init__.py'))
    touch(os.path.join(longname, longname, longname + '.py'))
    sys.path.insert(0, os.getcwd())
    from areallylongpackageandmodulenametotestreprtruncation.areallylongpackageandmodulenametotestreprtruncation import areallylongpackageandmodulenametotestreprtruncation
    if `areallylongpackageandmodulenametotestreprtruncation` <> \
       "<module 'areallylongpackageandmodulenametotestreprtruncation.areallylongpackageandmodulenametotestreprtruncation.areallylongpackageandmodulenametotestreprtruncation' from '%s'>" % areallylongpackageandmodulenametotestreprtruncation.__file__:
        raise TestFailed, 'module name truncation'
finally:
    # Delete recursively
    del sys.path[0]
    def zap(actions, dirname, names):
        for name in names:
            actions.append(os.path.join(dirname, name))
    actions = []
    os.path.walk(longname, zap, actions)
    actions.append(longname)
    actions.sort()
    actions.reverse()
    for p in actions:
        if os.path.isdir(p):
            os.rmdir(p)
        else:
            os.remove(p)
