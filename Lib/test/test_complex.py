from test_support import TestFailed, fcmp
from random import random

# XXX need many, many more tests here.

nerrors = 0

def check_close(x, y):
    """Return true iff complexes x and y "are close\""""
    return fcmp(x.real, y.real) == 0 == fcmp(x.imag, y.imag)

def test_div(x, y):
    """Compute complex z=x*y, and check that z/x==y and z/y==x."""
    global nerrors
    z = x * y
    if x != 0:
        q = z / x
        if not check_close(q, y):
            nerrors += 1
            print "%r / %r == %r but expected %r" % (z, x, q, y)
    if y != 0:
        q = z / y
        if not check_close(q, x):
            nerrors += 1
            print "%r / %r == %r but expected %r" % (z, y, q, x)

simple_real = [float(i) for i in range(-5, 6)]
simple_complex = [complex(x, y) for x in simple_real for y in simple_real]
for x in simple_complex:
    for y in simple_complex:
        test_div(x, y)

# A naive complex division algorithm (such as in 2.0) is very prone to
# nonsense errors for these (overflows and underflows).
test_div(complex(1e200, 1e200), 1+0j)
test_div(complex(1e-200, 1e-200), 1+0j)

# Just for fun.
for i in range(100):
    test_div(complex(random(), random()),
             complex(random(), random()))

try:
    z = 1.0 / (0+0j)
except ZeroDivisionError:
    pass
else:
    nerrors += 1
    raise TestFailed("Division by complex 0 didn't raise ZeroDivisionError")

if nerrors:
    raise TestFailed("%d tests failed" % nerrors)
