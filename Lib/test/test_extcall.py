from UserList import UserList
from test_support import TestFailed
import string

def f(*a, **k):
    print a, k

def g(x, *y, **z):
    print x, y, z

def h(j=1, a=2, h=3):
    print j, a, h

f()
f(1)
f(1, 2)
f(1, 2, 3)

f(1, 2, 3, *(4, 5))
f(1, 2, 3, *[4, 5])
f(1, 2, 3, *UserList([4, 5]))
f(1, 2, 3, **{'a':4, 'b':5})
f(1, 2, 3, *(4, 5), **{'a':6, 'b':7})
f(1, 2, 3, x=4, y=5, *(6, 7), **{'a':8, 'b':9})

try:
    g()
except TypeError, err:
    print "TypeError:", err
else:
    print "should raise TypeError: not enough arguments; expected 1, got 0"

try:
    g(*())
except TypeError, err:
    print "TypeError:", err
else:
    print "should raise TypeError: not enough arguments; expected 1, got 0"

try:
    g(*(), **{})
except TypeError, err:
    print "TypeError:", err
else:
    print "should raise TypeError: not enough arguments; expected 1, got 0"

g(1)
g(1, 2)
g(1, 2, 3)
g(1, 2, 3, *(4, 5))
class Nothing: pass
try:
    g(*Nothing())
except AttributeError, attr:
    pass
else:
    print "should raise AttributeError: __len__"

class Nothing:
    def __len__(self):
        return 5
try:
    g(*Nothing())
except AttributeError, attr:
    pass
else:
    print "should raise AttributeError: __getitem__"

class Nothing:
    def __len__(self):
        return 5
    def __getitem__(self, i):
        if i < 3:
            return i
        else:
            raise IndexError, i
g(*Nothing())

# make sure the function call doesn't stomp on the dictionary?
d = {'a': 1, 'b': 2, 'c': 3}
d2 = d.copy()
assert d == d2
g(1, d=4, **d)
print d
print d2
assert d == d2, "function call modified dictionary"

# what about willful misconduct?
def saboteur(**kw):
    kw['x'] = locals() # yields a cyclic kw
    return kw
d = {}
kw = saboteur(a=1, **d)
assert d == {}
# break the cycle
del kw['x']

try:
    g(1, 2, 3, **{'x':4, 'y':5})
except TypeError, err:
    print err
else:
    print "should raise TypeError: keyword parameter redefined"

try:
    g(1, 2, 3, a=4, b=5, *(6, 7), **{'a':8, 'b':9})
except TypeError, err:
    print err
else:
    print "should raise TypeError: keyword parameter redefined"

try:
    f(**{1:2})
except TypeError, err:
    print err
else:
    print "should raise TypeError: keywords must be strings"

try:
    h(**{'e': 2})
except TypeError, err:
    print err
else:
    print "should raise TypeError: unexpected keyword argument: e"

try:
    h(*h)
except TypeError, err:
    print err
else:
    print "should raise TypeError: * argument must be a tuple"

try:
    h(**h)
except TypeError, err:
    print err
else:
    print "should raise TypeError: ** argument must be a dictionary"

def f2(*a, **b):
    return a, b

d = {}
for i in range(512):
    key = 'k%d' % i
    d[key] = i
a, b = f2(1, *(2, 3), **d)
print len(a), len(b), b == d

class Foo:
    def method(self, arg1, arg2):
        return arg1 + arg2

x = Foo()
print Foo.method(*(x, 1, 2))
print Foo.method(x, *(1, 2))
try:
    print Foo.method(*(1, 2, 3))
except TypeError, err:
    print err
try:
    print Foo.method(1, *(2, 3))
except TypeError, err:
    print err

# A PyCFunction that takes only positional parameters should allow an
# empty keyword dictionary to pass without a complaint, but raise a
# TypeError if the dictionary is non-empty.
id(1, **{})
try:
    id(1, **{"foo": 1})
except TypeError:
    pass
else:
    raise TestFailed, 'expected TypeError; no exception raised'

a, b, d, e, v, k = 'A', 'B', 'D', 'E', 'V', 'K'
funcs = []
maxargs = {}
for args in ['', 'a', 'ab']:
    for defargs in ['', 'd', 'de']:
        for vararg in ['', 'v']:
            for kwarg in ['', 'k']:
                name = 'z' + args + defargs + vararg + kwarg
                arglist = list(args) + map(
                    lambda x: '%s="%s"' % (x, x), defargs)
                if vararg: arglist.append('*' + vararg)
                if kwarg: arglist.append('**' + kwarg)
                decl = 'def %s(%s): print "ok %s", a, b, d, e, v, k' % (
                    name, string.join(arglist, ', '), name)
                exec(decl)
                func = eval(name)
                funcs.append(func)
                maxargs[func] = len(args + defargs)

for name in ['za', 'zade', 'zabk', 'zabdv', 'zabdevk']:
    func = eval(name)
    for args in [(), (1, 2), (1, 2, 3, 4, 5)]:
        for kwargs in ['', 'a', 'd', 'ad', 'abde']:
            kwdict = {}
            for k in kwargs: kwdict[k] = k + k
            print func.func_name, args, kwdict, '->',
            try: apply(func, args, kwdict)
            except TypeError, err: print err
