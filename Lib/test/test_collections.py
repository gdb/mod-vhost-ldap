import unittest, doctest
from test import test_support
from collections import namedtuple, Counter, Mapping
import pickle, cPickle, copy
from random import randrange
import operator
from collections import Hashable, Iterable, Iterator
from collections import Sized, Container, Callable
from collections import Set, MutableSet
from collections import Mapping, MutableMapping
from collections import Sequence, MutableSequence

TestNT = namedtuple('TestNT', 'x y z')    # type used for pickle tests

class TestNamedTuple(unittest.TestCase):

    def test_factory(self):
        Point = namedtuple('Point', 'x y')
        self.assertEqual(Point.__name__, 'Point')
        self.assertEqual(Point.__doc__, 'Point(x, y)')
        self.assertEqual(Point.__slots__, ())
        self.assertEqual(Point.__module__, __name__)
        self.assertEqual(Point.__getitem__, tuple.__getitem__)
        self.assertEqual(Point._fields, ('x', 'y'))

        self.assertRaises(ValueError, namedtuple, 'abc%', 'efg ghi')       # type has non-alpha char
        self.assertRaises(ValueError, namedtuple, 'class', 'efg ghi')      # type has keyword
        self.assertRaises(ValueError, namedtuple, '9abc', 'efg ghi')       # type starts with digit

        self.assertRaises(ValueError, namedtuple, 'abc', 'efg g%hi')       # field with non-alpha char
        self.assertRaises(ValueError, namedtuple, 'abc', 'abc class')      # field has keyword
        self.assertRaises(ValueError, namedtuple, 'abc', '8efg 9ghi')      # field starts with digit
        self.assertRaises(ValueError, namedtuple, 'abc', '_efg ghi')       # field with leading underscore
        self.assertRaises(ValueError, namedtuple, 'abc', 'efg efg ghi')    # duplicate field

        namedtuple('Point0', 'x1 y2')   # Verify that numbers are allowed in names
        namedtuple('_', 'a b c')        # Test leading underscores in a typename

        nt = namedtuple('nt', u'the quick brown fox')                       # check unicode input
        self.assert_("u'" not in repr(nt._fields))
        nt = namedtuple('nt', (u'the', u'quick'))                           # check unicode input
        self.assert_("u'" not in repr(nt._fields))

        self.assertRaises(TypeError, Point._make, [11])                     # catch too few args
        self.assertRaises(TypeError, Point._make, [11, 22, 33])             # catch too many args

    def test_instance(self):
        Point = namedtuple('Point', 'x y')
        p = Point(11, 22)
        self.assertEqual(p, Point(x=11, y=22))
        self.assertEqual(p, Point(11, y=22))
        self.assertEqual(p, Point(y=22, x=11))
        self.assertEqual(p, Point(*(11, 22)))
        self.assertEqual(p, Point(**dict(x=11, y=22)))
        self.assertRaises(TypeError, Point, 1)                              # too few args
        self.assertRaises(TypeError, Point, 1, 2, 3)                        # too many args
        self.assertRaises(TypeError, eval, 'Point(XXX=1, y=2)', locals())   # wrong keyword argument
        self.assertRaises(TypeError, eval, 'Point(x=1)', locals())          # missing keyword argument
        self.assertEqual(repr(p), 'Point(x=11, y=22)')
        self.assert_('__dict__' not in dir(p))                              # verify instance has no dict
        self.assert_('__weakref__' not in dir(p))
        self.assertEqual(p, Point._make([11, 22]))                          # test _make classmethod
        self.assertEqual(p._fields, ('x', 'y'))                             # test _fields attribute
        self.assertEqual(p._replace(x=1), (1, 22))                          # test _replace method
        self.assertEqual(p._asdict(), dict(x=11, y=22))                     # test _asdict method

        try:
            p._replace(x=1, error=2)
        except ValueError:
            pass
        else:
            self._fail('Did not detect an incorrect fieldname')

        # verify that field string can have commas
        Point = namedtuple('Point', 'x, y')
        p = Point(x=11, y=22)
        self.assertEqual(repr(p), 'Point(x=11, y=22)')

        # verify that fieldspec can be a non-string sequence
        Point = namedtuple('Point', ('x', 'y'))
        p = Point(x=11, y=22)
        self.assertEqual(repr(p), 'Point(x=11, y=22)')

    def test_tupleness(self):
        Point = namedtuple('Point', 'x y')
        p = Point(11, 22)

        self.assert_(isinstance(p, tuple))
        self.assertEqual(p, (11, 22))                                       # matches a real tuple
        self.assertEqual(tuple(p), (11, 22))                                # coercable to a real tuple
        self.assertEqual(list(p), [11, 22])                                 # coercable to a list
        self.assertEqual(max(p), 22)                                        # iterable
        self.assertEqual(max(*p), 22)                                       # star-able
        x, y = p
        self.assertEqual(p, (x, y))                                         # unpacks like a tuple
        self.assertEqual((p[0], p[1]), (11, 22))                            # indexable like a tuple
        self.assertRaises(IndexError, p.__getitem__, 3)

        self.assertEqual(p.x, x)
        self.assertEqual(p.y, y)
        self.assertRaises(AttributeError, eval, 'p.z', locals())

    def test_odd_sizes(self):
        Zero = namedtuple('Zero', '')
        self.assertEqual(Zero(), ())
        self.assertEqual(Zero._make([]), ())
        self.assertEqual(repr(Zero()), 'Zero()')
        self.assertEqual(Zero()._asdict(), {})
        self.assertEqual(Zero()._fields, ())

        Dot = namedtuple('Dot', 'd')
        self.assertEqual(Dot(1), (1,))
        self.assertEqual(Dot._make([1]), (1,))
        self.assertEqual(Dot(1).d, 1)
        self.assertEqual(repr(Dot(1)), 'Dot(d=1)')
        self.assertEqual(Dot(1)._asdict(), {'d':1})
        self.assertEqual(Dot(1)._replace(d=999), (999,))
        self.assertEqual(Dot(1)._fields, ('d',))

        n = 5000
        import string, random
        names = list(set(''.join([random.choice(string.ascii_letters)
                                  for j in range(10)]) for i in range(n)))
        n = len(names)
        Big = namedtuple('Big', names)
        b = Big(*range(n))
        self.assertEqual(b, tuple(range(n)))
        self.assertEqual(Big._make(range(n)), tuple(range(n)))
        for pos, name in enumerate(names):
            self.assertEqual(getattr(b, name), pos)
        repr(b)                                 # make sure repr() doesn't blow-up
        d = b._asdict()
        d_expected = dict(zip(names, range(n)))
        self.assertEqual(d, d_expected)
        b2 = b._replace(**dict([(names[1], 999),(names[-5], 42)]))
        b2_expected = range(n)
        b2_expected[1] = 999
        b2_expected[-5] = 42
        self.assertEqual(b2, tuple(b2_expected))
        self.assertEqual(b._fields, tuple(names))

    def test_pickle(self):
        p = TestNT(x=10, y=20, z=30)
        for module in pickle, cPickle:
            loads = getattr(module, 'loads')
            dumps = getattr(module, 'dumps')
            for protocol in -1, 0, 1, 2:
                q = loads(dumps(p, protocol))
                self.assertEqual(p, q)
                self.assertEqual(p._fields, q._fields)

    def test_copy(self):
        p = TestNT(x=10, y=20, z=30)
        for copier in copy.copy, copy.deepcopy:
            q = copier(p)
            self.assertEqual(p, q)
            self.assertEqual(p._fields, q._fields)

class ABCTestCase(unittest.TestCase):

    def validate_abstract_methods(self, abc, *names):
        methodstubs = dict.fromkeys(names, lambda s, *args: 0)

        # everything should work will all required methods are present
        C = type('C', (abc,), methodstubs)
        C()

        # instantiation should fail if a required method is missing
        for name in names:
            stubs = methodstubs.copy()
            del stubs[name]
            C = type('C', (abc,), stubs)
            self.assertRaises(TypeError, C, name)


class TestOneTrickPonyABCs(ABCTestCase):

    def test_Hashable(self):
        # Check some non-hashables
        non_samples = [list(), set(), dict()]
        for x in non_samples:
            self.failIf(isinstance(x, Hashable), repr(x))
            self.failIf(issubclass(type(x), Hashable), repr(type(x)))
        # Check some hashables
        samples = [None,
                   int(), float(), complex(),
                   str(),
                   tuple(), frozenset(),
                   int, list, object, type,
                   ]
        for x in samples:
            self.failUnless(isinstance(x, Hashable), repr(x))
            self.failUnless(issubclass(type(x), Hashable), repr(type(x)))
        self.assertRaises(TypeError, Hashable)
        # Check direct subclassing
        class H(Hashable):
            def __hash__(self):
                return super(H, self).__hash__()
            __eq__ = Hashable.__eq__ # Silence Py3k warning
        self.assertEqual(hash(H()), 0)
        self.failIf(issubclass(int, H))
        self.validate_abstract_methods(Hashable, '__hash__')

    def test_Iterable(self):
        # Check some non-iterables
        non_samples = [None, 42, 3.14, 1j]
        for x in non_samples:
            self.failIf(isinstance(x, Iterable), repr(x))
            self.failIf(issubclass(type(x), Iterable), repr(type(x)))
        # Check some iterables
        samples = [str(),
                   tuple(), list(), set(), frozenset(), dict(),
                   dict().keys(), dict().items(), dict().values(),
                   (lambda: (yield))(),
                   (x for x in []),
                   ]
        for x in samples:
            self.failUnless(isinstance(x, Iterable), repr(x))
            self.failUnless(issubclass(type(x), Iterable), repr(type(x)))
        # Check direct subclassing
        class I(Iterable):
            def __iter__(self):
                return super(I, self).__iter__()
        self.assertEqual(list(I()), [])
        self.failIf(issubclass(str, I))
        self.validate_abstract_methods(Iterable, '__iter__')

    def test_Iterator(self):
        non_samples = [None, 42, 3.14, 1j, "".encode('ascii'), "", (), [],
            {}, set()]
        for x in non_samples:
            self.failIf(isinstance(x, Iterator), repr(x))
            self.failIf(issubclass(type(x), Iterator), repr(type(x)))
        samples = [iter(str()),
                   iter(tuple()), iter(list()), iter(dict()),
                   iter(set()), iter(frozenset()),
                   iter(dict().keys()), iter(dict().items()),
                   iter(dict().values()),
                   (lambda: (yield))(),
                   (x for x in []),
                   ]
        for x in samples:
            self.failUnless(isinstance(x, Iterator), repr(x))
            self.failUnless(issubclass(type(x), Iterator), repr(type(x)))
        self.validate_abstract_methods(Iterator, 'next')

    def test_Sized(self):
        non_samples = [None, 42, 3.14, 1j,
                       (lambda: (yield))(),
                       (x for x in []),
                       ]
        for x in non_samples:
            self.failIf(isinstance(x, Sized), repr(x))
            self.failIf(issubclass(type(x), Sized), repr(type(x)))
        samples = [str(),
                   tuple(), list(), set(), frozenset(), dict(),
                   dict().keys(), dict().items(), dict().values(),
                   ]
        for x in samples:
            self.failUnless(isinstance(x, Sized), repr(x))
            self.failUnless(issubclass(type(x), Sized), repr(type(x)))
        self.validate_abstract_methods(Sized, '__len__')

    def test_Container(self):
        non_samples = [None, 42, 3.14, 1j,
                       (lambda: (yield))(),
                       (x for x in []),
                       ]
        for x in non_samples:
            self.failIf(isinstance(x, Container), repr(x))
            self.failIf(issubclass(type(x), Container), repr(type(x)))
        samples = [str(),
                   tuple(), list(), set(), frozenset(), dict(),
                   dict().keys(), dict().items(),
                   ]
        for x in samples:
            self.failUnless(isinstance(x, Container), repr(x))
            self.failUnless(issubclass(type(x), Container), repr(type(x)))
        self.validate_abstract_methods(Container, '__contains__')

    def test_Callable(self):
        non_samples = [None, 42, 3.14, 1j,
                       "", "".encode('ascii'), (), [], {}, set(),
                       (lambda: (yield))(),
                       (x for x in []),
                       ]
        for x in non_samples:
            self.failIf(isinstance(x, Callable), repr(x))
            self.failIf(issubclass(type(x), Callable), repr(type(x)))
        samples = [lambda: None,
                   type, int, object,
                   len,
                   list.append, [].append,
                   ]
        for x in samples:
            self.failUnless(isinstance(x, Callable), repr(x))
            self.failUnless(issubclass(type(x), Callable), repr(type(x)))
        self.validate_abstract_methods(Callable, '__call__')

    def test_direct_subclassing(self):
        for B in Hashable, Iterable, Iterator, Sized, Container, Callable:
            class C(B):
                pass
            self.failUnless(issubclass(C, B))
            self.failIf(issubclass(int, C))

    def test_registration(self):
        for B in Hashable, Iterable, Iterator, Sized, Container, Callable:
            class C:
                __metaclass__ = type
                __hash__ = None  # Make sure it isn't hashable by default
            self.failIf(issubclass(C, B), B.__name__)
            B.register(C)
            self.failUnless(issubclass(C, B))


class TestCollectionABCs(ABCTestCase):

    # XXX For now, we only test some virtual inheritance properties.
    # We should also test the proper behavior of the collection ABCs
    # as real base classes or mix-in classes.

    def test_Set(self):
        for sample in [set, frozenset]:
            self.failUnless(isinstance(sample(), Set))
            self.failUnless(issubclass(sample, Set))
        self.validate_abstract_methods(Set, '__contains__', '__iter__', '__len__')

    def test_hash_Set(self):
        class OneTwoThreeSet(Set):
            def __init__(self):
                self.contents = [1, 2, 3]
            def __contains__(self, x):
                return x in self.contents
            def __len__(self):
                return len(self.contents)
            def __iter__(self):
                return iter(self.contents)
            def __hash__(self):
                return self._hash()
        a, b = OneTwoThreeSet(), OneTwoThreeSet()
        self.failUnless(hash(a) == hash(b))

    def test_MutableSet(self):
        self.failUnless(isinstance(set(), MutableSet))
        self.failUnless(issubclass(set, MutableSet))
        self.failIf(isinstance(frozenset(), MutableSet))
        self.failIf(issubclass(frozenset, MutableSet))
        self.validate_abstract_methods(MutableSet, '__contains__', '__iter__', '__len__',
            'add', 'discard')

    def test_issue_4920(self):
        # MutableSet.pop() method did not work
        class MySet(collections.MutableSet):
            __slots__=['__s']
            def __init__(self,items=None):
                if items is None:
                    items=[]
                self.__s=set(items)
            def __contains__(self,v):
                return v in self.__s
            def __iter__(self):
                return iter(self.__s)
            def __len__(self):
                return len(self.__s)
            def add(self,v):
                result=v not in self.__s
                self.__s.add(v)
                return result
            def discard(self,v):
                result=v in self.__s
                self.__s.discard(v)
                return result
            def __repr__(self):
                return "MySet(%s)" % repr(list(self))
        s = MySet([5,43,2,1])
        self.assertEqual(s.pop(), 1)

    def test_Mapping(self):
        for sample in [dict]:
            self.failUnless(isinstance(sample(), Mapping))
            self.failUnless(issubclass(sample, Mapping))
        self.validate_abstract_methods(Mapping, '__contains__', '__iter__', '__len__',
            '__getitem__')

    def test_MutableMapping(self):
        for sample in [dict]:
            self.failUnless(isinstance(sample(), MutableMapping))
            self.failUnless(issubclass(sample, MutableMapping))
        self.validate_abstract_methods(MutableMapping, '__contains__', '__iter__', '__len__',
            '__getitem__', '__setitem__', '__delitem__')

    def test_Sequence(self):
        for sample in [tuple, list, str]:
            self.failUnless(isinstance(sample(), Sequence))
            self.failUnless(issubclass(sample, Sequence))
        self.failUnless(issubclass(basestring, Sequence))
        self.validate_abstract_methods(Sequence, '__contains__', '__iter__', '__len__',
            '__getitem__')

    def test_MutableSequence(self):
        for sample in [tuple, str]:
            self.failIf(isinstance(sample(), MutableSequence))
            self.failIf(issubclass(sample, MutableSequence))
        for sample in [list]:
            self.failUnless(isinstance(sample(), MutableSequence))
            self.failUnless(issubclass(sample, MutableSequence))
        self.failIf(issubclass(basestring, MutableSequence))
        self.validate_abstract_methods(MutableSequence, '__contains__', '__iter__',
            '__len__', '__getitem__', '__setitem__', '__delitem__', 'insert')

class TestCounter(unittest.TestCase):

    def test_basics(self):
        c = Counter('abcaba')
        self.assertEqual(c, Counter({'a':3 , 'b': 2, 'c': 1}))
        self.assertEqual(c, Counter(a=3, b=2, c=1))
        self.assert_(isinstance(c, dict))
        self.assert_(isinstance(c, Mapping))
        self.assert_(issubclass(Counter, dict))
        self.assert_(issubclass(Counter, Mapping))
        self.assertEqual(len(c), 3)
        self.assertEqual(sum(c.values()), 6)
        self.assertEqual(sorted(c.values()), [1, 2, 3])
        self.assertEqual(sorted(c.keys()), ['a', 'b', 'c'])
        self.assertEqual(sorted(c), ['a', 'b', 'c'])
        self.assertEqual(sorted(c.items()),
                         [('a', 3), ('b', 2), ('c', 1)])
        self.assertEqual(c['b'], 2)
        self.assertEqual(c['z'], 0)
        self.assertEqual(c.has_key('c'), True)
        self.assertEqual(c.has_key('z'), False)
        self.assertEqual(c.__contains__('c'), True)
        self.assertEqual(c.__contains__('z'), False)
        self.assertEqual(c.get('b', 10), 2)
        self.assertEqual(c.get('z', 10), 10)
        self.assertEqual(c, dict(a=3, b=2, c=1))
        self.assertEqual(repr(c), "Counter({'a': 3, 'b': 2, 'c': 1})")
        self.assertEqual(c.most_common(), [('a', 3), ('b', 2), ('c', 1)])
        for i in range(5):
            self.assertEqual(c.most_common(i),
                             [('a', 3), ('b', 2), ('c', 1)][:i])
        self.assertEqual(''.join(sorted(c.elements())), 'aaabbc')
        c['a'] += 1         # increment an existing value
        c['b'] -= 2         # sub existing value to zero
        del c['c']          # remove an entry
        del c['c']          # make sure that del doesn't raise KeyError
        c['d'] -= 2         # sub from a missing value
        c['e'] = -5         # directly assign a missing value
        c['f'] += 4         # add to a missing value
        self.assertEqual(c, dict(a=4, b=0, d=-2, e=-5, f=4))
        self.assertEqual(''.join(sorted(c.elements())), 'aaaaffff')
        self.assertEqual(c.pop('f'), 4)
        self.assertEqual('f' in c, False)
        for i in range(3):
            elem, cnt = c.popitem()
            self.assertEqual(elem in c, False)
        c.clear()
        self.assertEqual(c, {})
        self.assertEqual(repr(c), 'Counter()')
        self.assertRaises(NotImplementedError, Counter.fromkeys, 'abc')
        self.assertRaises(TypeError, hash, c)
        c.update(dict(a=5, b=3))
        c.update(c=1)
        c.update(Counter('a' * 50 + 'b' * 30))
        c.update()          # test case with no args
        c.__init__('a' * 500 + 'b' * 300)
        c.__init__('cdc')
        c.__init__()
        self.assertEqual(c, dict(a=555, b=333, c=3, d=1))
        self.assertEqual(c.setdefault('d', 5), 1)
        self.assertEqual(c['d'], 1)
        self.assertEqual(c.setdefault('e', 5), 5)
        self.assertEqual(c['e'], 5)

    def test_copying(self):
        # Check that counters are copyable, deepcopyable, picklable, and
        #have a repr/eval round-trip
        words = Counter('which witch had which witches wrist watch'.split())
        update_test = Counter()
        update_test.update(words)
        for i, dup in enumerate([
                    words.copy(),
                    copy.copy(words),
                    copy.deepcopy(words),
                    pickle.loads(pickle.dumps(words, 0)),
                    pickle.loads(pickle.dumps(words, 1)),
                    pickle.loads(pickle.dumps(words, 2)),
                    pickle.loads(pickle.dumps(words, -1)),
                    cPickle.loads(cPickle.dumps(words, 0)),
                    cPickle.loads(cPickle.dumps(words, 1)),
                    cPickle.loads(cPickle.dumps(words, 2)),
                    cPickle.loads(cPickle.dumps(words, -1)),
                    eval(repr(words)),
                    update_test,
                    Counter(words),
                    ]):
            msg = (i, dup, words)
            self.assert_(dup is not words)
            self.assertEquals(dup, words)
            self.assertEquals(len(dup), len(words))
            self.assertEquals(type(dup), type(words))

    def test_conversions(self):
        # Convert to: set, list, dict
        s = 'she sells sea shells by the sea shore'
        self.assertEqual(sorted(Counter(s).elements()), sorted(s))
        self.assertEqual(sorted(Counter(s)), sorted(set(s)))
        self.assertEqual(dict(Counter(s)), dict(Counter(s).items()))
        self.assertEqual(set(Counter(s)), set(s))

    def test_invariant_for_the_in_operator(self):
        c = Counter(a=10, b=-2, c=0)
        for elem in c:
            self.assert_(elem in c)

    def test_multiset_operations(self):
        # Verify that adding a zero counter will strip zeros and negatives
        c = Counter(a=10, b=-2, c=0) + Counter()
        self.assertEqual(dict(c), dict(a=10))

        elements = 'abcd'
        for i in range(1000):
            # test random pairs of multisets
            p = Counter(dict((elem, randrange(-2,4)) for elem in elements))
            p.update(e=1, f=-1, g=0)
            q = Counter(dict((elem, randrange(-2,4)) for elem in elements))
            q.update(h=1, i=-1, j=0)
            for counterop, numberop in [
                (Counter.__add__, lambda x, y: max(0, x+y)),
                (Counter.__sub__, lambda x, y: max(0, x-y)),
                (Counter.__or__, lambda x, y: max(0,x,y)),
                (Counter.__and__, lambda x, y: max(0, min(x,y))),
            ]:
                result = counterop(p, q)
                for x in elements:
                    self.assertEqual(numberop(p[x], q[x]), result[x],
                                     (counterop, x, p, q))
                # verify that results exclude non-positive counts
                self.assert_(x>0 for x in result.values())

        elements = 'abcdef'
        for i in range(100):
            # verify that random multisets with no repeats are exactly like sets
            p = Counter(dict((elem, randrange(0, 2)) for elem in elements))
            q = Counter(dict((elem, randrange(0, 2)) for elem in elements))
            for counterop, setop in [
                (Counter.__sub__, set.__sub__),
                (Counter.__or__, set.__or__),
                (Counter.__and__, set.__and__),
            ]:
                counter_result = counterop(p, q)
                set_result = setop(set(p.elements()), set(q.elements()))
                self.assertEqual(counter_result, dict.fromkeys(set_result, 1))

import doctest, collections

def test_main(verbose=None):
    NamedTupleDocs = doctest.DocTestSuite(module=collections)
    test_classes = [TestNamedTuple, NamedTupleDocs, TestOneTrickPonyABCs,
                    TestCollectionABCs, TestCounter]
    test_support.run_unittest(*test_classes)
    test_support.run_doctest(collections, verbose)

if __name__ == "__main__":
    test_main(verbose=True)
