# Test iterators.

import unittest
from test_support import run_unittest, TESTFN, unlink

# Test result of triple loop (too big to inline)
TRIPLETS = [(0, 0, 0), (0, 0, 1), (0, 0, 2),
            (0, 1, 0), (0, 1, 1), (0, 1, 2),
            (0, 2, 0), (0, 2, 1), (0, 2, 2),

            (1, 0, 0), (1, 0, 1), (1, 0, 2),
            (1, 1, 0), (1, 1, 1), (1, 1, 2),
            (1, 2, 0), (1, 2, 1), (1, 2, 2),

            (2, 0, 0), (2, 0, 1), (2, 0, 2),
            (2, 1, 0), (2, 1, 1), (2, 1, 2),
            (2, 2, 0), (2, 2, 1), (2, 2, 2)]

# Helper classes

class BasicIterClass:
    def __init__(self, n):
        self.n = n
        self.i = 0
    def next(self):
        res = self.i
        if res >= self.n:
            raise StopIteration
        self.i = res + 1
        return res

class IteratingSequenceClass:
    def __init__(self, n):
        self.n = n
    def __iter__(self):
        return BasicIterClass(self.n)

class SequenceClass:
    def __init__(self, n):
        self.n = n
    def __getitem__(self, i):
        if 0 <= i < self.n:
            return i
        else:
            raise IndexError

# Main test suite

class TestCase(unittest.TestCase):

    # Helper to check that an iterator returns a given sequence
    def check_iterator(self, it, seq):
        res = []
        while 1:
            try:
                val = it.next()
            except StopIteration:
                break
            res.append(val)
        self.assertEqual(res, seq)

    # Helper to check that a for loop generates a given sequence
    def check_for_loop(self, expr, seq):
        res = []
        for val in expr:
            res.append(val)
        self.assertEqual(res, seq)

    # Test basic use of iter() function
    def test_iter_basic(self):
        self.check_iterator(iter(range(10)), range(10))

    # Test that iter(iter(x)) is the same as iter(x)
    def test_iter_idempotency(self):
        seq = range(10)
        it = iter(seq)
        it2 = iter(it)
        self.assert_(it is it2)

    # Test that for loops over iterators work
    def test_iter_for_loop(self):
        self.check_for_loop(iter(range(10)), range(10))

    # Test several independent iterators over the same list
    def test_iter_independence(self):
        seq = range(3)
        res = []
        for i in iter(seq):
            for j in iter(seq):
                for k in iter(seq):
                    res.append((i, j, k))
        self.assertEqual(res, TRIPLETS)

    # Test triple list comprehension using iterators
    def test_nested_comprehensions_iter(self):
        seq = range(3)
        res = [(i, j, k)
               for i in iter(seq) for j in iter(seq) for k in iter(seq)]
        self.assertEqual(res, TRIPLETS)

    # Test triple list comprehension without iterators
    def test_nested_comprehensions_for(self):
        seq = range(3)
        res = [(i, j, k) for i in seq for j in seq for k in seq]
        self.assertEqual(res, TRIPLETS)

    # Test a class with __iter__ in a for loop
    def test_iter_class_for(self):
        self.check_for_loop(IteratingSequenceClass(10), range(10))

    # Test a class with __iter__ with explicit iter()
    def test_iter_class_iter(self):
        self.check_iterator(iter(IteratingSequenceClass(10)), range(10))

    # Test for loop on a sequence class without __iter__
    def test_seq_class_for(self):
        self.check_for_loop(SequenceClass(10), range(10))

    # Test iter() on a sequence class without __iter__
    def test_seq_class_iter(self):
        self.check_iterator(iter(SequenceClass(10)), range(10))

    # Test two-argument iter() with callable instance
    def test_iter_callable(self):
        class C:
            def __init__(self):
                self.i = 0
            def __call__(self):
                i = self.i
                self.i = i + 1
                if i > 100:
                    raise IndexError # Emergency stop
                return i
        self.check_iterator(iter(C(), 10), range(10))

    # Test two-argument iter() with function
    def test_iter_function(self):
        def spam(state=[0]):
            i = state[0]
            state[0] = i+1
            return i
        self.check_iterator(iter(spam, 10), range(10))

    # Test two-argument iter() with function that raises StopIteration
    def test_iter_function_stop(self):
        def spam(state=[0]):
            i = state[0]
            if i == 10:
                raise StopIteration
            state[0] = i+1
            return i
        self.check_iterator(iter(spam, 20), range(10))

    # Test exception propagation through function iterator
    def test_exception_function(self):
        def spam(state=[0]):
            i = state[0]
            state[0] = i+1
            if i == 10:
                raise RuntimeError
            return i
        res = []
        try:
            for x in iter(spam, 20):
                res.append(x)
        except RuntimeError:
            self.assertEqual(res, range(10))
        else:
            self.fail("should have raised RuntimeError")

    # Test exception propagation through sequence iterator
    def test_exception_sequence(self):
        class MySequenceClass(SequenceClass):
            def __getitem__(self, i):
                if i == 10:
                    raise RuntimeError
                return SequenceClass.__getitem__(self, i)
        res = []
        try:
            for x in MySequenceClass(20):
                res.append(x)
        except RuntimeError:
            self.assertEqual(res, range(10))
        else:
            self.fail("should have raised RuntimeError")

    # Test for StopIteration from __getitem__
    def test_stop_sequence(self):
        class MySequenceClass(SequenceClass):
            def __getitem__(self, i):
                if i == 10:
                    raise StopIteration
                return SequenceClass.__getitem__(self, i)
        self.check_for_loop(MySequenceClass(20), range(10))

    # Test a big range
    def test_iter_big_range(self):
        self.check_for_loop(iter(range(10000)), range(10000))

    # Test an empty list
    def test_iter_empty(self):
        self.check_for_loop(iter([]), [])

    # Test a tuple
    def test_iter_tuple(self):
        self.check_for_loop(iter((0,1,2,3,4,5,6,7,8,9)), range(10))

    # Test an xrange
    def test_iter_xrange(self):
        self.check_for_loop(iter(xrange(10)), range(10))

    # Test a string
    def test_iter_string(self):
        self.check_for_loop(iter("abcde"), ["a", "b", "c", "d", "e"])

    # Test a Unicode string
    def test_iter_unicode(self):
        self.check_for_loop(iter(u"abcde"), [u"a", u"b", u"c", u"d", u"e"])

    # Test a directory
    def test_iter_dict(self):
        dict = {}
        for i in range(10):
            dict[i] = None
        self.check_for_loop(dict, dict.keys())

    # Test a file
    def test_iter_file(self):
        f = open(TESTFN, "w")
        try:
            for i in range(5):
                f.write("%d\n" % i)
        finally:
            f.close()
        f = open(TESTFN, "r")
        try:
            self.check_for_loop(f, ["0\n", "1\n", "2\n", "3\n", "4\n"])
            self.check_for_loop(f, [])
        finally:
            f.close()
            try:
                unlink(TESTFN)
            except OSError:
                pass

    # Test list()'s use of iterators.
    def test_builtin_list(self):
        self.assertEqual(list(SequenceClass(5)), range(5))
        self.assertEqual(list(SequenceClass(0)), [])
        self.assertEqual(list(()), [])
        self.assertEqual(list(range(10, -1, -1)), range(10, -1, -1))

        d = {"one": 1, "two": 2, "three": 3}
        self.assertEqual(list(d), d.keys())

        self.assertRaises(TypeError, list, list)
        self.assertRaises(TypeError, list, 42)

        f = open(TESTFN, "w")
        try:
            for i in range(5):
                f.write("%d\n" % i)
        finally:
            f.close()
        f = open(TESTFN, "r")
        try:
            self.assertEqual(list(f), ["0\n", "1\n", "2\n", "3\n", "4\n"])
            f.seek(0, 0)
            self.assertEqual(list(f.xreadlines()),
                             ["0\n", "1\n", "2\n", "3\n", "4\n"])
        finally:
            f.close()
            try:
                unlink(TESTFN)
            except OSError:
                pass

    # Test tuples()'s use of iterators.
    def test_builtin_tuple(self):
        self.assertEqual(tuple(SequenceClass(5)), (0, 1, 2, 3, 4))
        self.assertEqual(tuple(SequenceClass(0)), ())
        self.assertEqual(tuple([]), ())
        self.assertEqual(tuple(()), ())
        self.assertEqual(tuple("abc"), ("a", "b", "c"))

        d = {"one": 1, "two": 2, "three": 3}
        self.assertEqual(tuple(d), tuple(d.keys()))

        self.assertRaises(TypeError, tuple, list)
        self.assertRaises(TypeError, tuple, 42)

        f = open(TESTFN, "w")
        try:
            for i in range(5):
                f.write("%d\n" % i)
        finally:
            f.close()
        f = open(TESTFN, "r")
        try:
            self.assertEqual(tuple(f), ("0\n", "1\n", "2\n", "3\n", "4\n"))
            f.seek(0, 0)
            self.assertEqual(tuple(f.xreadlines()),
                             ("0\n", "1\n", "2\n", "3\n", "4\n"))
        finally:
            f.close()
            try:
                unlink(TESTFN)
            except OSError:
                pass

    # Test filter()'s use of iterators.
    def test_builtin_filter(self):
        self.assertEqual(filter(None, SequenceClass(5)), range(1, 5))
        self.assertEqual(filter(None, SequenceClass(0)), [])
        self.assertEqual(filter(None, ()), ())
        self.assertEqual(filter(None, "abc"), "abc")

        d = {"one": 1, "two": 2, "three": 3}
        self.assertEqual(filter(None, d), d.keys())

        self.assertRaises(TypeError, filter, None, list)
        self.assertRaises(TypeError, filter, None, 42)

        class Boolean:
            def __init__(self, truth):
                self.truth = truth
            def __nonzero__(self):
                return self.truth
        True = Boolean(1)
        False = Boolean(0)

        class Seq:
            def __init__(self, *args):
                self.vals = args
            def __iter__(self):
                class SeqIter:
                    def __init__(self, vals):
                        self.vals = vals
                        self.i = 0
                    def __iter__(self):
                        return self
                    def next(self):
                        i = self.i
                        self.i = i + 1
                        if i < len(self.vals):
                            return self.vals[i]
                        else:
                            raise StopIteration
                return SeqIter(self.vals)

        seq = Seq(*([True, False] * 25))
        self.assertEqual(filter(lambda x: not x, seq), [False]*25)
        self.assertEqual(filter(lambda x: not x, iter(seq)), [False]*25)

    # Test max() and min()'s use of iterators.
    def test_builtin_max_min(self):
        self.assertEqual(max(SequenceClass(5)), 4)
        self.assertEqual(min(SequenceClass(5)), 0)
        self.assertEqual(max(8, -1), 8)
        self.assertEqual(min(8, -1), -1)

        d = {"one": 1, "two": 2, "three": 3}
        self.assertEqual(max(d), "two")
        self.assertEqual(min(d), "one")
        self.assertEqual(max(d.itervalues()), 3)
        self.assertEqual(min(iter(d.itervalues())), 1)

        f = open(TESTFN, "w")
        try:
            f.write("medium line\n")
            f.write("xtra large line\n")
            f.write("itty-bitty line\n")
        finally:
            f.close()
        f = open(TESTFN, "r")
        try:
            self.assertEqual(min(f), "itty-bitty line\n")
            f.seek(0, 0)
            self.assertEqual(max(f), "xtra large line\n")
        finally:
            f.close()
            try:
                unlink(TESTFN)
            except OSError:
                pass

    # Test map()'s use of iterators.
    def test_builtin_map(self):
        self.assertEqual(map(None, SequenceClass(5)), range(5))
        self.assertEqual(map(lambda x: x+1, SequenceClass(5)), range(1, 6))

        d = {"one": 1, "two": 2, "three": 3}
        self.assertEqual(map(None, d), d.keys())
        self.assertEqual(map(lambda k, d=d: (k, d[k]), d), d.items())
        dkeys = d.keys()
        expected = [(i < len(d) and dkeys[i] or None,
                     i,
                     i < len(d) and dkeys[i] or None)
                    for i in range(5)]
        self.assertEqual(map(None, d,
                                   SequenceClass(5),
                                   iter(d.iterkeys())),
                         expected)

        f = open(TESTFN, "w")
        try:
            for i in range(10):
                f.write("xy" * i + "\n") # line i has len 2*i+1
        finally:
            f.close()
        f = open(TESTFN, "r")
        try:
            self.assertEqual(map(len, f), range(1, 21, 2))
        finally:
            f.close()
            try:
                unlink(TESTFN)
            except OSError:
                pass

    # Test reduces()'s use of iterators.
    def test_builtin_reduce(self):
        from operator import add
        self.assertEqual(reduce(add, SequenceClass(5)), 10)
        self.assertEqual(reduce(add, SequenceClass(5), 42), 52)
        self.assertRaises(TypeError, reduce, add, SequenceClass(0))
        self.assertEqual(reduce(add, SequenceClass(0), 42), 42)
        self.assertEqual(reduce(add, SequenceClass(1)), 0)
        self.assertEqual(reduce(add, SequenceClass(1), 42), 42)

        d = {"one": 1, "two": 2, "three": 3}
        self.assertEqual(reduce(add, d), "".join(d.keys()))

run_unittest(TestCase)
