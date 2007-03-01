import unittest
from test import test_support
from collections import NamedTuple

class TestNamedTuple(unittest.TestCase):

    def test_factory(self):
        Point = NamedTuple('Point', 'x y')
        self.assertEqual(Point.__name__, 'Point')
        self.assertEqual(Point.__doc__, 'Point(x, y)')
        self.assertEqual(Point.__slots__, ())
        self.assertEqual(Point.__module__, __name__)
        self.assertEqual(Point.__getitem__, tuple.__getitem__)
        self.assert_('__getitem__' in Point.__dict__)                       # superclass methods localized

    def test_instance(self):
        Point = NamedTuple('Point', 'x y')
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

    def test_tupleness(self):
        Point = NamedTuple('Point', 'x y')
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


def test_main(verbose=None):
    test_classes = [TestNamedTuple]
    test_support.run_unittest(*test_classes)

if __name__ == "__main__":
    test_main(verbose=True)
