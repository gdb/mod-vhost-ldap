__all__ = ['deque', 'defaultdict', 'namedtuple']
# For bootstrapping reasons, the collection ABCs are defined in _abcoll.py.
# They should however be considered an integral part of collections.py.
from _abcoll import *
import _abcoll
__all__ += _abcoll.__all__

from _collections import deque, defaultdict
from operator import itemgetter as _itemgetter
from keyword import iskeyword as _iskeyword
import sys as _sys
import heapq as _heapq
import itertools as _itertools

########################################################################
###  namedtuple  #######################################################

def namedtuple(typename, field_names, verbose=False):
    """Returns a new subclass of tuple with named fields.

    >>> Point = namedtuple('Point', 'x y')
    >>> Point.__doc__                   # docstring for the new class
    'Point(x, y)'
    >>> p = Point(11, y=22)             # instantiate with positional args or keywords
    >>> p[0] + p[1]                     # indexable like a plain tuple
    33
    >>> x, y = p                        # unpack like a regular tuple
    >>> x, y
    (11, 22)
    >>> p.x + p.y                       # fields also accessable by name
    33
    >>> d = p._asdict()                 # convert to a dictionary
    >>> d['x']
    11
    >>> Point(**d)                      # convert from a dictionary
    Point(x=11, y=22)
    >>> p._replace(x=100)               # _replace() is like str.replace() but targets named fields
    Point(x=100, y=22)

    """

    # Parse and validate the field names.  Validation serves two purposes,
    # generating informative error messages and preventing template injection attacks.
    if isinstance(field_names, basestring):
        field_names = field_names.replace(',', ' ').split() # names separated by whitespace and/or commas
    field_names = tuple(map(str, field_names))
    for name in (typename,) + field_names:
        if not all(c.isalnum() or c=='_' for c in name):
            raise ValueError('Type names and field names can only contain alphanumeric characters and underscores: %r' % name)
        if _iskeyword(name):
            raise ValueError('Type names and field names cannot be a keyword: %r' % name)
        if name[0].isdigit():
            raise ValueError('Type names and field names cannot start with a number: %r' % name)
    seen_names = set()
    for name in field_names:
        if name.startswith('_'):
            raise ValueError('Field names cannot start with an underscore: %r' % name)
        if name in seen_names:
            raise ValueError('Encountered duplicate field name: %r' % name)
        seen_names.add(name)

    # Create and fill-in the class template
    numfields = len(field_names)
    argtxt = repr(field_names).replace("'", "")[1:-1]   # tuple repr without parens or quotes
    reprtxt = ', '.join('%s=%%r' % name for name in field_names)
    dicttxt = ', '.join('%r: t[%d]' % (name, pos) for pos, name in enumerate(field_names))
    template = '''class %(typename)s(tuple):
        '%(typename)s(%(argtxt)s)' \n
        __slots__ = () \n
        _fields = %(field_names)r \n
        def __new__(cls, %(argtxt)s):
            return tuple.__new__(cls, (%(argtxt)s)) \n
        @classmethod
        def _make(cls, iterable, new=tuple.__new__, len=len):
            'Make a new %(typename)s object from a sequence or iterable'
            result = new(cls, iterable)
            if len(result) != %(numfields)d:
                raise TypeError('Expected %(numfields)d arguments, got %%d' %% len(result))
            return result \n
        def __repr__(self):
            return '%(typename)s(%(reprtxt)s)' %% self \n
        def _asdict(t):
            'Return a new dict which maps field names to their values'
            return {%(dicttxt)s} \n
        def _replace(self, **kwds):
            'Return a new %(typename)s object replacing specified fields with new values'
            result = self._make(map(kwds.pop, %(field_names)r, self))
            if kwds:
                raise ValueError('Got unexpected field names: %%r' %% kwds.keys())
            return result \n
        def __getnewargs__(self):
            return tuple(self) \n\n''' % locals()
    for i, name in enumerate(field_names):
        template += '        %s = property(itemgetter(%d))\n' % (name, i)
    if verbose:
        print template

    # Execute the template string in a temporary namespace and
    # support tracing utilities by setting a value for frame.f_globals['__name__']
    namespace = dict(itemgetter=_itemgetter, __name__='namedtuple_%s' % typename)
    try:
        exec template in namespace
    except SyntaxError, e:
        raise SyntaxError(e.message + ':\n' + template)
    result = namespace[typename]

    # For pickling to work, the __module__ variable needs to be set to the frame
    # where the named tuple is created.  Bypass this step in enviroments where
    # sys._getframe is not defined (Jython for example).
    if hasattr(_sys, '_getframe'):
        result.__module__ = _sys._getframe(1).f_globals['__name__']

    return result


########################################################################
###  Counter  ##########################################################

class Counter(dict):
    '''Dict subclass for counting hashable items.  Sometimes called a bag
    or multiset.  Elements are stored as dictionary keys and their counts
    are stored as dictionary values.

    >>> c = Counter('abracadabra')      # count elements from a string

    >>> c.most_common(3)                # three most common elements
    [('a', 5), ('r', 2), ('b', 2)]
    >>> sorted(c)                       # list all unique elements
    ['a', 'b', 'c', 'd', 'r']
    >>> ''.join(sorted(c.elements()))   # list elements with repetitions
    'aaaaabbcdrr'
    >>> sum(c.values())                 # total of all counts
    11

    >>> c['a']                          # count of letter 'a'
    5
    >>> for elem in 'shazam':           # update counts from an iterable
    ...     c[elem] += 1                # by adding 1 to each element's count
    >>> c['a']                          # now there are seven 'a'
    7
    >>> del c['r']                      # remove all 'r'
    >>> c['r']                          # now there are zero 'r'
    0

    >>> d = Counter('simsalabim')       # make another counter
    >>> c.update(d)                     # add in the second counter
    >>> c['a']                          # now there are nine 'a'
    9

    >>> c.clear()                       # empty the counter
    >>> c
    Counter()

    Note:  If a count is set to zero or reduced to zero, it will remain
    in the counter until the entry is deleted or the counter is cleared:

    >>> c = Counter('aaabbc')
    >>> c['b'] -= 2                     # reduce the count of 'b' by two
    >>> c.most_common()                 # 'b' is still in, but its count is zero
    [('a', 3), ('c', 1), ('b', 0)]

    '''
    # References:
    #   http://en.wikipedia.org/wiki/Multiset
    #   http://www.gnu.org/software/smalltalk/manual-base/html_node/Bag.html
    #   http://www.demo2s.com/Tutorial/Cpp/0380__set-multiset/Catalog0380__set-multiset.htm
    #   http://code.activestate.com/recipes/259174/
    #   Knuth, TAOCP Vol. II section 4.6.3

    def __init__(self, iterable=None, items=None):
        '''Create a new, empty Counter object.  And if given, count elements
        from an input iterable.  Or, initialize the count from an items list
        of (element, count) pairs.

        >>> c = Counter('hocus pocus')              # count elements in an iterable
        >>> c = Counter(items=[('a', 4), ('b', 2)]) # take counts from an items list

        '''
        if iterable is not None:
            for elem in iterable:
                self[elem] += 1
        if items is not None:
            for elem, count in items:
                self[elem] += count

    def __missing__(self, key):
        'The count of elements not in the Counter is zero.'
        # Needed so that self[missing_item] does not raise KeyError
        return 0

    def most_common(self, n=None):
        '''List the n most common elements and their counts from the most
        common to the least.  If n is None, then list all element counts.

        >>> Counter('abracadabra').most_common(3)
        [('a', 5), ('r', 2), ('b', 2)]

        '''
        # Emulate Bag.sortedByCount from Smalltalk
        if n is None:
            return sorted(self.iteritems(), key=_itemgetter(1), reverse=True)
        return _heapq.nlargest(n, self.iteritems(), key=_itemgetter(1))

    def elements(self):
        '''Iterator over elements repeating each as many times as its count.

        >>> c = Counter('ABCABC')
        >>> sorted(c.elements())
        ['A', 'A', 'B', 'B', 'C', 'C']

        # Knuth's example of prime factors of 1836:  2**2 * 3**3 * 17**1
        >>> import operator
        >>> prime_factors = Counter(items=[(2,2), (3,3), (17,1)])
        >>> sorted(prime_factors.elements())         # list individual factors
        [2, 2, 3, 3, 3, 17]
        >>> reduce(operator.mul, prime_factors.elements(), 1)  # multiply them
        1836

        Note, if an element's count has been set to zero or a negative number,
        elements() will ignore it.

        '''
        # Emulate Bag.do from Smalltalk and Multiset.begin from C++.
        return _itertools.chain.from_iterable(
                                    _itertools.starmap(_itertools.repeat,
                                                       self.iteritems()))

    # Override dict methods where necessary

    @classmethod
    def fromkeys(cls, iterable, v=None):
        # There is no equivalent method for counters because setting v=1
        # means that no element can have a count greater than one.
        raise NotImplementedError(
            'Counter.fromkeys() is undefined.  Use Counter(iterable) instead.')

    def update(self, mapping):
        '''Like dict.update() but add counts instead of replacing them.

        Source can be another dictionary or a Counter.instance().

        >>> c = Counter('which')
        >>> d = Counter('witch')
        >>> c.update(d)                 # Add counts from d to those in c
        >>> c['h']                      # Count of 'h' is now three
        3

        '''
        # The regular dict.update() operation makes no sense here because the
        # replace behavior results in the some of original untouched counts
        # being mixed-in with all of the other counts for a mismash that
        # doesn't have a straight-forward interpretation in most counting
        # contexts.  Instead, we look to Knuth for suggested operations on
        # multisets and implement the union-add operation discussed in
        # TAOCP Volume II section 4.6.3 exercise 19.  The Wikipedia entry for
        # multisets calls that operation a sum or join.
        for elem, count in mapping.iteritems():
            self[elem] += count

    def copy(self):
        'Like dict.copy() but returns a Counter instance instead of a dict.'
        c = Counter()
        c.update(self)
        return c

    def __repr__(self):
        if not self:
            return '%s()' % self.__class__.__name__
        return '%s(items=%r)' % (self.__class__.__name__, self.most_common())



if __name__ == '__main__':
    # verify that instances can be pickled
    from cPickle import loads, dumps
    Point = namedtuple('Point', 'x, y', True)
    p = Point(x=10, y=20)
    assert p == loads(dumps(p))

    # test and demonstrate ability to override methods
    class Point(namedtuple('Point', 'x y')):
        __slots__ = ()
        @property
        def hypot(self):
            return (self.x ** 2 + self.y ** 2) ** 0.5
        def __str__(self):
            return 'Point: x=%6.3f  y=%6.3f  hypot=%6.3f' % (self.x, self.y, self.hypot)

    for p in Point(3, 4), Point(14, 5/7.):
        print p

    class Point(namedtuple('Point', 'x y')):
        'Point class with optimized _make() and _replace() without error-checking'
        __slots__ = ()
        _make = classmethod(tuple.__new__)
        def _replace(self, _map=map, **kwds):
            return self._make(_map(kwds.get, ('x', 'y'), self))

    print Point(11, 22)._replace(x=100)

    Point3D = namedtuple('Point3D', Point._fields + ('z',))
    print Point3D.__doc__

    # Check that counters are copyable, deepcopyable, picklable, and have a
    # repr/eval round-trip
    import copy
    words = Counter('which witch had which witches wrist watch'.split())
    update_test = Counter()
    update_test.update(words)
    for i, dup in enumerate([
                words.copy(),
                copy.copy(words),
                copy.deepcopy(words),
                loads(dumps(words, 0)),
                loads(dumps(words, 1)),
                loads(dumps(words, 2)),
                loads(dumps(words, -1)),
                eval(repr(words)),
                update_test,
                ]):
        msg = (i, dup, words)
        assert dup is not words, msg
        assert dup == words, msg
        assert len(dup) == len(words), msg
        assert type(dup) == type(words), msg

    # Verify that counters are unhashable
    try:
        hash(words)
    except TypeError:
        pass
    else:
        print 'Failed hashing test'

    # Verify that Counter.fromkeys() is disabled
    try:
        Counter.fromkeys('razmataz')
    except NotImplementedError:
        pass
    else:
        print 'Failed fromkeys() test'

    # Check ABCs
    assert issubclass(Counter, Mapping)
    assert isinstance(Counter('asdfasdf'), Mapping)

    import doctest
    TestResults = namedtuple('TestResults', 'failed attempted')
    print TestResults(*doctest.testmod())
