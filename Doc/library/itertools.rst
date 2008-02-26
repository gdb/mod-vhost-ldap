
:mod:`itertools` --- Functions creating iterators for efficient looping
=======================================================================

.. module:: itertools
   :synopsis: Functions creating iterators for efficient looping.
.. moduleauthor:: Raymond Hettinger <python@rcn.com>
.. sectionauthor:: Raymond Hettinger <python@rcn.com>


.. versionadded:: 2.3

This module implements a number of :term:`iterator` building blocks inspired by
constructs from the Haskell and SML programming languages.  Each has been recast
in a form suitable for Python.

The module standardizes a core set of fast, memory efficient tools that are
useful by themselves or in combination.  Standardization helps avoid the
readability and reliability problems which arise when many different individuals
create their own slightly varying implementations, each with their own quirks
and naming conventions.

The tools are designed to combine readily with one another.  This makes it easy
to construct more specialized tools succinctly and efficiently in pure Python.

For instance, SML provides a tabulation tool: ``tabulate(f)`` which produces a
sequence ``f(0), f(1), ...``.  This toolbox provides :func:`imap` and
:func:`count` which can be combined to form ``imap(f, count())`` and produce an
equivalent result.

Likewise, the functional tools are designed to work well with the high-speed
functions provided by the :mod:`operator` module.

The module author welcomes suggestions for other basic building blocks to be
added to future versions of the module.

Whether cast in pure python form or compiled code, tools that use iterators are
more memory efficient (and faster) than their list based counterparts. Adopting
the principles of just-in-time manufacturing, they create data when and where
needed instead of consuming memory with the computer equivalent of "inventory".

The performance advantage of iterators becomes more acute as the number of
elements increases -- at some point, lists grow large enough to severely impact
memory cache performance and start running slowly.


.. seealso::

   The Standard ML Basis Library, `The Standard ML Basis Library
   <http://www.standardml.org/Basis/>`_.

   Haskell, A Purely Functional Language, `Definition of Haskell and the Standard
   Libraries <http://www.haskell.org/definition/>`_.


.. _itertools-functions:

Itertool functions
------------------

The following module functions all construct and return iterators. Some provide
streams of infinite length, so they should only be accessed by functions or
loops that truncate the stream.


.. function:: chain(*iterables)

   Make an iterator that returns elements from the first iterable until it is
   exhausted, then proceeds to the next iterable, until all of the iterables are
   exhausted.  Used for treating consecutive sequences as a single sequence.
   Equivalent to::

      def chain(*iterables):
          for it in iterables:
              for element in it:
                  yield element


.. function:: combinations(iterable, r)

   Return successive *r* length combinations of elements in the *iterable*.

   Combinations are emitted in a lexicographic sort order.  So, if the 
   input *iterable* is sorted, the combination tuples will be produced
   in sorted order.  

   Elements are treated as unique based on their position, not on their
   value.  So if the input elements are unique, there will be no repeat
   values within a single combination.

   Each result tuple is ordered to match the input order.  So, every
   combination is a subsequence of the input *iterable*.

   Example:  ``combinations(range(4), 3) --> (0,1,2), (0,1,3), (0,2,3), (1,2,3)``

   Equivalent to::

        def combinations(iterable, r):
            pool = tuple(iterable)
            n = len(pool)
            assert 0 <= r <= n
            vec = range(r)
            yield tuple(pool[i] for i in vec)
            while 1:
                for i in reversed(range(r)):
                    if vec[i] == i + n-r:
                        continue
                    vec[i] += 1
                    for j in range(i+1, r):
                        vec[j] = vec[j-1] + 1
                    yield tuple(pool[i] for i in vec)
                    break
                else:
                    return

   .. versionadded:: 2.6

.. function:: count([n])

   Make an iterator that returns consecutive integers starting with *n*. If not
   specified *n* defaults to zero.   Often used as an argument to :func:`imap` to
   generate consecutive data points. Also, used with :func:`izip` to add sequence
   numbers.  Equivalent to::

      def count(n=0):
          while True:
              yield n
              n += 1


.. function:: cycle(iterable)

   Make an iterator returning elements from the iterable and saving a copy of each.
   When the iterable is exhausted, return elements from the saved copy.  Repeats
   indefinitely.  Equivalent to::

      def cycle(iterable):
          saved = []
          for element in iterable:
              yield element
              saved.append(element)
          while saved:
              for element in saved:
                    yield element

   Note, this member of the toolkit may require significant auxiliary storage
   (depending on the length of the iterable).


.. function:: dropwhile(predicate, iterable)

   Make an iterator that drops elements from the iterable as long as the predicate
   is true; afterwards, returns every element.  Note, the iterator does not produce
   *any* output until the predicate first becomes false, so it may have a lengthy
   start-up time.  Equivalent to::

      def dropwhile(predicate, iterable):
          iterable = iter(iterable)
          for x in iterable:
              if not predicate(x):
                  yield x
                  break
          for x in iterable:
              yield x


.. function:: groupby(iterable[, key])

   Make an iterator that returns consecutive keys and groups from the *iterable*.
   The *key* is a function computing a key value for each element.  If not
   specified or is ``None``, *key* defaults to an identity function and returns
   the element unchanged.  Generally, the iterable needs to already be sorted on
   the same key function.

   The operation of :func:`groupby` is similar to the ``uniq`` filter in Unix.  It
   generates a break or new group every time the value of the key function changes
   (which is why it is usually necessary to have sorted the data using the same key
   function).  That behavior differs from SQL's GROUP BY which aggregates common
   elements regardless of their input order.

   The returned group is itself an iterator that shares the underlying iterable
   with :func:`groupby`.  Because the source is shared, when the :func:`groupby`
   object is advanced, the previous group is no longer visible.  So, if that data
   is needed later, it should be stored as a list::

      groups = []
      uniquekeys = []
      data = sorted(data, key=keyfunc)
      for k, g in groupby(data, keyfunc):
          groups.append(list(g))      # Store group iterator as a list
          uniquekeys.append(k)

   :func:`groupby` is equivalent to::

      class groupby(object):
          def __init__(self, iterable, key=None):
              if key is None:
                  key = lambda x: x
              self.keyfunc = key
              self.it = iter(iterable)
              self.tgtkey = self.currkey = self.currvalue = object()
          def __iter__(self):
              return self
          def next(self):
              while self.currkey == self.tgtkey:
                  self.currvalue = self.it.next() # Exit on StopIteration
                  self.currkey = self.keyfunc(self.currvalue)
              self.tgtkey = self.currkey
              return (self.currkey, self._grouper(self.tgtkey))
          def _grouper(self, tgtkey):
              while self.currkey == tgtkey:
                  yield self.currvalue
                  self.currvalue = self.it.next() # Exit on StopIteration
                  self.currkey = self.keyfunc(self.currvalue)

   .. versionadded:: 2.4


.. function:: ifilter(predicate, iterable)

   Make an iterator that filters elements from iterable returning only those for
   which the predicate is ``True``. If *predicate* is ``None``, return the items
   that are true. Equivalent to::

      def ifilter(predicate, iterable):
          if predicate is None:
              predicate = bool
          for x in iterable:
              if predicate(x):
                  yield x


.. function:: ifilterfalse(predicate, iterable)

   Make an iterator that filters elements from iterable returning only those for
   which the predicate is ``False``. If *predicate* is ``None``, return the items
   that are false. Equivalent to::

      def ifilterfalse(predicate, iterable):
          if predicate is None:
              predicate = bool
          for x in iterable:
              if not predicate(x):
                  yield x


.. function:: imap(function, *iterables)

   Make an iterator that computes the function using arguments from each of the
   iterables.  If *function* is set to ``None``, then :func:`imap` returns the
   arguments as a tuple.  Like :func:`map` but stops when the shortest iterable is
   exhausted instead of filling in ``None`` for shorter iterables.  The reason for
   the difference is that infinite iterator arguments are typically an error for
   :func:`map` (because the output is fully evaluated) but represent a common and
   useful way of supplying arguments to :func:`imap`. Equivalent to::

      def imap(function, *iterables):
          iterables = map(iter, iterables)
          while True:
              args = [it.next() for it in iterables]
              if function is None:
                  yield tuple(args)
              else:
                  yield function(*args)


.. function:: islice(iterable, [start,] stop [, step])

   Make an iterator that returns selected elements from the iterable. If *start* is
   non-zero, then elements from the iterable are skipped until start is reached.
   Afterward, elements are returned consecutively unless *step* is set higher than
   one which results in items being skipped.  If *stop* is ``None``, then iteration
   continues until the iterator is exhausted, if at all; otherwise, it stops at the
   specified position.  Unlike regular slicing, :func:`islice` does not support
   negative values for *start*, *stop*, or *step*.  Can be used to extract related
   fields from data where the internal structure has been flattened (for example, a
   multi-line report may list a name field on every third line).  Equivalent to::

      def islice(iterable, *args):
          s = slice(*args)
          it = iter(xrange(s.start or 0, s.stop or sys.maxint, s.step or 1))
          nexti = it.next()
          for i, element in enumerate(iterable):
              if i == nexti:
                  yield element
                  nexti = it.next()          

   If *start* is ``None``, then iteration starts at zero. If *step* is ``None``,
   then the step defaults to one.

   .. versionchanged:: 2.5
      accept ``None`` values for default *start* and *step*.


.. function:: izip(*iterables)

   Make an iterator that aggregates elements from each of the iterables. Like
   :func:`zip` except that it returns an iterator instead of a list.  Used for
   lock-step iteration over several iterables at a time.  Equivalent to::

      def izip(*iterables):
          iterables = map(iter, iterables)
          while iterables:
              result = [it.next() for it in iterables]
              yield tuple(result)

   .. versionchanged:: 2.4
      When no iterables are specified, returns a zero length iterator instead of
      raising a :exc:`TypeError` exception.

   The left-to-right evaluation order of the iterables is guaranteed. This
   makes possible an idiom for clustering a data series into n-length groups
   using ``izip(*[iter(s)]*n)``.

   :func:`izip` should only be used with unequal length inputs when you don't
   care about trailing, unmatched values from the longer iterables.  If those
   values are important, use :func:`izip_longest` instead.


.. function:: izip_longest(*iterables[, fillvalue])

   Make an iterator that aggregates elements from each of the iterables. If the
   iterables are of uneven length, missing values are filled-in with *fillvalue*.
   Iteration continues until the longest iterable is exhausted.  Equivalent to::

      def izip_longest(*args, **kwds):
          fillvalue = kwds.get('fillvalue')
          def sentinel(counter = ([fillvalue]*(len(args)-1)).pop):
              yield counter()         # yields the fillvalue, or raises IndexError
          fillers = repeat(fillvalue)
          iters = [chain(it, sentinel(), fillers) for it in args]
          try:
              for tup in izip(*iters):
                  yield tup
          except IndexError:
              pass

   If one of the iterables is potentially infinite, then the :func:`izip_longest`
   function should be wrapped with something that limits the number of calls (for
   example :func:`islice` or :func:`takewhile`).

   .. versionadded:: 2.6

.. function:: product(*iterables)

   Cartesian product of input iterables.

   Equivalent to nested for-loops in a generator expression. For example,
   ``product(A, B)`` returns the same as ``((x,y) for x in A for y in B)``.

   The leftmost iterators are in the outermost for-loop, so the output tuples
   cycle in a manner similar to an odometer (with the rightmost element
   changing on every iteration).  This results in a lexicographic ordering
   so that if the inputs iterables are sorted, the product tuples are emitted
   in sorted order.

   Equivalent to the following except that the actual implementation does not
   build-up intermediate results in memory::

       def product(*args):
           pools = map(tuple, args)
           if pools:            
               result = [[]]
               for pool in pools:
                   result = [x+[y] for x in result for y in pool]
               for prod in result:
                   yield tuple(prod)

   .. versionadded:: 2.6

.. function:: repeat(object[, times])

   Make an iterator that returns *object* over and over again. Runs indefinitely
   unless the *times* argument is specified. Used as argument to :func:`imap` for
   invariant parameters to the called function.  Also used with :func:`izip` to
   create an invariant part of a tuple record.  Equivalent to::

      def repeat(object, times=None):
          if times is None:
              while True:
                  yield object
          else:
              for i in xrange(times):
                  yield object


.. function:: starmap(function, iterable)

   Make an iterator that computes the function using arguments obtained from
   the iterable.  Used instead of :func:`imap` when argument parameters are already
   grouped in tuples from a single iterable (the data has been "pre-zipped").  The
   difference between :func:`imap` and :func:`starmap` parallels the distinction
   between ``function(a,b)`` and ``function(*c)``. Equivalent to::

      def starmap(function, iterable):
          for args in iterable:
              yield function(*args)

   .. versionchanged:: 2.6
      Previously, :func:`starmap` required the function arguments to be tuples.
      Now, any iterable is allowed.

.. function:: takewhile(predicate, iterable)

   Make an iterator that returns elements from the iterable as long as the
   predicate is true.  Equivalent to::

      def takewhile(predicate, iterable):
          for x in iterable:
              if predicate(x):
                  yield x
              else:
                  break


.. function:: tee(iterable[, n=2])

   Return *n* independent iterators from a single iterable. The case where ``n==2``
   is equivalent to::

      def tee(iterable):
          def gen(next, data={}):
              for i in count():
                  if i in data:
                      yield data.pop(i)
                  else:
                      data[i] = next()
                      yield data[i]
          it = iter(iterable)
          return gen(it.next), gen(it.next)

   Note, once :func:`tee` has made a split, the original *iterable* should not be
   used anywhere else; otherwise, the *iterable* could get advanced without the tee
   objects being informed.

   Note, this member of the toolkit may require significant auxiliary storage
   (depending on how much temporary data needs to be stored). In general, if one
   iterator is going to use most or all of the data before the other iterator, it
   is faster to use :func:`list` instead of :func:`tee`.

   .. versionadded:: 2.4


.. _itertools-example:

Examples
--------

The following examples show common uses for each tool and demonstrate ways they
can be combined. ::

   >>> amounts = [120.15, 764.05, 823.14]
   >>> for checknum, amount in izip(count(1200), amounts):
   ...     print 'Check %d is for $%.2f' % (checknum, amount)
   ...
   Check 1200 is for $120.15
   Check 1201 is for $764.05
   Check 1202 is for $823.14

   >>> import operator
   >>> for cube in imap(operator.pow, xrange(1,5), repeat(3)):
   ...    print cube
   ...
   1
   8
   27
   64

   # Show a dictionary sorted and grouped by value
   >>> from operator import itemgetter
   >>> d = dict(a=1, b=2, c=1, d=2, e=1, f=2, g=3)
   >>> di = sorted(d.iteritems(), key=itemgetter(1))
   >>> for k, g in groupby(di, key=itemgetter(1)):
   ...     print k, map(itemgetter(0), g)
   ...
   1 ['a', 'c', 'e']
   2 ['b', 'd', 'f']
   3 ['g']

   # Find runs of consecutive numbers using groupby.  The key to the solution
   # is differencing with a range so that consecutive numbers all appear in
   # same group.
   >>> data = [ 1,  4,5,6, 10, 15,16,17,18, 22, 25,26,27,28]
   >>> for k, g in groupby(enumerate(data), lambda (i,x):i-x):
   ...     print map(operator.itemgetter(1), g)
   ... 
   [1]
   [4, 5, 6]
   [10]
   [15, 16, 17, 18]
   [22]
   [25, 26, 27, 28]



.. _itertools-recipes:

Recipes
-------

This section shows recipes for creating an extended toolset using the existing
itertools as building blocks.

The extended tools offer the same high performance as the underlying toolset.
The superior memory performance is kept by processing elements one at a time
rather than bringing the whole iterable into memory all at once. Code volume is
kept small by linking the tools together in a functional style which helps
eliminate temporary variables.  High speed is retained by preferring
"vectorized" building blocks over the use of for-loops and :term:`generator`\s
which incur interpreter overhead. ::

   def take(n, seq):
       return list(islice(seq, n))

   def enumerate(iterable):
       return izip(count(), iterable)

   def tabulate(function):
       "Return function(0), function(1), ..."
       return imap(function, count())

   def iteritems(mapping):
       return izip(mapping.iterkeys(), mapping.itervalues())

   def nth(iterable, n):
       "Returns the nth item or raise StopIteration"
       return islice(iterable, n, None).next()

   def all(seq, pred=None):
       "Returns True if pred(x) is true for every element in the iterable"
       for elem in ifilterfalse(pred, seq):
           return False
       return True

   def any(seq, pred=None):
       "Returns True if pred(x) is true for at least one element in the iterable"
       for elem in ifilter(pred, seq):
           return True
       return False

   def no(seq, pred=None):
       "Returns True if pred(x) is false for every element in the iterable"
       for elem in ifilter(pred, seq):
           return False
       return True

   def quantify(seq, pred=None):
       "Count how many times the predicate is true in the sequence"
       return sum(imap(pred, seq))

   def padnone(seq):
       """Returns the sequence elements and then returns None indefinitely.

       Useful for emulating the behavior of the built-in map() function.
       """
       return chain(seq, repeat(None))

   def ncycles(seq, n):
       "Returns the sequence elements n times"
       return chain(*repeat(seq, n))

   def dotproduct(vec1, vec2):
       return sum(imap(operator.mul, vec1, vec2))

   def flatten(listOfLists):
       return list(chain(*listOfLists))

   def repeatfunc(func, times=None, *args):
       """Repeat calls to func with specified arguments.

       Example:  repeatfunc(random.random)
       """
       if times is None:
           return starmap(func, repeat(args))
       else:
           return starmap(func, repeat(args, times))

   def pairwise(iterable):
       "s -> (s0,s1), (s1,s2), (s2, s3), ..."
       a, b = tee(iterable)
       try:
           b.next()
       except StopIteration:
           pass
       return izip(a, b)

   def grouper(n, iterable, padvalue=None):
       "grouper(3, 'abcdefg', 'x') --> ('a','b','c'), ('d','e','f'), ('g','x','x')"
       return izip(*[chain(iterable, repeat(padvalue, n-1))]*n)

   def roundrobin(*iterables):
       "roundrobin('abc', 'd', 'ef') --> 'a', 'd', 'e', 'b', 'f', 'c'"
       # Recipe contributed by George Sakkis
       pending = len(iterables)
       nexts = cycle(iter(it).next for it in iterables)
       while pending:
           try:
               for next in nexts:
                   yield next()
           except StopIteration:
               pending -= 1
               nexts = cycle(islice(nexts, pending))

   def powerset(iterable):
       "powerset('ab') --> set([]), set(['b']), set(['a']), set(['a', 'b'])"
       skip = object()
       for t in product(*izip(repeat(skip), iterable)):
           yield set(e for e in t if e is not skip)

