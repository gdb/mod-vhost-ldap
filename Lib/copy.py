"""\
Generic (shallow and deep) copying operations
=============================================

Interface summary:

	import copy

	x = copy.copy(y)	# make a shallow copy of y
	x = copy.deepcopy(y)	# make a deep copy of y

For module specific errors, copy.Error is raised.

The difference between shallow and deep copying is only relevant for
compound objects (objects that contain other objects, like lists or
class instances).

- A shallow copy constructs a new compound object and then (to the
  extent possible) inserts *the same objects* into in that the
  original contains.

- A deep copy constructs a new compound object and then, recursively,
  inserts *copies* into it of the objects found in the original.

Two problems often exist with deep copy operations that don't exist
with shallow copy operations:

(a) recursive objects (compound objects that, directly or indirectly,
    contain a reference to themselves) may cause a recursive loop

(b) because deep copy copies *everything* it may copy too much, e.g.
    administrative data structures that should be shared even between
    copies

Python's deep copy operation avoids these problems by:

(a) keeping a table of objects already copied during the current
copying pass

(b) letting user-defined classes override the copying operation or the
    set of components copied

This version does not copy types like module, class, function, method,
nor stack trace, stack frame, nor file, socket, window, nor array, nor
any similar types.

Classes can use the same interfaces to control copying that they use
to control pickling: they can define methods called __getinitargs__(),
__getstate__() and __setstate__().  See the __doc__ string of module
"pickle" for information on these methods.
"""

import types

Error = 'copy.Error'

def copy(x):
	"""Shallow copy operation on arbitrary Python objects.

	See the module's __doc__ string for more info.
	"""

	try:
		copierfunction = _copy_dispatch[type(x)]
	except KeyError:
		try:
			copier = x.__copy__
		except AttributeError:
			raise Error, \
			      "un(shallow)copyable object of type %s" % type(x)
		y = copier()
	else:
		y = copierfunction(x)
	return y

_copy_dispatch = d = {}

def _copy_atomic(x):
	return x
d[types.NoneType] = _copy_atomic
d[types.IntType] = _copy_atomic
d[types.LongType] = _copy_atomic
d[types.FloatType] = _copy_atomic
d[types.StringType] = _copy_atomic
d[types.CodeType] = _copy_atomic
d[types.TypeType] = _copy_atomic
d[types.XRangeType] = _copy_atomic

def _copy_list(x):
	return x[:]
d[types.ListType] = _copy_list

def _copy_tuple(x):
	return x[:]
d[types.TupleType] = _copy_tuple

def _copy_dict(x):
	y = {}
	for key in x.keys():
		y[key] = x[key]
	return y
d[types.DictionaryType] = _copy_dict

def _copy_inst(x):
	if hasattr(x, '__copy__'):
		return x.__copy__()
	if hasattr(x, '__getinitargs__'):
		args = x.__getinitargs__()
	else:
		args = ()
	y = apply(x.__class__, args)
	if hasattr(x, '__getstate__'):
			state = x.__getstate__()
	else:
			state = x.__dict__
	if y.hasattr('__setstate__'):
			y.__setstate__(state)
	else:
			for key in state.keys():
				setattr(y, key, state[key])
	return y
d[types.InstanceType] = _copy_inst

del d

def deepcopy(x, memo = None):
	"""Deep copy operation on arbitrary Python objects.

	See the module's __doc__ string for more info.
	"""

	if memo is None:
		memo = {}
	d = id(x)
	if memo.has_key(d):
		return memo[d]
	try:
		copierfunction = _deepcopy_dispatch[type(x)]
	except KeyError:
		try:
			copier = x.__deepcopy__
		except AttributeError:
			raise Error, \
			      "un-deep-copyable object of type %s" % type(x)
		y = copier(memo)
	else:
		y = copierfunction(x, memo)
	memo[d] = y
	return y

_deepcopy_dispatch = d = {}

def _deepcopy_atomic(x, memo):
	return x
d[types.NoneType] = _deepcopy_atomic
d[types.IntType] = _deepcopy_atomic
d[types.LongType] = _deepcopy_atomic
d[types.FloatType] = _deepcopy_atomic
d[types.StringType] = _deepcopy_atomic
d[types.CodeType] = _deepcopy_atomic
d[types.TypeType] = _deepcopy_atomic
d[types.XRangeType] = _deepcopy_atomic

def _deepcopy_list(x, memo):
	y = []
	memo[id(x)] = y
	for a in x:
		y.append(deepcopy(a, memo))
	return y
d[types.ListType] = _deepcopy_list

def _deepcopy_tuple(x, memo):
	y = []
	for a in x:
		y.append(deepcopy(a, memo))
	d = id(x)
	try:
		return memo[d]
	except KeyError:
		pass
	for i in range(len(x)):
		if x[i] is not y[i]:
			return tuple(y)
	return x
d[types.TupleType] = _deepcopy_tuple

def _deepcopy_dict(x, memo):
	y = {}
	memo[id(x)] = y
	for key in x.keys():
		y[deepcopy(key, memo)] = deepcopy(x[key], memo)
	return y
d[types.DictionaryType] = _deepcopy_dict

def _deepcopy_inst(x, memo):
	if hasattr(x, '__deepcopy__'):
		return x.__deepcopy__()
	if hasattr(x, '__getinitargs__'):
		args = x.__getinitargs__()
		args = deepcopy(args, memo)
	else:
		args = ()
	y = apply(x.__class__, args)
	memo[id(x)] = y
	if hasattr(x, '__getstate__'):
			state = x.__getstate__()
	else:
			state = x.__dict__
	state = deepcopy(state, memo)
	if y.hasattr('__setstate__'):
			y.__setstate__(state)
	else:
			for key in state.keys():
				setattr(y, key, state[key])
	return y
d[types.InstanceType] = _deepcopy_inst

del d

del types

def _test():
	l = [None, 1, 2L, 3.14, 'xyzzy', (1, 2L), [3.14, 'abc'], {'abc': 'ABC'}, (), [], {}]
	l1 = copy(l)
	print l1==l
	l1 = map(copy, l)
	print l1==l
	l1 = deepcopy(l)
	print l1==l
	class C:
		def __init__(self, arg=None):
			self.a = 1
			self.arg = arg
			self.fp = open('copy.py')
			self.fp.close()
		def __getstate__(self):
			return {'a': self.a, 'arg': self.arg}
		def __setstate__(self, state):
			for key in state.keys():
				setattr(self, key, state[key])
		def __deepcopy__(self, memo = None):
			new = self.__class__(deepcopy(self.arg, memo))
			new.a = self.a
			return new
	c = C('argument sketch')
	l.append(c)
	l2 = copy(l)
	print l == l2
	print l
	print l2
	l2 = deepcopy(l)
	print l == l2
	print l
	print l2
	l.append({l[1]: l, 'xyz': l[2]})
	l3 = copy(l)
	import repr
	print map(repr.repr, l)
	print map(repr.repr, l1)
	print map(repr.repr, l2)
	print map(repr.repr, l3)
	l3 = deepcopy(l)
	import repr
	print map(repr.repr, l)
	print map(repr.repr, l1)
	print map(repr.repr, l2)
	print map(repr.repr, l3)

if __name__ == '__main__':
	_test()
