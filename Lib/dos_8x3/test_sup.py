# Python test set -- supporting definitions.

TestFailed = 'test_support -- test failed'	# Exception

def unload(name):
	import sys
	try:
		del sys.modules[name]
	except KeyError:
		pass

def forget(modname):
	unload(modname)
	import sys, os
	for dirname in sys.path:
		try:
			os.unlink(os.path.join(dirname, modname + '.pyc'))
		except os.error:
			pass

FUZZ = 1e-6

def fcmp(x, y): # fuzzy comparison function
	if type(x) == type(0.0) or type(y) == type(0.0):
		try:
			x, y = coerce(x, y)
			fuzz = (abs(x) + abs(y)) * FUZZ
			if abs(x-y) <= fuzz:
				return 0
		except:
			pass
	elif type(x) == type(y) and type(x) in (type(()), type([])):
		for i in range(min(len(x), len(y))):
			outcome = fcmp(x[i], y[i])
			if outcome <> 0:
				return outcome
		return cmp(len(x), len(y))
	return cmp(x, y)

TESTFN = '@test' # Filename used for testing
from os import unlink
