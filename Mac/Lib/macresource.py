"""macresource - Locate and open the resources needed for a script."""

from Carbon import Res
import os
import sys

class ArgumentError(TypeError): pass
class ResourceFileNotFoundError(ImportError): pass

def need(restype, resid, filename=None, modname=None):
	"""Open a resource file, if needed. restype and resid
	are required parameters, and identify the resource for which to test. If it
	is available we are done. If it is not available we look for a file filename
	(default: modname with .rsrc appended) either in the same folder as
	where modname was loaded from, or otherwise across sys.path."""

	if modname is None and filename is None:
		raise ArgumentError, "Either filename or modname argument (or both) must be given"
	
	if type(resid) is type(1):
		try:
			h = Res.GetResource(restype, resid)
		except Res.Error:
			pass
		else:
			return
	else:
		try:
			h = Res.GetNamedResource(restype, resid)
		except Res.Error:
			pass
		else:
			return
			
	# Construct a filename if we don't have one
	if not filename:
		if '.' in modname:
			filename = modname.split('.')[-1] + '.rsrc'
		else:
			filename = modname + '.rsrc'
	
	# Now create a list of folders to search
	searchdirs = []
	if modname == '__main__':
		# If we're main we look in the current directory
		searchdirs = [os.curdir]
	if sys.modules.has_key(modname):
		mod = sys.modules[modname]
		if hasattr(mod, '__file__'):
			searchdirs = [mod.__file__]
	if not searchdirs:
		searchdirs = sys.path
	
	# And look for the file
	for dir in searchdirs:
		pathname = os.path.join(dir, filename)
		if os.path.exists(pathname):
			break
	else:
		raise ResourceFileNotFoundError, filename
	
	Res.FSpOpenResFile(pathname, 1)
	
	# And check that the resource exists now
	if type(resid) is type(1):
		h = Res.GetResource(restype, resid)
	else:
		h = Res.GetNamedResource(restype, resid)
