"""Create an applet from a Python script.

This puts up a dialog asking for a Python source file ('TEXT').
The output is a file with the same name but its ".py" suffix dropped.
It is created by copying an applet template and then adding a 'PYC '
resource named __main__ containing the compiled, marshalled script.
"""

import sys
sys.stdout = sys.stderr

import string
import os
import marshal
import imp
import macfs
import MacOS
from Res import *

# .pyc file (and 'PYC ' resource magic number)
MAGIC = imp.get_magic()

# Template file (searched on sys.path)
TEMPLATE = "PythonApplet"

# Specification of our resource
RESTYPE = 'PYC '
RESNAME = '__main__'

# OpenResFile mode parameters
READ = 1
WRITE = 2

def main():
	
	# Find the template
	# (there's no point in proceeding if we can't find it)
	
	for p in sys.path:
		template = os.path.join(p, TEMPLATE)
		try:
			tmpl = open(template, "rb")
			tmpl.close()
			break
		except IOError:
			continue
	else:
		die("Template %s not found" % `template`)
		return
	
	# Ask for source text if not specified in sys.argv[1:]
	
	if not sys.argv[1:]:
		srcfss, ok = macfs.StandardGetFile('TEXT')
		if not ok:
			return
		filename = srcfss.as_pathname()
		if not sys.argv: sys.argv.append('')
		sys.argv.append(filename)
	
	# Loop over all files to be processed
	
	for filename in sys.argv[1:]:
		process(template, filename)

undefs = ('????', '    ', '\0\0\0\0')

def process(template, filename):
	
	print "Processing", `filename`, "..."
	
	# Read the source and compile it
	# (there's no point overwriting the destination if it has a syntax error)
	
	fp = open(filename)
	text = fp.read()
	fp.close()
	try:
		code = compile(text, filename, "exec")
	except (SyntaxError, EOFError):
		die("Syntax error in script %s" % `filename`)
		return
	
	# Set the destination file name
	
	if string.lower(filename[-3:]) == ".py":
		destname = filename[:-3]
		rsrcname = destname + '.rsrc'
	else:
		destname = filename + ".applet"
		rsrcname = filename + '.rsrc'
	
	# Copy the data from the template (creating the file as well)
	
	tmpl = open(template, "rb")
	dest = open(destname, "wb")
	data = tmpl.read()
	if data:
		dest.write(data)
	dest.close()
	tmpl.close()
	
	# Copy the creator of the template to the destination
	# unless it already got one.  Set type to APPL
	
	tctor, ttype = MacOS.GetCreatorAndType(template)
	ctor, type = MacOS.GetCreatorAndType(destname)
	if type in undefs: type = 'APPL'
	if ctor in undefs: ctor = tctor
	MacOS.SetCreatorAndType(destname, ctor, type)
	
	# Open the output resource fork
	
	try:
		output = FSpOpenResFile(destname, WRITE)
	except MacOS.Error:
		print "Creating resource fork..."
		CreateResFile(destname)
		output = FSpOpenResFile(destname, WRITE)
	
	# Copy the resources from the template
	
	input = FSpOpenResFile(template, READ)
	copyres(input, output)
	CloseResFile(input)
	
	# Copy the resources from the target specific resource template, if any
	
	try:
		input = FSpOpenResFile(rsrcname, READ)
	except MacOS.Error:
		pass
	else:
		copyres(input, output)
		CloseResFile(input)
	
	# Make sure we're manipulating the output resource file now
	
	UseResFile(output)
	
	# Delete any existing 'PYC 'resource named __main__
	
	try:
		res = Get1NamedResource(RESTYPE, RESNAME)
		res.RmveResource()
	except Error:
		pass
	
	# Create the raw data for the resource from the code object
	
	data = marshal.dumps(code)
	del code
	data = (MAGIC + '\0\0\0\0') + data
	
	# Create the resource and write it
	
	id = 0
	while id < 128:
		id = Unique1ID(RESTYPE)
	res = Resource(data)
	res.AddResource(RESTYPE, id, RESNAME)
	res.WriteResource()
	res.ReleaseResource()
	
	# Close the output file
	
	CloseResFile(output)
	
	# Give positive feedback
	
	message("Applet %s created." % `destname`)


# Copy resources between two resource file descriptors
# Exception: don't copy a __main__ resource

def copyres(input, output):
	UseResFile(input)
	ntypes = Count1Types()
	for itype in range(1, 1+ntypes):
		type = Get1IndType(itype)
		nresources = Count1Resources(type)
		for ires in range(1, 1+nresources):
			res = Get1IndResource(type, ires)
			id, type, name = res.GetResInfo()
			if (type, name) == (RESTYPE, RESNAME):
				continue # Don't copy __main__ from template
			size = res.SizeResource()
			attrs = res.GetResAttrs()
			print id, type, name, size, hex(attrs)
			res.LoadResource()
			res.DetachResource()
			UseResFile(output)
			try:
				res2 = Get1Resource(type, id)
			except MacOS.Error:
				res2 = None
			if res2:
				print "Overwriting..."
				res2.RmveResource()
			res.AddResource(type, id, name)
			#res.SetResAttrs(attrs)
			res.WriteResource()
			UseResFile(input)


# Show a message and exit

def die(str):
	message(str)
	sys.exit(1)


# Show a message

def message(str, id = 256):
	from Dlg import *
	d = GetNewDialog(id, -1)
	if not d:
		print "Error:", `str`
		print "DLOG id =", id, "not found."
		return
	tp, h, rect = d.GetDItem(2)
	SetIText(h, str)
	while 1:
		n = ModalDialog(None)
		if n == 1: break
	del d


if __name__ == '__main__':
	main()
