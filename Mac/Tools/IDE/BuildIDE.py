"""Build a "big" applet for the IDE, and put it in the Python home 
directory. It will contain all IDE-specific modules as PYC resources,
which reduces the startup time (especially on slower machines)."""

import sys
import os
import buildtools
import Res
import py_resource
import macfs
import MACFS

buildtools.DEBUG=1

template = buildtools.findtemplate()

ide_home = os.path.join(sys.exec_prefix, ":Mac:Tools:IDE")

mainfilename = os.path.join(ide_home, "PythonIDE.py")
dstfilename = os.path.join(sys.exec_prefix, "Python IDE")

buildtools.process(template, mainfilename, dstfilename, 1)

# Override the owner: IDE gets its bundle stuff from the applet
# template and only needs to set the file creator.
dest_fss = macfs.FSSpec(dstfilename)
dest_finfo = dest_fss.GetFInfo()
dest_finfo.Creator = ownertype
dest_finfo.Type = 'APPL'
dest_finfo.Flags = dest_finfo.Flags | MACFS.kHasBundle
dest_finfo.Flags = dest_finfo.Flags & ~MACFS.kHasBeenInited
dest_fss.SetFInfo(dest_finfo)


targetref = Res.OpenResFile(dstfilename)
Res.UseResFile(targetref)

files = os.listdir(ide_home)

# skip this script and the main program
files = filter(lambda x: x[-3:] == '.py' and 
		x not in ("BuildIDE.py", "PythonIDE.py"), files)

# add the modules as PYC resources
for name in files:
	print "adding", name
	fullpath = os.path.join(ide_home, name)
	id, name = py_resource.frompyfile(fullpath, name[:-3], preload=1,
		ispackage=0)

# add W resources
wresref = Res.OpenResFile(os.path.join(ide_home, "Widgets.rsrc"))
buildtools.copyres(wresref, targetref, [], 0)

