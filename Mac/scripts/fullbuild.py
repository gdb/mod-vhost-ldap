#
# fullbuild creates everything that needs to be created before a
# distribution can be made, and puts it all in the right place.
#
# It expects the projects to be in the places where Jack likes them:
# in directories named like 'build.mac'. That is fixable,
# however.
#
# NOTE: You should proably make a copy of python with which to execute this
# script, rebuilding running programs does not work...

MACBUILDNO=":Mac:Include:macbuildno.h"

import os
import sys
import macfs
import MacOS
import EasyDialogs
import re
import string

import aetools
import AppleEvents

OLDAESUPPORT = 0

if OLDAESUPPORT:
	from Metrowerks_Shell_Suite import Metrowerks_Shell_Suite
	from CodeWarrior_suite import CodeWarrior_suite
	from Metrowerks_Standard_Suite import Metrowerks_Standard_Suite
	from Required_Suite import Required_Suite
else:
	import CodeWarrior

import Res
import Dlg

import buildtools
import cfmfile

# Dialog resource. Note that the item numbers should correspond
# to those in the DITL resource. Also note that the order is important:
# things are built in this order, so there should be no forward dependencies.
DIALOG_ID = 512

I_OK=1
I_CANCEL=2
# label 3
I_PPC_EXTLIBS=4
I_GEN_PROJECTS=5
I_GEN_IMGPROJECTS=6
I_INC_BUILDNO=7
# label 8
I_CORE=9
I_PPC_PLUGINS=10
I_PPC_EXTENSIONS=11
# label 12
I_PPC_FULL=13
I_PPC_SMALL=14
# label 15
I_APPLETS=16

N_BUTTONS=17

if OLDAESUPPORT:
	class MwShell(Metrowerks_Shell_Suite, CodeWarrior_suite, Metrowerks_Standard_Suite,
					Required_Suite, aetools.TalkTo):
		pass
else:
	MwShell = CodeWarrior.CodeWarrior

RUNNING=[]

def buildmwproject(top, creator, projects):
	"""Build projects with an MW compiler"""
	mgr = MwShell(creator, start=1)
	mgr.send_timeout = AppleEvents.kNoTimeOut
	
	failed = []
	for file in projects:
		if type(file) == type(()):
			file, target = file
		else:
			target = ''
		file = os.path.join(top, file)
		try:
			fss = macfs.FSSpec(file)
		except MacOS.Error:
			print '** file not found:', file
			continue
		print 'Building', file, target
		try:
			mgr.open(fss)
		except aetools.Error, detail:
			print '**', detail, file
			continue
		if target:
			try:
				mgr.Set_Current_Target(target)
			except aetools.Error, arg:
				print '**', file, target, 'Cannot select:', arg
		try:
			mgr.Make_Project()
		except aetools.Error, arg:
			print '**', file, target, 'Failed:', arg
			failed.append(fss)
		mgr.Close_Project()
	if failed:
		print 'Open failed projects and exit?',
		rv = sys.stdin.readline()
		if rv[0] in ('y', 'Y'):
			for fss in failed:
				mgr.open(fss)
			sys.exit(0)
##	mgr.quit()
	
def buildapplet(top, dummy, list):
	"""Create python applets"""
	template = buildtools.findtemplate()
	for src, dst in list:
		if src[-3:] != '.py':
			raise 'Should end in .py', src
		base = os.path.basename(src)
		src = os.path.join(top, src)
		dst = os.path.join(top, dst)
		try:
			os.unlink(dst)
		except os.error:
			pass
		print 'Building applet', dst
		buildtools.process(template, src, dst, 1)
		
def buildprojectfile(top, dummy, list):
	"""Create CodeWarrior project files with a script"""
	for folder, module, routine in list:
		print "Generating project files with", module
		sys.path.insert(0, os.path.join(top, folder))
		m = __import__(module)
		r = getattr(m, routine)
		r()
		del sys.path[0]
		
def buildfat(top, dummy, list):
	"""Build fat binaries"""
	for dst, src1, src2 in list:
		dst = os.path.join(top, dst)
		src1 = os.path.join(top, src1)
		src2 = os.path.join(top, src2)
		print 'Building fat binary', dst
		cfmfile.mergecfmfiles((src1, src2), dst)
		
def handle_dialog(filename):
	"""Handle selection dialog, return list of selected items"""
	d = Dlg.GetNewDialog(DIALOG_ID, -1)
	d.SetDialogDefaultItem(I_OK)
	d.SetDialogCancelItem(I_CANCEL)
	results = [0]*N_BUTTONS
	while 1:
		n = Dlg.ModalDialog(None)
		if n == I_OK:
			break
		if n == I_CANCEL:
			return []
		if n == I_INC_BUILDNO:
			incbuildno(filename)
			continue
		if n < len(results):
			results[n] = (not results[n])
			ctl = d.GetDialogItemAsControl(n)
			ctl.SetControlValue(results[n])
	rv = []
	for i in range(len(results)):
		if results[i]:
			rv.append(i)
	return rv

#
# The build instructions. Entries are (routine, arg, list-of-files)
# XXXX We could also include the builds for stdwin and such here...
BUILD_DICT = {
I_GEN_PROJECTS : (buildprojectfile, None, [
	(":Mac:scripts", "genpluginprojects", "genallprojects")
	]),
	
I_GEN_IMGPROJECTS : (buildprojectfile, None, [
	(":Extensions:img:Mac", "genimgprojects", "genallprojects")
	]),
	
I_CORE : (buildmwproject, "CWIE", [
		(":Mac:Build:PythonCore.mcp", "PythonCore"),
		(":Mac:Build:PythonInterpreter.mcp", "PythonInterpreter"),
	]),

I_PPC_EXTLIBS : (buildmwproject, "CWIE", [
##	(":Mac:Build:buildlibs.mcp", "buildlibs ppc plus tcl/tk"),
	(":Mac:Build:buildlibs.mcp", "buildlibs ppc"),
	]),
	
I_PPC_PLUGINS : (buildmwproject, "CWIE", [
	(":Mac:Build:ucnhash.mcp", "ucnhash.ppc"),
	(":Mac:Build:pyexpat.mcp", "pyexpat.ppc"),
	(":Mac:Build:calldll.mcp", "calldll.ppc"),
	(":Mac:Build:ctb.mcp", "ctb.ppc"),
	(":Mac:Build:gdbm.mcp", "gdbm.ppc"),
	(":Mac:Build:icglue.mcp", "icglue.ppc"),
	(":Mac:Build:macspeech.mcp", "macspeech.ppc"),
	(":Mac:Build:waste.mcp", "waste.ppc"),
	(":Mac:Build:zlib.mcp", "zlib.ppc"),
##	(":Mac:Build:_tkinter.mcp", "_tkinter.ppc"),
	(":Extensions:Imaging:_tkinter.mcp", "_tkinter.ppc"),
	(":Mac:Build:ColorPicker.mcp", "ColorPicker.ppc"),
	(":Mac:Build:Printing.mcp", "Printing.ppc"),
	(":Mac:Build:App.mcp", "App.ppc"),
	(":Mac:Build:Cm.mcp", "Cm.ppc"),
	(":Mac:Build:Fm.mcp", "Fm.ppc"),
	(":Mac:Build:Help.mcp", "Help.ppc"),
	(":Mac:Build:Icn.mcp", "Icn.ppc"),
	(":Mac:Build:List.mcp", "List.ppc"),
	(":Mac:Build:Qdoffs.mcp", "Qdoffs.ppc"),
	(":Mac:Build:Qt.mcp", "Qt.ppc"),
	(":Mac:Build:Scrap.mcp", "Scrap.ppc"),
	(":Mac:Build:Snd.mcp", "Snd.ppc"),
	(":Mac:Build:Sndihooks.mcp", "Sndihooks.ppc"),
	(":Mac:Build:TE.mcp", "TE.ppc"),
	]),


I_PPC_SMALL : (buildmwproject, "CWIE", [
		(":Mac:Build:PythonStandSmall.mcp", "PythonStandSmall"),
	]),

I_PPC_EXTENSIONS : (buildmwproject, "CWIE", [
		(":Extensions:Imaging:_imaging.mcp", "_imaging.ppc"),
##		(":Extensions:Imaging:_tkinter.mcp", "_tkinter.ppc"),
		(":Extensions:img:Mac:imgmodules.mcp", "imgmodules"),
##		(":Extensions:Numerical:Mac:numpymodules.mcp", "multiarraymodule"),
##		(":Extensions:Numerical:Mac:numpymodules.mcp", "_numpy"),
##		(":Extensions:Numerical:Mac:numpymodules.mcp", "umathmodule"),
##		(":Extensions:Numerical:Mac:numpymodules.mcp", "arrayfns"),
##		(":Extensions:Numerical:Packages:FFT:Mac:fftpack.mcp", "fftpack.ppc"),
##		(":Extensions:Numerical:Packages:LALITE:Mac:lapack_lite.mcp", "lapack_lite.ppc"),
##		(":Extensions:Numerical:Packages:RANLIB:Mac:ranlib.mcp", "ranlib.ppc"),
##		(":Extensions:Numerical:Packages:RNG:Mac:RNG.mcp", "RNG.ppc"),
	]),

I_APPLETS : (buildapplet, None, [
		(":Mac:scripts:EditPythonPrefs.py", "EditPythonPrefs"),
		(":Mac:scripts:BuildApplet.py", "BuildApplet"),
		(":Mac:scripts:BuildApplication.py", "BuildApplication"),
		(":Mac:scripts:ConfigurePython.py", "ConfigurePython"),
		(":Mac:Tools:IDE:PythonIDE.py", "Python IDE"),
		(":Mac:Tools:CGI:PythonCGISlave.py", ":Mac:Tools:CGI:PythonCGISlave"),
		(":Mac:Tools:CGI:BuildCGIApplet.py", ":Mac:Tools:CGI:BuildCGIApplet"),
	]),
}

def incbuildno(filename):
	fp = open(filename)
	line = fp.readline()
	fp.close()
	
	pat = re.compile('#define BUILD ([0-9]+)')
	m = pat.search(line)
	if not m or not m.group(1):
		raise 'Incorrect macbuildno.h line', line
	buildno = m.group(1)
	new = string.atoi(buildno) + 1
	fp = open(filename, 'w')
	fp.write('#define BUILD %d\n'%new)
	fp.close()
				
def main():
	try:
		h = Res.FSpOpenResFile('fullbuild.rsrc', 1)
	except Res.Error:
		pass	# Assume we already have acces to our own resource

	dir, ok = macfs.GetDirectory('Python source folder:')
	if not ok:
		sys.exit(0)
	dir = dir.as_pathname()
	
	todo = handle_dialog(os.path.join(dir, MACBUILDNO))
		
	instructions = []
	for i in todo:
		instructions.append(BUILD_DICT[i])
		
	for routine, arg, list in instructions:
		routine(dir, arg, list)
		
	if todo:
		print "All done!"
	
if __name__ == '__main__':
	main()
	
