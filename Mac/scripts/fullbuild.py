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

CARBON_ONLY = 1

MACBUILDNO=":Mac:Include:macbuildno.h"

import os
import sys
import macfs
import MacOS
import EasyDialogs
import re
import string
import genpluginprojects
import macresource

import aetools
from Carbon import AppleEvents

import CodeWarrior

from Carbon import Res
from Carbon import Dlg

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
I_GEN_PROJECTS_FORCE=6
I_GEN_IMGPROJECTS=7
I_GEN_IMGPROJECTS_FORCE=8
I_INC_BUILDNO=9
# label 10
I_PPC_CORE=11
I_PPC_PLUGINS=12
I_PPC_EXTENSIONS=13
# label 14
I_CARBON_CORE=15
I_CARBON_PLUGINS=16
I_CARBON_EXTENSIONS=17
I_INTERPRETER=18
# label 19
I_PPC_FULL=20
I_PPC_SMALL=21
# label 22
I_CARBON_FULL=23
I_CARBON_SMALL=24
# label 25
I_APPLETS=26

N_BUTTONS=27

if CARBON_ONLY:
	BUTTONS_DISABLE = [
		I_PPC_EXTLIBS,
		I_PPC_CORE,
		I_PPC_PLUGINS,
		I_PPC_EXTENSIONS,
		I_INTERPRETER,
		I_PPC_FULL,
		I_PPC_SMALL,
	]
else:
	BUTTONS_DISABLE = []
	
RUNNING=[]

def buildmwproject(top, creator, projects):
	"""Build projects with an MW compiler"""
	mgr = CodeWarrior.CodeWarrior(creator, start=1)
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
	for src, dst, tmpl in list:
		template = buildtools.findtemplate(tmpl)
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
		try:
			buildtools.process(template, src, dst, 1)
		except buildtools.BuildError, arg:
			print '**', dst, arg
		
def buildprojectfile(top, arg, list):
	"""Create CodeWarrior project files with a script"""
	for folder, module, routine in list:
		print "Generating project files with", module
		sys.path.insert(0, os.path.join(top, folder))
		m = __import__(module)
		r = getattr(m, routine)
		r(arg)
		del sys.path[0]
		
def buildfat(top, dummy, list):
	"""Build fat binaries"""
	for dst, src1, src2 in list:
		dst = os.path.join(top, dst)
		src1 = os.path.join(top, src1)
		src2 = os.path.join(top, src2)
		print 'Building fat binary', dst
		cfmfile.mergecfmfiles((src1, src2), dst)
		
def buildcopy(top, dummy, list):
	import macostools
	for src, dst in list:
		src = os.path.join(top, src)
		dst = os.path.join(top, dst)
		macostools.copy(src, dst, forcetype="APPL")
		
def buildsetup(top, dummy, list):
	print 'Building extensions with setup.py ', ' '.join(list)
	argv = ['setup.py'] + list[:]
	save_argv = sys.argv
	sys.argv = argv
	sys.path.insert(0, top)
	m = __import__('setup')
	r = getattr(m, 'main')
	r()
	del sys.path[0]
	sys.argv = save_argv

def buildcarbonplugins(top, dummy1, dummy2):
## XXXX Need to convert pathnames, I guess, and adapt distutils Mac-specific
## code to not call GetArgv if not needed.
##	buildsetup(top, None, [
##		'--dry_run',
##        	'install',
##                '--prefix=%s' % sys.prefix,
##                '--install-scripts=%s' % os.path.join(sys.prefix, 'Scripts'),
##                '--install-platlib=%s' % os.path.join(sys.prefix, 'Lib', 'lib-dynload')
##		])
	buildmwproject(top, "CWIE", [
		(":Mac:Build:_weakref.carbon.mcp", "_weakref.carbon"),
		(":Mac:Build:_symtable.carbon.mcp", "_symtable.carbon"),
		(":Mac:Build:_testcapi.carbon.mcp", "_testcapi.carbon"),
		(":Mac:Build:_hotshot.carbon.mcp", "_hotshot.carbon"),
		(":Mac:Build:xx.carbon.mcp", "xx.carbon"),
		(":Mac:Build:xxsubtype.carbon.mcp", "xxsubtype.carbon"),
		(":Mac:Build:pyexpat.carbon.mcp", "pyexpat.carbon"),
		(":Mac:Build:calldll.carbon.mcp", "calldll.carbon"),
		(":Mac:Build:gdbm.carbon.mcp", "gdbm.carbon"),
		(":Mac:Build:icglue.carbon.mcp", "icglue.carbon"),
		(":Mac:Build:waste.carbon.mcp", "waste.carbon"),
		(":Mac:Build:zlib.carbon.mcp", "zlib.carbon"),
		(":Mac:Build:hfsplus.carbon.mcp", "hfsplus.carbon"),
	##	(":Mac:Build:_dummy_tkinter.mcp", "_tkinter.carbon"),
		(":Extensions:Imaging:_tkinter.mcp", "_tkinter.carbon"),
		(":Mac:Build:ColorPicker.carbon.mcp", "ColorPicker.carbon"),
		(":Mac:Build:_AE.carbon.mcp", "_AE.carbon"),
		(":Mac:Build:_App.carbon.mcp", "_App.carbon"),
		(":Mac:Build:_CF.carbon.mcp", "_CF.carbon"),
		(":Mac:Build:_CG.carbon.mcp", "_CG.carbon"),
		(":Mac:Build:_CarbonEvt.carbon.mcp", "_CarbonEvt.carbon"),
		(":Mac:Build:_Cm.carbon.mcp", "_Cm.carbon"),
		(":Mac:Build:_Ctl.carbon.mcp", "_Ctl.carbon"),
		(":Mac:Build:_Dlg.carbon.mcp", "_Dlg.carbon"),
		(":Mac:Build:_Drag.carbon.mcp", "_Drag.carbon"),
		(":Mac:Build:_Evt.carbon.mcp", "_Evt.carbon"),
		(":Mac:Build:_Fm.carbon.mcp", "_Fm.carbon"),
		(":Mac:Build:_Help.carbon.mcp", "_Help.carbon"),
		(":Mac:Build:_IBCarbon.carbon.mcp", "_IBCarbon.carbon"),
		(":Mac:Build:_Icn.carbon.mcp", "_Icn.carbon"),
		(":Mac:Build:_List.carbon.mcp", "_List.carbon"),
		(":Mac:Build:_Menu.carbon.mcp", "_Menu.carbon"),
		(":Mac:Build:_Mlte.carbon.mcp", "_Mlte.carbon"),
		(":Mac:Build:_Qd.carbon.mcp", "_Qd.carbon"),
		(":Mac:Build:_Qdoffs.carbon.mcp", "_Qdoffs.carbon"),
		(":Mac:Build:_Qt.carbon.mcp", "_Qt.carbon"),
		(":Mac:Build:_Res.carbon.mcp", "_Res.carbon"),
		(":Mac:Build:_Scrap.carbon.mcp", "_Scrap.carbon"),
		(":Mac:Build:_Snd.carbon.mcp", "_Snd.carbon"),
		(":Mac:Build:_Sndihooks.carbon.mcp", "_Sndihooks.carbon"),
		(":Mac:Build:_TE.carbon.mcp", "_TE.carbon"),
		(":Mac:Build:_Win.carbon.mcp", "_Win.carbon"),
	])
	
def handle_dialog(filename):
	"""Handle selection dialog, return list of selected items"""
	d = Dlg.GetNewDialog(DIALOG_ID, -1)
	d.SetDialogDefaultItem(I_OK)
	d.SetDialogCancelItem(I_CANCEL)
	results = [0]*N_BUTTONS
	for n in BUTTONS_DISABLE:
		ctl = d.GetDialogItemAsControl(n)
		ctl.HideControl()
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
I_GEN_PROJECTS : (buildprojectfile, 0, [
	(":Mac:scripts", "genpluginprojects", "genallprojects")
	]),
	
I_GEN_PROJECTS_FORCE : (buildprojectfile, 1, [
	(":Mac:scripts", "genpluginprojects", "genallprojects")
	]),
	
I_GEN_IMGPROJECTS : (buildprojectfile, 0, [
	(":Extensions:img:Mac", "genimgprojects", "genallprojects")
	]),
	
I_GEN_IMGPROJECTS_FORCE : (buildprojectfile, 1, [
	(":Extensions:img:Mac", "genimgprojects", "genallprojects")
	]),
	
I_INTERPRETER : (buildcopy, None, [
		("PythonInterpreterCarbon", "PythonInterpreter"),
	]),

I_PPC_CORE : (buildmwproject, "CWIE", [
		(":Mac:Build:PythonCore.mcp", "PythonCore"),
		(":Mac:Build:PythonInterpreter.mcp", "PythonInterpreterClassic"),
	]),

I_CARBON_CORE : (buildmwproject, "CWIE", [
		(":Mac:Build:PythonCore.mcp", "PythonCoreCarbon"),
		(":Mac:Build:PythonInterpreter.mcp", "PythonInterpreterCarbon"),
	]),

I_PPC_EXTLIBS : (buildmwproject, "CWIE", [
##	(":Mac:Build:buildlibs.mcp", "buildlibs ppc plus tcl/tk"),
	(":Mac:Build:buildlibs.mcp", "buildlibs ppc"),
	]),
	
I_PPC_PLUGINS : (buildmwproject, "CWIE", [
	(":Mac:Build:_weakref.mcp", "_weakref.ppc"),
	(":Mac:Build:_symtable.mcp", "_symtable.ppc"),
	(":Mac:Build:_testcapi.mcp", "_testcapi.ppc"),
	(":Mac:Build:_hotshot.mcp", "_hotshot.ppc"),
	(":Mac:Build:xx.mcp", "xx.ppc"),
	(":Mac:Build:xxsubtype.mcp", "xxsubtype.ppc"),
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
	(":Mac:Build:_AE.mcp", "_AE.ppc"),
	(":Mac:Build:_App.mcp", "_App.ppc"),
	(":Mac:Build:_Cm.mcp", "_Cm.ppc"),
	(":Mac:Build:_Ctl.mcp", "_Ctl.ppc"),
	(":Mac:Build:_Dlg.mcp", "_Dlg.ppc"),
	(":Mac:Build:_Drag.mcp", "_Drag.ppc"),
	(":Mac:Build:_Evt.mcp", "_Evt.ppc"),
	(":Mac:Build:_Fm.mcp", "_Fm.ppc"),
	(":Mac:Build:_Help.mcp", "_Help.ppc"),
	(":Mac:Build:_Icn.mcp", "_Icn.ppc"),
	(":Mac:Build:_List.mcp", "_List.ppc"),
	(":Mac:Build:_Menu.mcp", "_Menu.ppc"),
	(":Mac:Build:_Mlte.mcp", "_Mlte.ppc"),
	(":Mac:Build:_Qd.mcp", "_Qd.ppc"),
	(":Mac:Build:_Qdoffs.mcp", "_Qdoffs.ppc"),
	(":Mac:Build:_Qt.mcp", "_Qt.ppc"),
	(":Mac:Build:_Res.mcp", "_Res.ppc"),
	(":Mac:Build:_Scrap.mcp", "_Scrap.ppc"),
	(":Mac:Build:_Snd.mcp", "_Snd.ppc"),
	(":Mac:Build:_Sndihooks.mcp", "_Sndihooks.ppc"),
	(":Mac:Build:_TE.mcp", "_TE.ppc"),
	(":Mac:Build:_Win.mcp", "_Win.ppc"),
	]),

I_CARBON_PLUGINS :  (buildcarbonplugins, None, []),

I_PPC_FULL : (buildmwproject, "CWIE", [
		(":Mac:Build:PythonStandalone.mcp", "PythonStandalone"),
	]),

I_PPC_SMALL : (buildmwproject, "CWIE", [
		(":Mac:Build:PythonStandSmall.mcp", "PythonStandSmall"),
	]),

I_CARBON_FULL : (buildmwproject, "CWIE", [
		(":Mac:Build:PythonStandalone.mcp", "PythonCarbonStandalone"),
	]),

I_CARBON_SMALL : (buildmwproject, "CWIE", [
		(":Mac:Build:PythonStandSmall.mcp", "PythonStandSmallCarbon"),
	]),

I_PPC_EXTENSIONS : (buildmwproject, "CWIE", [
		(":Extensions:Imaging:_imaging.mcp", "_imaging.ppc"),
##		(":Extensions:Imaging:_tkinter.mcp", "_tkinter.ppc"),
		(":Extensions:img:Mac:imgmodules.mcp", "imgmodules.ppc"),
	]),

I_CARBON_EXTENSIONS : (buildmwproject, "CWIE", [
		(":Extensions:Imaging:_imaging.mcp", "_imaging.carbon"),
##		(":Extensions:Imaging:_tkinter.mcp", "_tkinter.carbon"),
		(":Extensions:img:Mac:imgmodules.mcp", "imgmodules.carbon"),
	]),
	
I_APPLETS : (buildapplet, None, [
		(":Mac:scripts:EditPythonPrefs.py", "EditPythonPrefs", None),
		(":Mac:scripts:BuildApplet.py", "BuildApplet", None),
		(":Mac:scripts:BuildApplication.py", "BuildApplication", None),
		(":Mac:scripts:ConfigurePython.py", "ConfigurePython", None),
##		(":Mac:scripts:ConfigurePython.py", "ConfigurePythonCarbon", "PythonInterpreterCarbon"),
##		(":Mac:scripts:ConfigurePython.py", "ConfigurePythonClassic", "PythonInterpreterClassic"),
		(":Mac:Tools:IDE:PythonIDE.py", "Python IDE", None),
		(":Mac:Tools:CGI:PythonCGISlave.py", ":Mac:Tools:CGI:PythonCGISlave", None),
		(":Mac:Tools:CGI:BuildCGIApplet.py", ":Mac:Tools:CGI:BuildCGIApplet", None),
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
	macresource.need('DLOG', DIALOG_ID, 'fullbuild.rsrc')
	dir, ok = macfs.GetDirectory('Python source folder:')
	if not ok:
		sys.exit(0)
	dir = dir.as_pathname()
	# Set genpluginprojects to use this folder (slight hack)
	genpluginprojects.PYTHONDIR = dir
	
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
	
