#
# fullbuild creates everything that needs to be created before a
# distribution can be made, and puts it all in the right place.
#
# It expects the projects to be in the places where Jack likes them:
# in directories named like 'build.macppc.shared'. That is fixable,
# however.
#
# NOTE: You should proably make a copy of python with which to execute this
# script, rebuilding running programs does not work...

import os
import sys
import macfs
import MacOS
import EasyDialogs

import addpack
import aetools
import AppleEvents
from Metrowerks_Shell_Suite import Metrowerks_Shell_Suite
from Required_Suite import Required_Suite 

import mkapplet

class MwShell(aetools.TalkTo, Metrowerks_Shell_Suite, Required_Suite):
	pass

RUNNING=[]

def buildmwproject(top, creator, projects):
	"""Build projects with an MW compiler"""
	mgr = MwShell(creator, start=1)
	mgr.send_timeout = AppleEvents.kNoTimeOut
	
	for file in projects:
		file = os.path.join(top, file)
		fss = macfs.FSSpec(file)
		print 'Building', file
		mgr.open(fss)
		try:
			mgr.Make_Project()
		except aetools.Error, arg:
			print '** Failed:', arg
		mgr.Close_Project()
##	mgr.quit()
	
def buildapplet(top, dummy, list):
	"""Create a PPC python applet"""
	template = mkapplet.findtemplate()
	for src in list:
		if src[-3:] != '.py':
			raise 'Should end in .py', src
		base = os.path.basename(src)
		dst = os.path.join(top, base)[:-3]
		src = os.path.join(top, src)
		try:
			os.unlink(dst)
		except os.error:
			pass
		print 'Building applet', dst
		mkapplet.process(template, src, dst)

#
# The build instructions. Entries are (routine, arg, list-of-files)
# XXXX We could also include the builds for stdwin and such here...
PPC_INSTRUCTIONS=[
	(buildmwproject, "CWIE", [
		":build.macppc.shared:PythonCorePPC.�",
		":build.macppc.shared:PythonPPC.�",
		":build.macppc.shared:PythonAppletPPC.�",
	])
]
CFM68K_INSTRUCTIONS=[
	(buildmwproject, "CWIE", [
		":build.mac68k.shared:PythonCoreCFM68K.�",
		":build.mac68k.shared:PythonCFM68K.�",
		":build.mac68k.shared:PythonAppletCFM68K.�",
	])
]
FAT_INSTRUCTIONS=[
	(buildmwproject, "CWIE", [
		":build.macppc.shared:Python.�",
		":build.macppc.shared:PythonApplet.�",
	])
]
PLUGIN_INSTRUCTIONS=[
	(buildmwproject, "CWIE", [
		":PlugIns:ctb.ppc.�",
		":PlugIns:imgmodules.ppc.�",
		":PlugIns:macspeech.ppc.�",
		":PlugIns:toolboxmodules.ppc.�",
		":PlugIns:qtmodules.ppc.�",
		":PlugIns:waste.ppc.�",
		":PlugIns:_tkinter.ppc.�",
	])
]
CFM68KPLUGIN_INSTRUCTIONS=[
	(buildmwproject, "CWIE", [
		":PlugIns:ctb.CFM68K.�",
		":PlugIns:imgmodules.CFM68K.�",
		":PlugIns:toolboxmodules.CFM68K.�",
		":PlugIns:qtmodules.CFM68K.�",
		":PlugIns:waste.CFM68K.�",
		":PlugIns:_tkinter.CFM68K.�",
	])
]
M68K_INSTRUCTIONS=[
	(buildmwproject, "CWIE", [
		":build.mac68k.stand:Python68K.�",
	])
]
PPCSTAND_INSTRUCTIONS=[
	(buildmwproject, "CWIE", [
		":build.macppc.stand:PythonStandalone.�",
	])
]
APPLET_INSTRUCTIONS=[
	(buildapplet, None, [
		":Mac:scripts:EditPythonPrefs.py",
		":Mac:scripts:mkapplet.py",
		":Mac:scripts:MkPluginAliases.py"
	])
]

ALLINST=[
	("PPC shared executable", PPC_INSTRUCTIONS),
	("PPC plugin modules", PLUGIN_INSTRUCTIONS),
	("CFM68K shared executable", CFM68K_INSTRUCTIONS),
	("CFM68K plugin modules", CFM68KPLUGIN_INSTRUCTIONS),
	("FAT shared executables", FAT_INSTRUCTIONS),
	("68K standalone executable", M68K_INSTRUCTIONS),
	("PPC standalone executable", PPCSTAND_INSTRUCTIONS),
	("Applets", APPLET_INSTRUCTIONS)
]
				
def main():
	dir, ok = macfs.GetDirectory('Python source folder:')
	if not ok:
		sys.exit(0)
	dir = dir.as_pathname()
	INSTRUCTIONS = []
	for string, inst in ALLINST:
		answer = EasyDialogs.AskYesNoCancel("Build %s?"%string, 1)
		if answer < 0:
			sys.exit(0)
		if answer:
			INSTRUCTIONS = INSTRUCTIONS + inst
	for routine, arg, list in INSTRUCTIONS:
		routine(dir, arg, list)
	print "All done!"
	sys.exit(1)	
	
if __name__ == '__main__':
	main()
	
