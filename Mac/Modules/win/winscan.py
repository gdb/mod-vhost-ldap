# Scan an Apple header file, generating a Python file of generator calls.
import sys
import os
BGENDIR=os.path.join(sys.prefix, ':Tools:bgen:bgen')
sys.path.append(BGENDIR)
from bgenlocations import TOOLBOXDIR

from scantools import Scanner

def main():
	input = "MacWindows.h"
	output = "wingen.py"
	defsoutput = TOOLBOXDIR + "Windows.py"
	scanner = MyScanner(input, output, defsoutput)
	scanner.scan()
	scanner.close()
	print "=== Done scanning and generating, now importing the generated code... ==="
	import winsupport
	print "=== Done.  It's up to you to compile it now! ==="

class MyScanner(Scanner):

	def destination(self, type, name, arglist):
		classname = "Function"
		listname = "functions"
		if arglist:
			t, n, m = arglist[0]
			if t in ("WindowPtr", "WindowPeek", "WindowRef") and m == "InMode":
				classname = "Method"
				listname = "methods"
		return classname, listname

	def writeinitialdefs(self):
		self.defsfile.write("def FOUR_CHAR_CODE(x): return x\n")

	def makeblacklistnames(self):
		return [
			'DisposeWindow', # Implied when the object is deleted
			'CloseWindow',
			'SetWindowProperty',	# For the moment
			'GetWindowProperty',
			'GetWindowPropertySize',
			'RemoveWindowProperty',
			'MacCloseWindow',
			# Constants with funny definitions
			'kMouseUpOutOfSlop',
			]
			
	def makegreylist(self):
		return [
			('#ifndef TARGET_API_MAC_CARBON', [
				'GetAuxWin',
				'GetWindowDataHandle',
				'SaveOld',
				'DrawNew',
				'SetWinColor',
				'SetDeskCPat',
				'InitWindows',
				'InitFloatingWindows',
				'GetWMgrPort',
				'GetCWMgrPort',
				'ValidRgn',		# Use versions with Window in their name
				'ValidRect',
				'InvalRgn',
				'InvalRect',
				'IsValidWindowPtr', # I think this is useless for Python, but not sure...
			])]
			
	def makeblacklisttypes(self):
		return [
			'ProcPtr',
			'DragGrayRgnUPP',
			'Collection',		# For now, to be done later
			'DragReference',	# Ditto, dragmodule doesn't export it yet.
			]

	def makerepairinstructions(self):
		return [
			
			# GetWTitle
			([("Str255", "*", "InMode")],
			 [("*", "*", "OutMode")]),
			
			([("void_ptr", "*", "InMode"), ("long", "*", "InMode")],
			 [("InBuffer", "*", "*")]),
			
			([("void", "*", "OutMode"), ("long", "*", "InMode"),
			                            ("long", "*", "OutMode")],
			 [("VarVarOutBuffer", "*", "InOutMode")]),
			
			([("void", "wStorage", "OutMode")],
			 [("NullStorage", "*", "InMode")]),
			
			([("WindowPtr", "*", "OutMode")],
			 [("ExistingWindowPtr", "*", "*")]),
			([("WindowRef", "*", "OutMode")],	# Same, but other style headerfiles
			 [("ExistingWindowPtr", "*", "*")]),
			
			([("WindowPtr", "FrontWindow", "ReturnMode")],
			 [("ExistingWindowPtr", "*", "*")]),
			([("WindowRef", "FrontWindow", "ReturnMode")],	# Ditto
			 [("ExistingWindowPtr", "*", "*")]),
			]

if __name__ == "__main__":
	main()

