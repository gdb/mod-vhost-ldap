# Scan an Apple header file, generating a Python file of generator calls.

import addpack
addpack.addpack(':tools:bgen:bgen')
from scantools import Scanner

LONG = "Components"
SHORT = "Cm"

def main():
	input = "Components.h"
	output = SHORT + "gen.py"
	defsoutput = LONG + ".py"
	scanner = MyScanner(input, output, defsoutput)
	scanner.scan()
	scanner.close()
	print "=== Done scanning and generating, now importing the generated code... ==="
	exec "import " + SHORT + "support"
	print "=== Done.  It's up to you to compile it now! ==="

class MyScanner(Scanner):

	def destination(self, type, name, arglist):
		classname = "Function"
		listname = "functions"
		if arglist:
			t, n, m = arglist[0]
			#
			# FindNextComponent is a special case, since it call also be called
			# with None as the argument. Hence, we make it a function
			#
			if t == "Component" and m == "InMode" and name != "FindNextComponent":
				classname = "Method"
				listname = "c_methods"
			elif t == "ComponentInstance" and m == "InMode":
				classname = "Method"
				listname = "ci_methods"
		return classname, listname

	def makeblacklistnames(self):
		return [
			# "GetComponentInfo"  # XXXX I dont know how the Handle args are expected...
			]

	def makeblacklisttypes(self):
		return [
			"ResourceSpec",
			"ComponentResource",
			"ComponentPlatformInfo",
			"ComponentResourceExtension",
			"ComponentPlatformInfoArray",
			"ExtComponentResource",
			"ComponentParameters",
			
			"ComponentRoutineUPP",
			]

	def makerepairinstructions(self):
		return [
			([('ComponentDescription', 'looking', 'OutMode')],
			 [('ComponentDescription', '*', 'InMode')]),
			]
			
if __name__ == "__main__":
	main()
