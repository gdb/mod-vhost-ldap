# This script generates the Dialogs interface for Python.
# It uses the "bgen" package to generate C code.
# It execs the file dlggen.py which contain the function definitions
# (dlggen.py was generated by dlgscan.py, scanning the <Dialogs.h> header file).

from macsupport import *

# Create the type objects

DialogPtr = OpaqueByValueType("DialogPtr", "DlgObj")
DialogRef = DialogPtr

# An OptHandle is either a handle or None (in case NULL is passed in).
# This is needed for GetDialogItem().
OptHandle = OpaqueByValueType("Handle", "OptResObj")

ModalFilterProcPtr = InputOnlyType("PyObject*", "O")
ModalFilterProcPtr.passInput = lambda name: "NewModalFilterProc(Dlg_PassFilterProc(%s))" % name
ModalFilterUPP = ModalFilterProcPtr

RgnHandle = OpaqueByValueType("RgnHandle", "ResObj")

DITLMethod = Type("DITLMethod", "h")
DialogItemIndex = Type("DialogItemIndex", "h")
DialogItemType = Type("DialogItemType", "h")
DialogItemIndexZeroBased = Type("DialogItemIndexZeroBased", "h")
AlertType = Type("AlertType", "h")
StringPtr = Str255
EventMask = Type("EventMask", "h")

includestuff = includestuff + """
#include <Dialogs.h>

#ifndef HAVE_UNIVERSAL_HEADERS
#define NewModalFilterProc(x) (x)
#endif

#define resNotFound -192 /* Can't include <Errors.h> because of Python's "errors.h" */

/* XXX Shouldn't this be a stack? */
static PyObject *Dlg_FilterProc_callback = NULL;

static PyObject *DlgObj_New(DialogPtr); /* Forward */

static pascal Boolean Dlg_UnivFilterProc(DialogPtr dialog,
                                         EventRecord *event,
                                         short *itemHit)
{
	Boolean rv;
	PyObject *args, *res;
	PyObject *callback = Dlg_FilterProc_callback;
	if (callback == NULL)
		return 0; /* Default behavior */
	Dlg_FilterProc_callback = NULL; /* We'll restore it when call successful */
	args = Py_BuildValue("O&O&", WinObj_WhichWindow, dialog, PyMac_BuildEventRecord, event);
	if (args == NULL)
		res = NULL;
	else {
		res = PyEval_CallObject(callback, args);
		Py_DECREF(args);
	}
	if (res == NULL) {
		PySys_WriteStderr("Exception in Dialog Filter\\n");
		PyErr_Print();
		*itemHit = -1; /* Fake return item */
		return 1; /* We handled it */
	}
	else {
		Dlg_FilterProc_callback = callback;
		if (PyInt_Check(res)) {
			*itemHit = PyInt_AsLong(res);
			rv = 1;
		}
		else
			rv = PyObject_IsTrue(res);
	}
	Py_DECREF(res);
	return rv;
}

static ModalFilterProcPtr
Dlg_PassFilterProc(PyObject *callback)
{
	PyObject *tmp = Dlg_FilterProc_callback;
	Dlg_FilterProc_callback = NULL;
	if (callback == Py_None) {
		Py_XDECREF(tmp);
		return NULL;
	}
	Py_INCREF(callback);
	Dlg_FilterProc_callback = callback;
	Py_XDECREF(tmp);
	return &Dlg_UnivFilterProc;
}

static PyObject *Dlg_UserItemProc_callback = NULL;

static pascal void Dlg_UnivUserItemProc(DialogPtr dialog,
                                         short item)
{
	PyObject *args, *res;

	if (Dlg_UserItemProc_callback == NULL)
		return; /* Default behavior */
	Dlg_FilterProc_callback = NULL; /* We'll restore it when call successful */
	args = Py_BuildValue("O&h", WinObj_WhichWindow, dialog, item);
	if (args == NULL)
		res = NULL;
	else {
		res = PyEval_CallObject(Dlg_UserItemProc_callback, args);
		Py_DECREF(args);
	}
	if (res == NULL) {
		PySys_WriteStderr("Exception in Dialog UserItem proc\\n");
		PyErr_Print();
	}
	Py_XDECREF(res);
	return;
}

extern PyMethodChain WinObj_chain;
"""


# Define a class which specializes our object definition
class MyObjectDefinition(GlobalObjectDefinition):
	def __init__(self, name, prefix = None, itselftype = None):
		GlobalObjectDefinition.__init__(self, name, prefix, itselftype)
		self.basechain = "&WinObj_chain"
	def outputInitStructMembers(self):
		GlobalObjectDefinition.outputInitStructMembers(self)
		Output("SetWRefCon(itself, (long)it);")
	def outputCheckNewArg(self):
		Output("if (itself == NULL) return Py_None;")
	def outputCheckConvertArg(self):
		Output("if (v == Py_None) { *p_itself = NULL; return 1; }")
		Output("if (PyInt_Check(v)) { *p_itself = (DialogPtr)PyInt_AsLong(v);")
		Output("                      return 1; }")
	def outputFreeIt(self, itselfname):
		Output("DisposeDialog(%s);", itselfname)

# Create the generator groups and link them
module = MacModule('Dlg', 'Dlg', includestuff, finalstuff, initstuff)
object = MyObjectDefinition('Dialog', 'DlgObj', 'DialogPtr')
module.addobject(object)

# Create the generator classes used to populate the lists
Function = OSErrFunctionGenerator
Method = OSErrMethodGenerator

# Create and populate the lists
functions = []
methods = []
execfile("dlggen.py")

# add the populated lists to the generator groups
for f in functions: module.add(f)
for f in methods: object.add(f)

# Some methods that are currently macro's in C, but will be real routines
# in MacOS 8.

f = Method(ExistingDialogPtr, 'GetDialogWindow', (DialogRef, 'dialog', InMode))
object.add(f)
f = Method(SInt16, 'GetDialogDefaultItem', (DialogRef, 'dialog', InMode))
object.add(f)
f = Method(SInt16, 'GetDialogCancelItem', (DialogRef, 'dialog', InMode))
object.add(f)
f = Method(SInt16, 'GetDialogKeyboardFocusItem', (DialogRef, 'dialog', InMode))
object.add(f)
f = Method(void, 'SetGrafPortOfDialog', (DialogRef, 'dialog', InMode))
object.add(f)

setuseritembody = """
	PyObject *new = NULL;
	
	
	if (!PyArg_ParseTuple(_args, "|O", &new))
		return NULL;

	if (Dlg_UserItemProc_callback && new && new != Py_None) {
		PyErr_SetString(Dlg_Error, "Another UserItemProc is already installed");
		return NULL;
	}
	
	if (new == Py_None) {
		new = NULL;
		_res = Py_None;
		Py_INCREF(Py_None);
	} else {
		Py_INCREF(new);
		_res = Py_BuildValue("O&", ResObj_New, (Handle)NewUserItemProc(Dlg_UnivUserItemProc));
	}
	
	Dlg_UserItemProc_callback = new;
	return _res;
"""
f = ManualGenerator("SetUserItemHandler", setuseritembody)
module.add(f)

# generate output
SetOutputFileName('Dlgmodule.c')
module.generate()
