# This script generates a Python interface for an Apple Macintosh Manager.
# It uses the "bgen" package to generate C code.
# The function specifications are generated by scanning the mamager's header file,
# using the "scantools" package (customized for this particular manager).

import string

# Declarations that change for each manager
MACHEADERFILE = 'Controls.h'		# The Apple header file
MODNAME = 'Ctl'				# The name of the module
OBJECTNAME = 'Control'			# The basic name of the objects used here

# The following is *usually* unchanged but may still require tuning
MODPREFIX = MODNAME			# The prefix for module-wide routines
OBJECTTYPE = OBJECTNAME + 'Handle'	# The C type used to represent them
OBJECTPREFIX = MODPREFIX + 'Obj'	# The prefix for object methods
INPUTFILE = string.lower(MODPREFIX) + 'gen.py' # The file generated by the scanner
OUTPUTFILE = MODNAME + "module.c"	# The file generated by this program

from macsupport import *

# Create the type objects

ControlHandle = OpaqueByValueType(OBJECTTYPE, OBJECTPREFIX)
ControlRef = ControlHandle
ExistingControlHandle = OpaqueByValueType(OBJECTTYPE, "CtlObj_WhichControl", "BUG")

RgnHandle = OpaqueByValueType("RgnHandle", "ResObj")
CCTabHandle = OpaqueByValueType("CCTabHandle", "ResObj")
AuxCtlHandle = OpaqueByValueType("AuxCtlHandle", "ResObj")
ControlPartCode = Type("ControlPartCode", "h")
DragConstraint = Type("DragConstraint", "h")
ControlVariant = Type("ControlVariant", "h")
IconTransformType = Type("IconTransformType", "h")
ControlButtonGraphicAlignment = Type("ControlButtonGraphicAlignment", "h")
ControlButtonTextAlignment = Type("ControlButtonTextAlignment", "h")
ControlButtonTextPlacement = Type("ControlButtonTextPlacement", "h")
ControlContentType = Type("ControlContentType", "h")
ControlFocusPart = Type("ControlFocusPart", "h")

ControlFontStyleRec = OpaqueType('ControlFontStyleRec', 'ControlFontStyle')
ControlFontStyleRec_ptr = ControlFontStyleRec

includestuff = includestuff + """
#include <%s>""" % MACHEADERFILE + """

#define as_Control(h) ((ControlHandle)h)
#define as_Resource(ctl) ((Handle)ctl)

#define resNotFound -192 /* Can't include <Errors.h> because of Python's "errors.h" */

extern PyObject *CtlObj_WhichControl(ControlHandle); /* Forward */
extern PyObject *QdRGB_New(RGBColorPtr);
extern QdRGB_Convert(PyObject *, RGBColorPtr);

#ifdef THINK_C
#define  ControlActionUPP ProcPtr
#endif

/*
** Parse/generate ControlFontStyleRec records
*/
#if 0 /* Not needed */
PyObject *ControlFontStyle_New(itself)
	ControlFontStyleRec *itself;
{

	return Py_BuildValue("hhhhhhO&O&", itself->flags, itself->font,
		itself->size, itself->style, itself->mode, itself->just,
		QdRGB_New, &itself->foreColor, QdRGB_New, &itself->backColor);
}
#endif

ControlFontStyle_Convert(v, itself)
	PyObject *v;
	ControlFontStyleRec *itself;
{
	return PyArg_ParseTuple(v, "hhhhhhO&O&", &itself->flags,
		&itself->font, &itself->size, &itself->style, &itself->mode,
		&itself->just, QdRGB_Convert, &itself->foreColor,
		QdRGB_Convert, &itself->backColor);
}

/* TrackControl and HandleControlClick callback support */
static PyObject *tracker;
static ControlActionUPP mytracker_upp;

extern int settrackfunc(PyObject *); 	/* forward */
extern void clrtrackfunc(void);	/* forward */
"""

finalstuff = finalstuff + """
PyObject *CtlObj_NewUnmanaged(itself)
	ControlHandle itself;
{
	ControlObject *it;
	if (itself == NULL) return PyMac_Error(resNotFound);
	it = PyObject_NEW(ControlObject, &Control_Type);
	if (it == NULL) return NULL;
	it->ob_itself = itself;
	return (PyObject *)it;
}

PyObject *
CtlObj_WhichControl(ControlHandle c)
{
	PyObject *it;

	if (c == NULL)
		it = Py_None;
	else {
		it = (PyObject *) GetControlReference(c);
		/*
		** If the refcon is zero or doesn't point back to the Python object
		** the control is not ours. Return a temporary object.
		*/
		if (it == NULL || ((ControlObject *)it)->ob_itself != c)
			return CtlObj_NewUnmanaged(c);
	}
	Py_INCREF(it);
	return it;
}

static int
settrackfunc(obj)
	PyObject *obj;
{
	if (tracker) {
		PyErr_SetString(Ctl_Error, "Tracker function in use");
		return 0;
	}
	tracker = obj;
	Py_INCREF(tracker);
}

static void
clrtrackfunc()
{
	Py_XDECREF(tracker);
	tracker = 0;
}

static pascal void
mytracker(ctl, part)
	ControlHandle ctl;
	short part;
{
	PyObject *args, *rv=0;

	args = Py_BuildValue("(O&i)", CtlObj_WhichControl, ctl, (int)part);
	if (args && tracker) {
		rv = PyEval_CallObject(tracker, args);
		Py_DECREF(args);
	}
	if (rv)
		Py_DECREF(rv);
	else
		PySys_WriteStderr("TrackControl or HandleControlClick: exception in tracker function\\n");
}
"""

initstuff = initstuff + """
mytracker_upp = NewControlActionProc(mytracker);
"""

class MyObjectDefinition(ObjectIdentityMixin, GlobalObjectDefinition):
	def outputCheckNewArg(self):
		Output("if (itself == NULL) return PyMac_Error(resNotFound);")
	def outputInitStructMembers(self):
		GlobalObjectDefinition.outputInitStructMembers(self)
		Output("SetControlReference(itself, (long)it);")
	def outputCleanupStructMembers(self):
		Output("if (self->ob_itself)SetControlReference(self->ob_itself, (long)0); /* Make it forget about us */")

# Create the generator groups and link them
module = MacModule(MODNAME, MODPREFIX, includestuff, finalstuff, initstuff)
object = MyObjectDefinition(OBJECTNAME, OBJECTPREFIX, OBJECTTYPE)
module.addobject(object)

# Create the generator classes used to populate the lists
Function = OSErrFunctionGenerator
Method = OSErrMethodGenerator

# Create and populate the lists
functions = []
methods = []
execfile(INPUTFILE)
execfile('ctledit.py')

# add the populated lists to the generator groups
for f in functions: module.add(f)
for f in methods: object.add(f)

# Manual generator for TrackControl, due to callback ideosyncracies
trackcontrol_body = """
ControlPartCode _rv;
Point startPoint;
ControlActionUPP upp = 0;
PyObject *callback = 0;

if (!PyArg_ParseTuple(_args, "O&|O",
                      PyMac_GetPoint, &startPoint, &callback))
	return NULL;
if (callback && callback != Py_None) {
	if (PyInt_Check(callback) && PyInt_AS_LONG(callback) == -1)
		upp = (ControlActionUPP)-1;
	else {
		settrackfunc(callback);
		upp = mytracker_upp;
	}
}
_rv = TrackControl(_self->ob_itself,
                   startPoint,
                   upp);
clrtrackfunc();
_res = Py_BuildValue("h",
                     _rv);
return _res;
"""

f = ManualGenerator("TrackControl", trackcontrol_body);
f.docstring = lambda: "(Point startPoint [,trackercallback]) -> (ControlPartCode _rv)"
object.add(f)

# CJW - added 5/12/99
# Manual generator for HandleControlClick, as for TrackControl
handlecontrolclick_body = """
ControlPartCode _rv;
Point startPoint;
SInt16 modifiers;
ControlActionUPP upp = 0;
PyObject *callback = 0;

if (!PyArg_ParseTuple(_args, "O&h|O",
                      PyMac_GetPoint, &startPoint,
                      &modifiers,
                      &callback))
	return NULL;
if (callback && callback != Py_None) {
	if (PyInt_Check(callback) && PyInt_AS_LONG(callback) == -1)
		upp = (ControlActionUPP)-1;
	else {
		settrackfunc(callback);
		upp = mytracker_upp;
	}
}
_rv = HandleControlClick(_self->ob_itself,
                   startPoint,
                   modifiers,
                   upp);
clrtrackfunc();
_res = Py_BuildValue("h",
                     _rv);
return _res;
"""

f = ManualGenerator("HandleControlClick", handlecontrolclick_body);
f.docstring = lambda: "(Point startPoint, Integer modifiers, [,trackercallback]) -> (ControlPartCode _rv)"
object.add(f)

# Manual Generator for SetControlData
setcontroldata_body = """
OSErr _err;
ControlPartCode inPart;
ResType inTagName;
Size bufferSize;
Ptr buffer;

if (!PyArg_ParseTuple(_args, "hO&s#",
                      &inPart,
                      PyMac_GetOSType, &inTagName,
                      &buffer, &bufferSize))
	return NULL;

_err = SetControlData(_self->ob_itself,
	              inPart,
	              inTagName,
	              bufferSize,
                      buffer);

if (_err != noErr)
	return PyMac_Error(_err);
_res = Py_None;
return _res;
"""

f = ManualGenerator("SetControlData", setcontroldata_body);
f.docstring = lambda: "(stuff) -> None"
object.add(f)

# Manual Generator for GetControlData
getcontroldata_body = """
OSErr _err;
ControlPartCode inPart;
ResType inTagName;
Size bufferSize;
Ptr buffer;
Size outSize;

if (!PyArg_ParseTuple(_args, "hO&",
                      &inPart,
                      PyMac_GetOSType, &inTagName))
	return NULL;

/* allocate a buffer for the data */
_err = GetControlDataSize(_self->ob_itself,
	                  inPart,
	                  inTagName,
                          &bufferSize);
if (_err != noErr)
	return PyMac_Error(_err);
buffer = PyMem_NEW(char, bufferSize);
if (buffer == NULL)
	return PyErr_NoMemory();

_err = GetControlData(_self->ob_itself,
	              inPart,
	              inTagName,
	              bufferSize,
                      buffer,
                      &outSize);

if (_err != noErr) {
	PyMem_DEL(buffer);
	return PyMac_Error(_err);
}
_res = Py_BuildValue("s#", buffer, outSize);
PyMem_DEL(buffer);
return _res;
"""

f = ManualGenerator("GetControlData", getcontroldata_body);
f.docstring = lambda: "(part, type) -> String"
object.add(f)

# Manual Generator for SetControlDataHandle
setcontroldatahandle_body = """
OSErr _err;
ControlPartCode inPart;
ResType inTagName;
Handle buffer;

if (!PyArg_ParseTuple(_args, "hO&O&",
                      &inPart,
                      PyMac_GetOSType, &inTagName,
                      OptResObj_Convert, buffer))
	return NULL;

_err = SetControlData(_self->ob_itself,
	              inPart,
	              inTagName,
	              sizeof(buffer),
                      (Ptr)buffer);

if (_err != noErr)
	return PyMac_Error(_err);
_res = Py_None;
return _res;
"""

f = ManualGenerator("SetControlDataHandle", setcontroldatahandle_body);
f.docstring = lambda: "(ResObj) -> None"
object.add(f)

# Manual Generator for GetControlDataHandle
getcontroldatahandle_body = """
OSErr _err;
ControlPartCode inPart;
ResType inTagName;
Size bufferSize;
Handle hdl;

if (!PyArg_ParseTuple(_args, "hO&",
                      &inPart,
                      PyMac_GetOSType, &inTagName))
	return NULL;

/* Check it is handle-sized */
_err = GetControlDataSize(_self->ob_itself,
	                  inPart,
	                  inTagName,
                          &bufferSize);
if (_err != noErr)
	return PyMac_Error(_err);
if (bufferSize != sizeof(Handle)) {
	PyErr_SetString(Ctl_Error, "GetControlDataSize() != sizeof(Handle)");
	return NULL;
}

_err = GetControlData(_self->ob_itself,
	              inPart,
	              inTagName,
	              sizeof(Handle),
                      (Ptr)&hdl,
                      &bufferSize);

if (_err != noErr) {
	return PyMac_Error(_err);
}
return Py_BuildValue("O&", OptResObj_New, hdl);
"""

f = ManualGenerator("GetControlDataHandle", getcontroldatahandle_body);
f.docstring = lambda: "(part, type) -> ResObj"
object.add(f)

# And manual generators to get/set popup menu information
getpopupdata_body = """
PopupPrivateDataHandle hdl;

if ( (*_self->ob_itself)->contrlData == NULL ) {
	PyErr_SetString(Ctl_Error, "No contrlData handle in control");
	return 0;
}
hdl = (PopupPrivateDataHandle)(*_self->ob_itself)->contrlData;
HLock((Handle)hdl);
_res = Py_BuildValue("O&i", MenuObj_New, (*hdl)->mHandle, (int)(*hdl)->mID);
HUnlock((Handle)hdl);
return _res;
"""
f = ManualGenerator("GetPopupData", getpopupdata_body)
object.add(f)

setpopupdata_body = """
PopupPrivateDataHandle hdl;
MenuHandle mHandle;
short mID;

if (!PyArg_ParseTuple(_args, "O&h", MenuObj_Convert, &mHandle, &mID) )
	return 0;
if ( (*_self->ob_itself)->contrlData == NULL ) {
	PyErr_SetString(Ctl_Error, "No contrlData handle in control");
	return 0;
}
hdl = (PopupPrivateDataHandle)(*_self->ob_itself)->contrlData;
(*hdl)->mHandle = mHandle;
(*hdl)->mID = mID;
Py_INCREF(Py_None);
return Py_None;
"""
f = ManualGenerator("SetPopupData", setpopupdata_body)
object.add(f)


# generate output (open the output file as late as possible)
SetOutputFileName(OUTPUTFILE)
module.generate()
