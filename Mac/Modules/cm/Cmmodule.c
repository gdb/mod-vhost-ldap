
/* =========================== Module Cm ============================ */

#include "Python.h"



#define SystemSevenOrLater 1

#include "macglue.h"
#include <Memory.h>
#include <Dialogs.h>
#include <Menus.h>
#include <Controls.h>

extern PyObject *ResObj_New(Handle);
extern PyObject *ResObj_OptNew(Handle);
extern int ResObj_Convert(PyObject *, Handle *);

extern PyObject *WinObj_New(WindowPtr);
extern int WinObj_Convert(PyObject *, WindowPtr *);
extern PyTypeObject Window_Type;
#define WinObj_Check(x) ((x)->ob_type == &Window_Type)

extern PyObject *DlgObj_New(DialogPtr);
extern int DlgObj_Convert(PyObject *, DialogPtr *);
extern PyTypeObject Dialog_Type;
#define DlgObj_Check(x) ((x)->ob_type == &Dialog_Type)

extern PyObject *MenuObj_New(MenuHandle);
extern int MenuObj_Convert(PyObject *, MenuHandle *);

extern PyObject *CtlObj_New(ControlHandle);
extern int CtlObj_Convert(PyObject *, ControlHandle *);

extern PyObject *GrafObj_New(GrafPtr);
extern int GrafObj_Convert(PyObject *, GrafPtr *);

extern PyObject *BMObj_New(BitMapPtr);
extern int BMObj_Convert(PyObject *, BitMapPtr *);

extern PyObject *WinObj_WhichWindow(WindowPtr);

#include <Components.h>

/*
** Parse/generate ComponentDescriptor records
*/
PyObject *CmpDesc_New(itself)
	ComponentDescription *itself;
{

	return Py_BuildValue("O&O&O&ll", 
		PyMac_BuildOSType, itself->componentType,
		PyMac_BuildOSType, itself->componentSubType,
		PyMac_BuildOSType, itself->componentManufacturer,
		itself->componentFlags, itself->componentFlagsMask);
}

CmpDesc_Convert(v, p_itself)
	PyObject *v;
	ComponentDescription *p_itself;
{
	return PyArg_ParseTuple(v, "O&O&O&ll",
		PyMac_GetOSType, &p_itself->componentType,
		PyMac_GetOSType, &p_itself->componentSubType,
		PyMac_GetOSType, &p_itself->componentManufacturer,
		&p_itself->componentFlags, &p_itself->componentFlagsMask);
}


static PyObject *Cm_Error;

/* ----------------- Object type ComponentInstance ------------------ */

PyTypeObject ComponentInstance_Type;

#define CmpInstObj_Check(x) ((x)->ob_type == &ComponentInstance_Type)

typedef struct ComponentInstanceObject {
	PyObject_HEAD
	ComponentInstance ob_itself;
} ComponentInstanceObject;

PyObject *CmpInstObj_New(itself)
	ComponentInstance itself;
{
	ComponentInstanceObject *it;
	if (itself == NULL) {
						PyErr_SetString(Cm_Error,"NULL ComponentInstance");
						return NULL;
					}
	it = PyObject_NEW(ComponentInstanceObject, &ComponentInstance_Type);
	if (it == NULL) return NULL;
	it->ob_itself = itself;
	return (PyObject *)it;
}
CmpInstObj_Convert(v, p_itself)
	PyObject *v;
	ComponentInstance *p_itself;
{
	if (!CmpInstObj_Check(v))
	{
		PyErr_SetString(PyExc_TypeError, "ComponentInstance required");
		return 0;
	}
	*p_itself = ((ComponentInstanceObject *)v)->ob_itself;
	return 1;
}

static void CmpInstObj_dealloc(self)
	ComponentInstanceObject *self;
{
	/* Cleanup of self->ob_itself goes here */
	PyMem_DEL(self);
}

static PyObject *CmpInstObj_CloseComponent(_self, _args)
	ComponentInstanceObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = CloseComponent(_self->ob_itself);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *CmpInstObj_GetComponentInstanceError(_self, _args)
	ComponentInstanceObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = GetComponentInstanceError(_self->ob_itself);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *CmpInstObj_ComponentFunctionImplemented(_self, _args)
	ComponentInstanceObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	short ftnNumber;
	if (!PyArg_ParseTuple(_args, "h",
	                      &ftnNumber))
		return NULL;
	_rv = ComponentFunctionImplemented(_self->ob_itself,
	                                   ftnNumber);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *CmpInstObj_GetComponentVersion(_self, _args)
	ComponentInstanceObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetComponentVersion(_self->ob_itself);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *CmpInstObj_ComponentSetTarget(_self, _args)
	ComponentInstanceObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	ComponentInstance target;
	if (!PyArg_ParseTuple(_args, "O&",
	                      CmpInstObj_Convert, &target))
		return NULL;
	_rv = ComponentSetTarget(_self->ob_itself,
	                         target);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *CmpInstObj_SetComponentInstanceError(_self, _args)
	ComponentInstanceObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr theError;
	if (!PyArg_ParseTuple(_args, "h",
	                      &theError))
		return NULL;
	SetComponentInstanceError(_self->ob_itself,
	                          theError);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *CmpInstObj_GetComponentInstanceStorage(_self, _args)
	ComponentInstanceObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Handle _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetComponentInstanceStorage(_self->ob_itself);
	_res = Py_BuildValue("O&",
	                     ResObj_New, _rv);
	return _res;
}

static PyObject *CmpInstObj_SetComponentInstanceStorage(_self, _args)
	ComponentInstanceObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Handle theStorage;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &theStorage))
		return NULL;
	SetComponentInstanceStorage(_self->ob_itself,
	                            theStorage);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *CmpInstObj_GetComponentInstanceA5(_self, _args)
	ComponentInstanceObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetComponentInstanceA5(_self->ob_itself);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *CmpInstObj_SetComponentInstanceA5(_self, _args)
	ComponentInstanceObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long theA5;
	if (!PyArg_ParseTuple(_args, "l",
	                      &theA5))
		return NULL;
	SetComponentInstanceA5(_self->ob_itself,
	                       theA5);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyMethodDef CmpInstObj_methods[] = {
	{"CloseComponent", (PyCFunction)CmpInstObj_CloseComponent, 1,
	 "() -> None"},
	{"GetComponentInstanceError", (PyCFunction)CmpInstObj_GetComponentInstanceError, 1,
	 "() -> None"},
	{"ComponentFunctionImplemented", (PyCFunction)CmpInstObj_ComponentFunctionImplemented, 1,
	 "(short ftnNumber) -> (long _rv)"},
	{"GetComponentVersion", (PyCFunction)CmpInstObj_GetComponentVersion, 1,
	 "() -> (long _rv)"},
	{"ComponentSetTarget", (PyCFunction)CmpInstObj_ComponentSetTarget, 1,
	 "(ComponentInstance target) -> (long _rv)"},
	{"SetComponentInstanceError", (PyCFunction)CmpInstObj_SetComponentInstanceError, 1,
	 "(OSErr theError) -> None"},
	{"GetComponentInstanceStorage", (PyCFunction)CmpInstObj_GetComponentInstanceStorage, 1,
	 "() -> (Handle _rv)"},
	{"SetComponentInstanceStorage", (PyCFunction)CmpInstObj_SetComponentInstanceStorage, 1,
	 "(Handle theStorage) -> None"},
	{"GetComponentInstanceA5", (PyCFunction)CmpInstObj_GetComponentInstanceA5, 1,
	 "() -> (long _rv)"},
	{"SetComponentInstanceA5", (PyCFunction)CmpInstObj_SetComponentInstanceA5, 1,
	 "(long theA5) -> None"},
	{NULL, NULL, 0}
};

PyMethodChain CmpInstObj_chain = { CmpInstObj_methods, NULL };

static PyObject *CmpInstObj_getattr(self, name)
	ComponentInstanceObject *self;
	char *name;
{
	return Py_FindMethodInChain(&CmpInstObj_chain, (PyObject *)self, name);
}

#define CmpInstObj_setattr NULL

PyTypeObject ComponentInstance_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0, /*ob_size*/
	"ComponentInstance", /*tp_name*/
	sizeof(ComponentInstanceObject), /*tp_basicsize*/
	0, /*tp_itemsize*/
	/* methods */
	(destructor) CmpInstObj_dealloc, /*tp_dealloc*/
	0, /*tp_print*/
	(getattrfunc) CmpInstObj_getattr, /*tp_getattr*/
	(setattrfunc) CmpInstObj_setattr, /*tp_setattr*/
};

/* --------------- End object type ComponentInstance ---------------- */


/* --------------------- Object type Component ---------------------- */

PyTypeObject Component_Type;

#define CmpObj_Check(x) ((x)->ob_type == &Component_Type)

typedef struct ComponentObject {
	PyObject_HEAD
	Component ob_itself;
} ComponentObject;

PyObject *CmpObj_New(itself)
	Component itself;
{
	ComponentObject *it;
	if (itself == NULL) {
						/* XXXX Or should we return None? */
						PyErr_SetString(Cm_Error,"No such component");
						return NULL;
					}
	it = PyObject_NEW(ComponentObject, &Component_Type);
	if (it == NULL) return NULL;
	it->ob_itself = itself;
	return (PyObject *)it;
}
CmpObj_Convert(v, p_itself)
	PyObject *v;
	Component *p_itself;
{
	if ( v == Py_None ) {
						*p_itself = 0;
						return 1;
			}
	if (!CmpObj_Check(v))
	{
		PyErr_SetString(PyExc_TypeError, "Component required");
		return 0;
	}
	*p_itself = ((ComponentObject *)v)->ob_itself;
	return 1;
}

static void CmpObj_dealloc(self)
	ComponentObject *self;
{
	/* Cleanup of self->ob_itself goes here */
	PyMem_DEL(self);
}

static PyObject *CmpObj_UnregisterComponent(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = UnregisterComponent(_self->ob_itself);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *CmpObj_GetComponentInfo(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	ComponentDescription cd;
	Handle componentName;
	Handle componentInfo;
	Handle componentIcon;
	if (!PyArg_ParseTuple(_args, "O&O&O&",
	                      ResObj_Convert, &componentName,
	                      ResObj_Convert, &componentInfo,
	                      ResObj_Convert, &componentIcon))
		return NULL;
	_err = GetComponentInfo(_self->ob_itself,
	                        &cd,
	                        componentName,
	                        componentInfo,
	                        componentIcon);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&",
	                     CmpDesc_New, &cd);
	return _res;
}

static PyObject *CmpObj_OpenComponent(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	ComponentInstance _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = OpenComponent(_self->ob_itself);
	_res = Py_BuildValue("O&",
	                     CmpInstObj_New, _rv);
	return _res;
}

static PyObject *CmpObj_GetComponentRefcon(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetComponentRefcon(_self->ob_itself);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *CmpObj_SetComponentRefcon(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long theRefcon;
	if (!PyArg_ParseTuple(_args, "l",
	                      &theRefcon))
		return NULL;
	SetComponentRefcon(_self->ob_itself,
	                   theRefcon);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *CmpObj_OpenComponentResFile(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = OpenComponentResFile(_self->ob_itself);
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *CmpObj_CountComponentInstances(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = CountComponentInstances(_self->ob_itself);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *CmpObj_SetDefaultComponent(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	short flags;
	if (!PyArg_ParseTuple(_args, "h",
	                      &flags))
		return NULL;
	_err = SetDefaultComponent(_self->ob_itself,
	                           flags);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *CmpObj_CaptureComponent(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Component _rv;
	Component capturingComponent;
	if (!PyArg_ParseTuple(_args, "O&",
	                      CmpObj_Convert, &capturingComponent))
		return NULL;
	_rv = CaptureComponent(_self->ob_itself,
	                       capturingComponent);
	_res = Py_BuildValue("O&",
	                     CmpObj_New, _rv);
	return _res;
}

static PyObject *CmpObj_UncaptureComponent(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = UncaptureComponent(_self->ob_itself);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *CmpObj_GetComponentIconSuite(_self, _args)
	ComponentObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	Handle iconSuite;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = GetComponentIconSuite(_self->ob_itself,
	                             &iconSuite);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&",
	                     ResObj_New, iconSuite);
	return _res;
}

static PyMethodDef CmpObj_methods[] = {
	{"UnregisterComponent", (PyCFunction)CmpObj_UnregisterComponent, 1,
	 "() -> None"},
	{"GetComponentInfo", (PyCFunction)CmpObj_GetComponentInfo, 1,
	 "(Handle componentName, Handle componentInfo, Handle componentIcon) -> (ComponentDescription cd)"},
	{"OpenComponent", (PyCFunction)CmpObj_OpenComponent, 1,
	 "() -> (ComponentInstance _rv)"},
	{"GetComponentRefcon", (PyCFunction)CmpObj_GetComponentRefcon, 1,
	 "() -> (long _rv)"},
	{"SetComponentRefcon", (PyCFunction)CmpObj_SetComponentRefcon, 1,
	 "(long theRefcon) -> None"},
	{"OpenComponentResFile", (PyCFunction)CmpObj_OpenComponentResFile, 1,
	 "() -> (short _rv)"},
	{"CountComponentInstances", (PyCFunction)CmpObj_CountComponentInstances, 1,
	 "() -> (long _rv)"},
	{"SetDefaultComponent", (PyCFunction)CmpObj_SetDefaultComponent, 1,
	 "(short flags) -> None"},
	{"CaptureComponent", (PyCFunction)CmpObj_CaptureComponent, 1,
	 "(Component capturingComponent) -> (Component _rv)"},
	{"UncaptureComponent", (PyCFunction)CmpObj_UncaptureComponent, 1,
	 "() -> None"},
	{"GetComponentIconSuite", (PyCFunction)CmpObj_GetComponentIconSuite, 1,
	 "() -> (Handle iconSuite)"},
	{NULL, NULL, 0}
};

PyMethodChain CmpObj_chain = { CmpObj_methods, NULL };

static PyObject *CmpObj_getattr(self, name)
	ComponentObject *self;
	char *name;
{
	return Py_FindMethodInChain(&CmpObj_chain, (PyObject *)self, name);
}

#define CmpObj_setattr NULL

PyTypeObject Component_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0, /*ob_size*/
	"Component", /*tp_name*/
	sizeof(ComponentObject), /*tp_basicsize*/
	0, /*tp_itemsize*/
	/* methods */
	(destructor) CmpObj_dealloc, /*tp_dealloc*/
	0, /*tp_print*/
	(getattrfunc) CmpObj_getattr, /*tp_getattr*/
	(setattrfunc) CmpObj_setattr, /*tp_setattr*/
};

/* ------------------- End object type Component -------------------- */


static PyObject *Cm_RegisterComponentResource(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Component _rv;
	ComponentResourceHandle tr;
	short global;
	if (!PyArg_ParseTuple(_args, "O&h",
	                      ResObj_Convert, &tr,
	                      &global))
		return NULL;
	_rv = RegisterComponentResource(tr,
	                                global);
	_res = Py_BuildValue("O&",
	                     CmpObj_New, _rv);
	return _res;
}

static PyObject *Cm_FindNextComponent(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Component _rv;
	Component aComponent;
	ComponentDescription looking;
	if (!PyArg_ParseTuple(_args, "O&O&",
	                      CmpObj_Convert, &aComponent,
	                      CmpDesc_Convert, &looking))
		return NULL;
	_rv = FindNextComponent(aComponent,
	                        &looking);
	_res = Py_BuildValue("O&",
	                     CmpObj_New, _rv);
	return _res;
}

static PyObject *Cm_CountComponents(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	ComponentDescription looking;
	if (!PyArg_ParseTuple(_args, "O&",
	                      CmpDesc_Convert, &looking))
		return NULL;
	_rv = CountComponents(&looking);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *Cm_GetComponentListModSeed(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetComponentListModSeed();
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *Cm_CloseComponentResFile(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	short refnum;
	if (!PyArg_ParseTuple(_args, "h",
	                      &refnum))
		return NULL;
	_err = CloseComponentResFile(refnum);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Cm_OpenDefaultComponent(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	ComponentInstance _rv;
	OSType componentType;
	OSType componentSubType;
	if (!PyArg_ParseTuple(_args, "O&O&",
	                      PyMac_GetOSType, &componentType,
	                      PyMac_GetOSType, &componentSubType))
		return NULL;
	_rv = OpenDefaultComponent(componentType,
	                           componentSubType);
	_res = Py_BuildValue("O&",
	                     CmpInstObj_New, _rv);
	return _res;
}

static PyObject *Cm_RegisterComponentResourceFile(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	short resRefNum;
	short global;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &resRefNum,
	                      &global))
		return NULL;
	_rv = RegisterComponentResourceFile(resRefNum,
	                                    global);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyMethodDef Cm_methods[] = {
	{"RegisterComponentResource", (PyCFunction)Cm_RegisterComponentResource, 1,
	 "(ComponentResourceHandle tr, short global) -> (Component _rv)"},
	{"FindNextComponent", (PyCFunction)Cm_FindNextComponent, 1,
	 "(Component aComponent, ComponentDescription looking) -> (Component _rv)"},
	{"CountComponents", (PyCFunction)Cm_CountComponents, 1,
	 "(ComponentDescription looking) -> (long _rv)"},
	{"GetComponentListModSeed", (PyCFunction)Cm_GetComponentListModSeed, 1,
	 "() -> (long _rv)"},
	{"CloseComponentResFile", (PyCFunction)Cm_CloseComponentResFile, 1,
	 "(short refnum) -> None"},
	{"OpenDefaultComponent", (PyCFunction)Cm_OpenDefaultComponent, 1,
	 "(OSType componentType, OSType componentSubType) -> (ComponentInstance _rv)"},
	{"RegisterComponentResourceFile", (PyCFunction)Cm_RegisterComponentResourceFile, 1,
	 "(short resRefNum, short global) -> (long _rv)"},
	{NULL, NULL, 0}
};




void initCm()
{
	PyObject *m;
	PyObject *d;




	m = Py_InitModule("Cm", Cm_methods);
	d = PyModule_GetDict(m);
	Cm_Error = PyMac_GetOSErrException();
	if (Cm_Error == NULL ||
	    PyDict_SetItemString(d, "Error", Cm_Error) != 0)
		Py_FatalError("can't initialize Cm.Error");
}

/* ========================= End module Cm ========================== */

