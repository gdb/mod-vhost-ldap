
/* ========================= Module Qdoffs ========================== */

#include "Python.h"



#define SystemSevenOrLater 1

#include "macglue.h"
#include <Memory.h>
#include <Dialogs.h>
#include <Menus.h>
#include <Controls.h>

extern PyObject *ResObj_New(Handle);
extern int ResObj_Convert(PyObject *, Handle *);
extern PyObject *OptResObj_New(Handle);
extern int OptResObj_Convert(PyObject *, Handle *);

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

#include <QDOffscreen.h>

#define resNotFound -192 /* Can't include <Errors.h> because of Python's "errors.h" */


static PyObject *Qdoffs_Error;

/* ----------------------- Object type GWorld ----------------------- */

PyTypeObject GWorld_Type;

#define GWorldObj_Check(x) ((x)->ob_type == &GWorld_Type)

typedef struct GWorldObject {
	PyObject_HEAD
	GWorldPtr ob_itself;
} GWorldObject;

PyObject *GWorldObj_New(itself)
	GWorldPtr itself;
{
	GWorldObject *it;
	if (itself == NULL) return PyMac_Error(resNotFound);
	it = PyObject_NEW(GWorldObject, &GWorld_Type);
	if (it == NULL) return NULL;
	it->ob_itself = itself;
	return (PyObject *)it;
}
GWorldObj_Convert(v, p_itself)
	PyObject *v;
	GWorldPtr *p_itself;
{
	if (!GWorldObj_Check(v))
	{
		PyErr_SetString(PyExc_TypeError, "GWorld required");
		return 0;
	}
	*p_itself = ((GWorldObject *)v)->ob_itself;
	return 1;
}

static void GWorldObj_dealloc(self)
	GWorldObject *self;
{
	DisposeGWorld(self->ob_itself);
	PyMem_DEL(self);
}

static PyObject *GWorldObj_GetGWorldDevice(_self, _args)
	GWorldObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	GDHandle _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetGWorldDevice(_self->ob_itself);
	_res = Py_BuildValue("O&",
	                     ResObj_New, _rv);
	return _res;
}

static PyObject *GWorldObj_GetGWorldPixMap(_self, _args)
	GWorldObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	PixMapHandle _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetGWorldPixMap(_self->ob_itself);
	_res = Py_BuildValue("O&",
	                     ResObj_New, _rv);
	return _res;
}

static PyMethodDef GWorldObj_methods[] = {
	{"GetGWorldDevice", (PyCFunction)GWorldObj_GetGWorldDevice, 1,
	 "() -> (GDHandle _rv)"},
	{"GetGWorldPixMap", (PyCFunction)GWorldObj_GetGWorldPixMap, 1,
	 "() -> (PixMapHandle _rv)"},
	{NULL, NULL, 0}
};

PyMethodChain GWorldObj_chain = { GWorldObj_methods, NULL };

static PyObject *GWorldObj_getattr(self, name)
	GWorldObject *self;
	char *name;
{
	return Py_FindMethodInChain(&GWorldObj_chain, (PyObject *)self, name);
}

#define GWorldObj_setattr NULL

PyTypeObject GWorld_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0, /*ob_size*/
	"GWorld", /*tp_name*/
	sizeof(GWorldObject), /*tp_basicsize*/
	0, /*tp_itemsize*/
	/* methods */
	(destructor) GWorldObj_dealloc, /*tp_dealloc*/
	0, /*tp_print*/
	(getattrfunc) GWorldObj_getattr, /*tp_getattr*/
	(setattrfunc) GWorldObj_setattr, /*tp_setattr*/
};

/* --------------------- End object type GWorld --------------------- */


static PyObject *Qdoffs_NewGWorld(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	QDErr _err;
	GWorldPtr offscreenGWorld;
	short PixelDepth;
	Rect boundsRect;
	CTabHandle cTable;
	GDHandle aGDevice;
	GWorldFlags flags;
	if (!PyArg_ParseTuple(_args, "hO&O&O&l",
	                      &PixelDepth,
	                      PyMac_GetRect, &boundsRect,
	                      OptResObj_Convert, &cTable,
	                      OptResObj_Convert, &aGDevice,
	                      &flags))
		return NULL;
	_err = NewGWorld(&offscreenGWorld,
	                 PixelDepth,
	                 &boundsRect,
	                 cTable,
	                 aGDevice,
	                 flags);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&",
	                     GWorldObj_New, offscreenGWorld);
	return _res;
}

static PyObject *Qdoffs_LockPixels(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	PixMapHandle pm;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &pm))
		return NULL;
	_rv = LockPixels(pm);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *Qdoffs_UnlockPixels(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	PixMapHandle pm;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &pm))
		return NULL;
	UnlockPixels(pm);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Qdoffs_UpdateGWorld(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	GWorldFlags _rv;
	GWorldPtr offscreenGWorld;
	short pixelDepth;
	Rect boundsRect;
	CTabHandle cTable;
	GDHandle aGDevice;
	GWorldFlags flags;
	if (!PyArg_ParseTuple(_args, "hO&O&O&l",
	                      &pixelDepth,
	                      PyMac_GetRect, &boundsRect,
	                      OptResObj_Convert, &cTable,
	                      OptResObj_Convert, &aGDevice,
	                      &flags))
		return NULL;
	_rv = UpdateGWorld(&offscreenGWorld,
	                   pixelDepth,
	                   &boundsRect,
	                   cTable,
	                   aGDevice,
	                   flags);
	_res = Py_BuildValue("lO&",
	                     _rv,
	                     GWorldObj_New, offscreenGWorld);
	return _res;
}

static PyObject *Qdoffs_GetGWorld(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	CGrafPtr port;
	GDHandle gdh;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	GetGWorld(&port,
	          &gdh);
	_res = Py_BuildValue("O&O&",
	                     GrafObj_New, port,
	                     ResObj_New, gdh);
	return _res;
}

static PyObject *Qdoffs_SetGWorld(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	CGrafPtr port;
	GDHandle gdh;
	if (!PyArg_ParseTuple(_args, "O&O&",
	                      GrafObj_Convert, &port,
	                      OptResObj_Convert, &gdh))
		return NULL;
	SetGWorld(port,
	          gdh);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Qdoffs_CTabChanged(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	CTabHandle ctab;
	if (!PyArg_ParseTuple(_args, "O&",
	                      OptResObj_Convert, &ctab))
		return NULL;
	CTabChanged(ctab);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Qdoffs_PixPatChanged(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	PixPatHandle ppat;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &ppat))
		return NULL;
	PixPatChanged(ppat);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Qdoffs_PortChanged(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	GrafPtr port;
	if (!PyArg_ParseTuple(_args, "O&",
	                      GrafObj_Convert, &port))
		return NULL;
	PortChanged(port);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Qdoffs_GDeviceChanged(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	GDHandle gdh;
	if (!PyArg_ParseTuple(_args, "O&",
	                      OptResObj_Convert, &gdh))
		return NULL;
	GDeviceChanged(gdh);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Qdoffs_AllowPurgePixels(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	PixMapHandle pm;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &pm))
		return NULL;
	AllowPurgePixels(pm);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Qdoffs_NoPurgePixels(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	PixMapHandle pm;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &pm))
		return NULL;
	NoPurgePixels(pm);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Qdoffs_GetPixelsState(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	GWorldFlags _rv;
	PixMapHandle pm;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &pm))
		return NULL;
	_rv = GetPixelsState(pm);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *Qdoffs_SetPixelsState(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	PixMapHandle pm;
	GWorldFlags state;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      ResObj_Convert, &pm,
	                      &state))
		return NULL;
	SetPixelsState(pm,
	               state);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Qdoffs_NewScreenBuffer(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	QDErr _err;
	Rect globalRect;
	Boolean purgeable;
	GDHandle gdh;
	PixMapHandle offscreenPixMap;
	if (!PyArg_ParseTuple(_args, "O&b",
	                      PyMac_GetRect, &globalRect,
	                      &purgeable))
		return NULL;
	_err = NewScreenBuffer(&globalRect,
	                       purgeable,
	                       &gdh,
	                       &offscreenPixMap);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&O&",
	                     ResObj_New, gdh,
	                     ResObj_New, offscreenPixMap);
	return _res;
}

static PyObject *Qdoffs_DisposeScreenBuffer(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	PixMapHandle offscreenPixMap;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &offscreenPixMap))
		return NULL;
	DisposeScreenBuffer(offscreenPixMap);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Qdoffs_QDDone(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	GrafPtr port;
	if (!PyArg_ParseTuple(_args, "O&",
	                      GrafObj_Convert, &port))
		return NULL;
	_rv = QDDone(port);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *Qdoffs_OffscreenVersion(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = OffscreenVersion();
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *Qdoffs_NewTempScreenBuffer(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	QDErr _err;
	Rect globalRect;
	Boolean purgeable;
	GDHandle gdh;
	PixMapHandle offscreenPixMap;
	if (!PyArg_ParseTuple(_args, "O&b",
	                      PyMac_GetRect, &globalRect,
	                      &purgeable))
		return NULL;
	_err = NewTempScreenBuffer(&globalRect,
	                           purgeable,
	                           &gdh,
	                           &offscreenPixMap);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&O&",
	                     ResObj_New, gdh,
	                     ResObj_New, offscreenPixMap);
	return _res;
}

static PyObject *Qdoffs_PixMap32Bit(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	PixMapHandle pmHandle;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &pmHandle))
		return NULL;
	_rv = PixMap32Bit(pmHandle);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyMethodDef Qdoffs_methods[] = {
	{"NewGWorld", (PyCFunction)Qdoffs_NewGWorld, 1,
	 "(short PixelDepth, Rect boundsRect, CTabHandle cTable, GDHandle aGDevice, GWorldFlags flags) -> (GWorldPtr offscreenGWorld)"},
	{"LockPixels", (PyCFunction)Qdoffs_LockPixels, 1,
	 "(PixMapHandle pm) -> (Boolean _rv)"},
	{"UnlockPixels", (PyCFunction)Qdoffs_UnlockPixels, 1,
	 "(PixMapHandle pm) -> None"},
	{"UpdateGWorld", (PyCFunction)Qdoffs_UpdateGWorld, 1,
	 "(short pixelDepth, Rect boundsRect, CTabHandle cTable, GDHandle aGDevice, GWorldFlags flags) -> (GWorldFlags _rv, GWorldPtr offscreenGWorld)"},
	{"GetGWorld", (PyCFunction)Qdoffs_GetGWorld, 1,
	 "() -> (CGrafPtr port, GDHandle gdh)"},
	{"SetGWorld", (PyCFunction)Qdoffs_SetGWorld, 1,
	 "(CGrafPtr port, GDHandle gdh) -> None"},
	{"CTabChanged", (PyCFunction)Qdoffs_CTabChanged, 1,
	 "(CTabHandle ctab) -> None"},
	{"PixPatChanged", (PyCFunction)Qdoffs_PixPatChanged, 1,
	 "(PixPatHandle ppat) -> None"},
	{"PortChanged", (PyCFunction)Qdoffs_PortChanged, 1,
	 "(GrafPtr port) -> None"},
	{"GDeviceChanged", (PyCFunction)Qdoffs_GDeviceChanged, 1,
	 "(GDHandle gdh) -> None"},
	{"AllowPurgePixels", (PyCFunction)Qdoffs_AllowPurgePixels, 1,
	 "(PixMapHandle pm) -> None"},
	{"NoPurgePixels", (PyCFunction)Qdoffs_NoPurgePixels, 1,
	 "(PixMapHandle pm) -> None"},
	{"GetPixelsState", (PyCFunction)Qdoffs_GetPixelsState, 1,
	 "(PixMapHandle pm) -> (GWorldFlags _rv)"},
	{"SetPixelsState", (PyCFunction)Qdoffs_SetPixelsState, 1,
	 "(PixMapHandle pm, GWorldFlags state) -> None"},
	{"NewScreenBuffer", (PyCFunction)Qdoffs_NewScreenBuffer, 1,
	 "(Rect globalRect, Boolean purgeable) -> (GDHandle gdh, PixMapHandle offscreenPixMap)"},
	{"DisposeScreenBuffer", (PyCFunction)Qdoffs_DisposeScreenBuffer, 1,
	 "(PixMapHandle offscreenPixMap) -> None"},
	{"QDDone", (PyCFunction)Qdoffs_QDDone, 1,
	 "(GrafPtr port) -> (Boolean _rv)"},
	{"OffscreenVersion", (PyCFunction)Qdoffs_OffscreenVersion, 1,
	 "() -> (long _rv)"},
	{"NewTempScreenBuffer", (PyCFunction)Qdoffs_NewTempScreenBuffer, 1,
	 "(Rect globalRect, Boolean purgeable) -> (GDHandle gdh, PixMapHandle offscreenPixMap)"},
	{"PixMap32Bit", (PyCFunction)Qdoffs_PixMap32Bit, 1,
	 "(PixMapHandle pmHandle) -> (Boolean _rv)"},
	{NULL, NULL, 0}
};




void initQdoffs()
{
	PyObject *m;
	PyObject *d;




	m = Py_InitModule("Qdoffs", Qdoffs_methods);
	d = PyModule_GetDict(m);
	Qdoffs_Error = PyMac_GetOSErrException();
	if (Qdoffs_Error == NULL ||
	    PyDict_SetItemString(d, "Error", Qdoffs_Error) != 0)
		Py_FatalError("can't initialize Qdoffs.Error");
	GWorld_Type.ob_type = &PyType_Type;
	Py_INCREF(&GWorld_Type);
	if (PyDict_SetItemString(d, "GWorldType", (PyObject *)&GWorld_Type) != 0)
		Py_FatalError("can't initialize GWorldType");
}

/* ======================= End module Qdoffs ======================== */

