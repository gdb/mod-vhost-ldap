
/* =========================== Module Dlg =========================== */

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
		fprintf(stderr, "Exception in Dialog Filter\n");
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
		fprintf(stderr, "Exception in Dialog UserItem proc\n");
		PyErr_Print();
	}
	Py_XDECREF(res);
	return;
}

extern PyMethodChain WinObj_chain;

static PyObject *Dlg_Error;

/* ----------------------- Object type Dialog ----------------------- */

PyTypeObject Dialog_Type;

#define DlgObj_Check(x) ((x)->ob_type == &Dialog_Type)

typedef struct DialogObject {
	PyObject_HEAD
	DialogPtr ob_itself;
} DialogObject;

PyObject *DlgObj_New(itself)
	DialogPtr itself;
{
	DialogObject *it;
	if (itself == NULL) return Py_None;
	it = PyObject_NEW(DialogObject, &Dialog_Type);
	if (it == NULL) return NULL;
	it->ob_itself = itself;
	SetWRefCon(itself, (long)it);
	return (PyObject *)it;
}
DlgObj_Convert(v, p_itself)
	PyObject *v;
	DialogPtr *p_itself;
{
	if (v == Py_None) { *p_itself = NULL; return 1; }
	if (PyInt_Check(v)) { *p_itself = (DialogPtr)PyInt_AsLong(v);
	                      return 1; }
	if (!DlgObj_Check(v))
	{
		PyErr_SetString(PyExc_TypeError, "Dialog required");
		return 0;
	}
	*p_itself = ((DialogObject *)v)->ob_itself;
	return 1;
}

static void DlgObj_dealloc(self)
	DialogObject *self;
{
	DisposeDialog(self->ob_itself);
	PyMem_DEL(self);
}

static PyObject *DlgObj_DrawDialog(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	DrawDialog(_self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_UpdateDialog(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	RgnHandle updateRgn;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &updateRgn))
		return NULL;
	UpdateDialog(_self->ob_itself,
	             updateRgn);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_HideDialogItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex itemNo;
	if (!PyArg_ParseTuple(_args, "h",
	                      &itemNo))
		return NULL;
	HideDialogItem(_self->ob_itself,
	               itemNo);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_ShowDialogItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex itemNo;
	if (!PyArg_ParseTuple(_args, "h",
	                      &itemNo))
		return NULL;
	ShowDialogItem(_self->ob_itself,
	               itemNo);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_FindDialogItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndexZeroBased _rv;
	Point thePt;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetPoint, &thePt))
		return NULL;
	_rv = FindDialogItem(_self->ob_itself,
	                     thePt);
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *DlgObj_DialogCut(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	DialogCut(_self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_DialogPaste(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	DialogPaste(_self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_DialogCopy(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	DialogCopy(_self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_DialogDelete(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	DialogDelete(_self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_GetDialogItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex itemNo;
	DialogItemType itemType;
	Handle item;
	Rect box;
	if (!PyArg_ParseTuple(_args, "h",
	                      &itemNo))
		return NULL;
	GetDialogItem(_self->ob_itself,
	              itemNo,
	              &itemType,
	              &item,
	              &box);
	_res = Py_BuildValue("hO&O&",
	                     itemType,
	                     OptResObj_New, item,
	                     PyMac_BuildRect, &box);
	return _res;
}

static PyObject *DlgObj_SetDialogItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex itemNo;
	DialogItemType itemType;
	Handle item;
	Rect box;
	if (!PyArg_ParseTuple(_args, "hhO&O&",
	                      &itemNo,
	                      &itemType,
	                      ResObj_Convert, &item,
	                      PyMac_GetRect, &box))
		return NULL;
	SetDialogItem(_self->ob_itself,
	              itemNo,
	              itemType,
	              item,
	              &box);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_SelectDialogItemText(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex itemNo;
	SInt16 strtSel;
	SInt16 endSel;
	if (!PyArg_ParseTuple(_args, "hhh",
	                      &itemNo,
	                      &strtSel,
	                      &endSel))
		return NULL;
	SelectDialogItemText(_self->ob_itself,
	                     itemNo,
	                     strtSel,
	                     endSel);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_AppendDITL(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Handle theHandle;
	DITLMethod method;
	if (!PyArg_ParseTuple(_args, "O&h",
	                      ResObj_Convert, &theHandle,
	                      &method))
		return NULL;
	AppendDITL(_self->ob_itself,
	           theHandle,
	           method);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_CountDITL(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = CountDITL(_self->ob_itself);
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *DlgObj_ShortenDITL(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex numberItems;
	if (!PyArg_ParseTuple(_args, "h",
	                      &numberItems))
		return NULL;
	ShortenDITL(_self->ob_itself,
	            numberItems);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_StdFilterProc(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	EventRecord event;
	DialogItemIndex itemHit;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = StdFilterProc(_self->ob_itself,
	                    &event,
	                    &itemHit);
	_res = Py_BuildValue("bO&h",
	                     _rv,
	                     PyMac_BuildEventRecord, &event,
	                     itemHit);
	return _res;
}

static PyObject *DlgObj_SetDialogDefaultItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	DialogItemIndex newItem;
	if (!PyArg_ParseTuple(_args, "h",
	                      &newItem))
		return NULL;
	_err = SetDialogDefaultItem(_self->ob_itself,
	                            newItem);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_SetDialogCancelItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	DialogItemIndex newItem;
	if (!PyArg_ParseTuple(_args, "h",
	                      &newItem))
		return NULL;
	_err = SetDialogCancelItem(_self->ob_itself,
	                           newItem);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_SetDialogTracksCursor(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	Boolean tracks;
	if (!PyArg_ParseTuple(_args, "b",
	                      &tracks))
		return NULL;
	_err = SetDialogTracksCursor(_self->ob_itself,
	                             tracks);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_AutoSizeDialog(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = AutoSizeDialog(_self->ob_itself);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_GetDialogItemAsControl(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItemNo;
	ControlHandle outControl;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItemNo))
		return NULL;
	_err = GetDialogItemAsControl(_self->ob_itself,
	                              inItemNo,
	                              &outControl);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("O&",
	                     CtlObj_New, outControl);
	return _res;
}

static PyObject *DlgObj_MoveDialogItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItemNo;
	SInt16 inHoriz;
	SInt16 inVert;
	if (!PyArg_ParseTuple(_args, "hhh",
	                      &inItemNo,
	                      &inHoriz,
	                      &inVert))
		return NULL;
	_err = MoveDialogItem(_self->ob_itself,
	                      inItemNo,
	                      inHoriz,
	                      inVert);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_SizeDialogItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItemNo;
	SInt16 inWidth;
	SInt16 inHeight;
	if (!PyArg_ParseTuple(_args, "hhh",
	                      &inItemNo,
	                      &inWidth,
	                      &inHeight))
		return NULL;
	_err = SizeDialogItem(_self->ob_itself,
	                      inItemNo,
	                      inWidth,
	                      inHeight);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *DlgObj_GetDialogWindow(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogPtr _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetDialogWindow(_self->ob_itself);
	_res = Py_BuildValue("O&",
	                     WinObj_WhichWindow, _rv);
	return _res;
}

static PyObject *DlgObj_GetDialogDefaultItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	SInt16 _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetDialogDefaultItem(_self->ob_itself);
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *DlgObj_GetDialogCancelItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	SInt16 _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetDialogCancelItem(_self->ob_itself);
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *DlgObj_GetDialogKeyboardFocusItem(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	SInt16 _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetDialogKeyboardFocusItem(_self->ob_itself);
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *DlgObj_SetGrafPortOfDialog(_self, _args)
	DialogObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	SetGrafPortOfDialog(_self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyMethodDef DlgObj_methods[] = {
	{"DrawDialog", (PyCFunction)DlgObj_DrawDialog, 1,
	 "() -> None"},
	{"UpdateDialog", (PyCFunction)DlgObj_UpdateDialog, 1,
	 "(RgnHandle updateRgn) -> None"},
	{"HideDialogItem", (PyCFunction)DlgObj_HideDialogItem, 1,
	 "(DialogItemIndex itemNo) -> None"},
	{"ShowDialogItem", (PyCFunction)DlgObj_ShowDialogItem, 1,
	 "(DialogItemIndex itemNo) -> None"},
	{"FindDialogItem", (PyCFunction)DlgObj_FindDialogItem, 1,
	 "(Point thePt) -> (DialogItemIndexZeroBased _rv)"},
	{"DialogCut", (PyCFunction)DlgObj_DialogCut, 1,
	 "() -> None"},
	{"DialogPaste", (PyCFunction)DlgObj_DialogPaste, 1,
	 "() -> None"},
	{"DialogCopy", (PyCFunction)DlgObj_DialogCopy, 1,
	 "() -> None"},
	{"DialogDelete", (PyCFunction)DlgObj_DialogDelete, 1,
	 "() -> None"},
	{"GetDialogItem", (PyCFunction)DlgObj_GetDialogItem, 1,
	 "(DialogItemIndex itemNo) -> (DialogItemType itemType, Handle item, Rect box)"},
	{"SetDialogItem", (PyCFunction)DlgObj_SetDialogItem, 1,
	 "(DialogItemIndex itemNo, DialogItemType itemType, Handle item, Rect box) -> None"},
	{"SelectDialogItemText", (PyCFunction)DlgObj_SelectDialogItemText, 1,
	 "(DialogItemIndex itemNo, SInt16 strtSel, SInt16 endSel) -> None"},
	{"AppendDITL", (PyCFunction)DlgObj_AppendDITL, 1,
	 "(Handle theHandle, DITLMethod method) -> None"},
	{"CountDITL", (PyCFunction)DlgObj_CountDITL, 1,
	 "() -> (DialogItemIndex _rv)"},
	{"ShortenDITL", (PyCFunction)DlgObj_ShortenDITL, 1,
	 "(DialogItemIndex numberItems) -> None"},
	{"StdFilterProc", (PyCFunction)DlgObj_StdFilterProc, 1,
	 "() -> (Boolean _rv, EventRecord event, DialogItemIndex itemHit)"},
	{"SetDialogDefaultItem", (PyCFunction)DlgObj_SetDialogDefaultItem, 1,
	 "(DialogItemIndex newItem) -> None"},
	{"SetDialogCancelItem", (PyCFunction)DlgObj_SetDialogCancelItem, 1,
	 "(DialogItemIndex newItem) -> None"},
	{"SetDialogTracksCursor", (PyCFunction)DlgObj_SetDialogTracksCursor, 1,
	 "(Boolean tracks) -> None"},
	{"AutoSizeDialog", (PyCFunction)DlgObj_AutoSizeDialog, 1,
	 "() -> None"},
	{"GetDialogItemAsControl", (PyCFunction)DlgObj_GetDialogItemAsControl, 1,
	 "(SInt16 inItemNo) -> (ControlHandle outControl)"},
	{"MoveDialogItem", (PyCFunction)DlgObj_MoveDialogItem, 1,
	 "(SInt16 inItemNo, SInt16 inHoriz, SInt16 inVert) -> None"},
	{"SizeDialogItem", (PyCFunction)DlgObj_SizeDialogItem, 1,
	 "(SInt16 inItemNo, SInt16 inWidth, SInt16 inHeight) -> None"},
	{"GetDialogWindow", (PyCFunction)DlgObj_GetDialogWindow, 1,
	 "() -> (DialogPtr _rv)"},
	{"GetDialogDefaultItem", (PyCFunction)DlgObj_GetDialogDefaultItem, 1,
	 "() -> (SInt16 _rv)"},
	{"GetDialogCancelItem", (PyCFunction)DlgObj_GetDialogCancelItem, 1,
	 "() -> (SInt16 _rv)"},
	{"GetDialogKeyboardFocusItem", (PyCFunction)DlgObj_GetDialogKeyboardFocusItem, 1,
	 "() -> (SInt16 _rv)"},
	{"SetGrafPortOfDialog", (PyCFunction)DlgObj_SetGrafPortOfDialog, 1,
	 "() -> None"},
	{NULL, NULL, 0}
};

PyMethodChain DlgObj_chain = { DlgObj_methods, &WinObj_chain };

static PyObject *DlgObj_getattr(self, name)
	DialogObject *self;
	char *name;
{
	return Py_FindMethodInChain(&DlgObj_chain, (PyObject *)self, name);
}

#define DlgObj_setattr NULL

PyTypeObject Dialog_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0, /*ob_size*/
	"Dialog", /*tp_name*/
	sizeof(DialogObject), /*tp_basicsize*/
	0, /*tp_itemsize*/
	/* methods */
	(destructor) DlgObj_dealloc, /*tp_dealloc*/
	0, /*tp_print*/
	(getattrfunc) DlgObj_getattr, /*tp_getattr*/
	(setattrfunc) DlgObj_setattr, /*tp_setattr*/
};

/* --------------------- End object type Dialog --------------------- */


static PyObject *Dlg_NewDialog(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogPtr _rv;
	Rect boundsRect;
	Str255 title;
	Boolean visible;
	SInt16 procID;
	WindowPtr behind;
	Boolean goAwayFlag;
	SInt32 refCon;
	Handle items;
	if (!PyArg_ParseTuple(_args, "O&O&bhO&blO&",
	                      PyMac_GetRect, &boundsRect,
	                      PyMac_GetStr255, title,
	                      &visible,
	                      &procID,
	                      WinObj_Convert, &behind,
	                      &goAwayFlag,
	                      &refCon,
	                      ResObj_Convert, &items))
		return NULL;
	_rv = NewDialog((void *)0,
	                &boundsRect,
	                title,
	                visible,
	                procID,
	                behind,
	                goAwayFlag,
	                refCon,
	                items);
	_res = Py_BuildValue("O&",
	                     DlgObj_New, _rv);
	return _res;
}

static PyObject *Dlg_GetNewDialog(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogPtr _rv;
	SInt16 dialogID;
	WindowPtr behind;
	if (!PyArg_ParseTuple(_args, "hO&",
	                      &dialogID,
	                      WinObj_Convert, &behind))
		return NULL;
	_rv = GetNewDialog(dialogID,
	                   (void *)0,
	                   behind);
	_res = Py_BuildValue("O&",
	                     DlgObj_New, _rv);
	return _res;
}

static PyObject *Dlg_NewColorDialog(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogPtr _rv;
	Rect boundsRect;
	Str255 title;
	Boolean visible;
	SInt16 procID;
	WindowPtr behind;
	Boolean goAwayFlag;
	SInt32 refCon;
	Handle items;
	if (!PyArg_ParseTuple(_args, "O&O&bhO&blO&",
	                      PyMac_GetRect, &boundsRect,
	                      PyMac_GetStr255, title,
	                      &visible,
	                      &procID,
	                      WinObj_Convert, &behind,
	                      &goAwayFlag,
	                      &refCon,
	                      ResObj_Convert, &items))
		return NULL;
	_rv = NewColorDialog((void *)0,
	                     &boundsRect,
	                     title,
	                     visible,
	                     procID,
	                     behind,
	                     goAwayFlag,
	                     refCon,
	                     items);
	_res = Py_BuildValue("O&",
	                     DlgObj_New, _rv);
	return _res;
}

static PyObject *Dlg_ModalDialog(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	PyObject* modalFilter;
	DialogItemIndex itemHit;
	if (!PyArg_ParseTuple(_args, "O",
	                      &modalFilter))
		return NULL;
	ModalDialog(NewModalFilterProc(Dlg_PassFilterProc(modalFilter)),
	            &itemHit);
	_res = Py_BuildValue("h",
	                     itemHit);
	return _res;
}

static PyObject *Dlg_IsDialogEvent(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	EventRecord theEvent;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetEventRecord, &theEvent))
		return NULL;
	_rv = IsDialogEvent(&theEvent);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *Dlg_DialogSelect(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	EventRecord theEvent;
	DialogPtr theDialog;
	DialogItemIndex itemHit;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetEventRecord, &theEvent))
		return NULL;
	_rv = DialogSelect(&theEvent,
	                   &theDialog,
	                   &itemHit);
	_res = Py_BuildValue("bO&h",
	                     _rv,
	                     WinObj_WhichWindow, theDialog,
	                     itemHit);
	return _res;
}

static PyObject *Dlg_Alert(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex _rv;
	SInt16 alertID;
	PyObject* modalFilter;
	if (!PyArg_ParseTuple(_args, "hO",
	                      &alertID,
	                      &modalFilter))
		return NULL;
	_rv = Alert(alertID,
	            NewModalFilterProc(Dlg_PassFilterProc(modalFilter)));
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *Dlg_StopAlert(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex _rv;
	SInt16 alertID;
	PyObject* modalFilter;
	if (!PyArg_ParseTuple(_args, "hO",
	                      &alertID,
	                      &modalFilter))
		return NULL;
	_rv = StopAlert(alertID,
	                NewModalFilterProc(Dlg_PassFilterProc(modalFilter)));
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *Dlg_NoteAlert(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex _rv;
	SInt16 alertID;
	PyObject* modalFilter;
	if (!PyArg_ParseTuple(_args, "hO",
	                      &alertID,
	                      &modalFilter))
		return NULL;
	_rv = NoteAlert(alertID,
	                NewModalFilterProc(Dlg_PassFilterProc(modalFilter)));
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *Dlg_CautionAlert(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogItemIndex _rv;
	SInt16 alertID;
	PyObject* modalFilter;
	if (!PyArg_ParseTuple(_args, "hO",
	                      &alertID,
	                      &modalFilter))
		return NULL;
	_rv = CautionAlert(alertID,
	                   NewModalFilterProc(Dlg_PassFilterProc(modalFilter)));
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *Dlg_ParamText(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Str255 param0;
	Str255 param1;
	Str255 param2;
	Str255 param3;
	if (!PyArg_ParseTuple(_args, "O&O&O&O&",
	                      PyMac_GetStr255, param0,
	                      PyMac_GetStr255, param1,
	                      PyMac_GetStr255, param2,
	                      PyMac_GetStr255, param3))
		return NULL;
	ParamText(param0,
	          param1,
	          param2,
	          param3);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Dlg_GetDialogItemText(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Handle item;
	Str255 text;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &item))
		return NULL;
	GetDialogItemText(item,
	                  text);
	_res = Py_BuildValue("O&",
	                     PyMac_BuildStr255, text);
	return _res;
}

static PyObject *Dlg_SetDialogItemText(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Handle item;
	Str255 text;
	if (!PyArg_ParseTuple(_args, "O&O&",
	                      ResObj_Convert, &item,
	                      PyMac_GetStr255, text))
		return NULL;
	SetDialogItemText(item,
	                  text);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Dlg_GetAlertStage(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	SInt16 _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetAlertStage();
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *Dlg_SetDialogFont(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	SInt16 value;
	if (!PyArg_ParseTuple(_args, "h",
	                      &value))
		return NULL;
	SetDialogFont(value);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Dlg_ResetAlertStage(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	ResetAlertStage();
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Dlg_NewFeaturesDialog(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	DialogPtr _rv;
	Rect inBoundsRect;
	Str255 inTitle;
	Boolean inIsVisible;
	SInt16 inProcID;
	WindowPtr inBehind;
	Boolean inGoAwayFlag;
	SInt32 inRefCon;
	Handle inItemListHandle;
	UInt32 inFlags;
	if (!PyArg_ParseTuple(_args, "O&O&bhO&blO&l",
	                      PyMac_GetRect, &inBoundsRect,
	                      PyMac_GetStr255, inTitle,
	                      &inIsVisible,
	                      &inProcID,
	                      WinObj_Convert, &inBehind,
	                      &inGoAwayFlag,
	                      &inRefCon,
	                      ResObj_Convert, &inItemListHandle,
	                      &inFlags))
		return NULL;
	_rv = NewFeaturesDialog((void *)0,
	                        &inBoundsRect,
	                        inTitle,
	                        inIsVisible,
	                        inProcID,
	                        inBehind,
	                        inGoAwayFlag,
	                        inRefCon,
	                        inItemListHandle,
	                        inFlags);
	_res = Py_BuildValue("O&",
	                     DlgObj_New, _rv);
	return _res;
}

static PyObject *Dlg_SetUserItemHandler(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;

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

}

static PyMethodDef Dlg_methods[] = {
	{"NewDialog", (PyCFunction)Dlg_NewDialog, 1,
	 "(Rect boundsRect, Str255 title, Boolean visible, SInt16 procID, WindowPtr behind, Boolean goAwayFlag, SInt32 refCon, Handle items) -> (DialogPtr _rv)"},
	{"GetNewDialog", (PyCFunction)Dlg_GetNewDialog, 1,
	 "(SInt16 dialogID, WindowPtr behind) -> (DialogPtr _rv)"},
	{"NewColorDialog", (PyCFunction)Dlg_NewColorDialog, 1,
	 "(Rect boundsRect, Str255 title, Boolean visible, SInt16 procID, WindowPtr behind, Boolean goAwayFlag, SInt32 refCon, Handle items) -> (DialogPtr _rv)"},
	{"ModalDialog", (PyCFunction)Dlg_ModalDialog, 1,
	 "(PyObject* modalFilter) -> (DialogItemIndex itemHit)"},
	{"IsDialogEvent", (PyCFunction)Dlg_IsDialogEvent, 1,
	 "(EventRecord theEvent) -> (Boolean _rv)"},
	{"DialogSelect", (PyCFunction)Dlg_DialogSelect, 1,
	 "(EventRecord theEvent) -> (Boolean _rv, DialogPtr theDialog, DialogItemIndex itemHit)"},
	{"Alert", (PyCFunction)Dlg_Alert, 1,
	 "(SInt16 alertID, PyObject* modalFilter) -> (DialogItemIndex _rv)"},
	{"StopAlert", (PyCFunction)Dlg_StopAlert, 1,
	 "(SInt16 alertID, PyObject* modalFilter) -> (DialogItemIndex _rv)"},
	{"NoteAlert", (PyCFunction)Dlg_NoteAlert, 1,
	 "(SInt16 alertID, PyObject* modalFilter) -> (DialogItemIndex _rv)"},
	{"CautionAlert", (PyCFunction)Dlg_CautionAlert, 1,
	 "(SInt16 alertID, PyObject* modalFilter) -> (DialogItemIndex _rv)"},
	{"ParamText", (PyCFunction)Dlg_ParamText, 1,
	 "(Str255 param0, Str255 param1, Str255 param2, Str255 param3) -> None"},
	{"GetDialogItemText", (PyCFunction)Dlg_GetDialogItemText, 1,
	 "(Handle item) -> (Str255 text)"},
	{"SetDialogItemText", (PyCFunction)Dlg_SetDialogItemText, 1,
	 "(Handle item, Str255 text) -> None"},
	{"GetAlertStage", (PyCFunction)Dlg_GetAlertStage, 1,
	 "() -> (SInt16 _rv)"},
	{"SetDialogFont", (PyCFunction)Dlg_SetDialogFont, 1,
	 "(SInt16 value) -> None"},
	{"ResetAlertStage", (PyCFunction)Dlg_ResetAlertStage, 1,
	 "() -> None"},
	{"NewFeaturesDialog", (PyCFunction)Dlg_NewFeaturesDialog, 1,
	 "(Rect inBoundsRect, Str255 inTitle, Boolean inIsVisible, SInt16 inProcID, WindowPtr inBehind, Boolean inGoAwayFlag, SInt32 inRefCon, Handle inItemListHandle, UInt32 inFlags) -> (DialogPtr _rv)"},
	{"SetUserItemHandler", (PyCFunction)Dlg_SetUserItemHandler, 1,
	 NULL},
	{NULL, NULL, 0}
};




void initDlg()
{
	PyObject *m;
	PyObject *d;




	m = Py_InitModule("Dlg", Dlg_methods);
	d = PyModule_GetDict(m);
	Dlg_Error = PyMac_GetOSErrException();
	if (Dlg_Error == NULL ||
	    PyDict_SetItemString(d, "Error", Dlg_Error) != 0)
		Py_FatalError("can't initialize Dlg.Error");
	Dialog_Type.ob_type = &PyType_Type;
	Py_INCREF(&Dialog_Type);
	if (PyDict_SetItemString(d, "DialogType", (PyObject *)&Dialog_Type) != 0)
		Py_FatalError("can't initialize DialogType");
}

/* ========================= End module Dlg ========================= */

