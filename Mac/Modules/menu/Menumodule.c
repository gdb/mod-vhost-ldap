
/* ========================== Module Menu =========================== */

#include "Python.h"



#include "macglue.h"
#include "pymactoolbox.h"

#include <Devices.h> /* Defines OpenDeskAcc in universal headers */
#include <Menus.h>

#define as_Menu(h) ((MenuHandle)h)
#define as_Resource(h) ((Handle)h)

static PyObject *Menu_Error;

/* ------------------------ Object type Menu ------------------------ */

PyTypeObject Menu_Type;

#define MenuObj_Check(x) ((x)->ob_type == &Menu_Type)

typedef struct MenuObject {
	PyObject_HEAD
	MenuHandle ob_itself;
} MenuObject;

PyObject *MenuObj_New(itself)
	MenuHandle itself;
{
	MenuObject *it;
	it = PyObject_NEW(MenuObject, &Menu_Type);
	if (it == NULL) return NULL;
	it->ob_itself = itself;
	return (PyObject *)it;
}
MenuObj_Convert(v, p_itself)
	PyObject *v;
	MenuHandle *p_itself;
{
	if (!MenuObj_Check(v))
	{
		PyErr_SetString(PyExc_TypeError, "Menu required");
		return 0;
	}
	*p_itself = ((MenuObject *)v)->ob_itself;
	return 1;
}

static void MenuObj_dealloc(self)
	MenuObject *self;
{
	/* Cleanup of self->ob_itself goes here */
	PyMem_DEL(self);
}

static PyObject *MenuObj_DisposeMenu(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	DisposeMenu(_self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_CalcMenuSize(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	CalcMenuSize(_self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

#ifndef TARGET_API_MAC_CARBON

static PyObject *MenuObj_CountMItems(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = CountMItems(_self->ob_itself);
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}
#endif

static PyObject *MenuObj_GetMenuFont(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	SInt16 outFontID;
	UInt16 outFontSize;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = GetMenuFont(_self->ob_itself,
	                   &outFontID,
	                   &outFontSize);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("hH",
	                     outFontID,
	                     outFontSize);
	return _res;
}

static PyObject *MenuObj_SetMenuFont(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	SInt16 inFontID;
	UInt16 inFontSize;
	if (!PyArg_ParseTuple(_args, "hH",
	                      &inFontID,
	                      &inFontSize))
		return NULL;
	_err = SetMenuFont(_self->ob_itself,
	                   inFontID,
	                   inFontSize);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetMenuExcludesMarkColumn(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetMenuExcludesMarkColumn(_self->ob_itself);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *MenuObj_SetMenuExcludesMarkColumn(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Boolean excludesMark;
	if (!PyArg_ParseTuple(_args, "b",
	                      &excludesMark))
		return NULL;
	_err = SetMenuExcludesMarkColumn(_self->ob_itself,
	                                 excludesMark);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_MacAppendMenu(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Str255 data;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetStr255, data))
		return NULL;
	MacAppendMenu(_self->ob_itself,
	              data);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_InsertResMenu(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	ResType theType;
	short afterItem;
	if (!PyArg_ParseTuple(_args, "O&h",
	                      PyMac_GetOSType, &theType,
	                      &afterItem))
		return NULL;
	InsertResMenu(_self->ob_itself,
	              theType,
	              afterItem);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_AppendResMenu(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	ResType theType;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetOSType, &theType))
		return NULL;
	AppendResMenu(_self->ob_itself,
	              theType);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_MacInsertMenuItem(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Str255 itemString;
	short afterItem;
	if (!PyArg_ParseTuple(_args, "O&h",
	                      PyMac_GetStr255, itemString,
	                      &afterItem))
		return NULL;
	MacInsertMenuItem(_self->ob_itself,
	                  itemString,
	                  afterItem);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_DeleteMenuItem(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	if (!PyArg_ParseTuple(_args, "h",
	                      &item))
		return NULL;
	DeleteMenuItem(_self->ob_itself,
	               item);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_InsertFontResMenu(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short afterItem;
	short scriptFilter;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &afterItem,
	                      &scriptFilter))
		return NULL;
	InsertFontResMenu(_self->ob_itself,
	                  afterItem,
	                  scriptFilter);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_InsertIntlResMenu(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	ResType theType;
	short afterItem;
	short scriptFilter;
	if (!PyArg_ParseTuple(_args, "O&hh",
	                      PyMac_GetOSType, &theType,
	                      &afterItem,
	                      &scriptFilter))
		return NULL;
	InsertIntlResMenu(_self->ob_itself,
	                  theType,
	                  afterItem,
	                  scriptFilter);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_AppendMenuItemText(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Str255 inString;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetStr255, inString))
		return NULL;
	_err = AppendMenuItemText(_self->ob_itself,
	                          inString);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_InsertMenuItemText(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	Str255 inString;
	UInt16 afterItem;
	if (!PyArg_ParseTuple(_args, "O&H",
	                      PyMac_GetStr255, inString,
	                      &afterItem))
		return NULL;
	_err = InsertMenuItemText(_self->ob_itself,
	                          inString,
	                          afterItem);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_PopUpMenuSelect(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	short top;
	short left;
	short popUpItem;
	if (!PyArg_ParseTuple(_args, "hhh",
	                      &top,
	                      &left,
	                      &popUpItem))
		return NULL;
	_rv = PopUpMenuSelect(_self->ob_itself,
	                      top,
	                      left,
	                      popUpItem);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *MenuObj_MacInsertMenu(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short beforeID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &beforeID))
		return NULL;
	MacInsertMenu(_self->ob_itself,
	              beforeID);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

#ifndef TARGET_API_MAC_CARBON

static PyObject *MenuObj_CheckItem(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	Boolean checked;
	if (!PyArg_ParseTuple(_args, "hb",
	                      &item,
	                      &checked))
		return NULL;
	CheckItem(_self->ob_itself,
	          item,
	          checked);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}
#endif

static PyObject *MenuObj_SetMenuItemText(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	Str255 itemString;
	if (!PyArg_ParseTuple(_args, "hO&",
	                      &item,
	                      PyMac_GetStr255, itemString))
		return NULL;
	SetMenuItemText(_self->ob_itself,
	                item,
	                itemString);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetMenuItemText(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	Str255 itemString;
	if (!PyArg_ParseTuple(_args, "h",
	                      &item))
		return NULL;
	GetMenuItemText(_self->ob_itself,
	                item,
	                itemString);
	_res = Py_BuildValue("O&",
	                     PyMac_BuildStr255, itemString);
	return _res;
}

static PyObject *MenuObj_SetItemMark(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	CharParameter markChar;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &item,
	                      &markChar))
		return NULL;
	SetItemMark(_self->ob_itself,
	            item,
	            markChar);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetItemMark(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	CharParameter markChar;
	if (!PyArg_ParseTuple(_args, "h",
	                      &item))
		return NULL;
	GetItemMark(_self->ob_itself,
	            item,
	            &markChar);
	_res = Py_BuildValue("h",
	                     markChar);
	return _res;
}

static PyObject *MenuObj_SetItemCmd(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	CharParameter cmdChar;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &item,
	                      &cmdChar))
		return NULL;
	SetItemCmd(_self->ob_itself,
	           item,
	           cmdChar);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetItemCmd(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	CharParameter cmdChar;
	if (!PyArg_ParseTuple(_args, "h",
	                      &item))
		return NULL;
	GetItemCmd(_self->ob_itself,
	           item,
	           &cmdChar);
	_res = Py_BuildValue("h",
	                     cmdChar);
	return _res;
}

static PyObject *MenuObj_SetItemIcon(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	short iconIndex;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &item,
	                      &iconIndex))
		return NULL;
	SetItemIcon(_self->ob_itself,
	            item,
	            iconIndex);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetItemIcon(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	short iconIndex;
	if (!PyArg_ParseTuple(_args, "h",
	                      &item))
		return NULL;
	GetItemIcon(_self->ob_itself,
	            item,
	            &iconIndex);
	_res = Py_BuildValue("h",
	                     iconIndex);
	return _res;
}

static PyObject *MenuObj_SetItemStyle(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	StyleParameter chStyle;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &item,
	                      &chStyle))
		return NULL;
	SetItemStyle(_self->ob_itself,
	             item,
	             chStyle);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetItemStyle(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	Style chStyle;
	if (!PyArg_ParseTuple(_args, "h",
	                      &item))
		return NULL;
	GetItemStyle(_self->ob_itself,
	             item,
	             &chStyle);
	_res = Py_BuildValue("b",
	                     chStyle);
	return _res;
}

#ifndef TARGET_API_MAC_CARBON

static PyObject *MenuObj_DisableItem(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	if (!PyArg_ParseTuple(_args, "h",
	                      &item))
		return NULL;
	DisableItem(_self->ob_itself,
	            item);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}
#endif

#ifndef TARGET_API_MAC_CARBON

static PyObject *MenuObj_EnableItem(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short item;
	if (!PyArg_ParseTuple(_args, "h",
	                      &item))
		return NULL;
	EnableItem(_self->ob_itself,
	           item);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}
#endif

static PyObject *MenuObj_SetMenuItemCommandID(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	UInt32 inCommandID;
	if (!PyArg_ParseTuple(_args, "hl",
	                      &inItem,
	                      &inCommandID))
		return NULL;
	_err = SetMenuItemCommandID(_self->ob_itself,
	                            inItem,
	                            inCommandID);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetMenuItemCommandID(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	UInt32 outCommandID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItem))
		return NULL;
	_err = GetMenuItemCommandID(_self->ob_itself,
	                            inItem,
	                            &outCommandID);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("l",
	                     outCommandID);
	return _res;
}

static PyObject *MenuObj_SetMenuItemModifiers(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	UInt8 inModifiers;
	if (!PyArg_ParseTuple(_args, "hb",
	                      &inItem,
	                      &inModifiers))
		return NULL;
	_err = SetMenuItemModifiers(_self->ob_itself,
	                            inItem,
	                            inModifiers);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetMenuItemModifiers(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	UInt8 outModifiers;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItem))
		return NULL;
	_err = GetMenuItemModifiers(_self->ob_itself,
	                            inItem,
	                            &outModifiers);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("b",
	                     outModifiers);
	return _res;
}

static PyObject *MenuObj_SetMenuItemIconHandle(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	UInt8 inIconType;
	Handle inIconHandle;
	if (!PyArg_ParseTuple(_args, "hbO&",
	                      &inItem,
	                      &inIconType,
	                      ResObj_Convert, &inIconHandle))
		return NULL;
	_err = SetMenuItemIconHandle(_self->ob_itself,
	                             inItem,
	                             inIconType,
	                             inIconHandle);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetMenuItemIconHandle(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	UInt8 outIconType;
	Handle outIconHandle;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItem))
		return NULL;
	_err = GetMenuItemIconHandle(_self->ob_itself,
	                             inItem,
	                             &outIconType,
	                             &outIconHandle);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("bO&",
	                     outIconType,
	                     ResObj_New, outIconHandle);
	return _res;
}

static PyObject *MenuObj_SetMenuItemTextEncoding(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	TextEncoding inScriptID;
	if (!PyArg_ParseTuple(_args, "hl",
	                      &inItem,
	                      &inScriptID))
		return NULL;
	_err = SetMenuItemTextEncoding(_self->ob_itself,
	                               inItem,
	                               inScriptID);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetMenuItemTextEncoding(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	TextEncoding outScriptID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItem))
		return NULL;
	_err = GetMenuItemTextEncoding(_self->ob_itself,
	                               inItem,
	                               &outScriptID);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("l",
	                     outScriptID);
	return _res;
}

static PyObject *MenuObj_SetMenuItemHierarchicalID(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	SInt16 inHierID;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &inItem,
	                      &inHierID))
		return NULL;
	_err = SetMenuItemHierarchicalID(_self->ob_itself,
	                                 inItem,
	                                 inHierID);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetMenuItemHierarchicalID(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	SInt16 outHierID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItem))
		return NULL;
	_err = GetMenuItemHierarchicalID(_self->ob_itself,
	                                 inItem,
	                                 &outHierID);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("h",
	                     outHierID);
	return _res;
}

static PyObject *MenuObj_SetMenuItemFontID(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	SInt16 inFontID;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &inItem,
	                      &inFontID))
		return NULL;
	_err = SetMenuItemFontID(_self->ob_itself,
	                         inItem,
	                         inFontID);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetMenuItemFontID(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	SInt16 outFontID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItem))
		return NULL;
	_err = GetMenuItemFontID(_self->ob_itself,
	                         inItem,
	                         &outFontID);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("h",
	                     outFontID);
	return _res;
}

static PyObject *MenuObj_SetMenuItemRefCon(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	UInt32 inRefCon;
	if (!PyArg_ParseTuple(_args, "hl",
	                      &inItem,
	                      &inRefCon))
		return NULL;
	_err = SetMenuItemRefCon(_self->ob_itself,
	                         inItem,
	                         inRefCon);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetMenuItemRefCon(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	UInt32 outRefCon;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItem))
		return NULL;
	_err = GetMenuItemRefCon(_self->ob_itself,
	                         inItem,
	                         &outRefCon);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("l",
	                     outRefCon);
	return _res;
}

#ifndef TARGET_API_MAC_CARBON

static PyObject *MenuObj_SetMenuItemRefCon2(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	UInt32 inRefCon2;
	if (!PyArg_ParseTuple(_args, "hl",
	                      &inItem,
	                      &inRefCon2))
		return NULL;
	_err = SetMenuItemRefCon2(_self->ob_itself,
	                          inItem,
	                          inRefCon2);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}
#endif

#ifndef TARGET_API_MAC_CARBON

static PyObject *MenuObj_GetMenuItemRefCon2(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	UInt32 outRefCon2;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItem))
		return NULL;
	_err = GetMenuItemRefCon2(_self->ob_itself,
	                          inItem,
	                          &outRefCon2);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("l",
	                     outRefCon2);
	return _res;
}
#endif

static PyObject *MenuObj_SetMenuItemKeyGlyph(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	SInt16 inGlyph;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &inItem,
	                      &inGlyph))
		return NULL;
	_err = SetMenuItemKeyGlyph(_self->ob_itself,
	                           inItem,
	                           inGlyph);
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_GetMenuItemKeyGlyph(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSErr _err;
	SInt16 inItem;
	SInt16 outGlyph;
	if (!PyArg_ParseTuple(_args, "h",
	                      &inItem))
		return NULL;
	_err = GetMenuItemKeyGlyph(_self->ob_itself,
	                           inItem,
	                           &outGlyph);
	if (_err != noErr) return PyMac_Error(_err);
	_res = Py_BuildValue("h",
	                     outGlyph);
	return _res;
}

static PyObject *MenuObj_MacEnableMenuItem(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	UInt16 item;
	if (!PyArg_ParseTuple(_args, "H",
	                      &item))
		return NULL;
	MacEnableMenuItem(_self->ob_itself,
	                  item);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_DisableMenuItem(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	UInt16 item;
	if (!PyArg_ParseTuple(_args, "H",
	                      &item))
		return NULL;
	DisableMenuItem(_self->ob_itself,
	                item);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_IsMenuItemEnabled(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	UInt16 item;
	if (!PyArg_ParseTuple(_args, "H",
	                      &item))
		return NULL;
	_rv = IsMenuItemEnabled(_self->ob_itself,
	                        item);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *MenuObj_EnableMenuItemIcon(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	UInt16 item;
	if (!PyArg_ParseTuple(_args, "H",
	                      &item))
		return NULL;
	EnableMenuItemIcon(_self->ob_itself,
	                   item);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_DisableMenuItemIcon(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	UInt16 item;
	if (!PyArg_ParseTuple(_args, "H",
	                      &item))
		return NULL;
	DisableMenuItemIcon(_self->ob_itself,
	                    item);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_IsMenuItemIconEnabled(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	UInt16 item;
	if (!PyArg_ParseTuple(_args, "H",
	                      &item))
		return NULL;
	_rv = IsMenuItemIconEnabled(_self->ob_itself,
	                            item);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *MenuObj_as_Resource(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Handle _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = as_Resource(_self->ob_itself);
	_res = Py_BuildValue("O&",
	                     ResObj_New, _rv);
	return _res;
}

static PyObject *MenuObj_AppendMenu(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Str255 data;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetStr255, data))
		return NULL;
	AppendMenu(_self->ob_itself,
	           data);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_InsertMenu(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short beforeID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &beforeID))
		return NULL;
	InsertMenu(_self->ob_itself,
	           beforeID);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *MenuObj_InsertMenuItem(_self, _args)
	MenuObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Str255 itemString;
	short afterItem;
	if (!PyArg_ParseTuple(_args, "O&h",
	                      PyMac_GetStr255, itemString,
	                      &afterItem))
		return NULL;
	InsertMenuItem(_self->ob_itself,
	               itemString,
	               afterItem);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyMethodDef MenuObj_methods[] = {
	{"DisposeMenu", (PyCFunction)MenuObj_DisposeMenu, 1,
	 "() -> None"},
	{"CalcMenuSize", (PyCFunction)MenuObj_CalcMenuSize, 1,
	 "() -> None"},

#ifndef TARGET_API_MAC_CARBON
	{"CountMItems", (PyCFunction)MenuObj_CountMItems, 1,
	 "() -> (short _rv)"},
#endif
	{"GetMenuFont", (PyCFunction)MenuObj_GetMenuFont, 1,
	 "() -> (SInt16 outFontID, UInt16 outFontSize)"},
	{"SetMenuFont", (PyCFunction)MenuObj_SetMenuFont, 1,
	 "(SInt16 inFontID, UInt16 inFontSize) -> None"},
	{"GetMenuExcludesMarkColumn", (PyCFunction)MenuObj_GetMenuExcludesMarkColumn, 1,
	 "() -> (Boolean _rv)"},
	{"SetMenuExcludesMarkColumn", (PyCFunction)MenuObj_SetMenuExcludesMarkColumn, 1,
	 "(Boolean excludesMark) -> None"},
	{"MacAppendMenu", (PyCFunction)MenuObj_MacAppendMenu, 1,
	 "(Str255 data) -> None"},
	{"InsertResMenu", (PyCFunction)MenuObj_InsertResMenu, 1,
	 "(ResType theType, short afterItem) -> None"},
	{"AppendResMenu", (PyCFunction)MenuObj_AppendResMenu, 1,
	 "(ResType theType) -> None"},
	{"MacInsertMenuItem", (PyCFunction)MenuObj_MacInsertMenuItem, 1,
	 "(Str255 itemString, short afterItem) -> None"},
	{"DeleteMenuItem", (PyCFunction)MenuObj_DeleteMenuItem, 1,
	 "(short item) -> None"},
	{"InsertFontResMenu", (PyCFunction)MenuObj_InsertFontResMenu, 1,
	 "(short afterItem, short scriptFilter) -> None"},
	{"InsertIntlResMenu", (PyCFunction)MenuObj_InsertIntlResMenu, 1,
	 "(ResType theType, short afterItem, short scriptFilter) -> None"},
	{"AppendMenuItemText", (PyCFunction)MenuObj_AppendMenuItemText, 1,
	 "(Str255 inString) -> None"},
	{"InsertMenuItemText", (PyCFunction)MenuObj_InsertMenuItemText, 1,
	 "(Str255 inString, UInt16 afterItem) -> None"},
	{"PopUpMenuSelect", (PyCFunction)MenuObj_PopUpMenuSelect, 1,
	 "(short top, short left, short popUpItem) -> (long _rv)"},
	{"MacInsertMenu", (PyCFunction)MenuObj_MacInsertMenu, 1,
	 "(short beforeID) -> None"},

#ifndef TARGET_API_MAC_CARBON
	{"CheckItem", (PyCFunction)MenuObj_CheckItem, 1,
	 "(short item, Boolean checked) -> None"},
#endif
	{"SetMenuItemText", (PyCFunction)MenuObj_SetMenuItemText, 1,
	 "(short item, Str255 itemString) -> None"},
	{"GetMenuItemText", (PyCFunction)MenuObj_GetMenuItemText, 1,
	 "(short item) -> (Str255 itemString)"},
	{"SetItemMark", (PyCFunction)MenuObj_SetItemMark, 1,
	 "(short item, CharParameter markChar) -> None"},
	{"GetItemMark", (PyCFunction)MenuObj_GetItemMark, 1,
	 "(short item) -> (CharParameter markChar)"},
	{"SetItemCmd", (PyCFunction)MenuObj_SetItemCmd, 1,
	 "(short item, CharParameter cmdChar) -> None"},
	{"GetItemCmd", (PyCFunction)MenuObj_GetItemCmd, 1,
	 "(short item) -> (CharParameter cmdChar)"},
	{"SetItemIcon", (PyCFunction)MenuObj_SetItemIcon, 1,
	 "(short item, short iconIndex) -> None"},
	{"GetItemIcon", (PyCFunction)MenuObj_GetItemIcon, 1,
	 "(short item) -> (short iconIndex)"},
	{"SetItemStyle", (PyCFunction)MenuObj_SetItemStyle, 1,
	 "(short item, StyleParameter chStyle) -> None"},
	{"GetItemStyle", (PyCFunction)MenuObj_GetItemStyle, 1,
	 "(short item) -> (Style chStyle)"},

#ifndef TARGET_API_MAC_CARBON
	{"DisableItem", (PyCFunction)MenuObj_DisableItem, 1,
	 "(short item) -> None"},
#endif

#ifndef TARGET_API_MAC_CARBON
	{"EnableItem", (PyCFunction)MenuObj_EnableItem, 1,
	 "(short item) -> None"},
#endif
	{"SetMenuItemCommandID", (PyCFunction)MenuObj_SetMenuItemCommandID, 1,
	 "(SInt16 inItem, UInt32 inCommandID) -> None"},
	{"GetMenuItemCommandID", (PyCFunction)MenuObj_GetMenuItemCommandID, 1,
	 "(SInt16 inItem) -> (UInt32 outCommandID)"},
	{"SetMenuItemModifiers", (PyCFunction)MenuObj_SetMenuItemModifiers, 1,
	 "(SInt16 inItem, UInt8 inModifiers) -> None"},
	{"GetMenuItemModifiers", (PyCFunction)MenuObj_GetMenuItemModifiers, 1,
	 "(SInt16 inItem) -> (UInt8 outModifiers)"},
	{"SetMenuItemIconHandle", (PyCFunction)MenuObj_SetMenuItemIconHandle, 1,
	 "(SInt16 inItem, UInt8 inIconType, Handle inIconHandle) -> None"},
	{"GetMenuItemIconHandle", (PyCFunction)MenuObj_GetMenuItemIconHandle, 1,
	 "(SInt16 inItem) -> (UInt8 outIconType, Handle outIconHandle)"},
	{"SetMenuItemTextEncoding", (PyCFunction)MenuObj_SetMenuItemTextEncoding, 1,
	 "(SInt16 inItem, TextEncoding inScriptID) -> None"},
	{"GetMenuItemTextEncoding", (PyCFunction)MenuObj_GetMenuItemTextEncoding, 1,
	 "(SInt16 inItem) -> (TextEncoding outScriptID)"},
	{"SetMenuItemHierarchicalID", (PyCFunction)MenuObj_SetMenuItemHierarchicalID, 1,
	 "(SInt16 inItem, SInt16 inHierID) -> None"},
	{"GetMenuItemHierarchicalID", (PyCFunction)MenuObj_GetMenuItemHierarchicalID, 1,
	 "(SInt16 inItem) -> (SInt16 outHierID)"},
	{"SetMenuItemFontID", (PyCFunction)MenuObj_SetMenuItemFontID, 1,
	 "(SInt16 inItem, SInt16 inFontID) -> None"},
	{"GetMenuItemFontID", (PyCFunction)MenuObj_GetMenuItemFontID, 1,
	 "(SInt16 inItem) -> (SInt16 outFontID)"},
	{"SetMenuItemRefCon", (PyCFunction)MenuObj_SetMenuItemRefCon, 1,
	 "(SInt16 inItem, UInt32 inRefCon) -> None"},
	{"GetMenuItemRefCon", (PyCFunction)MenuObj_GetMenuItemRefCon, 1,
	 "(SInt16 inItem) -> (UInt32 outRefCon)"},

#ifndef TARGET_API_MAC_CARBON
	{"SetMenuItemRefCon2", (PyCFunction)MenuObj_SetMenuItemRefCon2, 1,
	 "(SInt16 inItem, UInt32 inRefCon2) -> None"},
#endif

#ifndef TARGET_API_MAC_CARBON
	{"GetMenuItemRefCon2", (PyCFunction)MenuObj_GetMenuItemRefCon2, 1,
	 "(SInt16 inItem) -> (UInt32 outRefCon2)"},
#endif
	{"SetMenuItemKeyGlyph", (PyCFunction)MenuObj_SetMenuItemKeyGlyph, 1,
	 "(SInt16 inItem, SInt16 inGlyph) -> None"},
	{"GetMenuItemKeyGlyph", (PyCFunction)MenuObj_GetMenuItemKeyGlyph, 1,
	 "(SInt16 inItem) -> (SInt16 outGlyph)"},
	{"MacEnableMenuItem", (PyCFunction)MenuObj_MacEnableMenuItem, 1,
	 "(UInt16 item) -> None"},
	{"DisableMenuItem", (PyCFunction)MenuObj_DisableMenuItem, 1,
	 "(UInt16 item) -> None"},
	{"IsMenuItemEnabled", (PyCFunction)MenuObj_IsMenuItemEnabled, 1,
	 "(UInt16 item) -> (Boolean _rv)"},
	{"EnableMenuItemIcon", (PyCFunction)MenuObj_EnableMenuItemIcon, 1,
	 "(UInt16 item) -> None"},
	{"DisableMenuItemIcon", (PyCFunction)MenuObj_DisableMenuItemIcon, 1,
	 "(UInt16 item) -> None"},
	{"IsMenuItemIconEnabled", (PyCFunction)MenuObj_IsMenuItemIconEnabled, 1,
	 "(UInt16 item) -> (Boolean _rv)"},
	{"as_Resource", (PyCFunction)MenuObj_as_Resource, 1,
	 "() -> (Handle _rv)"},
	{"AppendMenu", (PyCFunction)MenuObj_AppendMenu, 1,
	 "(Str255 data) -> None"},
	{"InsertMenu", (PyCFunction)MenuObj_InsertMenu, 1,
	 "(short beforeID) -> None"},
	{"InsertMenuItem", (PyCFunction)MenuObj_InsertMenuItem, 1,
	 "(Str255 itemString, short afterItem) -> None"},
	{NULL, NULL, 0}
};

PyMethodChain MenuObj_chain = { MenuObj_methods, NULL };

static PyObject *MenuObj_getattr(self, name)
	MenuObject *self;
	char *name;
{
	return Py_FindMethodInChain(&MenuObj_chain, (PyObject *)self, name);
}

#define MenuObj_setattr NULL

#define MenuObj_compare NULL

#define MenuObj_repr NULL

#define MenuObj_hash NULL

PyTypeObject Menu_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0, /*ob_size*/
	"Menu", /*tp_name*/
	sizeof(MenuObject), /*tp_basicsize*/
	0, /*tp_itemsize*/
	/* methods */
	(destructor) MenuObj_dealloc, /*tp_dealloc*/
	0, /*tp_print*/
	(getattrfunc) MenuObj_getattr, /*tp_getattr*/
	(setattrfunc) MenuObj_setattr, /*tp_setattr*/
	(cmpfunc) MenuObj_compare, /*tp_compare*/
	(reprfunc) MenuObj_repr, /*tp_repr*/
	(PyNumberMethods *)0, /* tp_as_number */
	(PySequenceMethods *)0, /* tp_as_sequence */
	(PyMappingMethods *)0, /* tp_as_mapping */
	(hashfunc) MenuObj_hash, /*tp_hash*/
};

/* ---------------------- End object type Menu ---------------------- */


#ifndef TARGET_API_MAC_CARBON

static PyObject *Menu_InitProcMenu(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short resID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &resID))
		return NULL;
	InitProcMenu(resID);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}
#endif

#ifndef TARGET_API_MAC_CARBON

static PyObject *Menu_InitMenus(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	InitMenus();
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}
#endif

static PyObject *Menu_NewMenu(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	MenuHandle _rv;
	short menuID;
	Str255 menuTitle;
	if (!PyArg_ParseTuple(_args, "hO&",
	                      &menuID,
	                      PyMac_GetStr255, menuTitle))
		return NULL;
	_rv = NewMenu(menuID,
	              menuTitle);
	_res = Py_BuildValue("O&",
	                     MenuObj_New, _rv);
	return _res;
}

static PyObject *Menu_MacGetMenu(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	MenuHandle _rv;
	short resourceID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &resourceID))
		return NULL;
	_rv = MacGetMenu(resourceID);
	_res = Py_BuildValue("O&",
	                     MenuObj_New, _rv);
	return _res;
}

static PyObject *Menu_MenuKey(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	CharParameter ch;
	if (!PyArg_ParseTuple(_args, "h",
	                      &ch))
		return NULL;
	_rv = MenuKey(ch);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *Menu_MenuSelect(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	Point startPt;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetPoint, &startPt))
		return NULL;
	_rv = MenuSelect(startPt);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *Menu_MenuChoice(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = MenuChoice();
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *Menu_MenuEvent(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	UInt32 _rv;
	EventRecord inEvent;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetEventRecord, &inEvent))
		return NULL;
	_rv = MenuEvent(&inEvent);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *Menu_GetMBarHeight(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetMBarHeight();
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *Menu_MacDrawMenuBar(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	MacDrawMenuBar();
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Menu_InvalMenuBar(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	InvalMenuBar();
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Menu_HiliteMenu(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short menuID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &menuID))
		return NULL;
	HiliteMenu(menuID);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Menu_GetNewMBar(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Handle _rv;
	short menuBarID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &menuBarID))
		return NULL;
	_rv = GetNewMBar(menuBarID);
	_res = Py_BuildValue("O&",
	                     ResObj_New, _rv);
	return _res;
}

static PyObject *Menu_GetMenuBar(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Handle _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = GetMenuBar();
	_res = Py_BuildValue("O&",
	                     ResObj_New, _rv);
	return _res;
}

static PyObject *Menu_SetMenuBar(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Handle menuList;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &menuList))
		return NULL;
	SetMenuBar(menuList);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Menu_GetMenuHandle(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	MenuHandle _rv;
	short menuID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &menuID))
		return NULL;
	_rv = GetMenuHandle(menuID);
	_res = Py_BuildValue("O&",
	                     MenuObj_New, _rv);
	return _res;
}

static PyObject *Menu_MacDeleteMenu(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short menuID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &menuID))
		return NULL;
	MacDeleteMenu(menuID);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Menu_ClearMenuBar(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	ClearMenuBar();
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

#ifndef TARGET_API_MAC_CARBON

static PyObject *Menu_SetMenuFlash(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short count;
	if (!PyArg_ParseTuple(_args, "h",
	                      &count))
		return NULL;
	SetMenuFlash(count);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}
#endif

static PyObject *Menu_FlashMenuBar(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short menuID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &menuID))
		return NULL;
	FlashMenuBar(menuID);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

#ifndef TARGET_API_MAC_CARBON

static PyObject *Menu_SystemEdit(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	short editCmd;
	if (!PyArg_ParseTuple(_args, "h",
	                      &editCmd))
		return NULL;
	_rv = SystemEdit(editCmd);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}
#endif

#ifndef TARGET_API_MAC_CARBON

static PyObject *Menu_SystemMenu(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	long menuResult;
	if (!PyArg_ParseTuple(_args, "l",
	                      &menuResult))
		return NULL;
	SystemMenu(menuResult);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}
#endif

static PyObject *Menu_IsMenuBarVisible(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = IsMenuBarVisible();
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *Menu_ShowMenuBar(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	ShowMenuBar();
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Menu_HideMenuBar(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	HideMenuBar();
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Menu_DeleteMCEntries(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short menuID;
	short menuItem;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &menuID,
	                      &menuItem))
		return NULL;
	DeleteMCEntries(menuID,
	                menuItem);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Menu_InitContextualMenus(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	OSStatus _err;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_err = InitContextualMenus();
	if (_err != noErr) return PyMac_Error(_err);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Menu_IsShowContextualMenuClick(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Boolean _rv;
	EventRecord inEvent;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetEventRecord, &inEvent))
		return NULL;
	_rv = IsShowContextualMenuClick(&inEvent);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

#ifndef TARGET_API_MAC_CARBON

static PyObject *Menu_OpenDeskAcc(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	Str255 name;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetStr255, name))
		return NULL;
	OpenDeskAcc(name);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}
#endif

static PyObject *Menu_as_Menu(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	MenuHandle _rv;
	Handle h;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &h))
		return NULL;
	_rv = as_Menu(h);
	_res = Py_BuildValue("O&",
	                     MenuObj_New, _rv);
	return _res;
}

static PyObject *Menu_GetMenu(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	MenuHandle _rv;
	short resourceID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &resourceID))
		return NULL;
	_rv = GetMenu(resourceID);
	_res = Py_BuildValue("O&",
	                     MenuObj_New, _rv);
	return _res;
}

static PyObject *Menu_DeleteMenu(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	short menuID;
	if (!PyArg_ParseTuple(_args, "h",
	                      &menuID))
		return NULL;
	DeleteMenu(menuID);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *Menu_DrawMenuBar(_self, _args)
	PyObject *_self;
	PyObject *_args;
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	DrawMenuBar();
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyMethodDef Menu_methods[] = {

#ifndef TARGET_API_MAC_CARBON
	{"InitProcMenu", (PyCFunction)Menu_InitProcMenu, 1,
	 "(short resID) -> None"},
#endif

#ifndef TARGET_API_MAC_CARBON
	{"InitMenus", (PyCFunction)Menu_InitMenus, 1,
	 "() -> None"},
#endif
	{"NewMenu", (PyCFunction)Menu_NewMenu, 1,
	 "(short menuID, Str255 menuTitle) -> (MenuHandle _rv)"},
	{"MacGetMenu", (PyCFunction)Menu_MacGetMenu, 1,
	 "(short resourceID) -> (MenuHandle _rv)"},
	{"MenuKey", (PyCFunction)Menu_MenuKey, 1,
	 "(CharParameter ch) -> (long _rv)"},
	{"MenuSelect", (PyCFunction)Menu_MenuSelect, 1,
	 "(Point startPt) -> (long _rv)"},
	{"MenuChoice", (PyCFunction)Menu_MenuChoice, 1,
	 "() -> (long _rv)"},
	{"MenuEvent", (PyCFunction)Menu_MenuEvent, 1,
	 "(EventRecord inEvent) -> (UInt32 _rv)"},
	{"GetMBarHeight", (PyCFunction)Menu_GetMBarHeight, 1,
	 "() -> (short _rv)"},
	{"MacDrawMenuBar", (PyCFunction)Menu_MacDrawMenuBar, 1,
	 "() -> None"},
	{"InvalMenuBar", (PyCFunction)Menu_InvalMenuBar, 1,
	 "() -> None"},
	{"HiliteMenu", (PyCFunction)Menu_HiliteMenu, 1,
	 "(short menuID) -> None"},
	{"GetNewMBar", (PyCFunction)Menu_GetNewMBar, 1,
	 "(short menuBarID) -> (Handle _rv)"},
	{"GetMenuBar", (PyCFunction)Menu_GetMenuBar, 1,
	 "() -> (Handle _rv)"},
	{"SetMenuBar", (PyCFunction)Menu_SetMenuBar, 1,
	 "(Handle menuList) -> None"},
	{"GetMenuHandle", (PyCFunction)Menu_GetMenuHandle, 1,
	 "(short menuID) -> (MenuHandle _rv)"},
	{"MacDeleteMenu", (PyCFunction)Menu_MacDeleteMenu, 1,
	 "(short menuID) -> None"},
	{"ClearMenuBar", (PyCFunction)Menu_ClearMenuBar, 1,
	 "() -> None"},

#ifndef TARGET_API_MAC_CARBON
	{"SetMenuFlash", (PyCFunction)Menu_SetMenuFlash, 1,
	 "(short count) -> None"},
#endif
	{"FlashMenuBar", (PyCFunction)Menu_FlashMenuBar, 1,
	 "(short menuID) -> None"},

#ifndef TARGET_API_MAC_CARBON
	{"SystemEdit", (PyCFunction)Menu_SystemEdit, 1,
	 "(short editCmd) -> (Boolean _rv)"},
#endif

#ifndef TARGET_API_MAC_CARBON
	{"SystemMenu", (PyCFunction)Menu_SystemMenu, 1,
	 "(long menuResult) -> None"},
#endif
	{"IsMenuBarVisible", (PyCFunction)Menu_IsMenuBarVisible, 1,
	 "() -> (Boolean _rv)"},
	{"ShowMenuBar", (PyCFunction)Menu_ShowMenuBar, 1,
	 "() -> None"},
	{"HideMenuBar", (PyCFunction)Menu_HideMenuBar, 1,
	 "() -> None"},
	{"DeleteMCEntries", (PyCFunction)Menu_DeleteMCEntries, 1,
	 "(short menuID, short menuItem) -> None"},
	{"InitContextualMenus", (PyCFunction)Menu_InitContextualMenus, 1,
	 "() -> None"},
	{"IsShowContextualMenuClick", (PyCFunction)Menu_IsShowContextualMenuClick, 1,
	 "(EventRecord inEvent) -> (Boolean _rv)"},

#ifndef TARGET_API_MAC_CARBON
	{"OpenDeskAcc", (PyCFunction)Menu_OpenDeskAcc, 1,
	 "(Str255 name) -> None"},
#endif
	{"as_Menu", (PyCFunction)Menu_as_Menu, 1,
	 "(Handle h) -> (MenuHandle _rv)"},
	{"GetMenu", (PyCFunction)Menu_GetMenu, 1,
	 "(short resourceID) -> (MenuHandle _rv)"},
	{"DeleteMenu", (PyCFunction)Menu_DeleteMenu, 1,
	 "(short menuID) -> None"},
	{"DrawMenuBar", (PyCFunction)Menu_DrawMenuBar, 1,
	 "() -> None"},
	{NULL, NULL, 0}
};




void initMenu()
{
	PyObject *m;
	PyObject *d;




	m = Py_InitModule("Menu", Menu_methods);
	d = PyModule_GetDict(m);
	Menu_Error = PyMac_GetOSErrException();
	if (Menu_Error == NULL ||
	    PyDict_SetItemString(d, "Error", Menu_Error) != 0)
		Py_FatalError("can't initialize Menu.Error");
	Menu_Type.ob_type = &PyType_Type;
	Py_INCREF(&Menu_Type);
	if (PyDict_SetItemString(d, "MenuType", (PyObject *)&Menu_Type) != 0)
		Py_FatalError("can't initialize MenuType");
}

/* ======================== End module Menu ========================= */

