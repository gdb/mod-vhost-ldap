
/* ========================== Module _List ========================== */

#include "Python.h"



#ifdef _WIN32
#include "pywintoolbox.h"
#else
#include "macglue.h"
#include "pymactoolbox.h"
#endif

/* Macro to test whether a weak-loaded CFM function exists */
#define PyMac_PRECHECK(rtn) do { if ( &rtn == NULL )  {\
    	PyErr_SetString(PyExc_NotImplementedError, \
    	"Not available in this shared library/OS version"); \
    	return NULL; \
    }} while(0)


#ifdef WITHOUT_FRAMEWORKS
#include <Lists.h>
#else
#include <Carbon/Carbon.h>
#endif

#ifdef USE_TOOLBOX_OBJECT_GLUE
extern PyObject *_ListObj_New(ListHandle);
extern int _ListObj_Convert(PyObject *, ListHandle *);

#define ListObj_New _ListObj_New
#define ListObj_Convert _ListObj_Convert
#endif

#if !ACCESSOR_CALLS_ARE_FUNCTIONS
#define GetListPort(list) ((CGrafPtr)(*(list))->port)
#define GetListVerticalScrollBar(list) ((*(list))->vScroll)
#define GetListHorizontalScrollBar(list) ((*(list))->hScroll)
#define GetListActive(list) ((*(list))->lActive)
#define GetListClickTime(list) ((*(list))->clikTime)
#define GetListRefCon(list) ((*(list))->refCon)
#define GetListDefinition(list) ((*(list))->listDefProc) /* XXX Is this indeed the same? */
#define GetListUserHandle(list) ((*(list))->userHandle)
#define GetListDataHandle(list) ((*(list))->cells)
#define GetListFlags(list) ((*(list))->listFlags)
#define GetListSelectionFlags(list) ((*(list))->selFlags)
#define SetListViewBounds(list, bounds) (((*(list))->rView) = *(bounds))

#define SetListPort(list, port) (((*(list))->port) = (GrafPtr)(port))
#define SetListCellIndent(list, ind) (((*(list))->indent) = *(ind))
#define SetListClickTime(list, time) (((*(list))->clikTime) = (time))
#define SetListLastClick(list, click) (((*(list)->lastClick) = *(click))
#define SetListRefCon(list, refcon) (((*(list))->refCon) = (refcon))
#define SetListUserHandle(list, handle) (((*(list))->userHandle) = (handle))
#define SetListFlags(list, flags) (((*(list))->listFlags) = (flags))
#define SetListSelectionFlags(list, flags) (((*(list))->selFlags) = (flags))

#endif

#define as_List(x) ((ListHandle)x)
#define as_Resource(lh) ((Handle)lh)

static ListDefUPP myListDefFunctionUPP;

#if !TARGET_API_MAC_CARBON

#define kJumpAbs 0x4EF9

#pragma options align=mac68k
typedef struct {
	short jmpabs;       /* 4EF9 */
	ListDefUPP theUPP;  /* 00000000 */
} LDEFStub, **LDEFStubHandle;
#pragma options align=reset

static OSErr installLDEFStub(ListHandle list) {
	LDEFStubHandle stubH;

	stubH = (LDEFStubHandle)NewHandleClear(sizeof(LDEFStub));
	if (stubH == NULL)
		return MemError();
	
	(*stubH)->jmpabs = kJumpAbs;
	(*stubH)->theUPP = myListDefFunctionUPP;
	HLock((Handle) stubH);
	
	(*list)->listDefProc = (Handle)stubH;
	return noErr;
}

static void removeLDEFStub(ListHandle list) {
	if ((*list)->listDefProc)
		DisposeHandle((Handle)(*list)->listDefProc);
	(*list)->listDefProc = NULL;
}

#endif

static PyObject *List_Error;

/* ------------------------ Object type List ------------------------ */

PyTypeObject List_Type;

#define ListObj_Check(x) ((x)->ob_type == &List_Type)

typedef struct ListObject {
	PyObject_HEAD
	ListHandle ob_itself;
	PyObject *ob_ldef_func;
	int ob_have_ldef_stub;
	int ob_must_be_disposed;
} ListObject;

PyObject *ListObj_New(ListHandle itself)
{
	ListObject *it;
	if (itself == NULL) {
						PyErr_SetString(List_Error,"Cannot create null List");
						return NULL;
					}
	it = PyObject_NEW(ListObject, &List_Type);
	if (it == NULL) return NULL;
	it->ob_itself = itself;
	it->ob_ldef_func = NULL;
	it->ob_have_ldef_stub = 0;
	it->ob_must_be_disposed = 1;
	SetListRefCon(itself, (long)it);
	return (PyObject *)it;
}
int ListObj_Convert(PyObject *v, ListHandle *p_itself)
{
	if (!ListObj_Check(v))
	{
		PyErr_SetString(PyExc_TypeError, "List required");
		return 0;
	}
	*p_itself = ((ListObject *)v)->ob_itself;
	return 1;
}

static void ListObj_dealloc(ListObject *self)
{
	Py_XDECREF(self->ob_ldef_func);
	self->ob_ldef_func = NULL;
#if !TARGET_API_MAC_CARBON
	if (self->ob_have_ldef_stub) removeLDEFStub(self->ob_itself);
#endif
	SetListRefCon(self->ob_itself, (long)0);
	if (self->ob_must_be_disposed && self->ob_itself) LDispose(self->ob_itself);
	PyObject_Del(self);
}

static PyObject *ListObj_LAddColumn(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	short _rv;
	short count;
	short colNum;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &count,
	                      &colNum))
		return NULL;
	_rv = LAddColumn(count,
	                 colNum,
	                 _self->ob_itself);
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *ListObj_LAddRow(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	short _rv;
	short count;
	short rowNum;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &count,
	                      &rowNum))
		return NULL;
	_rv = LAddRow(count,
	              rowNum,
	              _self->ob_itself);
	_res = Py_BuildValue("h",
	                     _rv);
	return _res;
}

static PyObject *ListObj_LDelColumn(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	short count;
	short colNum;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &count,
	                      &colNum))
		return NULL;
	LDelColumn(count,
	           colNum,
	           _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LDelRow(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	short count;
	short rowNum;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &count,
	                      &rowNum))
		return NULL;
	LDelRow(count,
	        rowNum,
	        _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LGetSelect(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Boolean _rv;
	Boolean next;
	Point theCell;
	if (!PyArg_ParseTuple(_args, "bO&",
	                      &next,
	                      PyMac_GetPoint, &theCell))
		return NULL;
	_rv = LGetSelect(next,
	                 &theCell,
	                 _self->ob_itself);
	_res = Py_BuildValue("bO&",
	                     _rv,
	                     PyMac_BuildPoint, theCell);
	return _res;
}

static PyObject *ListObj_LLastClick(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Point _rv;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	_rv = LLastClick(_self->ob_itself);
	_res = Py_BuildValue("O&",
	                     PyMac_BuildPoint, _rv);
	return _res;
}

static PyObject *ListObj_LNextCell(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Boolean _rv;
	Boolean hNext;
	Boolean vNext;
	Point theCell;
	if (!PyArg_ParseTuple(_args, "bbO&",
	                      &hNext,
	                      &vNext,
	                      PyMac_GetPoint, &theCell))
		return NULL;
	_rv = LNextCell(hNext,
	                vNext,
	                &theCell,
	                _self->ob_itself);
	_res = Py_BuildValue("bO&",
	                     _rv,
	                     PyMac_BuildPoint, theCell);
	return _res;
}

static PyObject *ListObj_LSize(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	short listWidth;
	short listHeight;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &listWidth,
	                      &listHeight))
		return NULL;
	LSize(listWidth,
	      listHeight,
	      _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LSetDrawingMode(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Boolean drawIt;
	if (!PyArg_ParseTuple(_args, "b",
	                      &drawIt))
		return NULL;
	LSetDrawingMode(drawIt,
	                _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LScroll(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	short dCols;
	short dRows;
	if (!PyArg_ParseTuple(_args, "hh",
	                      &dCols,
	                      &dRows))
		return NULL;
	LScroll(dCols,
	        dRows,
	        _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LAutoScroll(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	if (!PyArg_ParseTuple(_args, ""))
		return NULL;
	LAutoScroll(_self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LUpdate(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	RgnHandle theRgn;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ResObj_Convert, &theRgn))
		return NULL;
	LUpdate(theRgn,
	        _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LActivate(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Boolean act;
	if (!PyArg_ParseTuple(_args, "b",
	                      &act))
		return NULL;
	LActivate(act,
	          _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LCellSize(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Point cSize;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetPoint, &cSize))
		return NULL;
	LCellSize(cSize,
	          _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LClick(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Boolean _rv;
	Point pt;
	EventModifiers modifiers;
	if (!PyArg_ParseTuple(_args, "O&H",
	                      PyMac_GetPoint, &pt,
	                      &modifiers))
		return NULL;
	_rv = LClick(pt,
	             modifiers,
	             _self->ob_itself);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *ListObj_LAddToCell(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	char *dataPtr__in__;
	short dataPtr__len__;
	int dataPtr__in_len__;
	Point theCell;
	if (!PyArg_ParseTuple(_args, "s#O&",
	                      &dataPtr__in__, &dataPtr__in_len__,
	                      PyMac_GetPoint, &theCell))
		return NULL;
	dataPtr__len__ = dataPtr__in_len__;
	LAddToCell(dataPtr__in__, dataPtr__len__,
	           theCell,
	           _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LClrCell(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Point theCell;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetPoint, &theCell))
		return NULL;
	LClrCell(theCell,
	         _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LGetCell(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	char *dataPtr__out__;
	short dataPtr__len__;
	int dataPtr__in_len__;
	Point theCell;
	if (!PyArg_ParseTuple(_args, "iO&",
	                      &dataPtr__in_len__,
	                      PyMac_GetPoint, &theCell))
		return NULL;
	if ((dataPtr__out__ = malloc(dataPtr__in_len__)) == NULL)
	{
		PyErr_NoMemory();
		goto dataPtr__error__;
	}
	dataPtr__len__ = dataPtr__in_len__;
	LGetCell(dataPtr__out__, &dataPtr__len__,
	         theCell,
	         _self->ob_itself);
	_res = Py_BuildValue("s#",
	                     dataPtr__out__, (int)dataPtr__len__);
	free(dataPtr__out__);
 dataPtr__error__: ;
	return _res;
}

static PyObject *ListObj_LRect(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Rect cellRect;
	Point theCell;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetPoint, &theCell))
		return NULL;
	LRect(&cellRect,
	      theCell,
	      _self->ob_itself);
	_res = Py_BuildValue("O&",
	                     PyMac_BuildRect, &cellRect);
	return _res;
}

static PyObject *ListObj_LSetCell(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	char *dataPtr__in__;
	short dataPtr__len__;
	int dataPtr__in_len__;
	Point theCell;
	if (!PyArg_ParseTuple(_args, "s#O&",
	                      &dataPtr__in__, &dataPtr__in_len__,
	                      PyMac_GetPoint, &theCell))
		return NULL;
	dataPtr__len__ = dataPtr__in_len__;
	LSetCell(dataPtr__in__, dataPtr__len__,
	         theCell,
	         _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LSetSelect(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Boolean setIt;
	Point theCell;
	if (!PyArg_ParseTuple(_args, "bO&",
	                      &setIt,
	                      PyMac_GetPoint, &theCell))
		return NULL;
	LSetSelect(setIt,
	           theCell,
	           _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LDraw(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Point theCell;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetPoint, &theCell))
		return NULL;
	LDraw(theCell,
	      _self->ob_itself);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *ListObj_LGetCellDataLocation(ListObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	short offset;
	short len;
	Point theCell;
	if (!PyArg_ParseTuple(_args, "O&",
	                      PyMac_GetPoint, &theCell))
		return NULL;
	LGetCellDataLocation(&offset,
	                     &len,
	                     theCell,
	                     _self->ob_itself);
	_res = Py_BuildValue("hh",
	                     offset,
	                     len);
	return _res;
}

static PyObject *ListObj_as_Resource(ListObject *_self, PyObject *_args)
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

static PyMethodDef ListObj_methods[] = {
	{"LAddColumn", (PyCFunction)ListObj_LAddColumn, 1,
	 "(short count, short colNum) -> (short _rv)"},
	{"LAddRow", (PyCFunction)ListObj_LAddRow, 1,
	 "(short count, short rowNum) -> (short _rv)"},
	{"LDelColumn", (PyCFunction)ListObj_LDelColumn, 1,
	 "(short count, short colNum) -> None"},
	{"LDelRow", (PyCFunction)ListObj_LDelRow, 1,
	 "(short count, short rowNum) -> None"},
	{"LGetSelect", (PyCFunction)ListObj_LGetSelect, 1,
	 "(Boolean next, Point theCell) -> (Boolean _rv, Point theCell)"},
	{"LLastClick", (PyCFunction)ListObj_LLastClick, 1,
	 "() -> (Point _rv)"},
	{"LNextCell", (PyCFunction)ListObj_LNextCell, 1,
	 "(Boolean hNext, Boolean vNext, Point theCell) -> (Boolean _rv, Point theCell)"},
	{"LSize", (PyCFunction)ListObj_LSize, 1,
	 "(short listWidth, short listHeight) -> None"},
	{"LSetDrawingMode", (PyCFunction)ListObj_LSetDrawingMode, 1,
	 "(Boolean drawIt) -> None"},
	{"LScroll", (PyCFunction)ListObj_LScroll, 1,
	 "(short dCols, short dRows) -> None"},
	{"LAutoScroll", (PyCFunction)ListObj_LAutoScroll, 1,
	 "() -> None"},
	{"LUpdate", (PyCFunction)ListObj_LUpdate, 1,
	 "(RgnHandle theRgn) -> None"},
	{"LActivate", (PyCFunction)ListObj_LActivate, 1,
	 "(Boolean act) -> None"},
	{"LCellSize", (PyCFunction)ListObj_LCellSize, 1,
	 "(Point cSize) -> None"},
	{"LClick", (PyCFunction)ListObj_LClick, 1,
	 "(Point pt, EventModifiers modifiers) -> (Boolean _rv)"},
	{"LAddToCell", (PyCFunction)ListObj_LAddToCell, 1,
	 "(Buffer dataPtr, Point theCell) -> None"},
	{"LClrCell", (PyCFunction)ListObj_LClrCell, 1,
	 "(Point theCell) -> None"},
	{"LGetCell", (PyCFunction)ListObj_LGetCell, 1,
	 "(Buffer dataPtr, Point theCell) -> (Buffer dataPtr)"},
	{"LRect", (PyCFunction)ListObj_LRect, 1,
	 "(Point theCell) -> (Rect cellRect)"},
	{"LSetCell", (PyCFunction)ListObj_LSetCell, 1,
	 "(Buffer dataPtr, Point theCell) -> None"},
	{"LSetSelect", (PyCFunction)ListObj_LSetSelect, 1,
	 "(Boolean setIt, Point theCell) -> None"},
	{"LDraw", (PyCFunction)ListObj_LDraw, 1,
	 "(Point theCell) -> None"},
	{"LGetCellDataLocation", (PyCFunction)ListObj_LGetCellDataLocation, 1,
	 "(Point theCell) -> (short offset, short len)"},
	{"as_Resource", (PyCFunction)ListObj_as_Resource, 1,
	 "() -> (Handle _rv)"},
	{NULL, NULL, 0}
};

PyMethodChain ListObj_chain = { ListObj_methods, NULL };

static PyObject *ListObj_getattr(ListObject *self, char *name)
{
	{
		if ( strcmp(name, "listFlags") == 0 )
			return Py_BuildValue("l", (long)GetListFlags(self->ob_itself) & 0xff);
		if ( strcmp(name, "selFlags") == 0 )
			return Py_BuildValue("l", (long)GetListSelectionFlags(self->ob_itself) & 0xff);
		if ( strcmp(name, "cellSize") == 0 )
			return Py_BuildValue("O&", PyMac_BuildPoint, (*self->ob_itself)->cellSize);
	}
	return Py_FindMethodInChain(&ListObj_chain, (PyObject *)self, name);
}

static int
ListObj_setattr(ListObject *self, char *name, PyObject *value)
{
	long intval;
	int err = 0;
	
	if ( value == NULL ) {
		PyErr_SetString(PyExc_AttributeError, "Cannot delete attribute");
		return -1;
	}
	if (strcmp(name, "listFlags") == 0 )
		err = PyArg_Parse(value, "B", &(*self->ob_itself)->listFlags);
	else if (strcmp(name, "selFlags") == 0 )
		err = PyArg_Parse(value, "B", &(*self->ob_itself)->selFlags);
	else if (strcmp(name, "cellSize") == 0 )
		err = PyArg_Parse(value, "O&", PyMac_GetPoint, &(*self->ob_itself)->cellSize);
	else
		PyErr_SetString(PyExc_AttributeError, "No such attribute");
	if (err) return 0;
	else return -1;
}


#define ListObj_compare NULL

#define ListObj_repr NULL

#define ListObj_hash NULL

PyTypeObject List_Type = {
	PyObject_HEAD_INIT(NULL)
	0, /*ob_size*/
	"_List.List", /*tp_name*/
	sizeof(ListObject), /*tp_basicsize*/
	0, /*tp_itemsize*/
	/* methods */
	(destructor) ListObj_dealloc, /*tp_dealloc*/
	0, /*tp_print*/
	(getattrfunc) ListObj_getattr, /*tp_getattr*/
	(setattrfunc) ListObj_setattr, /*tp_setattr*/
	(cmpfunc) ListObj_compare, /*tp_compare*/
	(reprfunc) ListObj_repr, /*tp_repr*/
	(PyNumberMethods *)0, /* tp_as_number */
	(PySequenceMethods *)0, /* tp_as_sequence */
	(PyMappingMethods *)0, /* tp_as_mapping */
	(hashfunc) ListObj_hash, /*tp_hash*/
};

/* ---------------------- End object type List ---------------------- */


static PyObject *List_CreateCustomList(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Rect rView;
	Rect dataBounds;
	Point cellSize;

	PyObject *listDefFunc;
	ListDefSpec theSpec;
	WindowPtr theWindow;
	Boolean drawIt;
	Boolean hasGrow;
	Boolean scrollHoriz;
	Boolean scrollVert;
	ListHandle outList;

	if (!PyArg_ParseTuple(_args, "O&O&O&(iO)O&bbbb",
	                      PyMac_GetRect, &rView,
	                      PyMac_GetRect, &dataBounds,
	                      PyMac_GetPoint, &cellSize,
	                      &theSpec.defType, &listDefFunc,
	                      WinObj_Convert, &theWindow,
	                      &drawIt,
	                      &hasGrow,
	                      &scrollHoriz,
	                      &scrollVert))
		return NULL;


#if TARGET_API_MAC_CARBON
	/* Carbon applications use the CreateCustomList API */ 
	theSpec.u.userProc = myListDefFunctionUPP;
	CreateCustomList(&rView,
	                 &dataBounds,
	                 cellSize,
	                 &theSpec,
	                 theWindow,
	                 drawIt,
	                 hasGrow,
	                 scrollHoriz,
	                 scrollVert,
	                 &outList);

#else
	/* pre-Carbon applications set the address in the LDEF
	to a routine descriptor referring to their list
	definition routine. */
	outList = LNew(&rView,
	               &dataBounds,
	               cellSize,
	               0,
	               theWindow,
	               drawIt, /* XXX must be false */
	               hasGrow,
	               scrollHoriz,
	               scrollVert);
	if (installLDEFStub(outList) != noErr) {
		PyErr_SetString(PyExc_MemoryError, "can't create LDEF stub");
		return NULL;
	}
#endif

	_res = ListObj_New(outList);
	if (_res == NULL)
		return NULL;
	Py_INCREF(listDefFunc);
	((ListObject*)_res)->ob_ldef_func = listDefFunc;
#if !TARGET_API_MAC_CARBON
	((ListObject*)_res)->ob_have_ldef_stub = 1;
#endif
	return _res;
}

static PyObject *List_LNew(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ListHandle _rv;
	Rect rView;
	Rect dataBounds;
	Point cSize;
	short theProc;
	WindowPtr theWindow;
	Boolean drawIt;
	Boolean hasGrow;
	Boolean scrollHoriz;
	Boolean scrollVert;
	if (!PyArg_ParseTuple(_args, "O&O&O&hO&bbbb",
	                      PyMac_GetRect, &rView,
	                      PyMac_GetRect, &dataBounds,
	                      PyMac_GetPoint, &cSize,
	                      &theProc,
	                      WinObj_Convert, &theWindow,
	                      &drawIt,
	                      &hasGrow,
	                      &scrollHoriz,
	                      &scrollVert))
		return NULL;
	_rv = LNew(&rView,
	           &dataBounds,
	           cSize,
	           theProc,
	           theWindow,
	           drawIt,
	           hasGrow,
	           scrollHoriz,
	           scrollVert);
	_res = Py_BuildValue("O&",
	                     ListObj_New, _rv);
	return _res;
}

static PyObject *List_GetListPort(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	CGrafPtr _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListPort(list);
	_res = Py_BuildValue("O&",
	                     GrafObj_New, _rv);
	return _res;
}

static PyObject *List_GetListVerticalScrollBar(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ControlHandle _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListVerticalScrollBar(list);
	_res = Py_BuildValue("O&",
	                     CtlObj_New, _rv);
	return _res;
}

static PyObject *List_GetListHorizontalScrollBar(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ControlHandle _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListHorizontalScrollBar(list);
	_res = Py_BuildValue("O&",
	                     CtlObj_New, _rv);
	return _res;
}

static PyObject *List_GetListActive(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Boolean _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListActive(list);
	_res = Py_BuildValue("b",
	                     _rv);
	return _res;
}

static PyObject *List_GetListClickTime(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	SInt32 _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListClickTime(list);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *List_GetListRefCon(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	SInt32 _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListRefCon(list);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *List_GetListDefinition(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Handle _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListDefinition(list);
	_res = Py_BuildValue("O&",
	                     ResObj_New, _rv);
	return _res;
}

static PyObject *List_GetListUserHandle(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	Handle _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListUserHandle(list);
	_res = Py_BuildValue("O&",
	                     ResObj_New, _rv);
	return _res;
}

static PyObject *List_GetListDataHandle(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	DataHandle _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListDataHandle(list);
	_res = Py_BuildValue("O&",
	                     ResObj_New, _rv);
	return _res;
}

static PyObject *List_GetListFlags(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	OptionBits _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListFlags(list);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *List_GetListSelectionFlags(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	OptionBits _rv;
	ListHandle list;
	if (!PyArg_ParseTuple(_args, "O&",
	                      ListObj_Convert, &list))
		return NULL;
	_rv = GetListSelectionFlags(list);
	_res = Py_BuildValue("l",
	                     _rv);
	return _res;
}

static PyObject *List_SetListViewBounds(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ListHandle list;
	Rect view;
	if (!PyArg_ParseTuple(_args, "O&O&",
	                      ListObj_Convert, &list,
	                      PyMac_GetRect, &view))
		return NULL;
	SetListViewBounds(list,
	                  &view);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *List_SetListPort(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ListHandle list;
	CGrafPtr port;
	if (!PyArg_ParseTuple(_args, "O&O&",
	                      ListObj_Convert, &list,
	                      GrafObj_Convert, &port))
		return NULL;
	SetListPort(list,
	            port);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *List_SetListCellIndent(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ListHandle list;
	Point indent;
	if (!PyArg_ParseTuple(_args, "O&O&",
	                      ListObj_Convert, &list,
	                      PyMac_GetPoint, &indent))
		return NULL;
	SetListCellIndent(list,
	                  &indent);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *List_SetListClickTime(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ListHandle list;
	SInt32 time;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      ListObj_Convert, &list,
	                      &time))
		return NULL;
	SetListClickTime(list,
	                 time);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *List_SetListRefCon(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ListHandle list;
	SInt32 refCon;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      ListObj_Convert, &list,
	                      &refCon))
		return NULL;
	SetListRefCon(list,
	              refCon);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *List_SetListUserHandle(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ListHandle list;
	Handle userHandle;
	if (!PyArg_ParseTuple(_args, "O&O&",
	                      ListObj_Convert, &list,
	                      ResObj_Convert, &userHandle))
		return NULL;
	SetListUserHandle(list,
	                  userHandle);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *List_SetListFlags(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ListHandle list;
	OptionBits listFlags;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      ListObj_Convert, &list,
	                      &listFlags))
		return NULL;
	SetListFlags(list,
	             listFlags);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *List_SetListSelectionFlags(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;
	ListHandle list;
	OptionBits selectionFlags;
	if (!PyArg_ParseTuple(_args, "O&l",
	                      ListObj_Convert, &list,
	                      &selectionFlags))
		return NULL;
	SetListSelectionFlags(list,
	                      selectionFlags);
	Py_INCREF(Py_None);
	_res = Py_None;
	return _res;
}

static PyObject *List_as_List(PyObject *_self, PyObject *_args)
{
	PyObject *_res = NULL;

	Handle h;
	ListObject *l;
	if (!PyArg_ParseTuple(_args, "O&", ResObj_Convert, &h))
		return NULL;
	l = (ListObject *)ListObj_New(as_List(h));
	l->ob_must_be_disposed = 0;
	_res = Py_BuildValue("O", l);
	return _res;

}

static PyMethodDef List_methods[] = {
	{"CreateCustomList", (PyCFunction)List_CreateCustomList, 1,
	 "(Rect rView, Rect dataBounds, Point cellSize, ListDefSpec theSpec, WindowPtr theWindow, Boolean drawIt, Boolean hasGrow, Boolean scrollHoriz, Boolean scrollVert) -> (ListHandle outList)"},
	{"LNew", (PyCFunction)List_LNew, 1,
	 "(Rect rView, Rect dataBounds, Point cSize, short theProc, WindowPtr theWindow, Boolean drawIt, Boolean hasGrow, Boolean scrollHoriz, Boolean scrollVert) -> (ListHandle _rv)"},
	{"GetListPort", (PyCFunction)List_GetListPort, 1,
	 "(ListHandle list) -> (CGrafPtr _rv)"},
	{"GetListVerticalScrollBar", (PyCFunction)List_GetListVerticalScrollBar, 1,
	 "(ListHandle list) -> (ControlHandle _rv)"},
	{"GetListHorizontalScrollBar", (PyCFunction)List_GetListHorizontalScrollBar, 1,
	 "(ListHandle list) -> (ControlHandle _rv)"},
	{"GetListActive", (PyCFunction)List_GetListActive, 1,
	 "(ListHandle list) -> (Boolean _rv)"},
	{"GetListClickTime", (PyCFunction)List_GetListClickTime, 1,
	 "(ListHandle list) -> (SInt32 _rv)"},
	{"GetListRefCon", (PyCFunction)List_GetListRefCon, 1,
	 "(ListHandle list) -> (SInt32 _rv)"},
	{"GetListDefinition", (PyCFunction)List_GetListDefinition, 1,
	 "(ListHandle list) -> (Handle _rv)"},
	{"GetListUserHandle", (PyCFunction)List_GetListUserHandle, 1,
	 "(ListHandle list) -> (Handle _rv)"},
	{"GetListDataHandle", (PyCFunction)List_GetListDataHandle, 1,
	 "(ListHandle list) -> (DataHandle _rv)"},
	{"GetListFlags", (PyCFunction)List_GetListFlags, 1,
	 "(ListHandle list) -> (OptionBits _rv)"},
	{"GetListSelectionFlags", (PyCFunction)List_GetListSelectionFlags, 1,
	 "(ListHandle list) -> (OptionBits _rv)"},
	{"SetListViewBounds", (PyCFunction)List_SetListViewBounds, 1,
	 "(ListHandle list, Rect view) -> None"},
	{"SetListPort", (PyCFunction)List_SetListPort, 1,
	 "(ListHandle list, CGrafPtr port) -> None"},
	{"SetListCellIndent", (PyCFunction)List_SetListCellIndent, 1,
	 "(ListHandle list, Point indent) -> None"},
	{"SetListClickTime", (PyCFunction)List_SetListClickTime, 1,
	 "(ListHandle list, SInt32 time) -> None"},
	{"SetListRefCon", (PyCFunction)List_SetListRefCon, 1,
	 "(ListHandle list, SInt32 refCon) -> None"},
	{"SetListUserHandle", (PyCFunction)List_SetListUserHandle, 1,
	 "(ListHandle list, Handle userHandle) -> None"},
	{"SetListFlags", (PyCFunction)List_SetListFlags, 1,
	 "(ListHandle list, OptionBits listFlags) -> None"},
	{"SetListSelectionFlags", (PyCFunction)List_SetListSelectionFlags, 1,
	 "(ListHandle list, OptionBits selectionFlags) -> None"},
	{"as_List", (PyCFunction)List_as_List, 1,
	 "(Resource)->List.\nReturns List object (which is not auto-freed!)"},
	{NULL, NULL, 0}
};



static void myListDefFunction(SInt16 message,
                       Boolean selected,
                       Rect *cellRect,
                       Cell theCell,
                       SInt16 dataOffset,
                       SInt16 dataLen,
                       ListHandle theList)  
{
	PyObject *listDefFunc, *args, *rv=NULL;
	ListObject *self;
	
	self = (ListObject*)GetListRefCon(theList);
	if (self == NULL || self->ob_itself != theList)
		return;  /* nothing we can do */
	listDefFunc = self->ob_ldef_func;
	if (listDefFunc == NULL)
		return;  /* nothing we can do */
	args = Py_BuildValue("hbO&O&hhO", message,
	                                  selected,
	                                  PyMac_BuildRect, cellRect,
	                                  PyMac_BuildPoint, theCell,
	                                  dataOffset,
	                                  dataLen,
	                                  self);
	if (args != NULL) {
		rv = PyEval_CallObject(listDefFunc, args);
		Py_DECREF(args);
	}
	if (rv == NULL) {
		PySys_WriteStderr("error in list definition callback:\n");
		PyErr_Print();
	} else {
		Py_DECREF(rv);
	}
}


void init_List(void)
{
	PyObject *m;
	PyObject *d;



	myListDefFunctionUPP = NewListDefUPP((ListDefProcPtr)myListDefFunction);

	PyMac_INIT_TOOLBOX_OBJECT_NEW(ListHandle, ListObj_New);
	PyMac_INIT_TOOLBOX_OBJECT_CONVERT(ListHandle, ListObj_Convert);


	m = Py_InitModule("_List", List_methods);
	d = PyModule_GetDict(m);
	List_Error = PyMac_GetOSErrException();
	if (List_Error == NULL ||
	    PyDict_SetItemString(d, "Error", List_Error) != 0)
		return;
	List_Type.ob_type = &PyType_Type;
	Py_INCREF(&List_Type);
	if (PyDict_SetItemString(d, "ListType", (PyObject *)&List_Type) != 0)
		Py_FatalError("can't initialize ListType");
}

/* ======================== End module _List ======================== */

