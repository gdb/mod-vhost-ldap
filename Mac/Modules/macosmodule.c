/***********************************************************
Copyright 1991-1997 by Stichting Mathematisch Centrum, Amsterdam,
The Netherlands.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the names of Stichting Mathematisch
Centrum or CWI not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior permission.

STICHTING MATHEMATISCH CENTRUM DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH CENTRUM BE LIABLE
FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

******************************************************************/

/* Macintosh OS-specific interface */

#include "Python.h"
#include "macglue.h"
#include "pythonresources.h"

#ifdef WITHOUT_FRAMEWORKS
#include <Windows.h>
#include <Files.h>
#include <LowMem.h>
#include <Sound.h>
#include <Events.h>
#else
#include <Carbon/Carbon.h>
#include <ApplicationServices/ApplicationServices.h>
#endif

static PyObject *MacOS_Error; /* Exception MacOS.Error */

#ifdef TARGET_API_MAC_OSX
#define PATHNAMELEN 1024
#else
#define PATHNAMELEN 256
#endif

/* ----------------------------------------------------- */

/* Declarations for objects of type Resource fork */

typedef struct {
	PyObject_HEAD
	short fRefNum;
	int isclosed;
} rfobject;

static PyTypeObject Rftype;



/* ---------------------------------------------------------------- */

static void
do_close(rfobject *self)
{
	if (self->isclosed ) return;
	(void)FSClose(self->fRefNum);
	self->isclosed = 1;
}

static char rf_read__doc__[] = 
"Read data from resource fork"
;

static PyObject *
rf_read(rfobject *self, PyObject *args)
{
	long n;
	PyObject *v;
	OSErr err;
	
	if (self->isclosed) {
		PyErr_SetString(PyExc_ValueError, "Operation on closed file");
		return NULL;
	}
	
	if (!PyArg_ParseTuple(args, "l", &n))
		return NULL;
		
	v = PyString_FromStringAndSize((char *)NULL, n);
	if (v == NULL)
		return NULL;
		
	err = FSRead(self->fRefNum, &n, PyString_AsString(v));
	if (err && err != eofErr) {
		PyMac_Error(err);
		Py_DECREF(v);
		return NULL;
	}
	_PyString_Resize(&v, n);
	return v;
}


static char rf_write__doc__[] = 
"Write to resource fork"
;

static PyObject *
rf_write(rfobject *self, PyObject *args)
{
	char *buffer;
	long size;
	OSErr err;
	
	if (self->isclosed) {
		PyErr_SetString(PyExc_ValueError, "Operation on closed file");
		return NULL;
	}
	if (!PyArg_ParseTuple(args, "s#", &buffer, &size))
		return NULL;
	err = FSWrite(self->fRefNum, &size, buffer);
	if (err) {
		PyMac_Error(err);
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}


static char rf_seek__doc__[] = 
"Set file position"
;

static PyObject *
rf_seek(rfobject *self, PyObject *args)
{
	long amount, pos;
	int whence = SEEK_SET;
	long eof;
	OSErr err;
	
	if (self->isclosed) {
		PyErr_SetString(PyExc_ValueError, "Operation on closed file");
		return NULL;
	}
	if (!PyArg_ParseTuple(args, "l|i", &amount, &whence))
		return NULL;
	
	if ((err = GetEOF(self->fRefNum, &eof)))
		goto ioerr;
	
	switch (whence) {
	case SEEK_CUR:
		if ((err = GetFPos(self->fRefNum, &pos)))
			goto ioerr; 
		break;
	case SEEK_END:
		pos = eof;
		break;
	case SEEK_SET:
		pos = 0;
		break;
	default:
		PyErr_BadArgument();
		return NULL;
	}
	
	pos += amount;
	
	/* Don't bother implementing seek past EOF */
	if (pos > eof || pos < 0) {
		PyErr_BadArgument();
		return NULL;
	}
	
	if ((err = SetFPos(self->fRefNum, fsFromStart, pos)) ) {
ioerr:
		PyMac_Error(err);
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}


static char rf_tell__doc__[] = 
"Get file position"
;

static PyObject *
rf_tell(rfobject *self, PyObject *args)
{
	long where;
	OSErr err;
	
	if (self->isclosed) {
		PyErr_SetString(PyExc_ValueError, "Operation on closed file");
		return NULL;
	}
	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	if ((err = GetFPos(self->fRefNum, &where)) ) {
		PyMac_Error(err);
		return NULL;
	}
	return PyInt_FromLong(where);
}

static char rf_close__doc__[] = 
"Close resource fork"
;

static PyObject *
rf_close(rfobject *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	do_close(self);
	Py_INCREF(Py_None);
	return Py_None;
}


static struct PyMethodDef rf_methods[] = {
 {"read",	(PyCFunction)rf_read,	1,	rf_read__doc__},
 {"write",	(PyCFunction)rf_write,	1,	rf_write__doc__},
 {"seek",	(PyCFunction)rf_seek,	1,	rf_seek__doc__},
 {"tell",	(PyCFunction)rf_tell,	1,	rf_tell__doc__},
 {"close",	(PyCFunction)rf_close,	1,	rf_close__doc__},
 
	{NULL,		NULL}		/* sentinel */
};

/* ---------- */


static rfobject *
newrfobject(void)
{
	rfobject *self;
	
	self = PyObject_NEW(rfobject, &Rftype);
	if (self == NULL)
		return NULL;
	self->isclosed = 1;
	return self;
}


static void
rf_dealloc(rfobject *self)
{
	do_close(self);
	PyObject_DEL(self);
}

static PyObject *
rf_getattr(rfobject *self, char *name)
{
	return Py_FindMethod(rf_methods, (PyObject *)self, name);
}

static char Rftype__doc__[] = 
"Resource fork file object"
;

static PyTypeObject Rftype = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,				/*ob_size*/
	"MacOS.ResourceFork",		/*tp_name*/
	sizeof(rfobject),		/*tp_basicsize*/
	0,				/*tp_itemsize*/
	/* methods */
	(destructor)rf_dealloc,	/*tp_dealloc*/
	(printfunc)0,		/*tp_print*/
	(getattrfunc)rf_getattr,	/*tp_getattr*/
	(setattrfunc)0,	/*tp_setattr*/
	(cmpfunc)0,		/*tp_compare*/
	(reprfunc)0,		/*tp_repr*/
	0,			/*tp_as_number*/
	0,		/*tp_as_sequence*/
	0,		/*tp_as_mapping*/
	(hashfunc)0,		/*tp_hash*/
	(ternaryfunc)0,		/*tp_call*/
	(reprfunc)0,		/*tp_str*/

	/* Space for future expansion */
	0L,0L,0L,0L,
	Rftype__doc__ /* Documentation string */
};

/* End of code for Resource fork objects */
/* -------------------------------------------------------- */

/*----------------------------------------------------------------------*/
/* Miscellaneous File System Operations */

static char getcrtp_doc[] = "Get MacOS 4-char creator and type for a file";

static PyObject *
MacOS_GetCreatorAndType(PyObject *self, PyObject *args)
{
	FSSpec fss;
	FInfo info;
	PyObject *creator, *type, *res;
	OSErr err;
	
	if (!PyArg_ParseTuple(args, "O&", PyMac_GetFSSpec, &fss))
		return NULL;
	if ((err = FSpGetFInfo(&fss, &info)) != noErr)
		return PyErr_Mac(MacOS_Error, err);
	creator = PyString_FromStringAndSize((char *)&info.fdCreator, 4);
	type = PyString_FromStringAndSize((char *)&info.fdType, 4);
	res = Py_BuildValue("OO", creator, type);
	Py_DECREF(creator);
	Py_DECREF(type);
	return res;
}

static char setcrtp_doc[] = "Set MacOS 4-char creator and type for a file";

static PyObject *
MacOS_SetCreatorAndType(PyObject *self, PyObject *args)
{
	FSSpec fss;
	ResType creator, type;
	FInfo info;
	OSErr err;
	
	if (!PyArg_ParseTuple(args, "O&O&O&",
			PyMac_GetFSSpec, &fss, PyMac_GetOSType, &creator, PyMac_GetOSType, &type))
		return NULL;
	if ((err = FSpGetFInfo(&fss, &info)) != noErr)
		return PyErr_Mac(MacOS_Error, err);
	info.fdCreator = creator;
	info.fdType = type;
	if ((err = FSpSetFInfo(&fss, &info)) != noErr)
		return PyErr_Mac(MacOS_Error, err);
	Py_INCREF(Py_None);
	return Py_None;
}

#if !TARGET_API_MAC_OSX
static char schedparams_doc[] = "Set/return mainloop interrupt check flag, etc";

/*
** Set scheduler parameters
*/
static PyObject *
MacOS_SchedParams(PyObject *self, PyObject *args)
{
	PyMacSchedParams old, new;
	
	PyMac_GetSchedParams(&old);
	new = old;
	if (!PyArg_ParseTuple(args, "|iiidd", &new.check_interrupt, &new.process_events,
			&new.besocial, &new.check_interval, &new.bg_yield))
		return NULL;
	PyMac_SetSchedParams(&new);
	return Py_BuildValue("iiidd", old.check_interrupt, old.process_events,
			old.besocial, old.check_interval, old.bg_yield);
}

static char appswitch_doc[] = "Obsolete, use SchedParams";

/* Obsolete, for backward compatability */
static PyObject *
MacOS_EnableAppswitch(PyObject *self, PyObject *args)
{
	int new, old;
	PyMacSchedParams schp;
	
	if (!PyArg_ParseTuple(args, "i", &new))
		return NULL;
	PyMac_GetSchedParams(&schp);
	if ( schp.process_events )
		old = 1;
	else if ( schp.check_interrupt )
		old = 0;
	else
		old = -1;
	if ( new > 0 ) {
		schp.process_events = mDownMask|keyDownMask|osMask;
		schp.check_interrupt = 1;
	} else if ( new == 0 ) {
		schp.process_events = 0;
		schp.check_interrupt = 1;
	} else {
		schp.process_events = 0;
		schp.check_interrupt = 0;
	}
	PyMac_SetSchedParams(&schp);
	return Py_BuildValue("i", old);
}

static char setevh_doc[] = "Set python event handler to be called in mainloop";

static PyObject *
MacOS_SetEventHandler(PyObject *self, PyObject *args)
{
	PyObject *evh = NULL;
	
	if (!PyArg_ParseTuple(args, "|O", &evh))
		return NULL;
	if (evh == Py_None)
		evh = NULL;
	if ( evh && !PyCallable_Check(evh) ) {
		PyErr_SetString(PyExc_ValueError, "SetEventHandler argument must be callable");
		return NULL;
	}
	if ( !PyMac_SetEventHandler(evh) )
		return NULL;
	Py_INCREF(Py_None);
	return Py_None;
}

static char handleev_doc[] = "Pass event to other interested parties like sioux";

static PyObject *
MacOS_HandleEvent(PyObject *self, PyObject *args)
{
	EventRecord ev;
	
	if (!PyArg_ParseTuple(args, "O&", PyMac_GetEventRecord, &ev))
		return NULL;
	PyMac_HandleEventIntern(&ev);
	Py_INCREF(Py_None);
	return Py_None;
}
#endif /* !TARGET_API_MAC_OSX */

static char geterr_doc[] = "Convert OSErr number to string";

static PyObject *
MacOS_GetErrorString(PyObject *self, PyObject *args)
{
	int errn;
	
	if (!PyArg_ParseTuple(args, "i", &errn))
		return NULL;
	return Py_BuildValue("s", PyMac_StrError(errn));
}

static char splash_doc[] = "Open a splash-screen dialog by resource-id (0=close)";

static PyObject *
MacOS_splash(PyObject *self, PyObject *args)
{
	int resid = -1;
	static DialogPtr curdialog = NULL;
	DialogPtr olddialog;
	WindowRef theWindow;
	CGrafPtr thePort;
#if 0
	short xpos, ypos, width, height, swidth, sheight;
#endif
	
	if (!PyArg_ParseTuple(args, "|i", &resid))
		return NULL;
	olddialog = curdialog;
	curdialog = NULL;
		
	if ( resid != -1 ) {
		curdialog = GetNewDialog(resid, NULL, (WindowPtr)-1);
		if ( curdialog ) {
			theWindow = GetDialogWindow(curdialog);
			thePort = GetWindowPort(theWindow);
#if 0
			width = thePort->portRect.right - thePort->portRect.left;
			height = thePort->portRect.bottom - thePort->portRect.top;
			swidth = qd.screenBits.bounds.right - qd.screenBits.bounds.left;
			sheight = qd.screenBits.bounds.bottom - qd.screenBits.bounds.top - LMGetMBarHeight();
			xpos = (swidth-width)/2;
			ypos = (sheight-height)/5 + LMGetMBarHeight();
			MoveWindow(theWindow, xpos, ypos, 0);
			ShowWindow(theWindow);
#endif
			DrawDialog(curdialog);
		}
	}
	if (olddialog)
		DisposeDialog(olddialog);
	Py_INCREF(Py_None);
	return Py_None;
}

static char DebugStr_doc[] = "Switch to low-level debugger with a message";

static PyObject *
MacOS_DebugStr(PyObject *self, PyObject *args)
{
	Str255 message;
	PyObject *object = 0;
	
	if (!PyArg_ParseTuple(args, "O&|O", PyMac_GetStr255, message, &object))
		return NULL;
	DebugStr(message);
	Py_INCREF(Py_None);
	return Py_None;
}

static char SysBeep_doc[] = "BEEEEEP!!!";

static PyObject *
MacOS_SysBeep(PyObject *self, PyObject *args)
{
	int duration = 6;
	
	if (!PyArg_ParseTuple(args, "|i", &duration))
		return NULL;
	SysBeep(duration);
	Py_INCREF(Py_None);
	return Py_None;
}

static char WMAvailable_doc[] = 
	"True if this process can interact with the display."
	"Will foreground the application on the first call as a side-effect."
	;

static PyObject *
MacOS_WMAvailable(PyObject *self, PyObject *args)
{
	static PyObject *rv = NULL;
	
	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	if (!rv) {
#if TARGET_API_MAC_OSX
		ProcessSerialNumber psn;
		
		/*
		** This is a fairly innocuous call to make if we don't have a window
		** manager, or if we have no permission to talk to it. It will print
		** a message on stderr, but at least it won't abort the process.
		** It appears the function caches the result itself, and it's cheap, so
		** no need for us to cache.
		*/
		if (CGMainDisplayID() == 0) {
			rv = Py_False;
		} else {
			if (GetCurrentProcess(&psn) < 0 ||
				SetFrontProcess(&psn) < 0) {
				rv = Py_False;
			} else {
				rv = Py_True;
			}
		}
#else
		rv = Py_True;
#endif
	}
	Py_INCREF(rv);
	return rv;
}

static char GetTicks_doc[] = "Return number of ticks since bootup";

static PyObject *
MacOS_GetTicks(PyObject *self, PyObject *args)
{
	return Py_BuildValue("i", (int)TickCount());
}

static char openrf_doc[] = "Open resource fork of a file";

static PyObject *
MacOS_openrf(PyObject *self, PyObject *args)
{
	OSErr err;
	char *mode = "r";
	FSSpec fss;
	SignedByte permission = 1;
	rfobject *fp;
		
	if (!PyArg_ParseTuple(args, "O&|s", PyMac_GetFSSpec, &fss, &mode))
		return NULL;
	while (*mode) {
		switch (*mode++) {
		case '*': break;
		case 'r': permission = 1; break;
		case 'w': permission = 2; break;
		case 'b': break;
		default:
			PyErr_BadArgument();
			return NULL;
		}
	}
	
	if ( (fp = newrfobject()) == NULL )
		return NULL;
		
	err = HOpenRF(fss.vRefNum, fss.parID, fss.name, permission, &fp->fRefNum);
	
	if ( err == fnfErr ) {
		/* In stead of doing complicated things here to get creator/type
		** correct we let the standard i/o library handle it
		*/
		FILE *tfp;
		char pathname[PATHNAMELEN];
		
		if ( (err=PyMac_GetFullPathname(&fss, pathname, PATHNAMELEN)) ) {
			PyMac_Error(err);
			Py_DECREF(fp);
			return NULL;
		}
		
		if ( (tfp = fopen(pathname, "w")) == NULL ) {
			PyMac_Error(fnfErr); /* What else... */
			Py_DECREF(fp);
			return NULL;
		}
		fclose(tfp);
		err = HOpenRF(fss.vRefNum, fss.parID, fss.name, permission, &fp->fRefNum);
	}
	if ( err ) {
		Py_DECREF(fp);
		PyMac_Error(err);
		return NULL;
	}
	fp->isclosed = 0;
	return (PyObject *)fp;
}

#if !TARGET_API_MAC_OSX
static char FreeMem_doc[] = "Return the total amount of free space in the heap";

static PyObject *
MacOS_FreeMem(PyObject *self, PyObject *args)
{
	long rv;
		
	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	rv = FreeMem();
	return Py_BuildValue("l", rv);
}

static char MaxBlock_doc[] = "Return the largest contiguous block of free space in the heap";

static PyObject *
MacOS_MaxBlock(PyObject *self, PyObject *args)
{
	long rv;
		
	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	rv = MaxBlock();
	return Py_BuildValue("l", rv);
}

static char CompactMem_doc[] = "(wanted size)->actual largest block after compacting";

static PyObject *
MacOS_CompactMem(PyObject *self, PyObject *args)
{
	long value;
	long rv;
		
	if (!PyArg_ParseTuple(args, "l", &value))
		return NULL;
	rv = CompactMem(value);
	return Py_BuildValue("l", rv);
}

static char KeepConsole_doc[] = "(flag) Keep console open 0:never, 1:on output 2:on error, 3:always";

static PyObject *
MacOS_KeepConsole(PyObject *self, PyObject *args)
{
	int value;
	
	if (!PyArg_ParseTuple(args, "i", &value))
		return NULL;
	PyMac_options.keep_console = value;
	Py_INCREF(Py_None);
	return Py_None;
}

static char OutputSeen_doc[] = "Call to reset the 'unseen output' flag for the keep-console-open option";

static PyObject *
MacOS_OutputSeen(PyObject *self, PyObject *args)
{
	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	PyMac_OutputSeen();
	Py_INCREF(Py_None);
	return Py_None;
}
#endif /* !TARGET_API_MAC_OSX */

static PyMethodDef MacOS_Methods[] = {
	{"GetCreatorAndType",		MacOS_GetCreatorAndType, 1,	getcrtp_doc},
	{"SetCreatorAndType",		MacOS_SetCreatorAndType, 1,	setcrtp_doc},
#if !TARGET_API_MAC_OSX
	{"SchedParams",			MacOS_SchedParams,	1,	schedparams_doc},
	{"EnableAppswitch",		MacOS_EnableAppswitch,	1,	appswitch_doc},
	{"SetEventHandler",		MacOS_SetEventHandler,	1,	setevh_doc},
	{"HandleEvent",			MacOS_HandleEvent,	1,	handleev_doc},
#endif
	{"GetErrorString",		MacOS_GetErrorString,	1,	geterr_doc},
	{"openrf",			MacOS_openrf, 		1, 	openrf_doc},
	{"splash",			MacOS_splash,		1, 	splash_doc},
	{"DebugStr",			MacOS_DebugStr,		1,	DebugStr_doc},
	{"GetTicks",			MacOS_GetTicks,		1,	GetTicks_doc},
	{"SysBeep",			MacOS_SysBeep,		1,	SysBeep_doc},
	{"WMAvailable",			MacOS_WMAvailable,		1,	WMAvailable_doc},
#if !TARGET_API_MAC_OSX
	{"FreeMem",			MacOS_FreeMem,		1,	FreeMem_doc},
	{"MaxBlock",		MacOS_MaxBlock,		1,	MaxBlock_doc},
	{"CompactMem",		MacOS_CompactMem,	1,	CompactMem_doc},
	{"KeepConsole",		MacOS_KeepConsole,	1,	KeepConsole_doc},
	{"OutputSeen",		MacOS_OutputSeen,	1,	OutputSeen_doc},
#endif
	{NULL,				NULL}		 /* Sentinel */
};


void
initMacOS(void)
{
	PyObject *m, *d;
	
	m = Py_InitModule("MacOS", MacOS_Methods);
	d = PyModule_GetDict(m);
	
	/* Initialize MacOS.Error exception */
	MacOS_Error = PyMac_GetOSErrException();
	if (MacOS_Error == NULL || PyDict_SetItemString(d, "Error", MacOS_Error) != 0)
		return;
	Rftype.ob_type = &PyType_Type;
	Py_INCREF(&Rftype);
	if (PyDict_SetItemString(d, "ResourceForkType", (PyObject *)&Rftype) != 0)
		return;
	/*
	** This is a hack: the following constant added to the id() of a string
	** object gives you the address of the data. Unfortunately, it is needed for
	** some of the image and sound processing interfaces on the mac:-(
	*/
	{
		PyStringObject *p = 0;
		long off = (long)&(p->ob_sval[0]);
		
		if( PyDict_SetItemString(d, "string_id_to_buffer", Py_BuildValue("i", off)) != 0)
			return;
	}
#if TARGET_API_MAC_OSX
#define PY_RUNTIMEMODEL "macho"
#elif TARGET_API_MAC_CARBON
#define PY_RUNTIMEMODEL "carbon"
#else
#error "None of the TARGET_API_MAC_XXX I know about is set"
#endif
	if (PyDict_SetItemString(d, "runtimemodel", 
				Py_BuildValue("s", PY_RUNTIMEMODEL)) != 0)
		return;
#if !TARGET_API_MAC_OSX
#define PY_LINKMODEL "cfm"
#elif defined(WITH_NEXT_FRAMEWORK)
#define PY_LINKMODEL "framework"
#elif defined(Py_ENABLE_SHARED)
#define PY_LINKMODEL "shared"
#else
#define PY_LINKMODEL "static"
#endif
	if (PyDict_SetItemString(d, "linkmodel", 
				Py_BuildValue("s", PY_LINKMODEL)) != 0)
		return;

}
