/***********************************************************
Copyright (C) 1994 Steen Lumholt.
Copyright 1994-1995 by Stichting Mathematisch Centrum, Amsterdam,
The Netherlands.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the names of Stichting Mathematisch
Centrum or CWI or Corporation for National Research Initiatives or
CNRI not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

While CWI is the initial source for this software, a modified version
is made available by the Corporation for National Research Initiatives
(CNRI) at the Internet address ftp://ftp.python.org.

STICHTING MATHEMATISCH CENTRUM AND CNRI DISCLAIM ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH
CENTRUM OR CNRI BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

******************************************************************/

/* _tkinter.c -- Interface to libtk.a and libtcl.a. */

/* TCL/TK VERSION INFO:

   Unix:
	Tcl/Tk 8.0 (even alpha or beta) or 7.6/4.2 are recommended.
	Versions 7.5/4.1 are the earliest versions still supported.
	Versions 7.4/4.0 or Tk 3.x are no longer supported.

   Mac and Windows:
	Use Tcl 8.0 if available (even alpha or beta).
	The oldest usable version is 4.1p1/7.5p1.

*/


#include "Python.h"
#include <ctype.h>

#ifdef macintosh
#define MAC_TCL
#include "myselect.h"
#endif

#include <tcl.h>
#include <tk.h>

#define TKMAJORMINOR (TK_MAJOR_VERSION*1000 + TK_MINOR_VERSION)

#if TKMAJORMINOR >= 8000 && defined(macintosh)
/* Sigh, we have to include this to get at the tcl qd pointer */
#include <tkMac.h>
#endif

#if TKMAJORMINOR < 4001
	#error "Tk 4.0 or 3.x are not supported -- use 4.1 or higher"
#endif

#if TKMAJORMINOR < 8000 || !defined(MS_WINDOWS)
#define HAVE_CREATEFILEHANDLER
#endif

extern int Tk_GetNumMainWindows();

#ifdef macintosh

/*
** Additional cruft needed by Tcl/Tk on the Mac.
** This is for Tcl 7.5 and Tk 4.1 (patch release 1).
*/

/* ckfree() expects a char* */
#define FREECAST (char *)

#include <Events.h> /* For EventRecord */

typedef int (*TclMacConvertEventPtr) Py_PROTO((EventRecord *eventPtr));
/* They changed the name... */
#if TKMAJORMINOR < 8000
#define Tcl_MacSetEventProc TclMacSetEventProc
#endif
void Tcl_MacSetEventProc Py_PROTO((TclMacConvertEventPtr procPtr));
int TkMacConvertEvent Py_PROTO((EventRecord *eventPtr));

staticforward int PyMacConvertEvent Py_PROTO((EventRecord *eventPtr));

#endif /* macintosh */

#ifndef FREECAST
#define FREECAST (char *)
#endif

/**** Tkapp Object Declaration ****/

staticforward PyTypeObject Tkapp_Type;

typedef struct
{
	PyObject_HEAD
	Tcl_Interp *interp;
}
TkappObject;

#define Tkapp_Check(v) ((v)->ob_type == &Tkapp_Type)
#define Tkapp_Interp(v) (((TkappObject *) (v))->interp)
#define Tkapp_Result(v) (((TkappObject *) (v))->interp->result)

#define DEBUG_REFCNT(v) (printf("DEBUG: id=%p, refcnt=%i\n", \
(void *) v, ((PyObject *) v)->ob_refcnt))



/**** Error Handling ****/

static PyObject *Tkinter_TclError;
static int quitMainLoop = 0;
static int errorInCmd = 0;
static PyObject *excInCmd;
static PyObject *valInCmd;
static PyObject *trbInCmd;



static PyObject *
Tkinter_Error(v)
	PyObject *v;
{
	PyErr_SetString(Tkinter_TclError, Tkapp_Result(v));
	return NULL;
}


int
PythonCmd_Error(interp)
	Tcl_Interp *interp;
{
	errorInCmd = 1;
	PyErr_Fetch(&excInCmd, &valInCmd, &trbInCmd);
	return TCL_ERROR;
}



/**** Utils ****/
static char *
AsString(value, tmp)
	PyObject *value;
	PyObject *tmp;
{
	if (PyString_Check(value))
		return PyString_AsString(value);
	else {
		PyObject *v = PyObject_Str(value);
		PyList_Append(tmp, v);
		Py_DECREF(v);
		return PyString_AsString(v);
	}
}



#define ARGSZ 64

static char *
Merge(args)
	PyObject *args;
{
	PyObject *tmp = NULL;
	char *argvStore[ARGSZ];
	char **argv = NULL;
	int fvStore[ARGSZ];
	int *fv = NULL;
	int argc = 0, i;
	char *res = NULL;

	if (!(tmp = PyList_New(0)))
	    return NULL;

	argv = argvStore;
	fv = fvStore;

	if (args == NULL)
		argc = 0;

	else if (!PyTuple_Check(args)) {
		argc = 1;
		fv[0] = 0;
		argv[0] = AsString(args, tmp);
	}
	else {
		argc = PyTuple_Size(args);

		if (argc > ARGSZ) {
			argv = (char **)ckalloc(argc * sizeof(char *));
			fv = (int *)ckalloc(argc * sizeof(int));
			if (argv == NULL || fv == NULL) {
				PyErr_NoMemory();
				goto finally;
			}
		}

		for (i = 0; i < argc; i++) {
			PyObject *v = PyTuple_GetItem(args, i);
			if (PyTuple_Check(v)) {
				fv[i] = 1;
				if (!(argv[i] = Merge(v)))
					goto finally;
			}
			else if (v == Py_None) {
				argc = i;
				break;
			}
			else {
				fv[i] = 0;
				argv[i] = AsString(v, tmp);
			}
		}
	}
	res = Tcl_Merge(argc, argv);

  finally:
	for (i = 0; i < argc; i++)
		if (fv[i]) {
			ckfree(argv[i]);
		}
	if (argv != argvStore)
		ckfree(FREECAST argv);
	if (fv != fvStore)
		ckfree(FREECAST fv);

	Py_DECREF(tmp);
	return res;
}



static PyObject *
Split(self, list)
	PyObject *self;
	char *list;
{
	int argc;
	char **argv;
	PyObject *v;

	if (list == NULL) {
		Py_INCREF(Py_None);
		return Py_None;
	}

	if (Tcl_SplitList(Tkapp_Interp(self), list, &argc, &argv) == TCL_ERROR)
	{
		/* Not a list.
		 * Could be a quoted string containing funnies, e.g. {"}.
		 * Return the string itself.
		 */
		PyErr_Clear();
		return PyString_FromString(list);
	}

	if (argc == 0)
		v = PyString_FromString("");
	else if (argc == 1)
		v = PyString_FromString(argv[0]);
	else if ((v = PyTuple_New(argc)) != NULL) {
		int i;
		PyObject *w;

		for (i = 0; i < argc; i++) {
			if ((w = Split(self, argv[i])) == NULL) {
				Py_DECREF(v);
				v = NULL;
				break;
			}
			PyTuple_SetItem(v, i, w);
		}
	}
	ckfree(FREECAST argv);
	return v;
}



/**** Tkapp Object ****/

#ifndef WITH_APPINIT
int
Tcl_AppInit(interp)
	Tcl_Interp *interp;
{
	Tk_Window main;

	main = Tk_MainWindow(interp);
	if (Tcl_Init(interp) == TCL_ERROR) {
		fprintf(stderr, "Tcl_Init error: %s\n", interp->result);
		return TCL_ERROR;
	}
	if (Tk_Init(interp) == TCL_ERROR) {
		fprintf(stderr, "Tk_Init error: %s\n", interp->result);
		return TCL_ERROR;
	}
	return TCL_OK;
}
#endif /* !WITH_APPINIT */




/* Initialize the Tk application; see the `main' function in
 * `tkMain.c'.
 */
static TkappObject *
Tkapp_New(screenName, baseName, className, interactive)
	char *screenName;
	char *baseName;
	char *className;
	int interactive;
{
	TkappObject *v;
	char *argv0;
  
	v = PyObject_NEW(TkappObject, &Tkapp_Type);
	if (v == NULL)
		return NULL;

	v->interp = Tcl_CreateInterp();

	/* Delete the 'exit' command, which can screw things up */
	Tcl_DeleteCommand(v->interp, "exit");

	if (screenName != NULL)
		Tcl_SetVar2(v->interp, "env", "DISPLAY",
			    screenName, TCL_GLOBAL_ONLY);

	if (interactive)
		Tcl_SetVar(v->interp, "tcl_interactive", "1", TCL_GLOBAL_ONLY);
	else
		Tcl_SetVar(v->interp, "tcl_interactive", "0", TCL_GLOBAL_ONLY);

	/* This is used to get the application class for Tk 4.1 and up */
	argv0 = (char*)ckalloc(strlen(className) + 1);
	if (!argv0) {
		PyErr_NoMemory();
		Py_DECREF(v);
		return NULL;
	}

	strcpy(argv0, className);
	if (isupper((int)(argv0[0])))
		argv0[0] = tolower(argv0[0]);
	Tcl_SetVar(v->interp, "argv0", argv0, TCL_GLOBAL_ONLY);
	ckfree(argv0);

	if (Tcl_AppInit(v->interp) != TCL_OK)
		return (TkappObject *)Tkinter_Error(v);

	return v;
}



/** Tcl Eval **/

static PyObject *
Tkapp_Call(self, args)
	PyObject *self;
	PyObject *args;
{
	char *cmd  = Merge(args);
	PyObject *res = NULL;

	if (!cmd)
		PyErr_SetString(Tkinter_TclError, "merge failed");

	else if (Tcl_Eval(Tkapp_Interp(self), cmd) == TCL_ERROR)
		res = Tkinter_Error(self);

	else
		res = PyString_FromString(Tkapp_Result(self));

	if (cmd)
		ckfree(cmd);

	return res;
}


static PyObject *
Tkapp_GlobalCall(self, args)
	PyObject *self;
	PyObject *args;
{
	char *cmd  = Merge(args);
	PyObject *res = NULL;
	

	if (!cmd)
		PyErr_SetString(Tkinter_TclError, "merge failed");

	else if (Tcl_GlobalEval(Tkapp_Interp(self), cmd) == TCL_ERROR)
		res = Tkinter_Error(self);
	else
		res = PyString_FromString(Tkapp_Result(self));

	if (cmd)
		ckfree(cmd);

	return res;
}

static PyObject *
Tkapp_Eval(self, args)
	PyObject *self;
	PyObject *args;
{
	char *script;
  
	if (!PyArg_ParseTuple(args, "s", &script))
		return NULL;

	if (Tcl_Eval(Tkapp_Interp(self), script) == TCL_ERROR)
		return Tkinter_Error(self);
  
	return PyString_FromString(Tkapp_Result(self));
}

static PyObject *
Tkapp_GlobalEval(self, args)
	PyObject *self;
	PyObject *args;
{
	char *script;
  
	if (!PyArg_ParseTuple(args, "s", &script))
		return NULL;

	if (Tcl_GlobalEval(Tkapp_Interp(self), script) == TCL_ERROR)
		return Tkinter_Error(self);

	return PyString_FromString(Tkapp_Result(self));
}

static PyObject *
Tkapp_EvalFile(self, args)
	PyObject *self;
	PyObject *args;
{
	char *fileName;

	if (!PyArg_ParseTuple(args, "s", &fileName))
		return NULL;

	if (Tcl_EvalFile(Tkapp_Interp(self), fileName) == TCL_ERROR)
		return Tkinter_Error(self);

	return PyString_FromString(Tkapp_Result(self));
}

static PyObject *
Tkapp_Record(self, args)
	PyObject *self;
	PyObject *args;
{
	char *script;

	if (!PyArg_ParseTuple(args, "s", &script))
		return NULL;

	if (TCL_ERROR == Tcl_RecordAndEval(Tkapp_Interp(self),
					   script, TCL_NO_EVAL))
		return Tkinter_Error(self);

	return PyString_FromString(Tkapp_Result(self));
}

static PyObject *
Tkapp_AddErrorInfo(self, args)
	PyObject *self;
	PyObject *args;
{
	char *msg;

	if (!PyArg_ParseTuple(args, "s", &msg))
		return NULL;
	Tcl_AddErrorInfo(Tkapp_Interp(self), msg);

	Py_INCREF(Py_None);
	return Py_None;
}



/** Tcl Variable **/

static PyObject *
SetVar(self, args, flags)
	PyObject *self;
	PyObject *args;
	int flags;
{
	char *name1, *name2, *ok;
	PyObject *newValue;
	PyObject *tmp = PyList_New(0);

	if (!tmp)
		return NULL;

	if (PyArg_ParseTuple(args, "sO", &name1, &newValue))
		/* XXX Merge? */
		ok = Tcl_SetVar(Tkapp_Interp(self), name1, 
				AsString(newValue, tmp), flags);

	else {
		PyErr_Clear();
		if (PyArg_ParseTuple(args, "ssO", &name1, &name2, &newValue))
			ok = Tcl_SetVar2(Tkapp_Interp(self), name1, name2, 
					 AsString (newValue, tmp), flags);
		else {
			Py_DECREF (tmp);
			return NULL;
		}
	}
	Py_DECREF(tmp);

	if (!ok)
		return Tkinter_Error(self);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
Tkapp_SetVar(self, args)
	PyObject *self;
	PyObject *args;
{
	return SetVar(self, args, TCL_LEAVE_ERR_MSG);
}

static PyObject *
Tkapp_GlobalSetVar(self, args)
	PyObject *self;
	PyObject *args;
{
	return SetVar(self, args, TCL_LEAVE_ERR_MSG | TCL_GLOBAL_ONLY);
}



static PyObject *
GetVar(self, args, flags)
	PyObject *self;
	PyObject *args;
	int flags;
{
	char *name1, *name2=NULL, *s;

	if (!PyArg_ParseTuple(args, "s|s", &name1, &name2))
		return NULL;
	if (name2 == NULL)
		s = Tcl_GetVar(Tkapp_Interp (self), name1, flags);

	else
		s = Tcl_GetVar2(Tkapp_Interp(self), name1, name2, flags);

	if (s == NULL)
		return Tkinter_Error(self);

	return PyString_FromString(s);
}

static PyObject *
Tkapp_GetVar(self, args)
	PyObject *self;
	PyObject *args;
{
	return GetVar(self, args, TCL_LEAVE_ERR_MSG);
}

static PyObject *
Tkapp_GlobalGetVar(self, args)
	PyObject *self;
	PyObject *args;
{
	return GetVar(self, args, TCL_LEAVE_ERR_MSG | TCL_GLOBAL_ONLY);
}



static PyObject *
UnsetVar(self, args, flags)
	PyObject *self;
	PyObject *args;
	int flags;
{
	char *name1, *name2=NULL;
	int code;

	if (!PyArg_ParseTuple(args, "s|s", &name1, &name2))
		return NULL;
	if (name2 == NULL)
		code = Tcl_UnsetVar(Tkapp_Interp(self), name1, flags);

	else
		code = Tcl_UnsetVar2(Tkapp_Interp(self), name1, name2, flags);

	if (code == TCL_ERROR)
		return Tkinter_Error(self);

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
Tkapp_UnsetVar(self, args)
	PyObject *self;
	PyObject *args;
{
	return UnsetVar(self, args, TCL_LEAVE_ERR_MSG);
}

static PyObject *
Tkapp_GlobalUnsetVar(self, args)
	PyObject *self;
	PyObject *args;
{
	return UnsetVar(self, args, TCL_LEAVE_ERR_MSG | TCL_GLOBAL_ONLY);
}



/** Tcl to Python **/

static PyObject *
Tkapp_GetInt(self, args)
	PyObject *self;
	PyObject *args;
{
	char *s;
	int v;

	if (!PyArg_ParseTuple(args, "s", &s))
		return NULL;
	if (Tcl_GetInt(Tkapp_Interp(self), s, &v) == TCL_ERROR)
		return Tkinter_Error(self);
	return Py_BuildValue("i", v);
}

static PyObject *
Tkapp_GetDouble(self, args)
	PyObject *self;
	PyObject *args;
{
	char *s;
	double v;

	if (!PyArg_ParseTuple(args, "s", &s))
		return NULL;
	if (Tcl_GetDouble(Tkapp_Interp(self), s, &v) == TCL_ERROR)
		return Tkinter_Error(self);
	return Py_BuildValue("d", v);
}

static PyObject *
Tkapp_GetBoolean(self, args)
	PyObject *self;
	PyObject *args;
{
	char *s;
	int v;

	if (!PyArg_ParseTuple(args, "s", &s))
		return NULL;
	if (Tcl_GetBoolean(Tkapp_Interp(self), s, &v) == TCL_ERROR)
		return Tkinter_Error(self);
	return Py_BuildValue("i", v);
}

static PyObject *
Tkapp_ExprString(self, args)
	PyObject *self;
	PyObject *args;
{
	char *s;

	if (!PyArg_ParseTuple(args, "s", &s))
		return NULL;
	if (Tcl_ExprString(Tkapp_Interp(self), s) == TCL_ERROR)
		return Tkinter_Error(self);
	return Py_BuildValue("s", Tkapp_Result(self));
}

static PyObject *
Tkapp_ExprLong(self, args)
	PyObject *self;
	PyObject *args;
{
	char *s;
	long v;

	if (!PyArg_ParseTuple(args, "s", &s))
		return NULL;
	if (Tcl_ExprLong(Tkapp_Interp(self), s, &v) == TCL_ERROR)
		return Tkinter_Error(self);
	return Py_BuildValue("l", v);
}

static PyObject *
Tkapp_ExprDouble(self, args)
	PyObject *self;
	PyObject *args;
{
	char *s;
	double v;
	int retval;

	if (!PyArg_ParseTuple(args, "s", &s))
		return NULL;
	PyFPE_START_PROTECT("Tkapp_ExprDouble", return 0)
	retval = Tcl_ExprDouble(Tkapp_Interp(self), s, &v);
	PyFPE_END_PROTECT(retval)
	if (retval == TCL_ERROR)
		return Tkinter_Error(self);
	return Py_BuildValue("d", v);
}

static PyObject *
Tkapp_ExprBoolean(self, args)
	PyObject *self;
	PyObject *args;
{
	char *s;
	int v;

	if (!PyArg_ParseTuple(args, "s", &s))
		return NULL;
	if (Tcl_ExprBoolean(Tkapp_Interp(self), s, &v) == TCL_ERROR)
		return Tkinter_Error(self);
	return Py_BuildValue("i", v);
}



static PyObject *
Tkapp_SplitList(self, args)
	PyObject *self;
	PyObject *args;
{
	char *list;
	int argc;
	char **argv;
	PyObject *v;
	int i;

	if (!PyArg_ParseTuple(args, "s", &list))
		return NULL;

	if (Tcl_SplitList(Tkapp_Interp(self), list, &argc, &argv) == TCL_ERROR)
		return Tkinter_Error(self);

	if (!(v = PyTuple_New(argc)))
		return NULL;
	
	for (i = 0; i < argc; i++) {
		PyObject *s = PyString_FromString(argv[i]);
		if (!s || PyTuple_SetItem(v, i, s)) {
			Py_DECREF(v);
			v = NULL;
			goto finally;
		}
	}

  finally:
	ckfree(FREECAST argv);
	return v;
}

static PyObject *
Tkapp_Split(self, args)
	PyObject *self;
	PyObject *args;
{
	char *list;

	if (!PyArg_ParseTuple(args, "s", &list))
		return NULL;
	return Split(self, list);
}

static PyObject *
Tkapp_Merge(self, args)
	PyObject *self;
	PyObject *args;
{
	char *s = Merge(args);
	PyObject *res = NULL;

	if (s) {
		res = PyString_FromString(s);
		ckfree(s);
	}
	else
		PyErr_SetString(Tkinter_TclError, "merge failed");

	return res;
}



/** Tcl Command **/

/* This is the Tcl command that acts as a wrapper for Python
 * function or method.
 */
static int
PythonCmd(clientData, interp, argc, argv)
	ClientData clientData;		     /* Is (self, func) */
	Tcl_Interp *interp;
	int argc;
	char *argv[];
{
	PyObject *self, *func, *arg, *res, *tmp;
	int i;

	/* TBD: no error checking here since we know, via the
	 * Tkapp_CreateCommand() that the client data is a two-tuple
	 */
	self = PyTuple_GetItem((PyObject *) clientData, 0);
	func = PyTuple_GetItem((PyObject *) clientData, 1);

	/* Create argument list (argv1, ..., argvN) */
	if (!(arg = PyTuple_New(argc - 1)))
		return PythonCmd_Error(interp);

	for (i = 0; i < (argc - 1); i++) {
		PyObject *s = PyString_FromString(argv[i + 1]);
		if (!s || PyTuple_SetItem(arg, i, s)) {
			Py_DECREF(arg);
			PythonCmd_Error(interp);
		}
	}
	res = PyEval_CallObject(func, arg);
	Py_DECREF(arg);

	if (res == NULL)
		return PythonCmd_Error(interp);

	if (!(tmp = PyList_New(0))) {
		Py_DECREF(res);
		return PythonCmd_Error(interp);
	}

	Tcl_SetResult(Tkapp_Interp(self), AsString(res, tmp), TCL_VOLATILE);
	Py_DECREF(res);
	Py_DECREF(tmp);

	return TCL_OK;
}

static void
PythonCmdDelete(clientData)
	ClientData clientData;	/* Is (self, func) */
{
	Py_DECREF((PyObject *) clientData);
}



static PyObject *
Tkapp_CreateCommand(self, args)
	PyObject *self;
	PyObject *args;
{
	char *cmdName;
	PyObject *func;
	PyObject *data;

	if (!PyArg_ParseTuple(args, "sO", &cmdName, &func))
		return NULL;
	if (!PyCallable_Check(func)) {
		PyErr_SetString(PyExc_TypeError, "command not callable");
		return NULL;
	}

	data = Py_BuildValue("OO", self, func);
	if (!data)
		return NULL;

	if (Tcl_CreateCommand(Tkapp_Interp(self), cmdName, PythonCmd,
			      (ClientData) data, PythonCmdDelete) == NULL)
	{
		PyErr_SetString(Tkinter_TclError, "can't create Tcl command");
		Py_DECREF(data);
		return NULL;
	}

	Py_INCREF(Py_None);
	return Py_None;
}



static PyObject *
Tkapp_DeleteCommand(self, args)
	PyObject *self;
	PyObject *args;
{
	char *cmdName;

	if (!PyArg_ParseTuple(args, "s", &cmdName))
		return NULL;
	if (Tcl_DeleteCommand(Tkapp_Interp(self), cmdName) == -1)
	{
		PyErr_SetString(Tkinter_TclError, "can't delete Tcl command");
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}



/** File Handler **/

static void
FileHandler(clientData, mask)
	ClientData clientData;		     /* Is: (func, file) */
	int mask;
{
	PyObject *func, *file, *arg, *res;

	func = PyTuple_GetItem((PyObject *) clientData, 0);
	file = PyTuple_GetItem((PyObject *) clientData, 1);

	arg = Py_BuildValue("(Oi)", file, (long) mask);
	res = PyEval_CallObject(func, arg);
	Py_DECREF(arg);

	if (res == NULL) {
		errorInCmd = 1;
		PyErr_Fetch(&excInCmd, &valInCmd, &trbInCmd);
	}
	Py_XDECREF(res);
}

static int
GetFileNo(file)
	/* Either an int >= 0 or an object with a
	 *.fileno() method that returns an int >= 0
	 */
	PyObject *file;
{
	PyObject *meth, *args, *res;
	int id;
	if (PyInt_Check(file)) {
		id = PyInt_AsLong(file);
		if (id < 0)
			PyErr_SetString(PyExc_ValueError, "invalid file id");
		return id;
	}
	args = PyTuple_New(0);
	if (args == NULL)
		return -1;

	meth = PyObject_GetAttrString(file, "fileno");
	if (meth == NULL) {
		Py_DECREF(args);
		return -1;
	}

	res = PyEval_CallObject(meth, args);
	Py_DECREF(args);
	Py_DECREF(meth);
	if (res == NULL)
		return -1;

	if (PyInt_Check(res))
		id = PyInt_AsLong(res);
	else
		id = -1;

	if (id < 0)
		PyErr_SetString(PyExc_ValueError,
				"invalid fileno() return value");
	Py_DECREF(res);
	return id;
}


static PyObject* Tkapp_ClientDataDict = NULL;

#ifdef HAVE_CREATEFILEHANDLER
static PyObject *
Tkapp_CreateFileHandler(self, args)
	PyObject *self;
	PyObject *args;			     /* Is (file, mask, func) */
{
	PyObject *file, *func, *data;
	PyObject *idkey;
	int mask, id;
#if TKMAJORMINOR < 8000
	Tcl_File tfile;
#endif

	if (!Tkapp_ClientDataDict) {
		if (!(Tkapp_ClientDataDict = PyDict_New()))
			return NULL;
	}

	if (!PyArg_ParseTuple(args, "OiO", &file, &mask, &func))
		return NULL;
	id = GetFileNo(file);
	if (id < 0)
		return NULL;
	if (!PyCallable_Check(func)) {
		PyErr_SetString(PyExc_TypeError, "bad argument list");
		return NULL;
	}

	if (!(idkey = PyInt_FromLong(id)))
		return NULL;

	/* ClientData is: (func, file) */
	data = Py_BuildValue("(OO)", func, file);
	if (!data || PyDict_SetItem(Tkapp_ClientDataDict, idkey, data)) {
		Py_DECREF(idkey);
		Py_XDECREF(data);
		return NULL;
	}
	Py_DECREF(idkey);

#if TKMAJORMINOR < 8000
#ifdef MS_WINDOWS
	/* We assume this is a socket... */
	tfile = Tcl_GetFile((ClientData)id, TCL_WIN_SOCKET);
#else /* !MS_WINDOWS */
	tfile = Tcl_GetFile((ClientData)id, TCL_UNIX_FD);
#endif /* !MS_WINDOWS */
	/* Ought to check for null Tcl_File object... */
	Tcl_CreateFileHandler(tfile, mask, FileHandler, (ClientData) data);
#else /* >= 8000 */
	Tcl_CreateFileHandler(id, mask, FileHandler, (ClientData) data);
#endif  /* >= 8000 */
	/* XXX fileHandlerDict */
	Py_INCREF(Py_None);
	return Py_None;
}


static PyObject *
Tkapp_DeleteFileHandler(self, args)
	PyObject *self;
	PyObject *args;			     /* Args: file */
{
	PyObject *file;
	PyObject *idkey;
	PyObject *data;
	int id;
#if TKMAJORMINOR < 8000
	Tcl_File tfile;
#endif
  
	if (!PyArg_ParseTuple(args, "O", &file))
		return NULL;
	id = GetFileNo(file);
	if (id < 0)
		return NULL;

	if (!(idkey = PyInt_FromLong(id)))
		return NULL;
	
	/* find and free the object created in the
	 * Tkapp_CreateFileHandler() call
	 */
	data = PyDict_GetItem(Tkapp_ClientDataDict, idkey);
	Py_XDECREF(data);
	PyDict_DelItem(Tkapp_ClientDataDict, idkey);
	Py_DECREF(idkey);

#if TKMAJORMINOR < 8000
#ifdef MS_WINDOWS
	/* We assume this is a socket... */
	tfile = Tcl_GetFile((ClientData)id, TCL_WIN_SOCKET);
#else
	tfile = Tcl_GetFile((ClientData)id, TCL_UNIX_FD);
#endif
	/* Ought to check for null Tcl_File object... */
	Tcl_DeleteFileHandler(tfile);
#else /* >= 8000 */
	Tcl_DeleteFileHandler(id);
#endif /* >= 8000 */
	/* XXX fileHandlerDict */
	Py_INCREF(Py_None);
	return Py_None;
}
#endif /* HAVE_CREATEFILEHANDLER */


/**** Tktt Object (timer token) ****/

staticforward PyTypeObject Tktt_Type;

typedef struct
{
	PyObject_HEAD
	Tcl_TimerToken token;
	PyObject *func;
}
TkttObject;

static PyObject *
Tktt_DeleteTimerHandler(self, args)
	PyObject *self;
	PyObject *args;
{
	TkttObject *v = (TkttObject *)self;

	if (!PyArg_ParseTuple(args, ""))
		return NULL;
	if (v->func != NULL) {
		Tcl_DeleteTimerHandler(v->token);
		PyMem_DEL(v->func);
		v->func = NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyMethodDef Tktt_methods[] =
{
	{"deletetimerhandler", Tktt_DeleteTimerHandler, 1},
	{NULL, NULL}
};

static TkttObject *
Tktt_New(token, func)
	Tcl_TimerToken token;
	PyObject *func;
{
	TkttObject *v;
  
	v = PyObject_NEW(TkttObject, &Tktt_Type);
	if (v == NULL)
		return NULL;

	v->token = token;
	v->func = func;
	Py_INCREF(v->func);
	return v;
}

static void
Tktt_Dealloc(self)
	PyObject *self;
{
	PyMem_DEL(self);
}

static int
Tktt_Print(self, fp, flags)
	PyObject *self;
	FILE *fp;
	int flags;
{
	TkttObject *v = (TkttObject *)self;

	fprintf(fp, "<tktimertoken at 0x%lx%s>", (long)v,
		v->func == NULL ? ", handler deleted" : "");
	return 0;
}

static PyObject *
Tktt_GetAttr(self, name)
	PyObject *self;
	char *name;
{
	return Py_FindMethod(Tktt_methods, self, name);
}

static PyTypeObject Tktt_Type =
{
	PyObject_HEAD_INIT(NULL)
	0,				     /*ob_size */
	"tktimertoken",			     /*tp_name */
	sizeof(TkttObject),		     /*tp_basicsize */
	0,				     /*tp_itemsize */
	Tktt_Dealloc,			     /*tp_dealloc */
	Tktt_Print,			     /*tp_print */
	Tktt_GetAttr,			     /*tp_getattr */
	0,				     /*tp_setattr */
	0,				     /*tp_compare */
	0,				     /*tp_repr */
	0,				     /*tp_as_number */
	0,				     /*tp_as_sequence */
	0,				     /*tp_as_mapping */
	0,				     /*tp_hash */
};



/** Timer Handler **/

static void
TimerHandler(clientData)
	ClientData clientData;
{
	PyObject *func = (PyObject *)clientData;
	PyObject *res  = PyEval_CallObject(func, NULL);

	if (res == NULL) {
		errorInCmd = 1;
		PyErr_Fetch(&excInCmd, &valInCmd, &trbInCmd);
	}
	else
		Py_DECREF(res);
}

static PyObject *
Tkapp_CreateTimerHandler(self, args)
	PyObject *self;
	PyObject *args;			     /* Is (milliseconds, func) */
{
	int milliseconds;
	PyObject *func;
	Tcl_TimerToken token;

	if (!PyArg_ParseTuple(args, "iO", &milliseconds, &func))
		return NULL;
	if (!PyCallable_Check(func)) {
		PyErr_SetString(PyExc_TypeError, "bad argument list");
		return NULL;
	}
	token = Tcl_CreateTimerHandler(milliseconds, TimerHandler,
				       (ClientData)func);

	return (PyObject *) Tktt_New(token, func);
}



/** Event Loop **/

static PyObject *
Tkapp_MainLoop(self, args)
	PyObject *self;
	PyObject *args;
{
	int threshold = 0;

	if (!PyArg_ParseTuple(args, "|i", &threshold))
		return NULL;

	quitMainLoop = 0;
	while (Tk_GetNumMainWindows() > threshold &&
	       !quitMainLoop &&
	       !errorInCmd)
	{
		int result;
#ifdef HAVE_PYTCL_WAITUNTILEVENT
		result = Tcl_DoOneEvent(TCL_DONT_WAIT);
		if (PyErr_CheckSignals() != 0)
			return NULL;
		if (result)
			continue;
		/* XXX It's not *quite* certain that this is
		   thread-safe, but it seems *rather* safe as long as
		   no two threads call mainloop() simultaneously. */
		Py_BEGIN_ALLOW_THREADS
		result = PyTcl_WaitUntilEvent();
		Py_END_ALLOW_THREADS
#else
		result = Tcl_DoOneEvent(0);
#endif
		if (PyErr_CheckSignals() != 0)
			return NULL;
		if (result < 0)
			break;
	}
	quitMainLoop = 0;

	if (errorInCmd) {
		errorInCmd = 0;
		PyErr_Restore(excInCmd, valInCmd, trbInCmd);
		excInCmd = valInCmd = trbInCmd = NULL;
		return NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
Tkapp_DoOneEvent(self, args)
	PyObject *self;
	PyObject *args;
{
	int flags = 0;
	int rv;

	if (!PyArg_ParseTuple(args, "|i", &flags))
		return NULL;

	rv = Tcl_DoOneEvent(flags);
	return Py_BuildValue("i", rv);
}

static PyObject *
Tkapp_Quit(self, args)
	PyObject *self;
	PyObject *args;
{

	if (!PyArg_ParseTuple(args, ""))
		return NULL;

	quitMainLoop = 1;
	Py_INCREF(Py_None);
	return Py_None;
}



/**** Tkapp Method List ****/

static PyMethodDef Tkapp_methods[] =
{
	{"call", 	       Tkapp_Call, 0},
	{"globalcall", 	       Tkapp_GlobalCall, 0},
	{"eval", 	       Tkapp_Eval, 1},
	{"globaleval", 	       Tkapp_GlobalEval, 1},
	{"evalfile", 	       Tkapp_EvalFile, 1},
	{"record", 	       Tkapp_Record, 1},
	{"adderrorinfo",       Tkapp_AddErrorInfo, 1},
	{"setvar", 	       Tkapp_SetVar, 1},
	{"globalsetvar",       Tkapp_GlobalSetVar, 1},
	{"getvar", 	       Tkapp_GetVar, 1},
	{"globalgetvar",       Tkapp_GlobalGetVar, 1},
	{"unsetvar", 	       Tkapp_UnsetVar, 1},
	{"globalunsetvar",     Tkapp_GlobalUnsetVar, 1},
	{"getint", 	       Tkapp_GetInt, 1},
	{"getdouble", 	       Tkapp_GetDouble, 1},
	{"getboolean", 	       Tkapp_GetBoolean, 1},
	{"exprstring", 	       Tkapp_ExprString, 1},
	{"exprlong", 	       Tkapp_ExprLong, 1},
	{"exprdouble", 	       Tkapp_ExprDouble, 1},
	{"exprboolean",        Tkapp_ExprBoolean, 1},
	{"splitlist", 	       Tkapp_SplitList, 1},
	{"split", 	       Tkapp_Split, 1},
	{"merge", 	       Tkapp_Merge, 0},
	{"createcommand",      Tkapp_CreateCommand, 1},
	{"deletecommand",      Tkapp_DeleteCommand, 1},
#ifdef HAVE_CREATEFILEHANDLER
	{"createfilehandler",  Tkapp_CreateFileHandler, 1},
	{"deletefilehandler",  Tkapp_DeleteFileHandler, 1},
#endif
	{"createtimerhandler", Tkapp_CreateTimerHandler, 1},
	{"mainloop", 	       Tkapp_MainLoop, 1},
	{"dooneevent", 	       Tkapp_DoOneEvent, 1},
	{"quit", 	       Tkapp_Quit, 1},
	{NULL, 		       NULL}
};



/**** Tkapp Type Methods ****/

static void
Tkapp_Dealloc(self)
	PyObject *self;
{
	Tcl_DeleteInterp(Tkapp_Interp(self));
	PyMem_DEL(self);
}

static PyObject *
Tkapp_GetAttr(self, name)
	PyObject *self;
	char *name;
{
	return Py_FindMethod(Tkapp_methods, self, name);
}

static PyTypeObject Tkapp_Type =
{
	PyObject_HEAD_INIT(NULL)
	0,				     /*ob_size */
	"tkapp",			     /*tp_name */
	sizeof(TkappObject),		     /*tp_basicsize */
	0,				     /*tp_itemsize */
	Tkapp_Dealloc,			     /*tp_dealloc */
	0,				     /*tp_print */
	Tkapp_GetAttr,			     /*tp_getattr */
	0,				     /*tp_setattr */
	0,				     /*tp_compare */
	0,				     /*tp_repr */
	0,				     /*tp_as_number */
	0,				     /*tp_as_sequence */
	0,				     /*tp_as_mapping */
	0,				     /*tp_hash */
};



/**** Tkinter Module ****/

static PyObject *
Tkinter_Create(self, args)
	PyObject *self;
	PyObject *args;
{
	char *screenName = NULL;
	char *baseName = NULL;
	char *className = NULL;
	int interactive = 0;

	baseName = strrchr(Py_GetProgramName(), '/');
	if (baseName != NULL)
		baseName++;
	else
		baseName = Py_GetProgramName();
	className = "Tk";
  
	if (!PyArg_ParseTuple(args, "|zssi",
			      &screenName, &baseName, &className,
			      &interactive))
		return NULL;

	return (PyObject *) Tkapp_New(screenName, baseName, className, 
				      interactive);
}

static PyMethodDef moduleMethods[] =
{
	{"create",             Tkinter_Create, 1},
#ifdef HAVE_CREATEFILEHANDLER
	{"createfilehandler",  Tkapp_CreateFileHandler, 1},
	{"deletefilehandler",  Tkapp_DeleteFileHandler, 1},
#endif
	{"createtimerhandler", Tkapp_CreateTimerHandler, 1},
	{"mainloop",           Tkapp_MainLoop, 1},
	{"dooneevent",         Tkapp_DoOneEvent, 1},
	{"quit",               Tkapp_Quit, 1},
	{NULL,                 NULL}
};

static PyInterpreterState *event_interp = NULL;

static int
EventHook()
{
	PyThreadState *tstate, *save_tstate;

	if (Tk_GetNumMainWindows() == 0)
		return 0;
	if (event_interp == NULL)
		return 0;
	tstate = PyThreadState_New(event_interp);
	save_tstate = PyThreadState_Swap(NULL);
	PyEval_RestoreThread(tstate);
	if (!errorInCmd)
		Tcl_DoOneEvent(TCL_DONT_WAIT);
	if (errorInCmd) {
		errorInCmd = 0;
		PyErr_Restore(excInCmd, valInCmd, trbInCmd);
		excInCmd = valInCmd = trbInCmd = NULL;
		PyErr_Print();
	}
	PyThreadState_Clear(tstate);
	PyEval_SaveThread();
	PyThreadState_Swap(save_tstate);
	PyThreadState_Delete(tstate);
	return 0;
}


/* all errors will be checked in one fell swoop in init_tkinter() */
static void
ins_long(d, name, val)
	PyObject *d;
	char *name;
	long val;
{
	PyObject *v = PyInt_FromLong(val);
	if (v) {
		PyDict_SetItemString(d, name, v);
		Py_DECREF(v);
	}
}
static void
ins_string(d, name, val)
	PyObject *d;
	char *name;
	char *val;
{
	PyObject *v = PyString_FromString(val);
	if (v) {
		PyDict_SetItemString(d, name, v);
		Py_DECREF(v);
	}
}


void
init_tkinter()
{
	PyObject *m, *d;

	Tkapp_Type.ob_type = &PyType_Type;
	Tktt_Type.ob_type = &PyType_Type;

	m = Py_InitModule("_tkinter", moduleMethods);

	d = PyModule_GetDict(m);
	Tkinter_TclError = Py_BuildValue("s", "TclError");
	PyDict_SetItemString(d, "TclError", Tkinter_TclError);

	ins_long(d, "READABLE", TCL_READABLE);
	ins_long(d, "WRITABLE", TCL_WRITABLE);
	ins_long(d, "EXCEPTION", TCL_EXCEPTION);
	ins_long(d, "WINDOW_EVENTS", TCL_WINDOW_EVENTS);
	ins_long(d, "FILE_EVENTS", TCL_FILE_EVENTS);
	ins_long(d, "TIMER_EVENTS", TCL_TIMER_EVENTS);
	ins_long(d, "IDLE_EVENTS", TCL_IDLE_EVENTS);
	ins_long(d, "ALL_EVENTS", TCL_ALL_EVENTS);
	ins_long(d, "DONT_WAIT", TCL_DONT_WAIT);
	ins_string(d, "TK_VERSION", TK_VERSION);
	ins_string(d, "TCL_VERSION", TCL_VERSION);

	PyDict_SetItemString(d, "TkappType", (PyObject *)&Tkapp_Type);
	PyDict_SetItemString(d, "TkttType", (PyObject *)&Tktt_Type);

	if (PyOS_InputHook == NULL) {
		event_interp = PyThreadState_Get()->interp;
		PyOS_InputHook = EventHook;
	}

	if (PyErr_Occurred())
		return;

	Py_AtExit(Tcl_Finalize);

#ifdef macintosh
	/*
	** Part of this code is stolen from MacintoshInit in tkMacAppInit.
	** Most of the initializations in that routine (toolbox init calls and
	** such) have already been done for us, so we only need these.
	*/
#if TKMAJORMINOR >= 8000
	tcl_macQdPtr = &qd;
#endif

	Tcl_MacSetEventProc(PyMacConvertEvent);
#if GENERATINGCFM
	mac_addlibresources();
#endif /* GENERATINGCFM */
#endif /* macintosh */
}



#ifdef macintosh

/*
** Anyone who embeds Tcl/Tk on the Mac must define panic().
*/

void
panic(char * format, ...)
{
	va_list varg;
	
	va_start(varg, format);
	
	vfprintf(stderr, format, varg);
	(void) fflush(stderr);
	
	va_end(varg);

	Py_FatalError("Tcl/Tk panic");
}

/*
** Pass events to SIOUX before passing them to Tk.
*/

static int
PyMacConvertEvent(eventPtr)
	EventRecord *eventPtr;
{
	if (SIOUXHandleOneEvent(eventPtr))
		return 0; /* Nothing happened to the Tcl event queue */
	return TkMacConvertEvent(eventPtr);
}

#if defined(USE_GUSI) && TKMAJORMINOR < 8000
/*
 * For Python we have to override this routine (from TclMacNotify),
 * since we use GUSI for our sockets, not Tcl streams. Hence, we have
 * to use GUSI select to see whether our socket is ready. Note that
 * createfilehandler (above) sets the type to TCL_UNIX_FD for our
 * files and sockets.
 *
 * NOTE: this code was lifted from Tcl 7.6, it may need to be modified
 * for other versions.  */

int
Tcl_FileReady(file, mask)
    Tcl_File file;		/* File handle for a stream. */
    int mask;			/* OR'ed combination of TCL_READABLE,
				 * TCL_WRITABLE, and TCL_EXCEPTION:
				 * indicates conditions caller cares about. */
{
    int type;
    int fd;

    fd = (int) Tcl_GetFileInfo(file, &type);

    if (type == TCL_MAC_SOCKET) {
	return TclMacSocketReady(file, mask);
    } else if (type == TCL_MAC_FILE) {
	/*
	 * Under the Macintosh, files are always ready, so we just 
	 * return the mask that was passed in.
	 */

	return mask;
    } else if (type == TCL_UNIX_FD) {
	fd_set readset, writeset, excset;
	struct timeval tv;
	
	FD_ZERO(&readset);
	FD_ZERO(&writeset);
	FD_ZERO(&excset);
	
	if ( mask & TCL_READABLE ) FD_SET(fd, &readset);
	if ( mask & TCL_WRITABLE ) FD_SET(fd, &writeset);
	if ( mask & TCL_EXCEPTION ) FD_SET(fd, &excset);
	
	tv.tv_sec = tv.tv_usec = 0;
	if ( select(fd+1, &readset, &writeset, &excset, &tv) <= 0 )
		return 0;
	
	mask = 0;
	if ( FD_ISSET(fd, &readset) ) mask |= TCL_READABLE;
	if ( FD_ISSET(fd, &writeset) ) mask |= TCL_WRITABLE;
	if ( FD_ISSET(fd, &excset) ) mask |= TCL_EXCEPTION;

	return mask;
    }
    
    return 0;
}
#endif /* USE_GUSI */

#if GENERATINGCFM

/*
** Additional Mac specific code for dealing with shared libraries.
*/

#include <Resources.h>
#include <CodeFragments.h>

static int loaded_from_shlib = 0;
static FSSpec library_fss;

/*
** If this module is dynamically loaded the following routine should
** be the init routine. It takes care of adding the shared library to
** the resource-file chain, so that the tk routines can find their
** resources.
*/
OSErr pascal
init_tkinter_shlib(CFragInitBlockPtr data)
{
	__initialize();
	if ( data == nil ) return noErr;
	if ( data->fragLocator.where == kDataForkCFragLocator ) {
		library_fss = *data->fragLocator.u.onDisk.fileSpec;
		loaded_from_shlib = 1;
	} else if ( data->fragLocator.where == kResourceCFragLocator ) {
		library_fss = *data->fragLocator.u.inSegs.fileSpec;
		loaded_from_shlib = 1;
	}
	return noErr;
}

/*
** Insert the library resources into the search path. Put them after
** the resources from the application. Again, we ignore errors.
*/
static
mac_addlibresources()
{
	if ( !loaded_from_shlib ) 
		return;
	(void)FSpOpenResFile(&library_fss, fsRdPerm);
}

#endif /* GENERATINGCFM */
#endif /* macintosh */
