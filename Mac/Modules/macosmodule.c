/***********************************************************
Copyright 1991, 1992, 1993, 1994 by Stichting Mathematisch Centrum,
Amsterdam, The Netherlands.

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

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <Resources.h>
#include <Sound.h>

/*----------------------------------------------------------------------*/
/* General tools */

static PyObject *MacOS_Error; /* Exception MacOS.Error */

/* Set a MAC-specific error from errno, and return NULL; return None if no error */
static PyObject * 
Err(OSErr err)
{
	char buf[100];
	PyObject *v;
	if (err == 0) {
		Py_INCREF(Py_None);
		return Py_None;
	}
	sprintf(buf, "Mac OS error code %d", (int)err);
	v = Py_BuildValue("(is)", (int)err, buf);
	PyErr_SetObject(MacOS_Error, v);
	Py_DECREF(v);
	return NULL;
}

/* Check for a ResType argument */
static int
GetOSType(PyObject *v, ResType *pr)
{
	if (!PyString_Check(v) || PyString_Size(v) != 4) {
		PyErr_SetString(MacOS_Error,
			"OSType arg must be string of 4 chars");
		return 0;
	}
	memcpy((char *)pr, PyString_AsString(v), 4);
	return 1;
}

/* Check for a Str255 argument */
static int
GetStr255(PyObject *v, Str255 pbuf)
{
	int len;
	if (!PyString_Check(v) || (len = PyString_Size(v)) > 255) {
		PyErr_SetString(MacOS_Error,
			"Str255 arg must be string <= 255 chars");
		return 0;
	}
	pbuf[0] = len;
	memcpy((char *)(pbuf+1), PyString_AsString(v), len);
	return 1;
}

/*----------------------------------------------------------------------*/
/* Resource objects */

typedef struct {
	OB_HEAD
	Handle h;
} RsrcObject;

staticforward PyTypeObject RsrcType;

#define RsrcObject_Check(r) ((r)->ob_type == &RsrcType)

static RsrcObject *
Rsrc_FromHandle(Handle h)
{
	RsrcObject *r;
	if (h == NULL)
		return (RsrcObject *)Err(ResError());
	r = PyObject_NEW(RsrcObject, &RsrcType);
	if (r != NULL)
		r->h = h;
	return r;
}

static void
Rsrc_Dealloc(RsrcObject *r)
{
	PyMem_DEL(r);
}

static PyObject *
Rsrc_GetResInfo(RsrcObject *r, PyObject *args)
{
	short id;
	ResType type;
	Str255 name;
	if (!PyArg_Parse(args, "()"))
		return NULL;
	GetResInfo(r->h, &id, &type, name);
	return Py_BuildValue("(is#s#)",
		(int)id, (char *)&type, 4, name+1, (int)name[0]);
}

static PyMethodDef Rsrc_Methods[] = {
	{"GetResInfo",	(PyCFunction)Rsrc_GetResInfo, 1},
	{NULL,			NULL}		 /* Sentinel */
};

static PyObject *
Rsrc_GetAttr(PyObject *r, char *name)
{
	return Py_FindMethod(Rsrc_Methods, r, name);
}

static PyTypeObject RsrcType = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,
	"Resource",			/*tp_name*/
	sizeof(RsrcObject),	/*tp_basicsize*/
	0,			/*tp_itemsize*/
	/* methods */
	(destructor)Rsrc_Dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	(getattrfunc)Rsrc_GetAttr, /*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
};

static PyObject *
MacOS_GetResource(PyObject *self, PyObject *args)
{
	ResType rt;
	int id;
	Handle h;
	if (!PyArg_Parse(args, "(O&i)", GetOSType, &rt, &id))
		return NULL;
	h = GetResource(rt, id);
	return (PyObject *)Rsrc_FromHandle(h);
}

static PyObject *
MacOS_GetNamedResource(PyObject *self, PyObject *args)
{
	ResType rt;
	Str255 name;
	Handle h;
	if (!PyArg_Parse(args, "(O&O&)", GetOSType, &rt, GetStr255, &name))
		return NULL;
	h = GetNamedResource(rt, name);
	return (PyObject *)Rsrc_FromHandle(h);
}

/*----------------------------------------------------------------------*/
/* SoundChannel objects */

/* Check for a SndCommand argument */
static int
GetSndCommand(PyObject *v, SndCommand *pc)
{
	int len;
	pc->param1 = 0;
	pc->param2 = 0;
	if (PyArg_Parse(v, "h", &pc->cmd))
		return 1;
	PyErr_Clear();
	if (PyArg_Parse(v, "(h)", &pc->cmd))
		return 1;
	PyErr_Clear();
	if (PyArg_Parse(v, "(hh)", &pc->cmd, &pc->param1))
		return 1;
	PyErr_Clear();
	if (PyArg_Parse(v, "(hhl)",
			&pc->cmd, &pc->param1, &pc->param2))
		return 1;
	PyErr_Clear();
	if (PyArg_Parse(v, "(hhs#);SndCommand arg must be 1-3 ints or 2 ints + string",
			&pc->cmd, &pc->param1, &pc->param2, &len))
		return 1;
	return 0;
}

typedef struct {
	OB_HEAD
	SndChannelPtr chan;
} SndChObject;

staticforward PyTypeObject SndChType;

#define SndChObject_Check(s) ((s)->ob_type == &SndChType)

static SndChObject *
SndCh_FromSndChannelPtr(SndChannelPtr chan)
{
	SndChObject *s = PyObject_NEW(SndChObject, &SndChType);
	if (s != NULL)
		s->chan = chan;
	return s;
}

static void
SndCh_Dealloc(SndChObject *s)
{
	if (s->chan != NULL) {
		SndDisposeChannel(s->chan, 1);
		s->chan = NULL;
	}
	PyMem_DEL(s);
}

static PyObject *
SndCh_Close(SndChObject *s, PyObject *args)
{
	int quietNow = 1;
	if (args != NULL) {
		if (!PyArg_Parse(args, "i", &quietNow))
			return NULL;
	}
	if (s->chan != NULL) {
		SndDisposeChannel(s->chan, quietNow);
		s->chan = NULL;
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
SndCh_SndPlay(SndChObject *s, PyObject *args)
{
	RsrcObject *r;
	int async = 0;
	if (!PyArg_Parse(args, "(O)", &r)) {
		PyErr_Clear();
		if (!PyArg_Parse(args, "(Oi)", &r, &async))
			return NULL;
	}
	if (!RsrcObject_Check(r)) {
		PyErr_SetString(MacOS_Error,
			"SndPlay argument must be resource");
		return NULL;
	}
	SndPlay(s->chan, r->h, async);
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
SndCh_SndDoCommand(SndChObject *s, PyObject *args)
{
	SndCommand c;
	int noWait = 0;
	OSErr err;
	if (!PyArg_Parse(args, "(O&)", GetSndCommand, &c)) {
		PyErr_Clear();
		if (!PyArg_Parse(args, "(O&i)", GetSndCommand, &c, &noWait))
			return 0;
	}
	err = SndDoCommand(s->chan, &c, noWait);
	return Err(err);
}

static PyObject *
SndCh_SndDoImmediate(SndChObject *s, PyObject *args)
{
	SndCommand c;
	OSErr err;
	if (!PyArg_Parse(args, "(O&)", GetSndCommand, &c))
		return 0;
	err = SndDoImmediate(s->chan, &c);
	return Err(err);
}

static PyMethodDef SndCh_Methods[] = {
	{"close",				(PyCFunction)SndCh_Close},
	{"SndDisposeChannel",	(PyCFunction)SndCh_Close},
	{"SndPlay",				(PyCFunction)SndCh_SndPlay, 1},
	{"SndDoCommand",		(PyCFunction)SndCh_SndDoCommand, 1},
	{"SndDoImmediate",		(PyCFunction)SndCh_SndDoImmediate, 1},
	{NULL,					NULL}		 /* Sentinel */
};

static PyObject *
SndCh_GetAttr(PyObject *s, char *name)
{
	return Py_FindMethod(SndCh_Methods, s, name);
}

static PyTypeObject SndChType = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,
	"SoundChannel",			/*tp_name*/
	sizeof(SndChObject),	/*tp_basicsize*/
	0,			/*tp_itemsize*/
	/* methods */
	(destructor)SndCh_Dealloc, /*tp_dealloc*/
	0,			/*tp_print*/
	(getattrfunc)SndCh_GetAttr, /*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	0,			/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
};

/*----------------------------------------------------------------------*/
/* Module */

static PyObject *
MacOS_SndNewChannel(PyObject *self, PyObject *args)
{
	SndChannelPtr chan;
	short synth;
	long init = 0;
	OSErr err;
	if (!PyArg_Parse(args, "(h)", &synth)) {
		PyErr_Clear();
		if (!PyArg_Parse(args, "(hl)", &synth, &init))
			return NULL;
	}
	chan = NULL;
	err = SndNewChannel(&chan, synth, init, (SndCallBackProcPtr)NULL);
	if (err)
		return Err(err);
	return (PyObject *)SndCh_FromSndChannelPtr(chan);
}

static PyObject *
MacOS_SndPlay(PyObject *self, PyObject *args)
{
	RsrcObject *r;
	OSErr err;
	if (!PyArg_Parse(args, "(O!)", &RsrcType, &r))
		return NULL;
	err = SndPlay((SndChannelPtr)NULL, r->h, 0);
	return Err(err);
}

static PyObject *
MacOS_SndControl(PyObject *self, PyObject *args)
{
	int id;
	SndCommand c;
	OSErr err;
	if (!PyArg_Parse(args, "(iO&)", &id, GetSndCommand, &c))
		return NULL;
	err = SndControl(id, &c);
	if (err)
		return Err(err);
	return Py_BuildValue("(hhl)", c.cmd, c.param1, c.param2);
}

static PyMethodDef MacOS_Methods[] = {
	{"GetResource",			MacOS_GetResource, 1},
	{"GetNamedResource",	MacOS_GetNamedResource, 1},
	{"SndNewChannel",		MacOS_SndNewChannel, 1},
	{"SndPlay",				MacOS_SndPlay, 1},
	{"SndControl",			MacOS_SndControl, 1},
	{NULL,					NULL}		 /* Sentinel */
};


void
MacOS_Init()
{
	PyObject *m, *d;
	
	m = Py_InitModule("MacOS", MacOS_Methods);
	d = PyModule_GetDict(m);
	
	/* Initialize MacOS.Error exception */
	MacOS_Error = PyString_FromString("MacOS.Error");
	if (MacOS_Error == NULL || PyDict_SetItemString(d, "Error", MacOS_Error) != 0)
		Py_FatalError("can't define MacOS.Error");
}
