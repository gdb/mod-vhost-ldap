#ifndef Py_IMPORT_H
#define Py_IMPORT_H
#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************
Copyright 1991-1995 by Stichting Mathematisch Centrum, Amsterdam,
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

/* Module definition and import interface */

void PyImport_Init Py_PROTO((void));
long PyImport_GetMagicNumber Py_PROTO((void));
PyObject *PyImport_ExecCodeModule Py_PROTO((char *name, PyObject *co));
PyObject *PyImport_GetModuleDict Py_PROTO((void));
PyObject *PyImport_AddModule Py_PROTO((char *name));
PyObject *PyImport_ImportModule Py_PROTO((char *name));
PyObject *PyImport_ReloadModule Py_PROTO((PyObject *m));
void PyImport_Cleanup Py_PROTO((void));
int PyImport_ImportFrozenModule Py_PROTO((char *));

struct _inittab {
	char *name;
	void (*initfunc)();
};

/* This table is defined in config.c: */

extern struct _inittab inittab[];

struct _frozen {
	char *name;
	unsigned char *code;
	int size;
};

/* Embedding apps may change this pointer to point to their favorite
   collection of frozen modules: */

extern DL_IMPORT(struct _frozen *) PyImport_FrozenModules;

#ifdef __cplusplus
}
#endif
#endif /* !Py_IMPORT_H */
