#ifndef Py_DICTOBJECT_H
#define Py_DICTOBJECT_H
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

/* All in the sake of backward compatibility... */

#include "mappingobject.h"

#define PyDict_Check(op) is_mappingobject(op)

#define newdictobject PyDict_New

extern PyObject *PyDict_GetItemString Py_PROTO((PyObject *dp, char *key));
extern int PyDict_SetItemString Py_PROTO((PyObject *dp, char *key, PyObject *item));
extern int PyDict_DelItemString Py_PROTO((PyObject *dp, char *key));

#define getdictkeys PyDict_Keys

#define dict2lookup PyDict_GetItem
#define dict2insert PyDict_SetItem
#define dict2remove PyDict_DelItem

#ifdef __cplusplus
}
#endif
#endif /* !Py_DICTOBJECT_H */
