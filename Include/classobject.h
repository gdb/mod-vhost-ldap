#ifndef Py_CLASSOBJECT_H
#define Py_CLASSOBJECT_H
#ifdef __cplusplus
extern "C" {
#endif

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

/* Class object interface */

/* Revealing some structures (not for general use) */

typedef struct {
	OB_HEAD
	object	*cl_bases;	/* A tuple of class objects */
	object	*cl_dict;	/* A dictionary */
	object	*cl_name;	/* A string */
} classobject;

typedef struct {
	OB_HEAD
	classobject	*in_class;	/* The class object */
	object		*in_dict;	/* A dictionary */
} instanceobject;

extern typeobject Classtype, Instancetype, Instancemethodtype;

#define is_classobject(op) ((op)->ob_type == &Classtype)
#define is_instanceobject(op) ((op)->ob_type == &Instancetype)
#define is_instancemethodobject(op) ((op)->ob_type == &Instancemethodtype)

extern object *newclassobject PROTO((object *, object *, object *));
extern object *newinstanceobject PROTO((object *, object *));
extern object *newinstancemethodobject PROTO((object *, object *, object *));

extern object *instancemethodgetfunc PROTO((object *));
extern object *instancemethodgetself PROTO((object *));
extern object *instancemethodgetclass PROTO((object *));

extern int issubclass PROTO((object *, object *));

#ifdef __cplusplus
}
#endif
#endif /* !Py_CLASSOBJECT_H */
