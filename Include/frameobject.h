#ifndef Py_FRAMEOBJECT_H
#define Py_FRAMEOBJECT_H
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

/* Frame object interface */

typedef struct {
	int b_type;		/* what kind of block this is */
	int b_handler;		/* where to jump to find handler */
	int b_level;		/* value stack level to pop to */
} block;

typedef struct _frame {
	OB_HEAD
	struct _frame *f_back;	/* previous frame, or NULL */
	codeobject *f_code;	/* code segment */
	object *f_globals;	/* global symbol table (dictobject) */
	object *f_locals;	/* local symbol table (dictobject) */
	object *f_owner;	/* owner (e.g. class or module) or NULL */
	object *f_fastlocals;	/* fast local variables (listobject) */
	object *f_localmap;	/* local variable names (dictobject) */
	object **f_valuestack;	/* malloc'ed array */
	block *f_blockstack;	/* malloc'ed array */
	int f_nvalues;		/* size of f_valuestack */
	int f_nblocks;		/* size of f_blockstack */
	int f_iblock;		/* index in f_blockstack */
	int f_lasti;		/* Last instruction if called */
	int f_lineno;		/* Current line number */
	object *f_trace;	/* Trace function */
} frameobject;


/* Standard object interface */

extern DL_IMPORT typeobject Frametype;

#define is_frameobject(op) ((op)->ob_type == &Frametype)

frameobject * newframeobject PROTO(
	(frameobject *, codeobject *, object *, object *, object *, int, int));


/* The rest of the interface is specific for frame objects */

/* List access macros */

#ifdef NDEBUG
#define GETITEM(v, i) GETTUPLEITEM((tupleobject *)(v), (i))
#define GETITEMNAME(v, i) GETSTRINGVALUE((stringobject *)GETITEM((v), (i)))
#else
#define GETITEM(v, i) gettupleitem((v), (i))
#define GETITEMNAME(v, i) getstringvalue(GETITEM(v, i))
#endif

#define GETUSTRINGVALUE(s) ((unsigned char *)GETSTRINGVALUE(s))

/* Code access macros */

#define Getconst(f, i)	(GETITEM((f)->f_code->co_consts, (i)))
#define Getname(f, i)	(GETITEMNAME((f)->f_code->co_names, (i)))
#define Getnamev(f, i)	(GETITEM((f)->f_code->co_names, (i)))


/* Block management functions */

void setup_block PROTO((frameobject *, int, int, int));
block *pop_block PROTO((frameobject *));

/* Extend the value stack */

object **extend_stack PROTO((frameobject *, int, int));

/* Conversions between "fast locals" and locals in dictionary */

void locals_2_fast PROTO((frameobject *, int));
void fast_2_locals PROTO((frameobject *));

#ifdef __cplusplus
}
#endif
#endif /* !Py_FRAMEOBJECT_H */
