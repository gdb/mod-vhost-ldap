#ifndef Py_METHODOBJECT_H
#define Py_METHODOBJECT_H
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

/* Method object interface */

extern DL_IMPORT typeobject Methodtype;

#define is_methodobject(op) ((op)->ob_type == &Methodtype)

typedef object *(*method) FPROTO((object *, object *));

extern method getmethod PROTO((object *));
extern object *getself PROTO((object *));
extern int getvarargs PROTO((object *));

struct methodlist {
	char	*ml_name;
	method	ml_meth;
	int	ml_flags;
	char	*ml_doc;
};

extern object *newmethodobject PROTO((struct methodlist *, object *));

extern object *findmethod PROTO((struct methodlist[], object *, char *));

/* Flag passed to newmethodobject */
#define METH_VARARGS  0x0001

#ifdef __cplusplus
}
#endif
#endif /* !Py_METHODOBJECT_H */
