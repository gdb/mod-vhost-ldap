#ifndef Py_DICTOBJECT_H
#define Py_DICTOBJECT_H
#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************
Copyright 1991, 1992, 1993 by Stichting Mathematisch Centrum,
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

/* All in the sake of backward compatibility... */

#include "mappingobject.h"

#define is_dictobject(op) is_mappingobject(op)

#define newdictobject newmappingobject

extern object *dictlookup PROTO((object *dp, char *key));
extern int dictinsert PROTO((object *dp, char *key, object *item));
extern int dictremove PROTO((object *dp, char *key));

#define getdictkeys getmappingkeys

#define dict2lookup mappinglookup
#define dict2insert mappinginsert
#define dict2remove mappingremove

#ifdef __cplusplus
}
#endif
#endif /* !Py_DICTOBJECT_H */
