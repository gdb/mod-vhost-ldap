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

/* Tuple object implementation */

#include "allobjects.h"

#ifndef MAXSAVESIZE
#define MAXSAVESIZE	20
#endif

#if MAXSAVESIZE > 0
/* Entries 1 upto MAXSAVESIZE are free lists, entry 0 is the empty
   tuple () of which at most one instance will be allocated.
*/
static tupleobject *free_tuples[MAXSAVESIZE];
#endif
#ifdef COUNT_ALLOCS
int fast_tuple_allocs;
int tuple_zero_allocs;
#endif

object *
newtupleobject(size)
	register int size;
{
	register int i;
	register tupleobject *op;
	if (size < 0) {
		err_badcall();
		return NULL;
	}
#if MAXSAVESIZE > 0
	if (size == 0 && free_tuples[0]) {
		op = free_tuples[0];
		INCREF(op);
#ifdef COUNT_ALLOCS
		tuple_zero_allocs++;
#endif
		return (object *) op;
	}
	if (0 < size && size < MAXSAVESIZE && (op = free_tuples[size]) != NULL) {
		free_tuples[size] = (tupleobject *) op->ob_item[0];
#ifdef COUNT_ALLOCS
		fast_tuple_allocs++;
#endif
	} else
#endif
	{
		op = (tupleobject *)
			malloc(sizeof(tupleobject) + size * sizeof(object *));
		if (op == NULL)
			return err_nomem();
	}
	op->ob_type = &Tupletype;
	op->ob_size = size;
	for (i = 0; i < size; i++)
		op->ob_item[i] = NULL;
	NEWREF(op);
#if MAXSAVESIZE > 0
	if (size == 0) {
		free_tuples[0] = op;
		INCREF(op);	/* extra INCREF so that this is never freed */
	}
#endif
	return (object *) op;
}

int
gettuplesize(op)
	register object *op;
{
	if (!is_tupleobject(op)) {
		err_badcall();
		return -1;
	}
	else
		return ((tupleobject *)op)->ob_size;
}

object *
gettupleitem(op, i)
	register object *op;
	register int i;
{
	if (!is_tupleobject(op)) {
		err_badcall();
		return NULL;
	}
	if (i < 0 || i >= ((tupleobject *)op) -> ob_size) {
		err_setstr(IndexError, "tuple index out of range");
		return NULL;
	}
	return ((tupleobject *)op) -> ob_item[i];
}

int
settupleitem(op, i, newitem)
	register object *op;
	register int i;
	object *newitem;
{
	register object *olditem;
	register object **p;
	if (!is_tupleobject(op)) {
		XDECREF(newitem);
		err_badcall();
		return -1;
	}
	if (i < 0 || i >= ((tupleobject *)op) -> ob_size) {
		XDECREF(newitem);
		err_setstr(IndexError, "tuple assignment index out of range");
		return -1;
	}
	p = ((tupleobject *)op) -> ob_item + i;
	olditem = *p;
	*p = newitem;
	XDECREF(olditem);
	return 0;
}

/* Methods */

static void
tupledealloc(op)
	register tupleobject *op;
{
	register int i;
	for (i = 0; i < op->ob_size; i++)
		XDECREF(op->ob_item[i]);
#if MAXSAVESIZE > 0
	if (0 < op->ob_size && op->ob_size < MAXSAVESIZE) {
		op->ob_item[0] = (object *) free_tuples[op->ob_size];
		free_tuples[op->ob_size] = op;
	} else
#endif
		free((ANY *)op);
}

static int
tupleprint(op, fp, flags)
	tupleobject *op;
	FILE *fp;
	int flags;
{
	int i;
	fprintf(fp, "(");
	for (i = 0; i < op->ob_size; i++) {
		if (i > 0)
			fprintf(fp, ", ");
		if (printobject(op->ob_item[i], fp, 0) != 0)
			return -1;
	}
	if (op->ob_size == 1)
		fprintf(fp, ",");
	fprintf(fp, ")");
	return 0;
}

static object *
tuplerepr(v)
	tupleobject *v;
{
	object *s, *comma;
	int i;
	s = newstringobject("(");
	comma = newstringobject(", ");
	for (i = 0; i < v->ob_size && s != NULL; i++) {
		if (i > 0)
			joinstring(&s, comma);
		joinstring_decref(&s, reprobject(v->ob_item[i]));
	}
	DECREF(comma);
	if (v->ob_size == 1)
		joinstring_decref(&s, newstringobject(","));
	joinstring_decref(&s, newstringobject(")"));
	return s;
}

static int
tuplecompare(v, w)
	register tupleobject *v, *w;
{
	register int len =
		(v->ob_size < w->ob_size) ? v->ob_size : w->ob_size;
	register int i;
	for (i = 0; i < len; i++) {
		int cmp = cmpobject(v->ob_item[i], w->ob_item[i]);
		if (cmp != 0)
			return cmp;
	}
	return v->ob_size - w->ob_size;
}

static long
tuplehash(v)
	tupleobject *v;
{
	register long x, y;
	register int len = v->ob_size;
	register object **p;
	x = 0x345678L;
	p = v->ob_item;
	while (--len >= 0) {
		y = hashobject(*p++);
		if (y == -1)
			return -1;
		x = (x + x + x) ^ y;
	}
	x ^= v->ob_size;
	if (x == -1)
		x = -2;
	return x;
}

static int
tuplelength(a)
	tupleobject *a;
{
	return a->ob_size;
}

static object *
tupleitem(a, i)
	register tupleobject *a;
	register int i;
{
	if (i < 0 || i >= a->ob_size) {
		err_setstr(IndexError, "tuple index out of range");
		return NULL;
	}
	INCREF(a->ob_item[i]);
	return a->ob_item[i];
}

static object *
tupleslice(a, ilow, ihigh)
	register tupleobject *a;
	register int ilow, ihigh;
{
	register tupleobject *np;
	register int i;
	if (ilow < 0)
		ilow = 0;
	if (ihigh > a->ob_size)
		ihigh = a->ob_size;
	if (ihigh < ilow)
		ihigh = ilow;
	if (ilow == 0 && ihigh == a->ob_size) {
		/* XXX can only do this if tuples are immutable! */
		INCREF(a);
		return (object *)a;
	}
	np = (tupleobject *)newtupleobject(ihigh - ilow);
	if (np == NULL)
		return NULL;
	for (i = ilow; i < ihigh; i++) {
		object *v = a->ob_item[i];
		INCREF(v);
		np->ob_item[i - ilow] = v;
	}
	return (object *)np;
}

object *
gettupleslice(op, i, j)
	object *op;
	int i, j;
{
	if (op == NULL || !is_tupleobject(op)) {
		err_badcall();
		return NULL;
	}
	return tupleslice((tupleobject *)op, i, j);
}

static object *
tupleconcat(a, bb)
	register tupleobject *a;
	register object *bb;
{
	register int size;
	register int i;
	tupleobject *np;
	if (!is_tupleobject(bb)) {
		err_badarg();
		return NULL;
	}
#define b ((tupleobject *)bb)
	size = a->ob_size + b->ob_size;
	np = (tupleobject *) newtupleobject(size);
	if (np == NULL) {
		return NULL;
	}
	for (i = 0; i < a->ob_size; i++) {
		object *v = a->ob_item[i];
		INCREF(v);
		np->ob_item[i] = v;
	}
	for (i = 0; i < b->ob_size; i++) {
		object *v = b->ob_item[i];
		INCREF(v);
		np->ob_item[i + a->ob_size] = v;
	}
	return (object *)np;
#undef b
}

static object *
tuplerepeat(a, n)
	tupleobject *a;
	int n;
{
	int i, j;
	int size;
	tupleobject *np;
	object **p;
	if (n < 0)
		n = 0;
	if (a->ob_size*n == a->ob_size) {
		/* Since tuples are immutable, we can return a shared
		   copy in this case */
		INCREF(a);
		return (object *)a;
	}
	size = a->ob_size * n;
	np = (tupleobject *) newtupleobject(size);
	if (np == NULL)
		return NULL;
	p = np->ob_item;
	for (i = 0; i < n; i++) {
		for (j = 0; j < a->ob_size; j++) {
			*p = a->ob_item[j];
			INCREF(*p);
			p++;
		}
	}
	return (object *) np;
}

static sequence_methods tuple_as_sequence = {
	(inquiry)tuplelength, /*sq_length*/
	(binaryfunc)tupleconcat, /*sq_concat*/
	(intargfunc)tuplerepeat, /*sq_repeat*/
	(intargfunc)tupleitem, /*sq_item*/
	(intintargfunc)tupleslice, /*sq_slice*/
	0,		/*sq_ass_item*/
	0,		/*sq_ass_slice*/
};

typeobject Tupletype = {
	OB_HEAD_INIT(&Typetype)
	0,
	"tuple",
	sizeof(tupleobject) - sizeof(object *),
	sizeof(object *),
	(destructor)tupledealloc, /*tp_dealloc*/
	(printfunc)tupleprint, /*tp_print*/
	0,		/*tp_getattr*/
	0,		/*tp_setattr*/
	(cmpfunc)tuplecompare, /*tp_compare*/
	(reprfunc)tuplerepr, /*tp_repr*/
	0,		/*tp_as_number*/
	&tuple_as_sequence,	/*tp_as_sequence*/
	0,		/*tp_as_mapping*/
	(hashfunc)tuplehash, /*tp_hash*/
};

/* The following function breaks the notion that tuples are immutable:
   it changes the size of a tuple.  We get away with this only if there
   is only one module referencing the object.  You can also think of it
   as creating a new tuple object and destroying the old one, only
   more efficiently.  In any case, don't use this if the tuple may
   already be known to some other part of the code...
   If last_is_sticky is set, the tuple will grow or shrink at the
   front, otherwise it will grow or shrink at the end. */

int
resizetuple(pv, newsize, last_is_sticky)
	object **pv;
	int newsize;
	int last_is_sticky;
{
	register tupleobject *v;
	register tupleobject *sv;
	int i;
	int sizediff;

	v = (tupleobject *) *pv;
	if (v == NULL || !is_tupleobject(v) || v->ob_refcnt != 1) {
		*pv = 0;
		DECREF(v);
		err_badcall();
		return -1;
	}
	sizediff = newsize - v->ob_size;
	if (sizediff == 0)
		return 0;
	/* XXX UNREF/NEWREF interface should be more symmetrical */
#ifdef Py_REF_DEBUG
	--_Py_RefTotal;
#endif
	UNREF(v);
	if (last_is_sticky && sizediff < 0) {
		/* shrinking: move entries to the front and zero moved entries */
		for (i = 0; i < newsize; i++) {
			XDECREF(v->ob_item[i]);
			v->ob_item[i] = v->ob_item[i - sizediff];
			v->ob_item[i - sizediff] = NULL;
		}
	}
	for (i = newsize; i < v->ob_size; i++) {
		XDECREF(v->ob_item[i]);
		v->ob_item[i] = NULL;
	}
	sv = (tupleobject *)
		realloc((char *)v,
			sizeof(tupleobject) + newsize * sizeof(object *));
	*pv = (object *) sv;
	if (sv == NULL) {
		DEL(v);
		err_nomem();
		return -1;
	}
	NEWREF(sv);
	for (i = sv->ob_size; i < newsize; i++)
		sv->ob_item[i] = NULL;
	if (last_is_sticky && sizediff > 0) {
		/* growing: move entries to the end and zero moved entries */
		for (i = newsize - 1; i >= sizediff; i--) {
			sv->ob_item[i] = sv->ob_item[i - sizediff];
			sv->ob_item[i - sizediff] = NULL;
		}
	}
	sv->ob_size = newsize;
	return 0;
}
