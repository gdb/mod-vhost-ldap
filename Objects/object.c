/***********************************************************
Copyright 1991-1995 by Stichting Mathematisch Centrum, Amsterdam,
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

/* Generic object operations; and implementation of None (NoObject) */

#include "allobjects.h"

#if defined( Py_TRACE_REFS ) || defined( Py_REF_DEBUG )
long ref_total;
#endif

/* Object allocation routines used by NEWOBJ and NEWVAROBJ macros.
   These are used by the individual routines for object creation.
   Do not call them otherwise, they do not initialize the object! */

#ifdef COUNT_ALLOCS
static typeobject *type_list;
extern int tuple_zero_allocs, fast_tuple_allocs;
extern int quick_int_allocs, quick_neg_int_allocs;
extern int null_strings, one_strings;
void
dump_counts()
{
	typeobject *tp;

	for (tp = type_list; tp; tp = tp->tp_next)
		fprintf(stderr, "%s alloc'd: %d, freed: %d, max in use: %d\n",
			tp->tp_name, tp->tp_alloc, tp->tp_free,
			tp->tp_maxalloc);
	fprintf(stderr, "fast tuple allocs: %d, empty: %d\n",
		fast_tuple_allocs, tuple_zero_allocs);
	fprintf(stderr, "fast int allocs: pos: %d, neg: %d\n",
		quick_int_allocs, quick_neg_int_allocs);
	fprintf(stderr, "null strings: %d, 1-strings: %d\n",
		null_strings, one_strings);
}

PyObject *
get_counts()
{
	PyTypeObject *tp;
	PyObject *result;
	PyObject *v;

	result = PyList_New(0);
	if (result == NULL)
		return NULL;
	for (tp = type_list; tp; tp = tp->tp_next) {
		v = Py_BuildValue("(siii)", tp->tp_name, tp->tp_alloc,
				  tp->tp_free, tp->tp_maxalloc);
		if (v == NULL) {
			Py_DECREF(result);
			return NULL;
		}
		if (PyList_Append(result, v) < 0) {
			Py_DECREF(v);
			Py_DECREF(result);
			return NULL;
		}
		Py_DECREF(v);
	}
	return result;
}

void
inc_count(tp)
	typeobject *tp;
{
	if (tp->tp_alloc == 0) {
		/* first time; insert in linked list */
		if (tp->tp_next != NULL) /* sanity check */
			fatal("XXX inc_count sanity check");
		tp->tp_next = type_list;
		type_list = tp;
	}
	tp->tp_alloc++;
	if (tp->tp_alloc - tp->tp_free > tp->tp_maxalloc)
		tp->tp_maxalloc = tp->tp_alloc - tp->tp_free;
}
#endif

#ifndef MS_COREDLL
object *
newobject(tp)
	typeobject *tp;
#else
object *
newobject(tp,op)
	typeobject *tp;
	PyObject *op;
#endif
{
#ifndef MS_COREDLL
	object *op = (object *) malloc(tp->tp_basicsize);
#endif
	if (op == NULL)
		return err_nomem();
	op->ob_type = tp;
	NEWREF(op);
	return op;
}

#ifndef MS_COREDLL
varobject *
newvarobject(tp, size)
	typeobject *tp;
	int size;
#else
varobject *
newvarobject(tp, size, op)
	typeobject *tp;
	int size;
	varobject *op;
#endif
{
#ifndef MS_COREDLL
	varobject *op = (varobject *)
		malloc(tp->tp_basicsize + size * tp->tp_itemsize);
#endif
	if (op == NULL)
		return (varobject *)err_nomem();
	op->ob_type = tp;
	op->ob_size = size;
	NEWREF(op);
	return op;
}

int
printobject(op, fp, flags)
	object *op;
	FILE *fp;
	int flags;
{
	int ret = 0;
	if (sigcheck())
		return -1;
	if (op == NULL) {
		fprintf(fp, "<nil>");
	}
	else {
		if (op->ob_refcnt <= 0)
			fprintf(fp, "<refcnt %u at %lx>",
				op->ob_refcnt, (long)op);
		else if (op->ob_type->tp_print == NULL) {
			if (op->ob_type->tp_repr == NULL) {
				fprintf(fp, "<%s object at %lx>",
					op->ob_type->tp_name, (long)op);
			}
			else {
				object *s;
				if (flags & PRINT_RAW)
					s = strobject(op);
				else
					s = reprobject(op);
				if (s == NULL)
					ret = -1;
				else if (!is_stringobject(s)) {
					err_setstr(TypeError,
						   "repr not string");
					ret = -1;
				}
				else {
					fprintf(fp, "%s", getstringvalue(s));
				}
				XDECREF(s);
			}
		}
		else
			ret = (*op->ob_type->tp_print)(op, fp, flags);
	}
	if (ret == 0) {
		if (ferror(fp)) {
			err_errno(IOError);
			clearerr(fp);
			ret = -1;
		}
	}
	return ret;
}

object *
reprobject(v)
	object *v;
{
	if (sigcheck())
		return NULL;
	if (v == NULL)
		return newstringobject("<NULL>");
	else if (v->ob_type->tp_repr == NULL) {
		char buf[120];
		sprintf(buf, "<%.80s object at %lx>",
			v->ob_type->tp_name, (long)v);
		return newstringobject(buf);
	}
	else
		return (*v->ob_type->tp_repr)(v);
}

object *
strobject(v)
	object *v;
{
	if (v == NULL)
		return newstringobject("<NULL>");
	else if (is_stringobject(v)) {
		INCREF(v);
		return v;
	}
	else if (v->ob_type->tp_str != NULL)
		return (*v->ob_type->tp_str)(v);
	else {
		object *func;
		object *res;
		if (!is_instanceobject(v) ||
		    (func = getattr(v, "__str__")) == NULL) {
			err_clear();
			return reprobject(v);
		}
		res = call_object(func, (object *)NULL);
		DECREF(func);
		return res;
	}
}

static object *
do_cmp(v, w)
	object *v, *w;
{
	/* __rcmp__ actually won't be called unless __cmp__ isn't defined,
	   because the check in cmpobject() reverses the objects first.
	   This is intentional -- it makes no sense to define cmp(x,y) different
	   than -cmp(y,x). */
	if (is_instanceobject(v) || is_instanceobject(w))
		return instancebinop(v, w, "__cmp__", "__rcmp__", do_cmp);
	return newintobject((long)cmpobject(v, w));
}

int
cmpobject(v, w)
	object *v, *w;
{
	typeobject *tp;
	if (v == w)
		return 0;
	if (v == NULL)
		return -1;
	if (w == NULL)
		return 1;
	if (is_instanceobject(v) || is_instanceobject(w)) {
		object *res;
		int c;
		if (!is_instanceobject(v))
			return -cmpobject(w, v);
		res = do_cmp(v, w);
		if (res == NULL) {
			err_clear();
			return (v < w) ? -1 : 1;
		}
		if (!is_intobject(res)) {
			DECREF(res);
			return (v < w) ? -1 : 1;
		}
		c = getintvalue(res);
		DECREF(res);
		return (c < 0) ? -1 : (c > 0) ? 1 : 0;	
	}
	if ((tp = v->ob_type) != w->ob_type) {
		if (tp->tp_as_number != NULL &&
				w->ob_type->tp_as_number != NULL) {
			if (coerce(&v, &w) != 0) {
				err_clear();
				/* XXX Should report the error,
				   XXX but the interface isn't there... */
			}
			else {
				int cmp = (*v->ob_type->tp_compare)(v, w);
				DECREF(v);
				DECREF(w);
				return cmp;
			}
		}
		return strcmp(tp->tp_name, w->ob_type->tp_name);
	}
	if (tp->tp_compare == NULL)
		return (v < w) ? -1 : 1;
	return (*tp->tp_compare)(v, w);
}

long
hashobject(v)
	object *v;
{
	typeobject *tp = v->ob_type;
	if (tp->tp_hash != NULL)
		return (*tp->tp_hash)(v);
	if (tp->tp_compare == NULL)
		return (long) v; /* Use address as hash value */
	/* If there's a cmp but no hash defined, the object can't be hashed */
	err_setstr(TypeError, "unhashable type");
	return -1;
}

object *
getattr(v, name)
	object *v;
	char *name;
{
	if (v->ob_type->tp_getattro != NULL) {
		object *w, *res;
		w = newstringobject(name);
		if (w == NULL)
			return NULL;
		res = (*v->ob_type->tp_getattro)(v, w);
		XDECREF(w);
		return res;
	}

	if (v->ob_type->tp_getattr == NULL) {
		err_setstr(AttributeError, "attribute-less object");
		return NULL;
	}
	else {
		return (*v->ob_type->tp_getattr)(v, name);
	}
}

int
hasattr(v, name)
	object *v;
	char *name;
{
	object *res = getattr(v, name);
	if (res != NULL) {
		DECREF(res);
		return 1;
	}
	err_clear();
	return 0;
}

int
setattr(v, name, w)
	object *v;
	char *name;
	object *w;
{
	if (v->ob_type->tp_setattro != NULL) {
		object *s;
		int res;
		s = newstringobject(name);
		if (s == NULL)
			return -1;
		res = (*v->ob_type->tp_setattro)(v, s, w);
		XDECREF(s);
		return res;
	}

	if (v->ob_type->tp_setattr == NULL) {
		if (v->ob_type->tp_getattr == NULL)
			err_setstr(TypeError,
				   "attribute-less object (assign or del)");
		else
			err_setstr(TypeError,
				   "object has read-only attributes");
		return -1;
	}
	else {
		return (*v->ob_type->tp_setattr)(v, name, w);
	}
}

/* Test a value used as condition, e.g., in a for or if statement.
   Return -1 if an error occurred */

int
testbool(v)
	object *v;
{
	int res;
	if (v == None)
		res = 0;
	else if (v->ob_type->tp_as_number != NULL)
		res = (*v->ob_type->tp_as_number->nb_nonzero)(v);
	else if (v->ob_type->tp_as_mapping != NULL)
		res = (*v->ob_type->tp_as_mapping->mp_length)(v);
	else if (v->ob_type->tp_as_sequence != NULL)
		res = (*v->ob_type->tp_as_sequence->sq_length)(v);
	else
		res = 1;
	if (res > 0)
		res = 1;
	return res;
}

/* Coerce two numeric types to the "larger" one.
   Increment the reference count on each argument.
   Return -1 and raise an exception if no coercion is possible
   (and then no reference count is incremented).
*/

int
coerce(pv, pw)
	object **pv, **pw;
{
	register object *v = *pv;
	register object *w = *pw;
	int res;

	if (v->ob_type == w->ob_type && !is_instanceobject(v)) {
		INCREF(v);
		INCREF(w);
		return 0;
	}
	if (v->ob_type->tp_as_number && v->ob_type->tp_as_number->nb_coerce) {
		res = (*v->ob_type->tp_as_number->nb_coerce)(pv, pw);
		if (res <= 0)
			return res;
	}
	if (w->ob_type->tp_as_number && w->ob_type->tp_as_number->nb_coerce) {
		res = (*w->ob_type->tp_as_number->nb_coerce)(pw, pv);
		if (res <= 0)
			return res;
	}
	err_setstr(TypeError, "number coercion failed");
	return -1;
}


/* Test whether an object can be called */

int
callable(x)
	object *x;
{
	if (x == NULL)
		return 0;
	if (x->ob_type->tp_call != NULL ||
	    is_funcobject(x) ||
	    is_instancemethodobject(x) ||
	    is_methodobject(x) ||
	    is_classobject(x))
		return 1;
	if (is_instanceobject(x)) {
		object *call = getattr(x, "__call__");
		if (call == NULL) {
			err_clear();
			return 0;
		}
		/* Could test recursively but don't, for fear of endless
		   recursion if some joker sets self.__call__ = self */
		DECREF(call);
		return 1;
	}
	return 0;
}


/*
NoObject is usable as a non-NULL undefined value, used by the macro None.
There is (and should be!) no way to create other objects of this type,
so there is exactly one (which is indestructible, by the way).
*/

/* ARGSUSED */
static object *
none_repr(op)
	object *op;
{
	return newstringobject("None");
}

static typeobject Notype = {
	OB_HEAD_INIT(&Typetype)
	0,
	"None",
	0,
	0,
	0,		/*tp_dealloc*/ /*never called*/
	0,		/*tp_print*/
	0,		/*tp_getattr*/
	0,		/*tp_setattr*/
	0,		/*tp_compare*/
	(reprfunc)none_repr, /*tp_repr*/
	0,		/*tp_as_number*/
	0,		/*tp_as_sequence*/
	0,		/*tp_as_mapping*/
	0,		/*tp_hash */
};

object NoObject = {
	OB_HEAD_INIT(&Notype)
};


#ifdef Py_TRACE_REFS

static object refchain = {&refchain, &refchain};

void
NEWREF(op)
	object *op;
{
	ref_total++;
	op->ob_refcnt = 1;
	op->_ob_next = refchain._ob_next;
	op->_ob_prev = &refchain;
	refchain._ob_next->_ob_prev = op;
	refchain._ob_next = op;
#ifdef COUNT_ALLOCS
	inc_count(op->ob_type);
#endif
}

void
UNREF(op)
	register object *op;
{
	register object *p;
	if (op->ob_refcnt < 0)
		fatal("UNREF negative refcnt");
	if (op == &refchain ||
	    op->_ob_prev->_ob_next != op || op->_ob_next->_ob_prev != op)
		fatal("UNREF invalid object");
#ifdef SLOW_UNREF_CHECK
	for (p = refchain._ob_next; p != &refchain; p = p->_ob_next) {
		if (p == op)
			break;
	}
	if (p == &refchain) /* Not found */
		fatal("UNREF unknown object");
#endif
	op->_ob_next->_ob_prev = op->_ob_prev;
	op->_ob_prev->_ob_next = op->_ob_next;
	op->_ob_next = op->_ob_prev = NULL;
#ifdef COUNT_ALLOCS
	op->ob_type->tp_free++;
#endif
}

void
DELREF(op)
	object *op;
{
	destructor dealloc = op->ob_type->tp_dealloc;
	UNREF(op);
	op->ob_type = NULL;
	(*dealloc)(op);
}

void
_Py_PrintReferences(fp)
	FILE *fp;
{
	object *op;
	fprintf(fp, "Remaining objects (except strings referenced once):\n");
	for (op = refchain._ob_next; op != &refchain; op = op->_ob_next) {
		if (op->ob_refcnt == 1 && is_stringobject(op))
			continue; /* Will be printed elsewhere */
		fprintf(fp, "[%d] ", op->ob_refcnt);
		if (printobject(op, fp, 0) != 0)
			err_clear();
		putc('\n', fp);
	}
}

PyObject *
_Py_GetObjects(self, args)
	PyObject *self;
	PyObject *args;
{
	int i, n;
	PyObject *t = NULL;
	PyObject *res, *op;

	if (!PyArg_ParseTuple(args, "i|O", &n, &t))
		return NULL;
	op = refchain._ob_next;
	res = PyList_New(0);
	if (res == NULL)
		return NULL;
	for (i = 0; (n == 0 || i < n) && op != &refchain; i++) {
		while (op == self || op == args || op == res || op == t ||
		       t != NULL && op->ob_type != (PyTypeObject *) t) {
			op = op->_ob_next;
			if (op == &refchain)
				return res;
		}
		if (PyList_Append(res, op) < 0) {
			Py_DECREF(res);
			return NULL;
		}
		op = op->_ob_next;
	}
	return res;
}

#endif


/* Hack to force loading of cobject.o */
PyTypeObject *_Py_cobject_hack = &PyCObject_Type;


/* Hack to force loading of abstract.o */
int (*_Py_abstract_hack) FPROTO((PyObject *)) = &PyObject_Length;
