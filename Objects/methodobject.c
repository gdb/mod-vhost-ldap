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

/* Method object implementation */

#include "allobjects.h"

#include "token.h"

typedef struct {
	OB_HEAD
	struct methodlist *m_ml;
	object	*m_self;
} methodobject;

object *
newmethodobject(ml, self)
	struct methodlist *ml;
	object *self;
{
	methodobject *op = NEWOBJ(methodobject, &Methodtype);
	if (op != NULL) {
		op->m_ml = ml;
		XINCREF(self);
		op->m_self = self;
	}
	return (object *)op;
}

method
getmethod(op)
	object *op;
{
	if (!is_methodobject(op)) {
		err_badcall();
		return NULL;
	}
	return ((methodobject *)op) -> m_ml -> ml_meth;
}

object *
getself(op)
	object *op;
{
	if (!is_methodobject(op)) {
		err_badcall();
		return NULL;
	}
	return ((methodobject *)op) -> m_self;
}

int
getflags(op)
	object *op;
{
	if (!is_methodobject(op)) {
		err_badcall();
		return -1;
	}
	return ((methodobject *)op) -> m_ml -> ml_flags;
}

/* Methods (the standard built-in methods, that is) */

static void
meth_dealloc(m)
	methodobject *m;
{
	XDECREF(m->m_self);
	free((char *)m);
}

static object *
meth_getattr(m, name)
	methodobject *m;
	char *name;
{
	if (strcmp(name, "__name__") == 0) {
		return newstringobject(m->m_ml->ml_name);
	}
	if (strcmp(name, "__doc__") == 0) {
		char *doc = m->m_ml->ml_doc;
		if (doc != NULL)
			return newstringobject(doc);
		INCREF(None);
		return None;
	}
	if (strcmp(name, "__self__") == 0) {
		object *self;
		if (getrestricted()) {
			err_setstr(RuntimeError,
			 "method.__self__ not accessible in restricted mode");
			return NULL;
		}
		self = m->m_self;
		if (self == NULL)
			self = None;
		INCREF(self);
		return self;
	}
	if (strcmp(name, "__members__") == 0) {
		return mkvalue("[sss]", "__doc__", "__name__", "__self__");
	}
	err_setstr(AttributeError, name);
	return NULL;
}

static object *
meth_repr(m)
	methodobject *m;
{
	char buf[200];
	if (m->m_self == NULL)
		sprintf(buf, "<built-in function %.80s>", m->m_ml->ml_name);
	else
		sprintf(buf,
			"<built-in method %.80s of %.80s object at %lx>",
			m->m_ml->ml_name, m->m_self->ob_type->tp_name,
			(long)m->m_self);
	return newstringobject(buf);
}

static int
meth_compare(a, b)
	methodobject *a, *b;
{
	if (a->m_self != b->m_self)
		return cmpobject(a->m_self, b->m_self);
	if (a->m_ml->ml_meth == b->m_ml->ml_meth)
		return 0;
	if (strcmp(a->m_ml->ml_name, b->m_ml->ml_name) < 0)
		return -1;
	else
		return 1;
}

static long
meth_hash(a)
	methodobject *a;
{
	long x;
	if (a->m_self == NULL)
		x = 0;
	else {
		x = hashobject(a->m_self);
		if (x == -1)
			return -1;
	}
	return x ^ (long) a->m_ml->ml_meth;
}

typeobject Methodtype = {
	OB_HEAD_INIT(&Typetype)
	0,
	"builtin_function_or_method",
	sizeof(methodobject),
	0,
	(destructor)meth_dealloc, /*tp_dealloc*/
	0,		/*tp_print*/
	(getattrfunc)meth_getattr, /*tp_getattr*/
	0,		/*tp_setattr*/
	(cmpfunc)meth_compare, /*tp_compare*/
	(reprfunc)meth_repr, /*tp_repr*/
	0,		/*tp_as_number*/
	0,		/*tp_as_sequence*/
	0,		/*tp_as_mapping*/
	(hashfunc)meth_hash, /*tp_hash*/
};

/* List all methods in a chain -- helper for findmethodinchain */

static object *
listmethodchain(chain)
	struct methodchain *chain;
{
	struct methodchain *c;
	struct methodlist *ml;
	int i, n;
	object *v;
	
	n = 0;
	for (c = chain; c != NULL; c = c->link) {
		for (ml = c->methods; ml->ml_name != NULL; ml++)
			n++;
	}
	v = newlistobject(n);
	if (v == NULL)
		return NULL;
	i = 0;
	for (c = chain; c != NULL; c = c->link) {
		for (ml = c->methods; ml->ml_name != NULL; ml++) {
			setlistitem(v, i, newstringobject(ml->ml_name));
			i++;
		}
	}
	if (err_occurred()) {
		DECREF(v);
		return NULL;
	}
	sortlist(v);
	return v;
}

/* Find a method in a method chain */

object *
findmethodinchain(chain, self, name)
	struct methodchain *chain;
	object *self;
	char *name;
{
	if (strcmp(name, "__methods__") == 0)
		return listmethodchain(chain);
	while (chain != NULL) {
		struct methodlist *ml = chain->methods;
		for (; ml->ml_name != NULL; ml++) {
			if (name[0] == ml->ml_name[0] &&
			    strcmp(name+1, ml->ml_name+1) == 0)
				return newmethodobject(ml, self);
		}
		chain = chain->link;
	}
	err_setstr(AttributeError, name);
	return NULL;
}

/* Find a method in a single method list */

object *
findmethod(methods, self, name)
	struct methodlist *methods;
	object *self;
	char *name;
{
	struct methodchain chain;
	chain.methods = methods;
	chain.link = NULL;
	return findmethodinchain(&chain, self, name);
}
