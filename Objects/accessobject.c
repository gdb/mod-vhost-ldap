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

/* Access object implementation */

#include "allobjects.h"

#include "structmember.h"
#include "modsupport.h"		/* For getargs() etc. */

typedef struct {
	OB_HEAD
	object		*ac_value;
	object		*ac_class;
	typeobject	*ac_type;
	int		ac_mode;
} accessobject;

/* Forward */
static int typecheck PROTO((object *, typeobject *));
static int classcheck PROTO((object *, object *, int, int));

object *
newaccessobject(value, class, type, mode)
	object *value;
	object *class;
	typeobject *type;
	int mode;
{
	accessobject *ap;
	if (class != NULL && !is_classobject(class)) {
		err_badcall();
		return NULL;
	}
	if (!typecheck(value, type)) {
		err_setstr(AccessError,
		"access: initial value has inappropriate type");
		return NULL;
	}
	ap = NEWOBJ(accessobject, &Accesstype);
	if (ap == NULL)
		return NULL;
	XINCREF(value);
	ap->ac_value = value;
	XINCREF(class);
	ap->ac_class = class;
	XINCREF(type);
	ap->ac_type = (typeobject *)type;
	ap->ac_mode = mode;
	return (object *)ap;
}

object *
cloneaccessobject(op)
	object *op;
{
	register accessobject *ap;
	if (!is_accessobject(op)) {
		err_badcall();
		return NULL;
	}
	ap = (accessobject *)op;
	return newaccessobject(ap->ac_value, ap->ac_class,
			       ap->ac_type, ap->ac_mode);
}

void
setaccessowner(op, class)
	object *op;
	object *class;
{
	register accessobject *ap;
	if (!is_accessobject(op) || class != NULL && !is_classobject(class))
		return; /* XXX no error */
	ap = (accessobject *)op;
	XDECREF(ap->ac_class);
	XINCREF(class);
	ap->ac_class = class;
}

object *
getaccessvalue(op, class)
	object *op;
	object *class;
{
	register accessobject *ap;
	if (!is_accessobject(op)) {
		err_badcall();
		return NULL;
	}
	ap = (accessobject *)op;
	
	if (!classcheck(class, ap->ac_class, AC_R, ap->ac_mode)) {
		err_setstr(AccessError, "read access denied");
		return NULL;
	}
	
	if (ap->ac_value == NULL) {
		err_setstr(AccessError, "no current value");
		return NULL;
	}
	INCREF(ap->ac_value);
	return ap->ac_value;
}

int
setaccessvalue(op, class, value)
	object *op;
	object *class;
	object *value;
{
	register accessobject *ap;
	if (!is_accessobject(op)) {
		err_badcall();
		return -1;
	}
	ap = (accessobject *)op;
	
	if (!classcheck(class, ap->ac_class, AC_W, ap->ac_mode)) {
		err_setstr(AccessError, "write access denied");
		return -1;
	}
	
	if (!typecheck(value, ap->ac_type)) {
		err_setstr(AccessError, "assign value of inappropriate type");
		return -1;
	}
	
	if (value == NULL) { /* Delete it */
		if (ap->ac_value == NULL) {
			err_setstr(AccessError, "no current value");
			return -1;
		}
		DECREF(ap->ac_value);
		ap->ac_value = NULL;
		return 0;
	}
	XDECREF(ap->ac_value);
	INCREF(value);
	ap->ac_value = value;
	return 0;
}

static int
typecheck(value, type)
	object *value;
	typeobject *type;
{
	object *x;
	if (value == NULL || type == NULL)
		return 1; /* No check */
	if (value->ob_type == type)
		return 1; /* Exact match */
	if (type == &Anynumbertype) {
		if (value->ob_type->tp_as_number == NULL)
			return 0;
		if (!is_instanceobject(value))
			return 1;
		/* For instances, make sure it really looks like a number */
		x = getattr(value, "__sub__");
		if (x == NULL) {
			err_clear();
			return 0;
		}
		DECREF(x);
		return 1;
	}
	if (type == &Anysequencetype) {
		if (value->ob_type->tp_as_sequence == NULL)
			return 0;
		if (!is_instanceobject(value))
			return 1;
		/* For instances, make sure it really looks like a sequence */
		x = getattr(value, "__getslice__");
		if (x == NULL) {
			err_clear();
			return 0;
		}
		DECREF(x);
		return 1;
	}
	if (type == &Anymappingtype) {
		if (value->ob_type->tp_as_mapping == NULL)
			return 0;
		if (!is_instanceobject(value))
			return 1;
		/* For instances, make sure it really looks like a mapping */
		x = getattr(value, "__getitem__");
		if (x == NULL) {
			err_clear();
			return 0;
		}
		DECREF(x);
		return 1;
	}
	return 0;
}

static int
classcheck(caller, owner, access, mode)
	object *caller;
	object *owner;
	int access;
	int mode;
{
	if (caller == owner && owner != NULL)
		return access & mode & (AC_PRIVATE|AC_PROTECTED|AC_PUBLIC);
	if (caller != NULL && owner != NULL && issubclass(caller, owner))
		return access & mode & (AC_PROTECTED|AC_PUBLIC);
	return access & mode & AC_PUBLIC;
}

/* Access methods */

static void
access_dealloc(ap)
	accessobject *ap;
{
	XDECREF(ap->ac_value);
	XDECREF(ap->ac_class);
	XDECREF(ap->ac_type);
	DEL(ap);
}

#define OFF(x) offsetof(accessobject, x)

static struct memberlist access_memberlist[] = {
	{"ac_value",	T_OBJECT,	OFF(ac_value)},
	{"ac_class",	T_OBJECT,	OFF(ac_class)},
	{"ac_type",	T_OBJECT,	OFF(ac_type)},
	{"ac_mode",	T_INT,		OFF(ac_mode)},
	{NULL}	/* Sentinel */
};

static object *
access_getattr(ap, name)
	accessobject *ap;
	char *name;
{
	return getmember((char *)ap, access_memberlist, name);
}

static object *
access_repr(ap)
	accessobject *ap;
{
	char buf[300];
	classobject *class = (classobject *)ap->ac_class;
	typeobject *type = ap->ac_type;
	sprintf(buf, "<access object, class %.100s, type %.100s, mode 0%o>",
		class ? getstringvalue(class->cl_name) : "-",
		type ? type->tp_name : "-",
		ap->ac_mode);
	return newstringobject(buf);
}

typeobject Accesstype = {
	OB_HEAD_INIT(&Typetype)
	0,			/*ob_size*/
	"access",		/*tp_name*/
	sizeof(accessobject),	/*tp_size*/
	0,			/*tp_itemsize*/
	/* methods */
	access_dealloc,		/*tp_dealloc*/
	0,			/*tp_print*/
	access_getattr,		/*tp_getattr*/
	0,			/*tp_setattr*/
	0,			/*tp_compare*/
	access_repr,		/*tp_repr*/
	0,			/*tp_as_number*/
	0,			/*tp_as_sequence*/
	0,			/*tp_as_mapping*/
	0,			/*tp_hash*/
};

/* Dummy type objects to indicate classes of types */

/* XXX This should be replaced by a more general "subclassing"
   XXX mechanism for type objects... */

typeobject Anynumbertype = {
	OB_HEAD_INIT(&Typetype)
	0,			/*ob_size*/
	"*number*",		/*tp_name*/
};

/* XXX Should really distinguish mutable and immutable sequences as well */

typeobject Anysequencetype = {
	OB_HEAD_INIT(&Typetype)
	0,			/*ob_size*/
	"*sequence*",		/*tp_name*/
};

typeobject Anymappingtype = {
	OB_HEAD_INIT(&Typetype)
	0,			/*ob_size*/
	"*mapping*",		/*tp_name*/
};
