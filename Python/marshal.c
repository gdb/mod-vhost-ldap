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

/* Write Python objects to files and read them back.
   This is intended for writing and reading compiled Python code only;
   a true persistent storage facility would be much harder, since
   it would have to take circular links and sharing into account. */

#include "allobjects.h"
#include "modsupport.h"
#include "longintrepr.h"
#include "compile.h"
#include "marshal.h"

#include <errno.h>

#define TYPE_NULL	'0'
#define TYPE_NONE	'N'
#define TYPE_INT	'i'
#define TYPE_FLOAT	'f'
#define TYPE_COMPLEX	'x'
#define TYPE_LONG	'l'
#define TYPE_STRING	's'
#define TYPE_TUPLE	'('
#define TYPE_LIST	'['
#define TYPE_DICT	'{'
#define TYPE_CODE	'c'
#define TYPE_UNKNOWN	'?'

typedef struct {
	FILE *fp;
	/* If fp == NULL, the following are valid: */
	object *str;
	char *ptr;
	char *end;
} WFILE;

#define w_byte(c, p) if (((p)->fp)) putc((c), (p)->fp); \
		      else if ((p)->ptr != (p)->end) *(p)->ptr++ = (c); \
			   else w_more(c, p)

static void
w_more(c, p)
	char c;
	WFILE *p;
{
	int size, newsize;
	if (p->str == NULL)
		return; /* An error already occurred */
	size = getstringsize(p->str);
	newsize = size + 1024;
	if (resizestring(&p->str, newsize) != 0) {
		p->ptr = p->end = NULL;
	}
	else {
		p->ptr = GETSTRINGVALUE((stringobject *)p->str) + size;
		p->end = GETSTRINGVALUE((stringobject *)p->str) + newsize;
		*p->ptr++ = c;
	}
}

static void
w_string(s, n, p)
	char *s;
	int n;
	WFILE *p;
{
	if (p->fp != NULL) {
		fwrite(s, 1, n, p->fp);
	}
	else {
		while (--n >= 0) {
			w_byte(*s, p);
			s++;
		}
	}
}

static void
w_short(x, p)
	int x;
	WFILE *p;
{
	w_byte( x      & 0xff, p);
	w_byte((x>> 8) & 0xff, p);
}

static void
w_long(x, p)
	long x;
	WFILE *p;
{
	w_byte((int)( x      & 0xff), p);
	w_byte((int)((x>> 8) & 0xff), p);
	w_byte((int)((x>>16) & 0xff), p);
	w_byte((int)((x>>24) & 0xff), p);
}

static void
w_object(v, p)
	object *v;
	WFILE *p;
{
	int i, n;
	
	if (v == NULL)
		w_byte(TYPE_NULL, p);
	else if (v == None)
		w_byte(TYPE_NONE, p);
	else if (is_intobject(v)) {
		w_byte(TYPE_INT, p);
		w_long(getintvalue(v), p);
	}
	else if (is_longobject(v)) {
		longobject *ob = (longobject *)v;
		w_byte(TYPE_LONG, p);
		n = ob->ob_size;
		w_long((long)n, p);
		if (n < 0)
			n = -n;
		for (i = 0; i < n; i++)
			w_short(ob->ob_digit[i], p);
	}
	else if (is_floatobject(v)) {
		extern void float_buf_repr PROTO((char *, floatobject *));
		char buf[256]; /* Plenty to format any double */
		float_buf_repr(buf, (floatobject *)v);
		n = strlen(buf);
		w_byte(TYPE_FLOAT, p);
		w_byte(n, p);
		w_string(buf, n, p);
	}
#ifndef WITHOUT_COMPLEX
	else if (is_complexobject(v)) {
		extern void float_buf_repr PROTO((char *, floatobject *));
		char buf[256]; /* Plenty to format any double */
		floatobject *temp;
		w_byte(TYPE_COMPLEX, p);
		temp = (floatobject*)newfloatobject(PyComplex_RealAsDouble(v));
		float_buf_repr(buf, temp);
		DECREF(temp);
		n = strlen(buf);
		w_byte(n, p);
		w_string(buf, n, p);
		temp = (floatobject*)newfloatobject(PyComplex_ImagAsDouble(v));
		float_buf_repr(buf, temp);
		DECREF(temp);
		n = strlen(buf);
		w_byte(n, p);
		w_string(buf, n, p);
	}
#endif
	else if (is_stringobject(v)) {
		w_byte(TYPE_STRING, p);
		n = getstringsize(v);
		w_long((long)n, p);
		w_string(getstringvalue(v), n, p);
	}
	else if (is_tupleobject(v)) {
		w_byte(TYPE_TUPLE, p);
		n = gettuplesize(v);
		w_long((long)n, p);
		for (i = 0; i < n; i++) {
			w_object(GETTUPLEITEM(v, i), p);
		}
	}
	else if (is_listobject(v)) {
		w_byte(TYPE_LIST, p);
		n = getlistsize(v);
		w_long((long)n, p);
		for (i = 0; i < n; i++) {
			w_object(getlistitem(v, i), p);
		}
	}
	else if (is_dictobject(v)) {
		int pos;
		object *key, *value;
		w_byte(TYPE_DICT, p);
		/* This one is NULL object terminated! */
		pos = 0;
		while (mappinggetnext(v, &pos, &key, &value)) {
			w_object(key, p);
			w_object(value, p);
		}
		w_object((object *)NULL, p);
	}
	else if (is_codeobject(v)) {
		codeobject *co = (codeobject *)v;
		w_byte(TYPE_CODE, p);
		w_short(co->co_argcount, p);
		w_short(co->co_nlocals, p);
		w_short(co->co_flags, p);
		w_object((object *)co->co_code, p);
		w_object(co->co_consts, p);
		w_object(co->co_names, p);
		w_object(co->co_varnames, p);
		w_object(co->co_filename, p);
		w_object(co->co_name, p);
	}
	else {
		w_byte(TYPE_UNKNOWN, p);
	}
}

void
wr_long(x, fp)
	long x;
	FILE *fp;
{
	WFILE wf;
	wf.fp = fp;
	w_long(x, &wf);
}

void
wr_object(x, fp)
	object *x;
	FILE *fp;
{
	WFILE wf;
	wf.fp = fp;
	w_object(x, &wf);
}

typedef WFILE RFILE; /* Same struct with different invariants */

#define rs_byte(p) (((p)->ptr != (p)->end) ? (unsigned char)*(p)->ptr++ : EOF)

#define r_byte(p) ((p)->fp ? getc((p)->fp) : rs_byte(p))

static int
r_string(s, n, p)
	char *s;
	int n;
	RFILE *p;
{
	if (p->fp != NULL)
		return fread(s, 1, n, p->fp);
	if (p->end - p->ptr < n)
		n = p->end - p->ptr;
	memcpy(s, p->ptr, n);
	p->ptr += n;
	return n;
}

static int
r_short(p)
	RFILE *p;
{
	register short x;
	x = r_byte(p);
	x |= r_byte(p) << 8;
	/* XXX If your short is > 16 bits, add sign-extension here!!! */
	return x;
}

static long
r_long(p)
	RFILE *p;
{
	register long x;
	register FILE *fp = p->fp;
	if (fp) {
		x = getc(fp);
		x |= (long)getc(fp) << 8;
		x |= (long)getc(fp) << 16;
		x |= (long)getc(fp) << 24;
	}
	else {
		x = rs_byte(p);
		x |= (long)rs_byte(p) << 8;
		x |= (long)rs_byte(p) << 16;
		x |= (long)rs_byte(p) << 24;
	}
	/* XXX If your long is > 32 bits, add sign-extension here!!! */
	return x;
}

static object *
r_object(p)
	RFILE *p;
{
	object *v, *v2;
	long i, n;
	int type = r_byte(p);
	
	switch (type) {
	
	case EOF:
		err_setstr(EOFError, "EOF read where object expected");
		return NULL;
	
	case TYPE_NULL:
		return NULL;
	
	case TYPE_NONE:
		INCREF(None);
		return None;
	
	case TYPE_INT:
		return newintobject(r_long(p));
	
	case TYPE_LONG:
		{
			int size;
			longobject *ob;
			n = r_long(p);
			size = n<0 ? -n : n;
			ob = alloclongobject(size);
			if (ob == NULL)
				return NULL;
			ob->ob_size = n;
			for (i = 0; i < size; i++)
				ob->ob_digit[i] = r_short(p);
			return (object *)ob;
		}
	
	case TYPE_FLOAT:
		{
			extern double atof PROTO((const char *));
			char buf[256];
			n = r_byte(p);
			if (r_string(buf, (int)n, p) != n) {
				err_setstr(EOFError,
					"EOF read where object expected");
				return NULL;
			}
			buf[n] = '\0';
			return newfloatobject(atof(buf));
		}
	
#ifndef WITHOUT_COMPLEX
	case TYPE_COMPLEX:
		{
			extern double atof PROTO((const char *));
			char buf[256];
			complex c;
			n = r_byte(p);
			if (r_string(buf, (int)n, p) != n) {
				err_setstr(EOFError,
					"EOF read where object expected");
				return NULL;
			}
			buf[n] = '\0';
			c.real = atof(buf);
			n = r_byte(p);
			if (r_string(buf, (int)n, p) != n) {
				err_setstr(EOFError,
					"EOF read where object expected");
				return NULL;
			}
			buf[n] = '\0';
			c.imag = atof(buf);
			return newcomplexobject(c);
		}
#endif
	
	case TYPE_STRING:
		n = r_long(p);
		v = newsizedstringobject((char *)NULL, n);
		if (v != NULL) {
			if (r_string(getstringvalue(v), (int)n, p) != n) {
				DECREF(v);
				v = NULL;
				err_setstr(EOFError,
					"EOF read where object expected");
			}
		}
		return v;
	
	case TYPE_TUPLE:
		n = r_long(p);
		v = newtupleobject((int)n);
		if (v == NULL)
			return v;
		for (i = 0; i < n; i++) {
			v2 = r_object(p);
			if ( v2 == NULL ) {
				DECREF(v);
				v = NULL;
				break;
			}
			SETTUPLEITEM(v, (int)i, v2);
		}
		return v;
	
	case TYPE_LIST:
		n = r_long(p);
		v = newlistobject((int)n);
		if (v == NULL)
			return v;
		for (i = 0; i < n; i++) {
			v2 = r_object(p);
			if ( v2 == NULL ) {
				DECREF(v);
				v = NULL;
				break;
			}
			setlistitem(v, (int)i, v2);
		}
		return v;
	
	case TYPE_DICT:
		v = newdictobject();
		if (v == NULL)
			return NULL;
		for (;;) {
			object *key, *val;
			key = r_object(p);
			if (key == NULL)
				break; /* XXXX and how about memory errors? */
			val = r_object(p);
			/* XXXX error check? */
			dict2insert(v, key, val);
			DECREF(key);
			XDECREF(val);
		}
		return v;
	
	case TYPE_CODE:
		{
			int argcount = r_short(p);
			int nlocals = r_short(p);
			int flags = r_short(p);
			object *code = NULL;
			object *consts = NULL;
			object *names = NULL;
			object *varnames = NULL;
			object *filename = NULL;
			object *name = NULL;
			
			code = r_object(p);
			if (code) consts = r_object(p);
			if (consts) names = r_object(p);
			if (names) varnames = r_object(p);
			if (varnames) filename = r_object(p);
			if (filename) name = r_object(p);
			
			if (!err_occurred()) {
				v = (object *) newcodeobject(
					argcount, nlocals, flags, 
					code, consts, names, varnames,
					filename, name);
			}
			else
				v = NULL;
			XDECREF(code);
			XDECREF(consts);
			XDECREF(names);
			XDECREF(filename);
			XDECREF(name);

		}
		return v;
	
	default:
		err_setstr(TypeError, "read unknown object");
		return NULL;
	
	}
}

long
rd_long(fp)
	FILE *fp;
{
	RFILE rf;
	rf.fp = fp;
	return r_long(&rf);
}

object *
rd_object(fp)
	FILE *fp;
{
	RFILE rf;
	if (err_occurred()) {
		fatal("XXX rd_object called with exception set"); /* tmp */
		fprintf(stderr, "XXX rd_object called with exception set\n");
		return NULL;
	}
	rf.fp = fp;
	return r_object(&rf);
}

object *
rds_object(str, len)
	char *str;
	int len;
{
	RFILE rf;
	if (err_occurred()) {
		fprintf(stderr, "XXX rds_object called with exception set\n");
		return NULL;
	}
	rf.fp = NULL;
	rf.str = NULL;
	rf.ptr = str;
	rf.end = str + len;
	return r_object(&rf);
}

/* And an interface for Python programs... */

static object *
marshal_dump(self, args)
	object *self;
	object *args;
{
	WFILE wf;
	object *x;
	object *f;
	if (!getargs(args, "(OO)", &x, &f))
		return NULL;
	if (!is_fileobject(f)) {
		err_setstr(TypeError, "marshal.dump() 2nd arg must be file");
		return NULL;
	}
	wf.fp = getfilefile(f);
	wf.str = NULL;
	wf.ptr = wf.end = NULL;
	w_object(x, &wf);
	INCREF(None);
	return None;
}

static object *
marshal_load(self, args)
	object *self;
	object *args;
{
	RFILE rf;
	object *f;
	object *v;
	if (!getargs(args, "O", &f))
		return NULL;
	if (!is_fileobject(f)) {
		err_setstr(TypeError, "marshal.load() arg must be file");
		return NULL;
	}
	rf.fp = getfilefile(f);
	rf.str = NULL;
	rf.ptr = rf.end = NULL;
	err_clear();
	v = r_object(&rf);
	if (err_occurred()) {
		XDECREF(v);
		v = NULL;
	}
	return v;
}

static object *
marshal_dumps(self, args)
	object *self;
	object *args;
{
	WFILE wf;
	object *x;
	if (!getargs(args, "O", &x))
		return NULL;
	wf.fp = NULL;
	wf.str = newsizedstringobject((char *)NULL, 50);
	if (wf.str == NULL)
		return NULL;
	wf.ptr = GETSTRINGVALUE((stringobject *)wf.str);
	wf.end = wf.ptr + getstringsize(wf.str);
	w_object(x, &wf);
	if (wf.str != NULL)
		resizestring(&wf.str,
		    (int) (wf.ptr - GETSTRINGVALUE((stringobject *)wf.str)));
	return wf.str;
}

static object *
marshal_loads(self, args)
	object *self;
	object *args;
{
	RFILE rf;
	object *v;
	char *s;
	int n;
	if (!getargs(args, "s#", &s, &n))
		return NULL;
	rf.fp = NULL;
	rf.str = args;
	rf.ptr = s;
	rf.end = s + n;
	err_clear();
	v = r_object(&rf);
	if (err_occurred()) {
		XDECREF(v);
		v = NULL;
	}
	return v;
}

static struct methodlist marshal_methods[] = {
	{"dump",	marshal_dump},
	{"load",	marshal_load},
	{"dumps",	marshal_dumps},
	{"loads",	marshal_loads},
	{NULL,		NULL}		/* sentinel */
};

void
initmarshal()
{
	(void) initmodule("marshal", marshal_methods);
}
