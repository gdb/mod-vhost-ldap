/***********************************************************
Copyright 1991 by Stichting Mathematisch Centrum, Amsterdam, The
Netherlands.

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

/* File object implementation */

/* XXX This should become a built-in module 'io'.  It should support more
   functionality, better exception handling for invalid calls, etc.
   (Especially reading on a write-only file or vice versa!)
   It should also cooperate with posix to support popen(), which should
   share most code but have a special close function. */

#include "allobjects.h"

#define BUF(v) GETSTRINGVALUE((stringobject *)v)

#include "errno.h"
#ifndef errno
extern int errno;
#endif

typedef struct {
	OB_HEAD
	FILE *f_fp;
	object *f_name;
	object *f_mode;
	/* XXX Should move the 'need space' on printing flag here */
} fileobject;

FILE *
getfilefile(f)
	object *f;
{
	if (!is_fileobject(f)) {
		err_badcall();
		return NULL;
	}
	return ((fileobject *)f)->f_fp;
}

object *
newopenfileobject(fp, name, mode)
	FILE *fp;
	char *name;
	char *mode;
{
	fileobject *f = NEWOBJ(fileobject, &Filetype);
	if (f == NULL)
		return NULL;
	f->f_fp = NULL;
	f->f_name = newstringobject(name);
	f->f_mode = newstringobject(mode);
	if (f->f_name == NULL || f->f_mode == NULL) {
		DECREF(f);
		return NULL;
	}
	f->f_fp = fp;
	return (object *) f;
}

object *
newfileobject(name, mode)
	char *name, *mode;
{
	fileobject *f;
	FILE *fp;
	f = (fileobject *) newopenfileobject((FILE *)NULL, name, mode);
	if (f == NULL)
		return NULL;
#ifdef THINK_C
	if (*mode == '*') {
		FILE *fopenRF();
		f->f_fp = fopenRF(name, mode+1);
	}
	else
#endif
	f->f_fp = fopen(name, mode);
	if (f->f_fp == NULL) {
		err_errno(RuntimeError);
		DECREF(f);
		return NULL;
	}
	return (object *)f;
}

/* Methods */

static void
file_dealloc(f)
	fileobject *f;
{
	if (f->f_fp != NULL)
		fclose(f->f_fp);
	if (f->f_name != NULL)
		DECREF(f->f_name);
	if (f->f_mode != NULL)
		DECREF(f->f_mode);
	free((char *)f);
}

static void
file_print(f, fp, flags)
	fileobject *f;
	FILE *fp;
	int flags;
{
	fprintf(fp, "<%s file ", f->f_fp == NULL ? "closed" : "open");
	printobject(f->f_name, fp, flags);
	fprintf(fp, ", mode ");
	printobject(f->f_mode, fp, flags);
	fprintf(fp, ">");
}

static object *
file_repr(f)
	fileobject *f;
{
	char buf[300];
	/* XXX This differs from file_print if the filename contains
	   quotes or other funny characters. */
	sprintf(buf, "<%s file '%.256s', mode '%.10s'>",
		f->f_fp == NULL ? "closed" : "open",
		getstringvalue(f->f_name),
		getstringvalue(f->f_mode));
	return newstringobject(buf);
}

static object *
file_close(f, args)
	fileobject *f;
	object *args;
{
	if (args != NULL) {
		err_badarg();
		return NULL;
	}
	if (f->f_fp != NULL) {
		fclose(f->f_fp);
		f->f_fp = NULL;
	}
	INCREF(None);
	return None;
}

static object *
file_seek(f, args)
	fileobject *f;
	object *args;
{
	long offset;
	long whence;
	
	if (f->f_fp == NULL) {
		err_badarg();
		return NULL;
	}
	if (args != NULL && is_intobject(args)) {
		offset = getintvalue(args);
		whence = 0; /* SEEK_SET */
	}
	else {
		if (!getlonglongargs(args, &offset, &whence))
			return NULL;
	}
	errno = 0;
	if (fseek(f->f_fp, offset, (int)whence) != 0) {
		if (errno == 0)
			errno = EIO;
		return err_errno(RuntimeError);
	}
	INCREF(None);
	return None;
}

static object *
file_tell(f, args)
	fileobject *f;
	object *args;
{
	long offset;
	if (args != NULL || f->f_fp == NULL) {
		err_badarg();
		return NULL;
	}
	errno = 0;
	offset = ftell(f->f_fp);
	if (offset == -1L) {
		if (errno == 0)
			errno = EIO;
		return err_errno(RuntimeError);
	}
	return newintobject(offset);
}

static object *
file_flush(f, args)
	fileobject *f;
	object *args;
{
	if (args != NULL || f->f_fp == NULL) {
		err_badarg();
		return NULL;
	}
	errno = 0;
	if (fflush(f->f_fp) != 0) {
		if (errno == 0)
			errno = EIO;
		return err_errno(RuntimeError);
	}
	INCREF(None);
	return None;
}

static object *
file_read(f, args)
	fileobject *f;
	object *args;
{
	int n, n1, n2, n3;
	object *v;
	
	if (f->f_fp == NULL) {
		err_badarg();
		return NULL;
	}
	if (args == 0)
		n = 0;
	else {
		if (!getintarg(args, &n))
			return NULL;
		if (n < 0) {
			err_badarg();
			return NULL;
		}
	}
	
	n2 = n != 0 ? n : BUFSIZ;
	v = newsizedstringobject((char *)NULL, n2);
	if (v == NULL)
		return NULL;
	n1 = 0;
	for (;;) {
		n3 = fread(BUF(v)+n1, 1, n2-n1, f->f_fp);
		/* XXX Error check? */
		if (n3 == 0)
			break;
		n1 += n3;
		if (n1 == n)
			break;
		if (n == 0) {
			n2 = n1 + BUFSIZ;
			if (resizestring(&v, n2) < 0)
				return NULL;
		}
	}
	if (n1 != n2)
		resizestring(&v, n1);
	return v;
}

/* Read a line.
   Without argument, or with a zero argument, read until end of line
   or EOF, whichever comes first.
   With a positive argument n, read at most n bytes until end of line
   or EOF, whichever comes first.
   Negative and non-integer arguments are illegal.
   When EOF is hit immediately, return an empty string.
   A newline character is returned as the last character of the buffer
   if it is read.
*/

/* XXX Should this be unified with raw_input()? */

static object *
file_readline(f, args)
	fileobject *f;
	object *args;
{
	register FILE *fp;
	register int c;
	register char *buf, *end;
	int n, n1, n2;
	object *v;
	
	if ((fp = f->f_fp) == NULL) {
		err_badarg();
		return NULL;
	}
	
	if (args == NULL)
		n = 0; /* Unlimited */
	else {
		if (!getintarg(args, &n))
			return NULL;
		if (n < 0) {
			err_badarg();
			return NULL;
		}
	}
	
	n2 = n != 0 ? n : 100;
	v = newsizedstringobject((char *)NULL, n2);
	if (v == NULL)
		return NULL;
	buf = BUF(v);
	end = buf + n2;
	
	for (;;) {
		if ((c = getc(fp)) == EOF || (*buf++ = c) == '\n')
			break;
		/* XXX Error check? */
		if (buf == end) {
			if (n != 0)
				break;
			n1 = n2;
			n2 += 1000;
			if (resizestring(&v, n2) < 0)
				return NULL;
			buf = BUF(v) + n1;
			end = BUF(v) + n2;
		}
	}
	
	n1 = buf - BUF(v);
	if (n1 != n2)
		resizestring(&v, n1);
	return v;
}

static object *
file_readlines(f, args)
	fileobject *f;
	object *args;
{
	object *list;
	object *line;
	
	if ((list = newlistobject(0)) == NULL)
		return NULL;
	for (;;) {
		line = file_readline(f, args);
		if (line != NULL && getstringsize(line) == 0) {
			DECREF(line);
			break;
		}
		if (line == NULL || addlistitem(list, line) != 0) {
			DECREF(list);
			XDECREF(line);
			return NULL;
		}
		DECREF(line);
	}
	return list;
}

static object *
file_write(f, args)
	fileobject *f;
	object *args;
{
	int n, n2;
	if (f->f_fp == NULL) {
		err_badarg();
		return NULL;
	}
	if (args == NULL || !is_stringobject(args)) {
		err_badarg();
		return NULL;
	}
	errno = 0;
	n2 = fwrite(getstringvalue(args), 1, n = getstringsize(args), f->f_fp);
	if (n2 != n) {
		if (errno == 0)
			errno = EIO;
		err_errno(RuntimeError);
		return NULL;
	}
	INCREF(None);
	return None;
}

static struct methodlist file_methods[] = {
	{"close",	file_close},
	{"flush",	file_flush},
	{"read",	file_read},
	{"readline",	file_readline},
	{"readlines",	file_readlines},
	{"seek",	file_seek},
	{"tell",	file_tell},
	{"write",	file_write},
	{NULL,		NULL}		/* sentinel */
};

static object *
file_getattr(f, name)
	fileobject *f;
	char *name;
{
	return findmethod(file_methods, (object *)f, name);
}

typeobject Filetype = {
	OB_HEAD_INIT(&Typetype)
	0,
	"file",
	sizeof(fileobject),
	0,
	file_dealloc,	/*tp_dealloc*/
	file_print,	/*tp_print*/
	file_getattr,	/*tp_getattr*/
	0,		/*tp_setattr*/
	0,		/*tp_compare*/
	file_repr,	/*tp_repr*/
};
