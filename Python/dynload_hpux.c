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

/* Support for dynamic loading of extension modules */

#include "dl.h"
#include <errno.h>

#include "Python.h"
#include "importdl.h"


const struct filedescr _PyImport_DynLoadFiletab[] = {
	{".sl", "rb", C_EXTENSION},
	{"module.sl", "rb", C_EXTENSION},
	{0, 0}
};

dl_funcptr _PyImport_GetDynLoadFunc(const char *name, const char *funcname,
				    const char *pathname, FILE *fp)
{
	dl_funcptr p;
	shl_t lib;
	int flags;

	flags = BIND_FIRST | BIND_DEFERRED;
	if (Py_VerboseFlag) {
		flags = DYNAMIC_PATH | BIND_FIRST | BIND_IMMEDIATE |
			BIND_NONFATAL | BIND_VERBOSE;
		printf("shl_load %s\n",pathname);
	}
	lib = shl_load(pathname, flags, 0);
	/* XXX Chuck Blake once wrote that 0 should be BIND_NOSTART? */
	if (lib == NULL) {
		char buf[256];
		if (Py_VerboseFlag)
			perror(pathname);
		sprintf(buf, "Failed to load %.200s", pathname);
		PyErr_SetString(PyExc_ImportError, buf);
		return NULL;
	}
	if (Py_VerboseFlag)
		printf("shl_findsym %s\n", funcname);
	shl_findsym(&lib, funcname, TYPE_UNDEFINED, (void *) &p);
	if (p == NULL && Py_VerboseFlag)
		perror(funcname);

	return p;
}
