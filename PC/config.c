/* -*- C -*- ***********************************************
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

/* Module configuration */

/* This file contains the table of built-in modules.
   See init_builtin() in import.c. */

#include "Python.h"

extern void initarray();
extern void initaudioop();
extern void initbinascii();
extern void initenvironment();
extern void initimageop();
extern void initmath();
extern void initmd5();
extern void initnew();
extern void initnt();
extern void initregex();
extern void initrgbimg();
extern void initrotor();
extern void initsignal();
extern void initsocket();
extern void initsoundex();
extern void initstrop();
extern void initstruct();
extern void inittime();

/* -- ADDMODULE MARKER 1 -- */

extern void PyMarshal_Init();
extern void initimp();

struct {
        char *name;
        void (*initfunc)();
} inittab[] = {

        {"array", initarray},
#ifdef M_I386
        {"audioop", initaudioop},
#endif
        {"binascii", initbinascii},
        {"environment", initenvironment},
        {"imageop", initimageop},
        {"math", initmath},
        {"md5", initmd5},
        {"new", initnew},
        {"nt", initnt},	/* Use the NT os functions, not posix */
        {"regex", initregex},
        {"rgbimg", initrgbimg},
        {"rotor", initrotor},
        {"signal", initsignal},
#ifdef USE_SOCKET
	{"socket", initsocket},
#endif
        {"soundex", initsoundex},
        {"strop", initstrop},
        {"struct", initstruct},
        {"time", inittime},

/* -- ADDMODULE MARKER 2 -- */

        /* This module "lives in" with marshal.c */
        {"marshal", PyMarshal_Init},

        /* This lives it with import.c */
        {"imp", initimp},

        /* These entries are here for sys.builtin_module_names */
        {"__main__", NULL},
        {"__builtin__", NULL},
        {"sys", NULL},

        /* Sentinel */
        {0, 0}
};
