/***********************************************************
Copyright 1991-1997 by Stichting Mathematisch Centrum, Amsterdam,
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

/* Macintosh Python main program for both applets and interpreter */

#include <Resources.h>

#ifdef __CFM68K__
#pragma lib_export on
#endif

extern void PyMac_InitApplet();
#ifdef USE_MAC_APPLET_SUPPORT
extern void PyMac_InitApplication();
#endif /* USE_MAC_APPLET_SUPPORT */

void
main() {
#ifdef USE_MAC_APPLET_SUPPORT
        Handle mainpyc;

        mainpyc = Get1NamedResource('PYC ', "\p__main__");
        if (mainpyc != NULL)
                PyMac_InitApplet();
        else
                PyMac_InitApplication();
#else
	PyMac_InitApplication();
#endif /* USE_MAC_APPLET_SUPPORT */
}
