/***********************************************************
Copyright 1991-1996 by Stichting Mathematisch Centrum, Amsterdam,
The Netherlands.

                        All Rights Reserved

Copyright (c) 2000, BeOpen.com.
Copyright (c) 1995-2000, Corporation for National Research Initiatives.
Copyright (c) 1990-1995, Stichting Mathematisch Centrum.
All rights reserved.

See the file "Misc/COPYRIGHT" for information on usage and
redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.

******************************************************************/

/* Return the copyright string.  This is updated manually. */

#include "Python.h"

static char cprt[] = 
"Copyright 1991-1995 Stichting Mathematisch Centrum, Amsterdam\n\
Copyright 1995-2000 Corporation for National Research Initiatives (CNRI)";

const char *
Py_GetCopyright(void)
{
	return cprt;
}
