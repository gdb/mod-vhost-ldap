/***********************************************************
Copyright (c) 2000, BeOpen.com.
Copyright (c) 1995-2000, Corporation for National Research Initiatives.
Copyright (c) 1990-1995, Stichting Mathematisch Centrum.
All rights reserved.

See the file "Misc/COPYRIGHT" for information on usage and
redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.
******************************************************************/

/* Subroutine to get the last modification time of a file */

/* (A separate file because this may be OS dependent) */

#include "Python.h"
#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>

time_t
PyOS_GetLastModificationTime(path, fp)
	char *path;
	FILE *fp;
{
	struct stat st;
	if (fstat(fileno(fp), &st) != 0)
		return -1;
	else
		return st.st_mtime;
}
