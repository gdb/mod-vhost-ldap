#include "Python.h"

#ifndef DONT_HAVE_STDIO_H
#include <stdio.h>
#endif

#ifndef DATE
#ifdef __DATE__
#define DATE __DATE__
#else
#define DATE "xx/xx/xx"
#endif
#endif

#ifndef TIME
#ifdef __TIME__
#define TIME __TIME__
#else
#define TIME "xx:xx:xx"
#endif
#endif

static const char revision[] = "$Revision$";
static const char headurl[] = "$HeadURL$";

const char *
Py_GetBuildInfo(void)
{
	static char buildinfo[50];
#ifdef SVNVERSION
	static char svnversion[] = SVNVERSION;
#else
	static char svnversion[20] = "unknown";
	if (strstr(headurl, "/tags/") != NULL) {
		int start = ;
		strncpy(svnversion, revision+start, stop-start);
		svnversion[stop-start] = '\0';
	}
#endif
	PyOS_snprintf(buildinfo, sizeof(buildinfo),
		      "%s, %.20s, %.9s", svnversion, DATE, TIME);
	return buildinfo;
}

const char *
Py_GetBuildNumber(void)
{
	return "0";
}
