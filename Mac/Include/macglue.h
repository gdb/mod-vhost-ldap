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

#ifndef SystemSevenOrLater
#define SystemSevenOrLater 1
#endif

#include <Types.h>
#include <Files.h>
#include <Events.h>
#include <StandardFile.h>

#ifdef __cplusplus
	extern "C" {
#endif

/* Scheduler parameters */
typedef struct {
	int		check_interrupt;	/* if true check for command-dot */
	int		process_events;		/* if nonzero enable evt processing, this mask */
	int		besocial;		/* Be social, give up CPU now and again */
	double		check_interval;		/* how often to check */
	double		bg_yield;		/* yield at most so long when in background */
} PyMacSchedParams;


#ifdef GENERATINGCFM				/* Defined to 0 or 1 in Universal headers */
#define HAVE_UNIVERSAL_HEADERS
#endif

#ifdef SYMANTEC__CFM68K__
#pragma lib_export on
#endif

#ifdef USE_GUSI1
void PyMac_FixGUSIcd(void);		/* Workaround for GUSI chdir() call */
extern void PyMac_SetGUSISpin(void);		/* Install our private GUSI spin routine */
#endif

char *PyMac_StrError(int);			/* strerror with mac errors */
unsigned char *Pstring(char *str);		/* Convert c-string to pascal-string in static buffer */

#ifdef USE_GUSI
extern int PyMac_ConsoleIsDead;			/* True when exiting */
extern void PyMac_StopGUSISpin(void);		/* Stop eventprocessing during exit() */
#endif

extern short PyMac_AppRefNum;			/* RefNum of application rsrcfork (from macmain.c) */
extern FSSpec PyMac_ApplicationFSSpec;		/* Application location (from macargv.c) */
extern char PyMac_ApplicationPath[];		/* Application location (from macargv.c) */
extern OSErr PyMac_init_application_location(void);	/* Init the above */
extern OSErr PyMac_GetFullPath(FSSpec *, char *); /* convert fsspec->path (macargv.c) */
extern int PyMac_GetArgv(char ***, int);	/* Get argc, argv (from macargv.c) */
extern int PyMac_AppearanceCompliant;	/* True if in appearance support mode */

extern PyObject *PyMac_OSErrException;		/* Exception for OSErr */
PyObject *PyMac_GetOSErrException(void);	/* Initialize & return it */

void PyMac_GetSchedParams(PyMacSchedParams *);	/* Get schedulers params */
void PyMac_SetSchedParams(PyMacSchedParams *);	/* Set schedulers params */
PyObject *PyErr_Mac(PyObject *, int);		/* Exception with a mac error */
PyObject *PyMac_Error(OSErr);			/* Uses PyMac_GetOSErrException */
int PyMac_DoYield(int, int);	/* Yield cpu. First arg is maxtime, second ok to call python */
int PyMac_HandleEvent(EventRecord *);	/* Handle one event, possibly in Python */
void PyMac_HandleEventIntern(EventRecord *); /* Handle one event internal only */
int PyMac_SetEventHandler(PyObject *);	/* set python-coded event handler */

void PyMac_InitMenuBar(void);			/* Setup menu bar as we want it */
void PyMac_RestoreMenuBar(void);		/* Restore menu bar for ease of exiting */

int PyMac_FindResourceModule(PyStringObject *, char *, char *); /* Test for 'PYC ' resource in a file */
PyObject * PyMac_LoadResourceModule(char *, char *); /* Load 'PYC ' resource from file */
int PyMac_FindCodeResourceModule(PyStringObject *, char *, char *); /* Test for 'PYD ' resource in a file */
PyObject * PyMac_LoadCodeResourceModule(char *, char *); /* Load 'PYD ' resource from file */
struct filedescr *PyMac_FindModuleExtension(char *, size_t *, char *); /* Look for module in single folder */

int PyMac_GetDirectory(FSSpec *dirfss, char *prompt);		/* Ask user for a directory */
void PyMac_PromptGetFile(short numTypes, ConstSFTypeListPtr typeList, 
	StandardFileReply *reply, char *prompt);	/* Ask user for file, with prompt */

int PyMac_GetOSType(PyObject *, OSType *);	/* argument parser for OSType */
PyObject *PyMac_BuildOSType(OSType);		/* Convert OSType to PyObject */

PyObject *PyMac_BuildNumVersion(NumVersion);	/* Convert NumVersion to PyObject */

int PyMac_GetStr255(PyObject *, Str255);	/* argument parser for Str255 */
PyObject *PyMac_BuildStr255(Str255);		/* Convert Str255 to PyObject */
PyObject *PyMac_BuildOptStr255(Str255);		/* Convert Str255 to PyObject, NULL to None */

int PyMac_GetFSSpec(PyObject *, FSSpec *);	/* argument parser for FSSpec */
PyObject *PyMac_BuildFSSpec(FSSpec *);		/* Convert FSSpec to PyObject */

int PyMac_GetRect(PyObject *, Rect *);		/* argument parser for Rect */
PyObject *PyMac_BuildRect(Rect *);		/* Convert Rect to PyObject */

int PyMac_GetPoint(PyObject *, Point *);	/* argument parser for Point */
PyObject *PyMac_BuildPoint(Point);		/* Convert Point to PyObject */

int PyMac_GetEventRecord(PyObject *, EventRecord *); /* argument parser for EventRecord */
PyObject *PyMac_BuildEventRecord(EventRecord *); /* Convert EventRecord to PyObject */

int PyMac_GetFixed(PyObject *, Fixed *);	/* argument parser for Fixed */
PyObject *PyMac_BuildFixed(Fixed);			/* Convert Fixed to PyObject */
int PyMac_Getwide(PyObject *, wide *);	/* argument parser for wide */
PyObject *PyMac_Buildwide(wide *);			/* Convert wide to PyObject */
void PyMac_InitApplet(void);			/* Initialize and run an Applet */
void PyMac_Initialize(void);			/* Initialize function for embedding Python */

#ifdef USE_GUSI2
short PyMac_OpenPrefFile(void);			/* From macgetpath.c, open and return preference file */
#endif

/* From macfiletype.c: */

long getfiletype(char *);			/* Get file type */
int setfiletype(char *, long, long);		/* Set file creator and type */
#ifdef __cplusplus
	}
#endif
