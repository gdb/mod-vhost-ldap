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

/* Python interpreter main program */

#include "Python.h"
#include "pythonresources.h"
#include "import.h"
#include "marshal.h"
#include "macglue.h"

#ifdef WITHOUT_FRAMEWORKS
#include <Memory.h>
#include <Resources.h>
#include <stdio.h>
#include <Events.h>
#include <Windows.h>
#include <Fonts.h>
#include <Balloons.h>
#include <CFBundle.h>
#include <CFURL.h>
#include <CFString.h>
#include <CFBase.h>
#include <CFArray.h>
#include <Gestalt.h>
#include <Appearance.h>
#else
#include <Carbon/Carbon.h>
#endif /* WITHOUT_FRAMEWORKS */

#ifdef __MWERKS__
#include <SIOUX.h>
#define USE_SIOUX
extern int ccommand(char ***);
#if __profile__ == 1
#include <profiler.h>
#endif /* __profile__ */
#endif /* __MWERKS__ */

#include <unistd.h>
#ifdef USE_MAC_SHARED_LIBRARY
extern PyMac_AddLibResources(void);
#endif

#define STARTUP "PythonStartup"

#define COPYRIGHT \
    "Type \"copyright\", \"credits\" or \"license\" for more information."

short PyMac_AppRefNum;	/* RefNum of application resource fork */

/* For Py_GetArgcArgv(); set by main() */
static char **orig_argv;
static int  orig_argc;

/* A flag which remembers whether the user has acknowledged all the console
** output (by typing something)
*/
#define STATE_UNKNOWN 0
#define STATE_LASTREAD 1
#define STATE_LASTWRITE 2
int console_output_state = STATE_UNKNOWN;

PyMac_PrefRecord PyMac_options;

static void PyMac_Main(int, char **, char *); /* Forward */
void PyMac_Exit(int); /* Forward */

/* Initialize the Mac toolbox world */

static void
init_mac_world(void)
{
	InitCursor();
}

/*
** PyMac_InteractiveOptions - Allow user to set options if option key is pressed
*/
static void
PyMac_InteractiveOptions(PyMac_PrefRecord *p, int *argcp, char ***argvp)
{
	KeyMap rmap;
	unsigned char *map;
	short item, type;
	ControlHandle handle;
	DialogPtr dialog;
	Rect rect;

	/*
	** If the preferences disallows interactive options we return,
	** similarly of <option> isn't pressed.
	*/
	if (p->nointopt) return;
	
	GetKeys(rmap);
	map = (unsigned char *)rmap;
	if ( ( map[0x3a>>3] & (1<<(0x3a&7)) ) == 0 )	/* option key is 3a */
		return;

	dialog = GetNewDialog(OPT_DIALOG, NULL, (WindowPtr)-1);
	if ( dialog == NULL ) {
		printf("Option dialog not found - cannot set options\n");
		return;
	}
	SetDialogDefaultItem(dialog, OPT_OK);
	SetDialogCancelItem(dialog, OPT_CANCEL);
	
	/* Set default values */
#define SET_OPT_ITEM(num, var) \
		GetDialogItem(dialog, (num), &type, (Handle *)&handle, &rect); \
		SetControlValue(handle, (short)p->var);

	SET_OPT_ITEM(OPT_INSPECT, inspect);
	SET_OPT_ITEM(OPT_VERBOSE, verbose);
	/* OPT_VERBOSEVERBOSE is default off */
	SET_OPT_ITEM(OPT_OPTIMIZE, optimize);
	SET_OPT_ITEM(OPT_UNBUFFERED, unbuffered);
	SET_OPT_ITEM(OPT_DEBUGGING, debugging);
	GetDialogItem(dialog, OPT_KEEPALWAYS, &type, (Handle *)&handle, &rect);
	SetControlValue(handle, (short)(p->keep_console == POPT_KEEPCONSOLE_ALWAYS));
	GetDialogItem(dialog, OPT_KEEPOUTPUT, &type, (Handle *)&handle, &rect);
	SetControlValue(handle, (short)(p->keep_console == POPT_KEEPCONSOLE_OUTPUT));
	GetDialogItem(dialog, OPT_KEEPERROR, &type, (Handle *)&handle, &rect);
	SetControlValue(handle, (short)(p->keep_console == POPT_KEEPCONSOLE_ERROR));
	GetDialogItem(dialog, OPT_KEEPNEVER, &type, (Handle *)&handle, &rect);
	SetControlValue(handle, (short)(p->keep_console == POPT_KEEPCONSOLE_NEVER));
/*	SET_OPT_ITEM(OPT_KEEPCONSOLE, keep_console); */
	SET_OPT_ITEM(OPT_TABWARN, tabwarn);
	SET_OPT_ITEM(OPT_NOSITE, nosite);
	SET_OPT_ITEM(OPT_DIVISIONWARN, divisionwarn);
	SET_OPT_ITEM(OPT_UNIXNEWLINES, unixnewlines);
	/* The rest are not settable interactively */

#undef SET_OPT_ITEM
	
	while (1) {
		handle = NULL;
		ModalDialog(NULL, &item);
		if ( item == OPT_OK )
			break;
		if ( item == OPT_CANCEL ) {
			DisposeDialog(dialog);
			exit(0);
		}
		if ( item == OPT_CMDLINE ) {
			int old_argc = *argcp;
			int i;
			int new_argc, newer_argc;
			char **new_argv, **newer_argv;
			
			new_argc = ccommand(&new_argv);
			newer_argc = (new_argc-1) + old_argc;
			newer_argv = malloc((newer_argc+1)*sizeof(char *));
			if( !newer_argv )
				Py_FatalError("Cannot malloc argv\n");
			for(i=0; i<old_argc; i++)
				newer_argv[i] = (*argvp)[i];
			for(i=old_argc; i<=newer_argc; i++) /* Copy the NULL too */
				newer_argv[i] = new_argv[i-old_argc+1];
			*argvp = newer_argv;
			*argcp = newer_argc;
			
			/* XXXX Is it not safe to use free() here, apparently */
		}
#define OPT_ITEM(num, var) \
		if ( item == (num) ) { \
			p->var = !p->var; \
			GetDialogItem(dialog, (num), &type, (Handle *)&handle, &rect); \
			SetControlValue(handle, (short)p->var); \
		}
		
		OPT_ITEM(OPT_INSPECT, inspect);
		OPT_ITEM(OPT_VERBOSE, verbose);
		if ( item == OPT_VERBOSEVERBOSE ) {
			if ( p->verbose == 2 )
				p->verbose = 1;
			else
				p->verbose = 2;
			GetDialogItem(dialog, OPT_VERBOSE, &type, (Handle *)&handle, &rect);
			SetControlValue(handle, 1);
		}
		GetDialogItem(dialog, OPT_VERBOSEVERBOSE, &type, (Handle *)&handle, &rect);
		SetControlValue(handle, p->verbose == 2);
		OPT_ITEM(OPT_OPTIMIZE, optimize);
		OPT_ITEM(OPT_UNBUFFERED, unbuffered);
		OPT_ITEM(OPT_DEBUGGING, debugging);
		if ( item == OPT_KEEPALWAYS ) p->keep_console = POPT_KEEPCONSOLE_ALWAYS;
		if ( item == OPT_KEEPOUTPUT ) p->keep_console = POPT_KEEPCONSOLE_OUTPUT;
		if ( item == OPT_KEEPERROR ) p->keep_console = POPT_KEEPCONSOLE_ERROR;
		if ( item == OPT_KEEPNEVER ) p->keep_console = POPT_KEEPCONSOLE_NEVER;
		GetDialogItem(dialog, OPT_KEEPALWAYS, &type, (Handle *)&handle, &rect);
		SetControlValue(handle, (short)(p->keep_console == POPT_KEEPCONSOLE_ALWAYS));
		GetDialogItem(dialog, OPT_KEEPOUTPUT, &type, (Handle *)&handle, &rect);
		SetControlValue(handle, (short)(p->keep_console == POPT_KEEPCONSOLE_OUTPUT));
		GetDialogItem(dialog, OPT_KEEPERROR, &type, (Handle *)&handle, &rect);
		SetControlValue(handle, (short)(p->keep_console == POPT_KEEPCONSOLE_ERROR));
		GetDialogItem(dialog, OPT_KEEPNEVER, &type, (Handle *)&handle, &rect);
		SetControlValue(handle, (short)(p->keep_console == POPT_KEEPCONSOLE_NEVER));
		OPT_ITEM(OPT_TABWARN, tabwarn);
		OPT_ITEM(OPT_NOSITE, nosite);
		OPT_ITEM(OPT_DIVISIONWARN, divisionwarn);
		OPT_ITEM(OPT_UNIXNEWLINES, unixnewlines);
		
#undef OPT_ITEM
	}
	DisposeDialog(dialog);
}

/*
** Initialization code, shared by interpreter and applets
*/
static void
init_common(int *argcp, char ***argvp, int embedded)
{
	/* Remember resource fork refnum, for later */
	PyMac_AppRefNum = CurResFile();
	
	/* Initialize toolboxes */
	init_mac_world();
	
#ifdef USE_MAC_SHARED_LIBRARY
	/* Add the shared library to the stack of resource files */
	(void)PyMac_init_process_location();
	PyMac_AddLibResources();
#endif

#if defined(USE_GUSI)
	atexit(PyMac_StopGUSISpin);
#endif	

#ifdef USE_SIOUX
	/* Set various SIOUX flags. Some are changed later based on options */
	SIOUXSettings.asktosaveonclose = 0;
	SIOUXSettings.showstatusline = 0;
	SIOUXSettings.tabspaces = 4;
#endif

	/* Get options from preference file (or from applet resource fork) */
	PyMac_options.keep_console = POPT_KEEPCONSOLE_OUTPUT;		/* default-default */
	PyMac_options.unixnewlines = 1;
	PyMac_PreferenceOptions(&PyMac_options);

	if ( embedded ) {
		static char *emb_argv[] = {"embedded-python", 0};
		
		*argcp = 1;
		*argvp = emb_argv;
	} else {
		/* Create argc/argv. Do it before we go into the options event loop.
		** In MachoPython we skip this step if we already have plausible
		** command line arguments.
		*/
			*argcp = PyMac_GetArgv(argvp, PyMac_options.noargs);
#ifndef NO_ARGV0_CHDIR
		if (*argcp >= 1 && (*argvp)[0] && (*argvp)[0][0]) {
			/* Workaround for MacOS X, which currently (DP4) doesn't set
			** the working folder correctly
			*/
			char app_wd[256], *p;
			
			strncpy(app_wd, (*argvp)[0], 256);
			p = strrchr(app_wd, ':');
			if ( p ) *p = 0;
			chdir(app_wd);
		}
#endif
		/* Do interactive option setting, if allowed and <option> depressed */
		PyMac_InteractiveOptions(&PyMac_options, argcp, argvp);
	}
	
	/* Copy selected options to where the machine-independent stuff wants it */
	Py_VerboseFlag = PyMac_options.verbose;
/*	Py_SuppressPrintingFlag = PyMac_options.suppress_print; */
	Py_OptimizeFlag = PyMac_options.optimize;
	Py_DebugFlag = PyMac_options.debugging;
	Py_NoSiteFlag = PyMac_options.nosite;
	Py_TabcheckFlag = PyMac_options.tabwarn;
	Py_DivisionWarningFlag = PyMac_options.divisionwarn;
	if ( PyMac_options.noargs ) {
		/* don't process events at all without the scripts permission */
		PyMacSchedParams scp;
		
		PyMac_GetSchedParams(&scp);
		scp.process_events = 0;
		/* Should we disable command-dot as well? */
		PyMac_SetSchedParams(&scp);
	}

	/* Set buffering */
	if (PyMac_options.unbuffered) {
#ifndef MPW
		setbuf(stdout, (char *)NULL);
		setbuf(stderr, (char *)NULL);
#else
		/* On MPW (3.2) unbuffered seems to hang */
		setvbuf(stdout, (char *)NULL, _IOLBF, BUFSIZ);
		setvbuf(stderr, (char *)NULL, _IOLBF, BUFSIZ);
#endif
	}
#if __profile__ == 1
	/* collectSummary or collectDetailed, timebase, #routines, max stack depth */
	ProfilerInit(collectSummary, bestTimeBase, 8000, 250);
#endif

	/* Tell the rest of python about our argc/argv */
	orig_argc = *argcp;	/* For Py_GetArgcArgv() */
	orig_argv = *argvp;
	Py_SetProgramName((*argvp)[0]);
}

/*
** Inspection mode after script/applet termination
*/
static int
run_inspect(void)
{
	int sts = 0;
	
	if (PyMac_options.inspect && isatty((int)fileno(stdin)))
		sts = PyRun_AnyFile(stdin, "<stdin>") != 0;
	return sts;
}
	
#ifdef USE_MAC_APPLET_SUPPORT
/* Applet support */

/* Run a compiled Python Python script from 'PYC ' resource __main__ */
static int
run_main_resource(void)
{
	Handle h;
	long size;
	PyObject *code;
	PyObject *result;
	
	h = GetNamedResource('PYC ', "\p__main__");
	if (h == NULL) {
		Alert(NOPYC_ALERT, NULL);
		return 1;
	}
	size = GetResourceSizeOnDisk(h);
	HLock(h);
	code = PyMarshal_ReadObjectFromString(*h + 8, (int)(size - 8));
	HUnlock(h);
	ReleaseResource(h);
	if (code == NULL) {
		PyErr_Print();
		return 1;
	}
	result = PyImport_ExecCodeModule("__main__", code);
	Py_DECREF(code);
	if (result == NULL) {
		PyErr_Print();
		return 1;
	}
	Py_DECREF(result);
	return 0;
}

/* Initialization sequence for applets */
void
PyMac_InitApplet(void)
{
	int argc;
	char **argv;
	int err;

	init_common(&argc, &argv, 0);
	
	Py_Initialize();
	PySys_SetArgv(argc, argv);
	
	err = run_main_resource();
	
	err = (run_inspect() || err);
	
	fflush(stderr);
	fflush(stdout);
	PyMac_Exit(err);
	/* XXX Should we bother to Py_Exit(sts)? */
}

/*
** Hook for embedding python.
*/
void
PyMac_Initialize(void)
{
	int argc;
	char **argv;
	
	init_common(&argc, &argv, 1);
	Py_Initialize();
	PySys_SetArgv(argc, argv);
}

#endif /* USE_MAC_APPLET_SUPPORT */

/* For normal application */
void
PyMac_InitApplication(void)
{
	int argc;
	char **argv;
	OSType filetype;
	
	static char scriptpath[1024];
	char *script = NULL;

	init_common(&argc, &argv, 0);

	if ( argc > 1 ) {
		/* We're running a script. Attempt to change current directory */
		char curwd[256], *endp;
		
		strcpy(curwd, argv[1]);
		endp = strrchr(curwd, ':');
		if ( endp && endp > curwd ) {
			*endp = '\0';

			chdir(curwd);
		}
		/* Check that the first argument is a text file */
		filetype = PyMac_getfiletype(argv[1]);
		if ( filetype != 'TEXT' && filetype != 0 ) {
			Alert(NOTASCRIPT_ID, NULL);
			exit(0);
		}
	}
	PyMac_Main(argc, argv, script);
}

/* Main program */

static void
PyMac_Main(int argc, char **argv, char *filename)
{
	int sts;
	char *command = NULL;
	FILE *fp = stdin;

	if ( filename ) {
		/* Someone else has found our "script" already */
		argv[0] = filename;
	} else {
		filename = argv[1];
		argv++;
		argc--;
	}

	if (Py_VerboseFlag ||
	    (command == NULL && filename == NULL && isatty((int)fileno(fp))))
		fprintf(stderr, "%s %s on %s\n%s\n",
			"Python",
			Py_GetVersion(), Py_GetPlatform(), COPYRIGHT);
	
	if (filename != NULL) {
		if ((fp = fopen(filename, "r" PY_STDIOTEXTMODE)) == NULL) {
			fprintf(stderr, "%s: can't open file '%s'\n",
				argv[0], filename);
			PyMac_Exit(2);
		}
	}
	
	/* We initialize the menubar here, hoping SIOUX is initialized by now */
	PyMac_InitMenuBar();

	Py_Initialize();
	
	PyUnicode_SetDefaultEncoding(PyMac_getscript());
	
	PySys_SetArgv(argc, argv);

	if (filename == NULL && isatty((int)fileno(fp))) {
		FILE *fp = fopen(STARTUP, "r" PY_STDIOTEXTMODE);
		if (fp != NULL) {
			(void) PyRun_SimpleFile(fp, STARTUP);
			PyErr_Clear();
			fclose(fp);
		}
	}
	sts = PyRun_AnyFile(
			fp, filename == NULL ? "<stdin>" : filename) != 0;
	if (filename != NULL)
		fclose(fp);
		
	if ( filename != NULL || command != NULL )
		sts = (run_inspect() || sts);

	Py_Exit(sts);
	/*NOTREACHED*/
}

/*
** Reset the "unseen output" flag
*/
void
PyMac_OutputSeen(void)
{
	if ( console_output_state == STATE_UNKNOWN )
		PyMac_InitMenuBar();
	console_output_state = STATE_LASTREAD;
}

/*
** Set the "unseen output" flag
*/
void
PyMac_OutputNotSeen(void)
{
	if ( console_output_state == STATE_UNKNOWN )
		PyMac_InitMenuBar();
	console_output_state = STATE_LASTWRITE;
}

/*
** Override abort() - The default one is not what we want.
*/
void
abort(void)
{
	console_output_state = STATE_LASTWRITE;
	PyMac_Exit(1);
}

/*
** Terminate application
*/
void
PyMac_Exit(int status)
{
#ifdef USE_SIOUX
	int keep = 0;
#endif

#if __profile__ == 1
	ProfilerDump("\pPython Profiler Results");
	ProfilerTerm();
#endif	
		
#ifdef USE_SIOUX
	switch (PyMac_options.keep_console) {
	case POPT_KEEPCONSOLE_NEVER:
		keep = 0;
		break;
	case POPT_KEEPCONSOLE_OUTPUT:
		if (console_output_state == STATE_LASTWRITE ||
				console_output_state == STATE_UNKNOWN )
			keep = 1;
		else
			keep = 0;
		break;
	case POPT_KEEPCONSOLE_ERROR:
		keep = (status != 0);
		break;
	default:
		keep = 1;
	}
	if (keep) {
		SIOUXSettings.standalone = 1;
		SIOUXSettings.autocloseonquit = 0;
		SIOUXSetTitle("\p\307terminated\310");
		PyMac_RaiseConsoleWindow();
		PyMac_RestoreMenuBar();
#ifdef USE_MSL
		/*
		** Temporary workaround: autocloseonquit clearing does not
		** currently work for the MSL/GUSI combo.
		*/
		while(getchar() > 0);
#endif
	}
	else
		SIOUXSettings.autocloseonquit = 1;
#endif /* USE_SIOUX */

	exit(status);
}

/* Make the *original* argc/argv available to other modules.
   This is rare, but it is needed by the secureware extension. */

void
Py_GetArgcArgv(int *argc,char ***argv)
{
	*argc = orig_argc;
	*argv = orig_argv;
}

/* More cruft that shouldn't really be here, used in sysmodule.c */
/* Return the program name -- some code out there needs this. */
char *
Py_GetProgramFullPath(void)
{
	return orig_argv[0];
}

char *
Py_GetPrefix(void)
{
	return PyMac_GetPythonDir();
}

char *
Py_GetExecPrefix(void)
{
	return PyMac_GetPythonDir();
}

int
PyMac_GetDelayConsoleFlag(void)
{
	return (int)PyMac_options.delayconsole;
}

#ifndef WITHOUT_UNIX_NEWLINES
/*
** Experimental feature (for 2.2a2): optionally allow unix newlines
** as well as Mac newlines on input. We replace a lowlevel
** MSL routine to accomplish this.
*/
void
__convert_to_newlines(unsigned char * buf, size_t * n_ptr)
{
	unsigned char *p;
	size_t n = *n_ptr;
	
	for(p=buf; n > 0; p++, n--)
		if ( *p == '\r' ) *p = '\n';
		else if ( *p == '\n' && !PyMac_options.unixnewlines )
			*p = '\r';
}
#endif /* WITHOUT_UNIX_NEWLINES */

