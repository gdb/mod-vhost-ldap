/*
** Resource-IDs in use by Python.
**
** All resources used by the python interpreter itself fall
** in the range 128-256.
**
** Standard python modules use resources in the range
** 256-512.
**
** Python programs that use their own resources are advised to
** choose resource numbers higher than 512.
*/

/*
** Resources that reside in the python executable (or, for
** shared ppc python, in the core dynamic library)
*/

/* The alert for "No Python directory, where is it?" (OBSOLETE) */
#define NOPYTHON_ALERT	128
#define YES_ITEM		1
#define NO_ITEM			2
#define CURWD_ITEM		3

/* The alert for "this is an applet template" */
#define NOPYC_ALERT		129

/* The dialog for our GetDirectory and PromptGetFile call */
#define GETDIR_ID 		130		/* Resource ID for our "get directory" */
#define GETFILEPROMPT_ID 132	/* Resource id for prompted get file */
#define PROMPT_ITEM		10		/* The prompt, at the top */
#define SELECTCUR_ITEM	11	/* "Select current directory" button */


/* The dialog for interactive options */
#define OPT_DIALOG		131		/* Resource ID for dialog */
#define OPT_OK			1
#define OPT_CANCEL		2
#define OPT_INSPECT		3
#define OPT_VERBOSE		4
#define OPT_SUPPRESS	5
#define OPT_UNBUFFERED	6
#define OPT_DEBUGGING	7
#define OPT_KEEPNORMAL	8
#define OPT_KEEPERROR	9
#define OPT_CMDLINE		10

/* Dialog for 'No preferences directory' */
#define NOPREFDIR_ID	133

/* Dialog for 'Create preferences file?' */
#define NOPREFFILE_ID	134
#define NOPREFFILE_YES	1
#define NOPREFFILE_NO	2

/* Dialog for 'Bad preference file' */
#define BADPREFFILE_ID	135

/* About box */
#define ABOUT_ID		136

/*
** The following are valid both in the binary (or shared library)
** and in the Preferences file.
** For all these the override is tried first, in the application resource fork
** only, this allows an applet to override standard settings.
** If there is no override resource the preferences file is added to the head
** of the resource file chain and the non-override version of the resource is
** searched in any resource file.
**
** The effect of this is that, for example, a 'Popt' of 128 in the application or
** shared library provides default options for use when no preferences are set,
** while a 'Popt' of 129 (in the application *only*) overrides any options in the
** preferences file.
*/

/* The STR# resource for sys.path initialization */
#define PYTHONPATH_ID 128
#define PYTHONPATHOVERRIDE_ID 129

/* The alis resource for locating the python home directory */
#define PYTHONHOME_ID 128
#define PYTHONHOMEOVERRIDE_ID 129

/* The Python options resource and offset of its members */
#define PYTHONOPTIONS_ID 128
#define PYTHONOPTIONSOVERRIDE_ID 129
#define POPT_INSPECT	0
#define POPT_VERBOSE	1
#define POPT_SUPPRESS	2
#define POPT_UNBUFFERED	3
#define POPT_DEBUGGING	4
#define POPT_KEEPNORM	5
#define POPT_KEEPERR	6
#define POPT_NOINTOPT	7	/* Not settable interactively */
#define POPT_NOARGS		8	/* Not settable interactively */

/* The GUSI options resources */
#define GUSIOPTIONS_ID	10240
#define GUSIOPTIONSOVERRIDE_ID 10241

/* From macgetpath.c: */
void PyMac_PreferenceOptions Py_PROTO((int *inspect, int *verbose, int *suppress_print, 
						 int *unbuffered, int *debugging, int *keep_normal,
						 int *keep_error));

 
