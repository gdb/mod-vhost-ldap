
/* Interfaces to parse and execute pieces of python code */

#ifndef Py_PYTHONRUN_H
#define Py_PYTHONRUN_H
#ifdef __cplusplus
extern "C" {
#endif

#define PyCF_MASK (CO_FUTURE_DIVISION)
#define PyCF_MASK_OBSOLETE (CO_GENERATOR_ALLOWED | CO_NESTED)

typedef struct {
	int cf_flags;  /* bitmask of CO_xxx flags relevant to future */
} PyCompilerFlags;

DL_IMPORT(void) Py_SetProgramName(char *);
DL_IMPORT(char *) Py_GetProgramName(void);

DL_IMPORT(void) Py_SetPythonHome(char *);
DL_IMPORT(char *) Py_GetPythonHome(void);

DL_IMPORT(void) Py_Initialize(void);
DL_IMPORT(void) Py_Finalize(void);
DL_IMPORT(int) Py_IsInitialized(void);
DL_IMPORT(PyThreadState *) Py_NewInterpreter(void);
DL_IMPORT(void) Py_EndInterpreter(PyThreadState *);

DL_IMPORT(int) PyRun_AnyFile(FILE *, char *);
DL_IMPORT(int) PyRun_AnyFileEx(FILE *, char *, int);

DL_IMPORT(int) PyRun_AnyFileFlags(FILE *, char *, PyCompilerFlags *);
DL_IMPORT(int) PyRun_AnyFileExFlags(FILE *, char *, int, PyCompilerFlags *);

DL_IMPORT(int) PyRun_SimpleString(char *);
DL_IMPORT(int) PyRun_SimpleStringFlags(char *, PyCompilerFlags *);
DL_IMPORT(int) PyRun_SimpleFile(FILE *, char *);
DL_IMPORT(int) PyRun_SimpleFileEx(FILE *, char *, int);
DL_IMPORT(int) PyRun_SimpleFileExFlags(FILE *, char *, int, PyCompilerFlags *);
DL_IMPORT(int) PyRun_InteractiveOne(FILE *, char *);
DL_IMPORT(int) PyRun_InteractiveOneFlags(FILE *, char *, PyCompilerFlags *);
DL_IMPORT(int) PyRun_InteractiveLoop(FILE *, char *);
DL_IMPORT(int) PyRun_InteractiveLoopFlags(FILE *, char *, PyCompilerFlags *);

DL_IMPORT(struct _node *) PyParser_SimpleParseString(char *, int);
DL_IMPORT(struct _node *) PyParser_SimpleParseFile(FILE *, char *, int);
DL_IMPORT(struct _node *) PyParser_SimpleParseStringFlags(char *, int, int);
DL_IMPORT(struct _node *) PyParser_SimpleParseStringFlagsFilename(char *,
								  char *,
								  int,
								  int);
DL_IMPORT(struct _node *) PyParser_SimpleParseFileFlags(FILE *, char *,
							int, int);

DL_IMPORT(PyObject *) PyRun_String(char *, int, PyObject *, PyObject *);
DL_IMPORT(PyObject *) PyRun_File(FILE *, char *, int, PyObject *, PyObject *);
DL_IMPORT(PyObject *) PyRun_FileEx(FILE *, char *, int,
				   PyObject *, PyObject *, int);
DL_IMPORT(PyObject *) PyRun_StringFlags(char *, int, PyObject *, PyObject *,
					PyCompilerFlags *);
DL_IMPORT(PyObject *) PyRun_FileFlags(FILE *, char *, int, PyObject *, 
				      PyObject *, PyCompilerFlags *);
DL_IMPORT(PyObject *) PyRun_FileExFlags(FILE *, char *, int, PyObject *, 
					PyObject *, int, PyCompilerFlags *);

DL_IMPORT(PyObject *) Py_CompileString(char *, char *, int);
DL_IMPORT(PyObject *) Py_CompileStringFlags(char *, char *, int,
					    PyCompilerFlags *);
DL_IMPORT(struct symtable *) Py_SymtableString(char *, char *, int);

DL_IMPORT(void) PyErr_Print(void);
DL_IMPORT(void) PyErr_PrintEx(int);
DL_IMPORT(void) PyErr_Display(PyObject *, PyObject *, PyObject *);

DL_IMPORT(int) Py_AtExit(void (*func)(void));

DL_IMPORT(void) Py_Exit(int);

DL_IMPORT(int) Py_FdIsInteractive(FILE *, char *);

/* Bootstrap */
PyAPI_FUNC(int) Py_Main(int argc, char **argv);

/* In getpath.c */
PyAPI_FUNC(char *) Py_GetProgramFullPath(void);
PyAPI_FUNC(char *) Py_GetPrefix(void);
PyAPI_FUNC(char *) Py_GetExecPrefix(void);
PyAPI_FUNC(char *) Py_GetPath(void);

/* In their own files */
PyAPI_FUNC(const char *) Py_GetVersion(void);
PyAPI_FUNC(const char *) Py_GetPlatform(void);
PyAPI_FUNC(const char *) Py_GetCopyright(void);
PyAPI_FUNC(const char *) Py_GetCompiler(void);
PyAPI_FUNC(const char *) Py_GetBuildInfo(void);

/* Internal -- various one-time initializations */
DL_IMPORT(PyObject *) _PyBuiltin_Init(void);
DL_IMPORT(PyObject *) _PySys_Init(void);
DL_IMPORT(void) _PyImport_Init(void);
PyAPI_FUNC(void) _PyExc_Init(void);

/* Various internal finalizers */
PyAPI_FUNC(void) _PyExc_Fini(void);
PyAPI_FUNC(void) _PyImport_Fini(void);
PyAPI_FUNC(void) PyMethod_Fini(void);
PyAPI_FUNC(void) PyFrame_Fini(void);
PyAPI_FUNC(void) PyCFunction_Fini(void);
PyAPI_FUNC(void) PyTuple_Fini(void);
PyAPI_FUNC(void) PyString_Fini(void);
PyAPI_FUNC(void) PyInt_Fini(void);
PyAPI_FUNC(void) PyFloat_Fini(void);
PyAPI_FUNC(void) PyOS_FiniInterrupts(void);

/* Stuff with no proper home (yet) */
DL_IMPORT(char *) PyOS_Readline(char *);
extern DL_IMPORT(int) (*PyOS_InputHook)(void);
extern DL_IMPORT(char) *(*PyOS_ReadlineFunctionPointer)(char *);

/* Stack size, in "pointers" (so we get extra safety margins
   on 64-bit platforms).  On a 32-bit platform, this translates
   to a 8k margin. */
#define PYOS_STACK_MARGIN 2048

#if defined(WIN32) && !defined(MS_WIN64) && defined(_MSC_VER)
/* Enable stack checking under Microsoft C */
#define USE_STACKCHECK
#endif

#ifdef USE_STACKCHECK
/* Check that we aren't overflowing our stack */
DL_IMPORT(int) PyOS_CheckStack(void);
#endif

/* Signals */
typedef void (*PyOS_sighandler_t)(int);
DL_IMPORT(PyOS_sighandler_t) PyOS_getsig(int);
DL_IMPORT(PyOS_sighandler_t) PyOS_setsig(int, PyOS_sighandler_t);


#ifdef __cplusplus
}
#endif
#endif /* !Py_PYTHONRUN_H */
