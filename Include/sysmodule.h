/***********************************************************
Copyright (c) 2000, BeOpen.com.
Copyright (c) 1995-2000, Corporation for National Research Initiatives.
Copyright (c) 1990-1995, Stichting Mathematisch Centrum.
All rights reserved.

See the file "Misc/COPYRIGHT" for information on usage and
redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.
******************************************************************/

/* System module interface */

#ifndef Py_SYSMODULE_H
#define Py_SYSMODULE_H
#ifdef __cplusplus
extern "C" {
#endif

DL_IMPORT(PyObject *) PySys_GetObject(char *);
DL_IMPORT(int) PySys_SetObject(char *, PyObject *);
DL_IMPORT(FILE *) PySys_GetFile(char *, FILE *);
DL_IMPORT(void) PySys_SetArgv(int, char **);
DL_IMPORT(void) PySys_SetPath(char *);

#ifdef HAVE_STDARG_PROTOTYPES
DL_IMPORT(void) PySys_WriteStdout(const char *format, ...);
DL_IMPORT(void) PySys_WriteStderr(const char *format, ...);
#else
/* Better to have no prototypes at all for varargs functions in this case */
DL_IMPORT(void) PySys_WriteStdout();
DL_IMPORT(void) PySys_WriteStderr();
#endif

extern DL_IMPORT(PyObject *) _PySys_TraceFunc, *_PySys_ProfileFunc;
extern DL_IMPORT(int) _PySys_CheckInterval;

#ifdef __cplusplus
}
#endif
#endif /* !Py_SYSMODULE_H */
