/***********************************************************
Copyright (c) 2000, BeOpen.com.
Copyright (c) 1995-2000, Corporation for National Research Initiatives.
Copyright (c) 1990-1995, Stichting Mathematisch Centrum.
All rights reserved.

See the file "Misc/COPYRIGHT" for information on usage and
redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.
******************************************************************/

/* Interface to execute compiled code */

#ifndef Py_EVAL_H
#define Py_EVAL_H
#ifdef __cplusplus
extern "C" {
#endif

DL_IMPORT(PyObject *) PyEval_EvalCode(PyCodeObject *, PyObject *, PyObject *);

#ifdef __cplusplus
}
#endif
#endif /* !Py_EVAL_H */
