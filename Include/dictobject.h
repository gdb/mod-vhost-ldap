#ifndef Py_DICTOBJECT_H
#define Py_DICTOBJECT_H
#ifdef __cplusplus
extern "C" {
#endif

/***********************************************************
Copyright (c) 2000, BeOpen.com.
Copyright (c) 1995-2000, Corporation for National Research Initiatives.
Copyright (c) 1990-1995, Stichting Mathematisch Centrum.
All rights reserved.

See the file "Misc/COPYRIGHT" for information on usage and
redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.
******************************************************************/

/* Dictionary object type -- mapping from hashable object to object */

extern DL_IMPORT(PyTypeObject) PyDict_Type;

#define PyDict_Check(op) ((op)->ob_type == &PyDict_Type)

extern DL_IMPORT(PyObject *) PyDict_New(void);
extern DL_IMPORT(PyObject *) PyDict_GetItem(PyObject *mp, PyObject *key);
extern DL_IMPORT(int) PyDict_SetItem(PyObject *mp, PyObject *key, PyObject *item);
extern DL_IMPORT(int) PyDict_DelItem(PyObject *mp, PyObject *key);
extern DL_IMPORT(void) PyDict_Clear(PyObject *mp);
extern DL_IMPORT(int) PyDict_Next
	(PyObject *mp, int *pos, PyObject **key, PyObject **value);
extern DL_IMPORT(PyObject *) PyDict_Keys(PyObject *mp);
extern DL_IMPORT(PyObject *) PyDict_Values(PyObject *mp);
extern DL_IMPORT(PyObject *) PyDict_Items(PyObject *mp);
extern DL_IMPORT(int) PyDict_Size(PyObject *mp);
extern DL_IMPORT(PyObject *) PyDict_Copy(PyObject *mp);


extern DL_IMPORT(PyObject *) PyDict_GetItemString(PyObject *dp, char *key);
extern DL_IMPORT(int) PyDict_SetItemString(PyObject *dp, char *key, PyObject *item);
extern DL_IMPORT(int) PyDict_DelItemString(PyObject *dp, char *key);

#ifdef __cplusplus
}
#endif
#endif /* !Py_DICTOBJECT_H */
