/* Iterator objects */

#include "Python.h"

typedef struct {
	PyObject_HEAD
	long      it_index;
	PyObject *it_seq;
} iterobject;

PyObject *
PyIter_New(PyObject *seq)
{
	iterobject *it;
	it = PyObject_NEW(iterobject, &PyIter_Type);
	if (it == NULL)
		return NULL;
	it->it_index = 0;
	Py_INCREF(seq);
	it->it_seq = seq;
	return (PyObject *)it;
}
static void
iter_dealloc(iterobject *it)
{
	Py_DECREF(it->it_seq);
	PyObject_DEL(it);
}

static PyObject *
iter_next(iterobject *it, PyObject *args)
{
	PyObject *seq = it->it_seq;

	if (PyList_Check(seq)) {
		PyObject *item;
		if (it->it_index >= PyList_GET_SIZE(seq)) {
			PyErr_SetObject(PyExc_StopIteration, Py_None);
			return NULL;
		}
		item = PyList_GET_ITEM(seq, it->it_index);
		it->it_index++;
		Py_INCREF(item);
		return item;
	}
	else {
		PyObject *result = PySequence_GetItem(seq, it->it_index++);
		if (result == NULL &&
		    PyErr_ExceptionMatches(PyExc_IndexError))
			PyErr_SetObject(PyExc_StopIteration, Py_None);
		return result;
	}
}

static PyObject *
iter_getiter(PyObject *it)
{
	Py_INCREF(it);
	return it;
}

static PyMethodDef iter_methods[] = {
	{"next",	(PyCFunction)iter_next,	METH_VARARGS,
	 "it.next() -- get the next value, or raise StopIteration"},
	{NULL,		NULL}		/* sentinel */
};

static PyObject *
iter_getattr(iterobject *it, char *name)
{
	return Py_FindMethod(iter_methods, (PyObject *)it, name);
}

PyTypeObject PyIter_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,					/* ob_size */
	"iterator",				/* tp_name */
	sizeof(iterobject),			/* tp_basicsize */
	0,					/* tp_itemsize */
	/* methods */
	(destructor)iter_dealloc, 		/* tp_dealloc */
	0,					/* tp_print */
	(getattrfunc)iter_getattr,		/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	0,					/* tp_repr */
	0,					/* tp_as_number */
	0,					/* tp_as_sequence */
	0,					/* tp_as_mapping */
	0,					/* tp_hash */
	0,					/* tp_call */
	0,					/* tp_str */
	0,					/* tp_getattro */
	0,					/* tp_setattro */
	0,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
 	0,					/* tp_doc */
 	0,					/* tp_traverse */
 	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	(getiterfunc)iter_getiter,		/* tp_iter */
};

/* -------------------------------------- */

typedef struct {
	PyObject_HEAD
	PyObject *it_callable;
	PyObject *it_sentinel;
} calliterobject;

PyObject *
PyCallIter_New(PyObject *callable, PyObject *sentinel)
{
	calliterobject *it;
	it = PyObject_NEW(calliterobject, &PyCallIter_Type);
	if (it == NULL)
		return NULL;
	Py_INCREF(callable);
	it->it_callable = callable;
	Py_INCREF(sentinel);
	it->it_sentinel = sentinel;
	return (PyObject *)it;
}
static void
calliter_dealloc(calliterobject *it)
{
	Py_DECREF(it->it_callable);
	Py_DECREF(it->it_sentinel);
	PyObject_DEL(it);
}
static PyObject *
calliter_next(calliterobject *it, PyObject *args)
{
	PyObject *result = PyObject_CallObject(it->it_callable, NULL);
	if (result != NULL) {
		if (PyObject_RichCompareBool(result, it->it_sentinel, Py_EQ)) {
			PyErr_SetObject(PyExc_StopIteration, Py_None);
			Py_DECREF(result);
			result = NULL;
		}
	}
	return result;
}

static PyMethodDef calliter_methods[] = {
	{"next",	(PyCFunction)calliter_next,	METH_VARARGS,
	 "it.next() -- get the next value, or raise StopIteration"},
	{NULL,		NULL}		/* sentinel */
};

static PyObject *
calliter_getattr(calliterobject *it, char *name)
{
	return Py_FindMethod(calliter_methods, (PyObject *)it, name);
}

PyTypeObject PyCallIter_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,					/* ob_size */
	"callable-iterator",			/* tp_name */
	sizeof(calliterobject),			/* tp_basicsize */
	0,					/* tp_itemsize */
	/* methods */
	(destructor)calliter_dealloc, 		/* tp_dealloc */
	0,					/* tp_print */
	(getattrfunc)calliter_getattr,		/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	0,					/* tp_repr */
	0,					/* tp_as_number */
	0,					/* tp_as_sequence */
	0,					/* tp_as_mapping */
	0,					/* tp_hash */
	0,					/* tp_call */
	0,					/* tp_str */
	0,					/* tp_getattro */
	0,					/* tp_setattro */
	0,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT,			/* tp_flags */
 	0,					/* tp_doc */
 	0,					/* tp_traverse */
 	0,					/* tp_clear */
	0,					/* tp_richcompare */
	0,					/* tp_weaklistoffset */
	(getiterfunc)iter_getiter,		/* tp_iter */
};
