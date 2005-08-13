/* Generator object implementation */

#include "Python.h"
#include "frameobject.h"
#include "genobject.h"
#include "ceval.h"
#include "structmember.h"

static int
gen_traverse(PyGenObject *gen, visitproc visit, void *arg)
{
	return visit((PyObject *)gen->gi_frame, arg);
}

static void
gen_dealloc(PyGenObject *gen)
{
	PyObject *self = (PyObject *) gen;

	_PyObject_GC_UNTRACK(gen);

	if (gen->gi_weakreflist != NULL)
		PyObject_ClearWeakRefs((PyObject *) gen);


	_PyObject_GC_TRACK(self);

	if (gen->gi_frame->f_stacktop!=NULL) {
		/* Generator is paused, so we need to close */
		gen->ob_type->tp_del(self);
		if (self->ob_refcnt > 0)
			return;		/* resurrected.  :( */
	}

	_PyObject_GC_UNTRACK(self);
	Py_XDECREF(gen->gi_frame);
	PyObject_GC_Del(gen);
}


static PyObject *
gen_send_ex(PyGenObject *gen, PyObject *arg, int exc)
{
	PyThreadState *tstate = PyThreadState_GET();
	PyFrameObject *f = gen->gi_frame;
	PyObject *result;

	if (gen->gi_running) {
		PyErr_SetString(PyExc_ValueError,
				"generator already executing");
		return NULL;
	}
	if ((PyObject *)f == Py_None || f->f_stacktop == NULL) {
		/* Only set exception if called from send() */
		if (arg && !exc) PyErr_SetNone(PyExc_StopIteration);
		return NULL;
	}

	if (f->f_lasti == -1) {
		if (arg && arg != Py_None) {
			PyErr_SetString(PyExc_TypeError,
				"can't send non-None value to a just-started generator");
			return NULL;
		}
	} else {
		/* Push arg onto the frame's value stack */
		result = arg ? arg : Py_None;
	        Py_INCREF(result);
	        *(f->f_stacktop++) = result;
	}

	/* Generators always return to their most recent caller, not
	 * necessarily their creator. */
	Py_XINCREF(tstate->frame);
	assert(f->f_back == NULL);
	f->f_back = tstate->frame;

	gen->gi_running = 1;
	result = PyEval_EvalFrameEx(f, exc);
	gen->gi_running = 0;

	/* Don't keep the reference to f_back any longer than necessary.  It
	 * may keep a chain of frames alive or it could create a reference
	 * cycle. */
	assert(f->f_back == tstate->frame);
	Py_CLEAR(f->f_back);

	/* If the generator just returned (as opposed to yielding), signal
	 * that the generator is exhausted. */
	if (result == Py_None && f->f_stacktop == NULL) {
		Py_DECREF(result);
		result = NULL;
		/* Set exception if not called by gen_iternext() */
		if (arg) PyErr_SetNone(PyExc_StopIteration);
	}

	if (!result || f->f_stacktop == NULL) {
		/* generator can't be rerun, so release the frame */
		Py_DECREF(f);
		gen->gi_frame = (PyFrameObject *)Py_None;
		Py_INCREF(Py_None);
	}

	return result;
}

PyDoc_STRVAR(send_doc,
"send(arg) -> send 'arg' into generator, return next yielded value or raise StopIteration.");

static PyObject *
gen_send(PyGenObject *gen, PyObject *arg)
{
	return gen_send_ex(gen, arg, 0);
}

PyDoc_STRVAR(close_doc,
"close(arg) -> raise GeneratorExit inside generator.");

static PyObject *
gen_close(PyGenObject *gen, PyObject *args)
{
	PyObject *retval;
	PyErr_SetNone(PyExc_GeneratorExit);
	retval = gen_send_ex(gen, Py_None, 1);
	if (retval) {
		Py_DECREF(retval);
		PyErr_SetString(PyExc_RuntimeError,
			"generator ignored GeneratorExit");
		return NULL;
	}
	if ( PyErr_ExceptionMatches(PyExc_StopIteration) 
	     || PyErr_ExceptionMatches(PyExc_GeneratorExit) ) 
	{
		PyErr_Clear();	/* ignore these errors */
		Py_INCREF(Py_None);
		return Py_None;
	}
	return NULL;
}

static void
gen_del(PyObject *self)
{
        PyObject *res;
        PyObject *error_type, *error_value, *error_traceback;
	PyGenObject *gen = (PyGenObject *)self;

	if ((PyObject *)gen->gi_frame == Py_None || gen->gi_frame->f_stacktop==NULL)
		/* Generator isn't paused, so no need to close */
		return;

        /* Temporarily resurrect the object. */
        assert(self->ob_refcnt == 0);
        self->ob_refcnt = 1;

        /* Save the current exception, if any. */
        PyErr_Fetch(&error_type, &error_value, &error_traceback);

	res = gen_close((PyGenObject *)self, NULL);

	if (res == NULL)
		PyErr_WriteUnraisable((PyObject *)self);
	else
		Py_DECREF(res);

        /* Restore the saved exception. */
        PyErr_Restore(error_type, error_value, error_traceback);

        /* Undo the temporary resurrection; can't use DECREF here, it would
         * cause a recursive call.
         */
        assert(self->ob_refcnt > 0);
        if (--self->ob_refcnt == 0)
                return; /* this is the normal path out */

        /* close() resurrected it!  Make it look like the original Py_DECREF
         * never happened.
         */
        {
                int refcnt = self->ob_refcnt;
                _Py_NewReference(self);
                self->ob_refcnt = refcnt;
        }
        assert(!PyType_IS_GC(self->ob_type) ||
               _Py_AS_GC(self)->gc.gc_refs != _PyGC_REFS_UNTRACKED);

        /* If Py_REF_DEBUG, _Py_NewReference bumped _Py_RefTotal, so
         * we need to undo that. */
        _Py_DEC_REFTOTAL;
        /* If Py_TRACE_REFS, _Py_NewReference re-added self to the object
         * chain, so no more to do there.
         * If COUNT_ALLOCS, the original decref bumped tp_frees, and
         * _Py_NewReference bumped tp_allocs:  both of those need to be
         * undone.
         */
#ifdef COUNT_ALLOCS
        --self->ob_type->tp_frees;
        --self->ob_type->tp_allocs;
#endif
}



PyDoc_STRVAR(throw_doc,
"throw(typ[,val[,tb]]) -> raise exception in generator, return next yielded value or raise StopIteration.");

static PyObject *
gen_throw(PyGenObject *gen, PyObject *args) 
{
	PyObject *typ;
	PyObject *tb = NULL;
	PyObject *val = NULL;

	if (!PyArg_ParseTuple(args, "O|OO:throw", &typ, &val, &tb))
		return NULL;

	if (tb && !PyTraceBack_Check(tb)) {
		PyErr_SetString(PyExc_TypeError,
			"throw() third argument must be a traceback object");
		return NULL;
	}

	Py_INCREF(typ);
	Py_XINCREF(val);
	Py_XINCREF(tb);

	if (PyClass_Check(typ)) {
		PyErr_NormalizeException(&typ, &val, &tb);
	}

	else if (PyInstance_Check(typ)) {
		/* Raising an instance.  The value should be a dummy. */
		if (val && val != Py_None) {
			PyErr_SetString(PyExc_TypeError,
			  "instance exception may not have a separate value");
			goto failed_throw;
		}
		else {
			/* Normalize to raise <class>, <instance> */
			val = typ;
			typ = (PyObject*) ((PyInstanceObject*)typ)->in_class;
			Py_INCREF(typ);
		}
	}
	else {
		/* Not something you can raise.  You get an exception
		   anyway, just not what you specified :-) */
		PyErr_Format(PyExc_TypeError,
			     "exceptions must be classes, or instances, not %s",
			     typ->ob_type->tp_name);
			goto failed_throw;
	}

	PyErr_Restore(typ,val,tb);
	return gen_send_ex(gen, Py_None, 1);

failed_throw:
	/* Didn't use our arguments, so restore their original refcounts */
	Py_DECREF(typ);
	Py_XDECREF(val);
	Py_XDECREF(tb);
	return NULL;
}


static PyObject *
gen_iternext(PyGenObject *gen)
{
	return gen_send_ex(gen, NULL, 0);
}


static PyMemberDef gen_memberlist[] = {
	{"gi_frame",	T_OBJECT, offsetof(PyGenObject, gi_frame),	RO},
	{"gi_running",	T_INT,    offsetof(PyGenObject, gi_running),	RO},
	{NULL}	/* Sentinel */
};

static PyMethodDef gen_methods[] = {
	{"send",(PyCFunction)gen_send, METH_O, send_doc},
	{"throw",(PyCFunction)gen_throw, METH_VARARGS, throw_doc},
	{"close",(PyCFunction)gen_close, METH_NOARGS, close_doc},
	{NULL, NULL}	/* Sentinel */
};

PyTypeObject PyGen_Type = {
	PyObject_HEAD_INIT(&PyType_Type)
	0,					/* ob_size */
	"generator",				/* tp_name */
	sizeof(PyGenObject),			/* tp_basicsize */
	0,					/* tp_itemsize */
	/* methods */
	(destructor)gen_dealloc, 		/* tp_dealloc */
	0,					/* tp_print */
	0, 					/* tp_getattr */
	0,					/* tp_setattr */
	0,					/* tp_compare */
	0,					/* tp_repr */
	0,					/* tp_as_number */
	0,					/* tp_as_sequence */
	0,					/* tp_as_mapping */
	0,					/* tp_hash */
	0,					/* tp_call */
	0,					/* tp_str */
	PyObject_GenericGetAttr,		/* tp_getattro */
	0,					/* tp_setattro */
	0,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_HAVE_GC,/* tp_flags */
 	0,					/* tp_doc */
 	(traverseproc)gen_traverse,		/* tp_traverse */
 	0,					/* tp_clear */
	0,					/* tp_richcompare */
	offsetof(PyGenObject, gi_weakreflist),	/* tp_weaklistoffset */
	PyObject_SelfIter,			/* tp_iter */
	(iternextfunc)gen_iternext,		/* tp_iternext */
	gen_methods,				/* tp_methods */
	gen_memberlist,				/* tp_members */
	0,					/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
        
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	0,					/* tp_init */
	0,					/* tp_alloc */
	0,					/* tp_new */
	0,					/* tp_free */
	0,					/* tp_is_gc */
	0,					/* tp_bases */
	0,					/* tp_mro */
	0,					/* tp_cache */
	0,					/* tp_subclasses */
	0,					/* tp_weaklist */
	gen_del,				/* tp_del */
};

PyObject *
PyGen_New(PyFrameObject *f)
{
	PyGenObject *gen = PyObject_GC_New(PyGenObject, &PyGen_Type);
	if (gen == NULL) {
		Py_DECREF(f);
		return NULL;
	}
	gen->gi_frame = f;
	gen->gi_running = 0;
	gen->gi_weakreflist = NULL;
	_PyObject_GC_TRACK(gen);
	return (PyObject *)gen;
}
