/*
 * C Extension module to test Python interpreter C APIs.
 *
 * The 'test_*' functions exported by this module are run as part of the
 * standard Python regression test, via Lib/test/test_capi.py.
 */

#include "Python.h"

static PyObject *TestError;	/* set to exception object in init */

/* Raise TestError with test_name + ": " + msg, and return NULL. */

static PyObject *
raiseTestError(const char* test_name, const char* msg)
{
	char buf[2048];

	if (strlen(test_name) + strlen(msg) > sizeof(buf) - 50)
		PyErr_SetString(TestError, "internal error msg too large");
	else {
		PyOS_snprintf(buf, sizeof(buf), "%s: %s", test_name, msg);
		PyErr_SetString(TestError, buf);
	}
	return NULL;
}

/* Test #defines from pyconfig.h (particularly the SIZEOF_* defines).

   The ones derived from autoconf on the UNIX-like OSes can be relied
   upon (in the absence of sloppy cross-compiling), but the Windows
   platforms have these hardcoded.  Better safe than sorry.
*/
static PyObject*
sizeof_error(const char* fatname, const char* typename,
        int expected, int got)
{
	char buf[1024];
	PyOS_snprintf(buf, sizeof(buf),
		"%.200s #define == %d but sizeof(%.200s) == %d",
		fatname, expected, typename, got);
	PyErr_SetString(TestError, buf);
	return (PyObject*)NULL;
}

static PyObject*
test_config(PyObject *self)
{
#define CHECK_SIZEOF(FATNAME, TYPE) \
	    if (FATNAME != sizeof(TYPE)) \
    	    	return sizeof_error(#FATNAME, #TYPE, FATNAME, sizeof(TYPE))

	CHECK_SIZEOF(SIZEOF_SHORT, short);
	CHECK_SIZEOF(SIZEOF_INT, int);
	CHECK_SIZEOF(SIZEOF_LONG, long);
	CHECK_SIZEOF(SIZEOF_VOID_P, void*);
	CHECK_SIZEOF(SIZEOF_TIME_T, time_t);
#ifdef HAVE_LONG_LONG
	CHECK_SIZEOF(SIZEOF_LONG_LONG, LONG_LONG);
#endif

#undef CHECK_SIZEOF

	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject*
test_list_api(PyObject *self)
{
	PyObject* list;
	int i;

	/* SF bug 132008:  PyList_Reverse segfaults */
#define NLIST 30
	list = PyList_New(NLIST);
	if (list == (PyObject*)NULL)
		return (PyObject*)NULL;
	/* list = range(NLIST) */
	for (i = 0; i < NLIST; ++i) {
		PyObject* anint = PyInt_FromLong(i);
		if (anint == (PyObject*)NULL) {
			Py_DECREF(list);
			return (PyObject*)NULL;
		}
		PyList_SET_ITEM(list, i, anint);
	}
	/* list.reverse(), via PyList_Reverse() */
	i = PyList_Reverse(list);   /* should not blow up! */
	if (i != 0) {
		Py_DECREF(list);
		return (PyObject*)NULL;
	}
	/* Check that list == range(29, -1, -1) now */
	for (i = 0; i < NLIST; ++i) {
		PyObject* anint = PyList_GET_ITEM(list, i);
		if (PyInt_AS_LONG(anint) != NLIST-1-i) {
			PyErr_SetString(TestError,
			                "test_list_api: reverse screwed up");
			Py_DECREF(list);
			return (PyObject*)NULL;
		}
	}
	Py_DECREF(list);
#undef NLIST

	Py_INCREF(Py_None);
	return Py_None;
}

static int
test_dict_inner(int count)
{
	int pos = 0, iterations = 0, i;
	PyObject *dict = PyDict_New();
	PyObject *v, *k;

	if (dict == NULL)
		return -1;

	for (i = 0; i < count; i++) {
		v = PyInt_FromLong(i);
		PyDict_SetItem(dict, v, v);
		Py_DECREF(v);
	}

	while (PyDict_Next(dict, &pos, &k, &v)) {
		PyObject *o;
		iterations++;

		i = PyInt_AS_LONG(v) + 1;
		o = PyInt_FromLong(i);
		if (o == NULL)
			return -1;
		if (PyDict_SetItem(dict, k, o) < 0) {
			Py_DECREF(o);
			return -1;
		}
		Py_DECREF(o);
	}

	Py_DECREF(dict);

	if (iterations != count) {
		PyErr_SetString(
			TestError,
			"test_dict_iteration: dict iteration went wrong ");
		return -1;
	} else {
		return 0;
	}
}

static PyObject*
test_dict_iteration(PyObject* self)
{
	int i;

	for (i = 0; i < 200; i++) {
		if (test_dict_inner(i) < 0) {
			return NULL;
		}
	}

	Py_INCREF(Py_None);
	return Py_None;
}


/* Tests of PyLong_{As, From}{Unsigned,}Long(), and (#ifdef HAVE_LONG_LONG)
   PyLong_{As, From}{Unsigned,}LongLong().

   Note that the meat of the test is contained in testcapi_long.h.
   This is revolting, but delicate code duplication is worse:  "almost
   exactly the same" code is needed to test LONG_LONG, but the ubiquitous
   dependence on type names makes it impossible to use a parameterized
   function.  A giant macro would be even worse than this.  A C++ template
   would be perfect.

   The "report an error" functions are deliberately not part of the #include
   file:  if the test fails, you can set a breakpoint in the appropriate
   error function directly, and crawl back from there in the debugger.
*/

#define UNBIND(X)  Py_DECREF(X); (X) = NULL

static PyObject *
raise_test_long_error(const char* msg)
{
	return raiseTestError("test_long_api", msg);
}

#define TESTNAME	test_long_api_inner
#define TYPENAME	long
#define F_S_TO_PY	PyLong_FromLong
#define F_PY_TO_S	PyLong_AsLong
#define F_U_TO_PY	PyLong_FromUnsignedLong
#define F_PY_TO_U	PyLong_AsUnsignedLong

#include "testcapi_long.h"

static PyObject *
test_long_api(PyObject* self)
{
	return TESTNAME(raise_test_long_error);
}

#undef TESTNAME
#undef TYPENAME
#undef F_S_TO_PY
#undef F_PY_TO_S
#undef F_U_TO_PY
#undef F_PY_TO_U

#ifdef HAVE_LONG_LONG

static PyObject *
raise_test_longlong_error(const char* msg)
{
	return raiseTestError("test_longlong_api", msg);
}

#define TESTNAME	test_longlong_api_inner
#define TYPENAME	LONG_LONG
#define F_S_TO_PY	PyLong_FromLongLong
#define F_PY_TO_S	PyLong_AsLongLong
#define F_U_TO_PY	PyLong_FromUnsignedLongLong
#define F_PY_TO_U	PyLong_AsUnsignedLongLong

#include "testcapi_long.h"

static PyObject *
test_longlong_api(PyObject* self)
{
	return TESTNAME(raise_test_longlong_error);
}

#undef TESTNAME
#undef TYPENAME
#undef F_S_TO_PY
#undef F_PY_TO_S
#undef F_U_TO_PY
#undef F_PY_TO_U

/* Test the L code for PyArg_ParseTuple.  This should deliver a LONG_LONG
   for both long and int arguments.  The test may leak a little memory if
   it fails.
*/
static PyObject *
test_L_code(PyObject *self)
{
	PyObject *tuple, *num;
	LONG_LONG value;

        tuple = PyTuple_New(1);
        if (tuple == NULL)
        	return NULL;

        num = PyLong_FromLong(42);
        if (num == NULL)
        	return NULL;

        PyTuple_SET_ITEM(tuple, 0, num);

        value = -1;
        if (PyArg_ParseTuple(tuple, "L:test_L_code", &value) < 0)
        	return NULL;
        if (value != 42)
        	return raiseTestError("test_L_code",
			"L code returned wrong value for long 42");

	Py_DECREF(num);
        num = PyInt_FromLong(42);
        if (num == NULL)
        	return NULL;

        PyTuple_SET_ITEM(tuple, 0, num);

	value = -1;
        if (PyArg_ParseTuple(tuple, "L:test_L_code", &value) < 0)
        	return NULL;
        if (value != 42)
        	return raiseTestError("test_L_code",
			"L code returned wrong value for int 42");

	Py_DECREF(tuple);
	Py_INCREF(Py_None);
	return Py_None;
}

#endif	/* ifdef HAVE_LONG_LONG */

#ifdef Py_USING_UNICODE

/* Test the u and u# codes for PyArg_ParseTuple. May leak memory in case
   of an error.
*/
static PyObject *
test_u_code(PyObject *self)
{
	PyObject *tuple, *obj;
	Py_UNICODE *value;
	int len;

        tuple = PyTuple_New(1);
        if (tuple == NULL)
        	return NULL;

        obj = PyUnicode_Decode("test", strlen("test"),
			       "ascii", NULL);
        if (obj == NULL)
        	return NULL;

        PyTuple_SET_ITEM(tuple, 0, obj);

        value = 0;
        if (PyArg_ParseTuple(tuple, "u:test_u_code", &value) < 0)
        	return NULL;
        if (value != PyUnicode_AS_UNICODE(obj))
        	return raiseTestError("test_u_code",
			"u code returned wrong value for u'test'");
        value = 0;
        if (PyArg_ParseTuple(tuple, "u#:test_u_code", &value, &len) < 0)
        	return NULL;
        if (value != PyUnicode_AS_UNICODE(obj) ||
	    len != PyUnicode_GET_SIZE(obj))
        	return raiseTestError("test_u_code",
			"u# code returned wrong values for u'test'");

	Py_DECREF(tuple);
	Py_INCREF(Py_None);
	return Py_None;
}

#endif

/* Simple test of _PyLong_NumBits and _PyLong_Sign. */
static PyObject *
test_long_numbits(PyObject *self)
{
	struct triple {
		long input;
		size_t nbits;
		int sign;
	} testcases[] = {{0, 0, 0},
			 {1L, 1, 1},
			 {-1L, 1, -1},
			 {2L, 2, 1},
			 {-2L, 2, -1},
			 {3L, 2, 1},
			 {-3L, 2, -1},
			 {4L, 3, 1},
			 {-4L, 3, -1},
			 {0x7fffL, 15, 1},	/* one Python long digit */
			 {-0x7fffL, 15, -1},
			 {0xffffL, 16, 1},
			 {-0xffffL, 16, -1},
			 {0xfffffffL, 28, 1},
			 {-0xfffffffL, 28, -1}};
	int i;

	for (i = 0; i < sizeof(testcases) / sizeof(struct triple); ++i) {
		PyObject *plong = PyLong_FromLong(testcases[i].input);
		size_t nbits = _PyLong_NumBits(plong);
		int sign = _PyLong_Sign(plong);

		Py_DECREF(plong);
		if (nbits != testcases[i].nbits)
			return raiseTestError("test_long_numbits",
					"wrong result for _PyLong_NumBits");
		if (sign != testcases[i].sign)
			return raiseTestError("test_long_numbits",
					"wrong result for _PyLong_Sign");
	}
	Py_INCREF(Py_None);
	return Py_None;
}

static PyObject *
raise_exception(PyObject *self, PyObject *args)
{
	PyObject *exc;
	PyObject *exc_args, *v;
	int num_args, i;

	if (!PyArg_ParseTuple(args, "Oi:raise_exception",
			      &exc, &num_args))
		return NULL;

	exc_args = PyTuple_New(num_args);
	if (exc_args == NULL)
		return NULL;
	for (i = 0; i < num_args; ++i) {
		v = PyInt_FromLong(i);
		if (v == NULL) {
			Py_DECREF(exc_args);
			return NULL;
		}
		PyTuple_SET_ITEM(exc_args, i, v);
	}
	PyErr_SetObject(exc, exc_args);
	return NULL;
}

static PyMethodDef TestMethods[] = {
	{"raise_exception",	raise_exception,		 METH_VARARGS},
	{"test_config",		(PyCFunction)test_config,	 METH_NOARGS},
	{"test_list_api",	(PyCFunction)test_list_api,	 METH_NOARGS},
	{"test_dict_iteration",	(PyCFunction)test_dict_iteration,METH_NOARGS},
	{"test_long_api",	(PyCFunction)test_long_api,	 METH_NOARGS},
	{"test_long_numbits",	(PyCFunction)test_long_numbits,	 METH_NOARGS},
#ifdef HAVE_LONG_LONG
	{"test_longlong_api",	(PyCFunction)test_longlong_api,	 METH_NOARGS},
	{"test_L_code",		(PyCFunction)test_L_code,	 METH_NOARGS},
#endif
#ifdef Py_USING_UNICODE
	{"test_u_code",		(PyCFunction)test_u_code,	 METH_NOARGS},
#endif
	{NULL, NULL} /* sentinel */
};

PyMODINIT_FUNC
init_testcapi(void)
{
	PyObject *m;

	m = Py_InitModule("_testcapi", TestMethods);

	TestError = PyErr_NewException("_testcapi.error", NULL, NULL);
	Py_INCREF(TestError);
	PyModule_AddObject(m, "error", TestError);
}
