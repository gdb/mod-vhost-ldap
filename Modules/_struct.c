/* struct module -- pack values into and (out of) strings */

/* New version supporting byte order, alignment and size options,
   character strings, and unsigned numbers */

#include "Python.h"
#include "structseq.h"
#include "structmember.h"
#include <ctype.h>

static PyTypeObject PyStructType;

/* compatibility macros */
#if (PY_VERSION_HEX < 0x02050000)
typedef int Py_ssize_t;
#endif

/* PY_USE_INT_WHEN_POSSIBLE is an experimental flag that changes the 
   struct API to return int instead of long when possible. This is
   often a significant performance improvement. */
/*
#define PY_USE_INT_WHEN_POSSIBLE 1
*/


/* The translation function for each format character is table driven */

typedef struct _formatdef {
	char format;
	int size;
	int alignment;
	PyObject* (*unpack)(const char *,
			    const struct _formatdef *);
	int (*pack)(char *, PyObject *,
		    const struct _formatdef *);
} formatdef;

typedef struct _formatcode {
	const struct _formatdef *fmtdef;
	int offset;
	int size;
} formatcode;

/* Struct object interface */

typedef struct {
	PyObject_HEAD
	int s_size;
	int s_len;
	formatcode *s_codes;
	PyObject *s_format;
	PyObject *weakreflist; /* List of weak references */
} PyStructObject;


#define PyStruct_Check(op) PyObject_TypeCheck(op, &PyStructType)
#define PyStruct_CheckExact(op) ((op)->ob_type == &PyStructType)


/* Exception */

static PyObject *StructError;


/* Define various structs to figure out the alignments of types */


typedef struct { char c; short x; } st_short;
typedef struct { char c; int x; } st_int;
typedef struct { char c; long x; } st_long;
typedef struct { char c; float x; } st_float;
typedef struct { char c; double x; } st_double;
typedef struct { char c; void *x; } st_void_p;

#define SHORT_ALIGN (sizeof(st_short) - sizeof(short))
#define INT_ALIGN (sizeof(st_int) - sizeof(int))
#define LONG_ALIGN (sizeof(st_long) - sizeof(long))
#define FLOAT_ALIGN (sizeof(st_float) - sizeof(float))
#define DOUBLE_ALIGN (sizeof(st_double) - sizeof(double))
#define VOID_P_ALIGN (sizeof(st_void_p) - sizeof(void *))

/* We can't support q and Q in native mode unless the compiler does;
   in std mode, they're 8 bytes on all platforms. */
#ifdef HAVE_LONG_LONG
typedef struct { char c; PY_LONG_LONG x; } s_long_long;
#define LONG_LONG_ALIGN (sizeof(s_long_long) - sizeof(PY_LONG_LONG))
#endif

#define STRINGIFY(x)    #x

#ifdef __powerc
#pragma options align=reset
#endif

/* Helper to get a PyLongObject by hook or by crook.  Caller should decref. */

static PyObject *
get_pylong(PyObject *v)
{
	PyNumberMethods *m;

	assert(v != NULL);
	if (PyInt_Check(v))
		return PyLong_FromLong(PyInt_AS_LONG(v));
	if (PyLong_Check(v)) {
		Py_INCREF(v);
		return v;
	}
	m = v->ob_type->tp_as_number;
	if (m != NULL && m->nb_long != NULL) {
		v = m->nb_long(v);
		if (v == NULL)
			return NULL;
		if (PyLong_Check(v))
			return v;
		Py_DECREF(v);
	}
	PyErr_SetString(StructError,
			"cannot convert argument to long");
	return NULL;
}

/* Helper routine to get a Python integer and raise the appropriate error
   if it isn't one */

static int
get_long(PyObject *v, long *p)
{
	long x = PyInt_AsLong(v);
	if (x == -1 && PyErr_Occurred()) {
		if (PyErr_ExceptionMatches(PyExc_TypeError))
			PyErr_SetString(StructError,
					"required argument is not an integer");
		return -1;
	}
	*p = x;
	return 0;
}


/* Same, but handling unsigned long */

static int
get_ulong(PyObject *v, unsigned long *p)
{
	if (PyLong_Check(v)) {
		unsigned long x = PyLong_AsUnsignedLong(v);
		if (x == (unsigned long)(-1) && PyErr_Occurred())
			return -1;
		*p = x;
		return 0;
	}
	else {
		return get_long(v, (long *)p);
	}
}

#ifdef HAVE_LONG_LONG

/* Same, but handling native long long. */

static int
get_longlong(PyObject *v, PY_LONG_LONG *p)
{
	PY_LONG_LONG x;

	v = get_pylong(v);
	if (v == NULL)
		return -1;
	assert(PyLong_Check(v));
	x = PyLong_AsLongLong(v);
	Py_DECREF(v);
	if (x == (PY_LONG_LONG)-1 && PyErr_Occurred())
		return -1;
	*p = x;
	return 0;
}

/* Same, but handling native unsigned long long. */

static int
get_ulonglong(PyObject *v, unsigned PY_LONG_LONG *p)
{
	unsigned PY_LONG_LONG x;

	v = get_pylong(v);
	if (v == NULL)
		return -1;
	assert(PyLong_Check(v));
	x = PyLong_AsUnsignedLongLong(v);
	Py_DECREF(v);
	if (x == (unsigned PY_LONG_LONG)-1 && PyErr_Occurred())
		return -1;
	*p = x;
	return 0;
}

#endif

/* Floating point helpers */

static PyObject *
unpack_float(const char *p,  /* start of 4-byte string */
             int le)	     /* true for little-endian, false for big-endian */
{
	double x;

	x = _PyFloat_Unpack4((unsigned char *)p, le);
	if (x == -1.0 && PyErr_Occurred())
		return NULL;
	return PyFloat_FromDouble(x);
}

static PyObject *
unpack_double(const char *p,  /* start of 8-byte string */
              int le)         /* true for little-endian, false for big-endian */
{
	double x;

	x = _PyFloat_Unpack8((unsigned char *)p, le);
	if (x == -1.0 && PyErr_Occurred())
		return NULL;
	return PyFloat_FromDouble(x);
}


/* A large number of small routines follow, with names of the form

	[bln][up]_TYPE

   [bln] distiguishes among big-endian, little-endian and native.
   [pu] distiguishes between pack (to struct) and unpack (from struct).
   TYPE is one of char, byte, ubyte, etc.
*/

/* Native mode routines. ****************************************************/
/* NOTE:
   In all n[up]_<type> routines handling types larger than 1 byte, there is
   *no* guarantee that the p pointer is properly aligned for each type,
   therefore memcpy is called.  An intermediate variable is used to
   compensate for big-endian architectures.
   Normally both the intermediate variable and the memcpy call will be
   skipped by C optimisation in little-endian architectures (gcc >= 2.91
   does this). */

static PyObject *
nu_char(const char *p, const formatdef *f)
{
	return PyString_FromStringAndSize(p, 1);
}

static PyObject *
nu_byte(const char *p, const formatdef *f)
{
	return PyInt_FromLong((long) *(signed char *)p);
}

static PyObject *
nu_ubyte(const char *p, const formatdef *f)
{
	return PyInt_FromLong((long) *(unsigned char *)p);
}

static PyObject *
nu_short(const char *p, const formatdef *f)
{
	short x;
	memcpy((char *)&x, p, sizeof x);
	return PyInt_FromLong((long)x);
}

static PyObject *
nu_ushort(const char *p, const formatdef *f)
{
	unsigned short x;
	memcpy((char *)&x, p, sizeof x);
	return PyInt_FromLong((long)x);
}

static PyObject *
nu_int(const char *p, const formatdef *f)
{
	int x;
	memcpy((char *)&x, p, sizeof x);
	return PyInt_FromLong((long)x);
}

static PyObject *
nu_uint(const char *p, const formatdef *f)
{
	unsigned int x;
	memcpy((char *)&x, p, sizeof x);
#ifdef PY_USE_INT_WHEN_POSSIBLE
	if (x <= INT_MAX)
		return PyInt_FromLong((long)x);
#endif
	return PyLong_FromUnsignedLong((unsigned long)x);
}

static PyObject *
nu_long(const char *p, const formatdef *f)
{
	long x;
	memcpy((char *)&x, p, sizeof x);
	return PyInt_FromLong(x);
}

static PyObject *
nu_ulong(const char *p, const formatdef *f)
{
	unsigned long x;
	memcpy((char *)&x, p, sizeof x);
#ifdef PY_USE_INT_WHEN_POSSIBLE
	if (x <= INT_MAX)
		return PyInt_FromLong((long)x);
#endif
	return PyLong_FromUnsignedLong(x);
}

/* Native mode doesn't support q or Q unless the platform C supports
   long long (or, on Windows, __int64). */

#ifdef HAVE_LONG_LONG

static PyObject *
nu_longlong(const char *p, const formatdef *f)
{
	PY_LONG_LONG x;
	memcpy((char *)&x, p, sizeof x);
#ifdef PY_USE_INT_WHEN_POSSIBLE
	if (x >= INT_MIN && x <= INT_MAX)
		return PyInt_FromLong(Py_SAFE_DOWNCAST(x, PY_LONG_LONG, long));
#endif
	return PyLong_FromLongLong(x);
}

static PyObject *
nu_ulonglong(const char *p, const formatdef *f)
{
	unsigned PY_LONG_LONG x;
	memcpy((char *)&x, p, sizeof x);
#ifdef PY_USE_INT_WHEN_POSSIBLE
	if (x <= INT_MAX)
		return PyInt_FromLong(Py_SAFE_DOWNCAST(x, unsigned PY_LONG_LONG, long));
#endif
	return PyLong_FromUnsignedLongLong(x);
}

#endif

static PyObject *
nu_float(const char *p, const formatdef *f)
{
	float x;
	memcpy((char *)&x, p, sizeof x);
	return PyFloat_FromDouble((double)x);
}

static PyObject *
nu_double(const char *p, const formatdef *f)
{
	double x;
	memcpy((char *)&x, p, sizeof x);
	return PyFloat_FromDouble(x);
}

static PyObject *
nu_void_p(const char *p, const formatdef *f)
{
	void *x;
	memcpy((char *)&x, p, sizeof x);
	return PyLong_FromVoidPtr(x);
}

static int
np_byte(char *p, PyObject *v, const formatdef *f)
{
	long x;
	if (get_long(v, &x) < 0)
		return -1;
	if (x < -128 || x > 127){
		PyErr_SetString(StructError,
				"byte format requires -128<=number<=127");
		return -1;
	}
	*p = (char)x;
	return 0;
}

static int
np_ubyte(char *p, PyObject *v, const formatdef *f)
{
	long x;
	if (get_long(v, &x) < 0)
		return -1;
	if (x < 0 || x > 255){
		PyErr_SetString(StructError,
				"ubyte format requires 0<=number<=255");
		return -1;
	}
	*p = (char)x;
	return 0;
}

static int
np_char(char *p, PyObject *v, const formatdef *f)
{
	if (!PyString_Check(v) || PyString_Size(v) != 1) {
		PyErr_SetString(StructError,
				"char format require string of length 1");
		return -1;
	}
	*p = *PyString_AsString(v);
	return 0;
}

static int
np_short(char *p, PyObject *v, const formatdef *f)
{
	long x;
	short y;
	if (get_long(v, &x) < 0)
		return -1;
	if (x < SHRT_MIN || x > SHRT_MAX){
		PyErr_SetString(StructError,
				"short format requires " STRINGIFY(SHRT_MIN)
				"<=number<=" STRINGIFY(SHRT_MAX));
		return -1;
	}
	y = (short)x;
	memcpy(p, (char *)&y, sizeof y);
	return 0;
}

static int
np_ushort(char *p, PyObject *v, const formatdef *f)
{
	long x;
	unsigned short y;
	if (get_long(v, &x) < 0)
		return -1;
	if (x < 0 || x > USHRT_MAX){
		PyErr_SetString(StructError,
				"short format requires 0<=number<=" STRINGIFY(USHRT_MAX));
		return -1;
	}
	y = (unsigned short)x;
	memcpy(p, (char *)&y, sizeof y);
	return 0;
}

static int
np_int(char *p, PyObject *v, const formatdef *f)
{
	long x;
	int y;
	if (get_long(v, &x) < 0)
		return -1;
	y = (int)x;
	memcpy(p, (char *)&y, sizeof y);
	return 0;
}

static int
np_uint(char *p, PyObject *v, const formatdef *f)
{
	unsigned long x;
	unsigned int y;
	if (get_ulong(v, &x) < 0)
		return -1;
	y = (unsigned int)x;
	memcpy(p, (char *)&y, sizeof y);
	return 0;
}

static int
np_long(char *p, PyObject *v, const formatdef *f)
{
	long x;
	if (get_long(v, &x) < 0)
		return -1;
	memcpy(p, (char *)&x, sizeof x);
	return 0;
}

static int
np_ulong(char *p, PyObject *v, const formatdef *f)
{
	unsigned long x;
	if (get_ulong(v, &x) < 0)
		return -1;
	memcpy(p, (char *)&x, sizeof x);
	return 0;
}

#ifdef HAVE_LONG_LONG

static int
np_longlong(char *p, PyObject *v, const formatdef *f)
{
	PY_LONG_LONG x;
	if (get_longlong(v, &x) < 0)
		return -1;
	memcpy(p, (char *)&x, sizeof x);
	return 0;
}

static int
np_ulonglong(char *p, PyObject *v, const formatdef *f)
{
	unsigned PY_LONG_LONG x;
	if (get_ulonglong(v, &x) < 0)
		return -1;
	memcpy(p, (char *)&x, sizeof x);
	return 0;
}
#endif

static int
np_float(char *p, PyObject *v, const formatdef *f)
{
	float x = (float)PyFloat_AsDouble(v);
	if (x == -1 && PyErr_Occurred()) {
		PyErr_SetString(StructError,
				"required argument is not a float");
		return -1;
	}
	memcpy(p, (char *)&x, sizeof x);
	return 0;
}

static int
np_double(char *p, PyObject *v, const formatdef *f)
{
	double x = PyFloat_AsDouble(v);
	if (x == -1 && PyErr_Occurred()) {
		PyErr_SetString(StructError,
				"required argument is not a float");
		return -1;
	}
	memcpy(p, (char *)&x, sizeof(double));
	return 0;
}

static int
np_void_p(char *p, PyObject *v, const formatdef *f)
{
	void *x;

	v = get_pylong(v);
	if (v == NULL)
		return -1;
	assert(PyLong_Check(v));
	x = PyLong_AsVoidPtr(v);
	Py_DECREF(v);
	if (x == NULL && PyErr_Occurred())
		return -1;
	memcpy(p, (char *)&x, sizeof x);
	return 0;
}

static formatdef native_table[] = {
	{'x',	sizeof(char),	0,		NULL},
	{'b',	sizeof(char),	0,		nu_byte,	np_byte},
	{'B',	sizeof(char),	0,		nu_ubyte,	np_ubyte},
	{'c',	sizeof(char),	0,		nu_char,	np_char},
	{'s',	sizeof(char),	0,		NULL},
	{'p',	sizeof(char),	0,		NULL},
	{'h',	sizeof(short),	SHORT_ALIGN,	nu_short,	np_short},
	{'H',	sizeof(short),	SHORT_ALIGN,	nu_ushort,	np_ushort},
	{'i',	sizeof(int),	INT_ALIGN,	nu_int,		np_int},
	{'I',	sizeof(int),	INT_ALIGN,	nu_uint,	np_uint},
	{'l',	sizeof(long),	LONG_ALIGN,	nu_long,	np_long},
	{'L',	sizeof(long),	LONG_ALIGN,	nu_ulong,	np_ulong},
	{'f',	sizeof(float),	FLOAT_ALIGN,	nu_float,	np_float},
	{'d',	sizeof(double),	DOUBLE_ALIGN,	nu_double,	np_double},
	{'P',	sizeof(void *),	VOID_P_ALIGN,	nu_void_p,	np_void_p},
#ifdef HAVE_LONG_LONG
	{'q',	sizeof(PY_LONG_LONG), LONG_LONG_ALIGN, nu_longlong, np_longlong},
	{'Q',	sizeof(PY_LONG_LONG), LONG_LONG_ALIGN, nu_ulonglong,np_ulonglong},
#endif
	{0}
};

/* Big-endian routines. *****************************************************/

static PyObject *
bu_int(const char *p, const formatdef *f)
{
	long x = 0;
	int i = f->size;
	do {
		x = (x<<8) | (*p++ & 0xFF);
	} while (--i > 0);
	/* Extend the sign bit. */
	if (SIZEOF_LONG > f->size)
		x |= -(x & (1L << (8*f->size - 1)));
	return PyInt_FromLong(x);
}

static PyObject *
bu_uint(const char *p, const formatdef *f)
{
	unsigned long x = 0;
	int i = f->size;
	do {
		x = (x<<8) | (*p++ & 0xFF);
	} while (--i > 0);
#ifdef PY_USE_INT_WHEN_POSSIBLE
	if (x <= INT_MAX)
		return PyInt_FromLong((long)x);
#else
	if (SIZEOF_LONG > f->size)
		return PyInt_FromLong((long)x);
#endif
	return PyLong_FromUnsignedLong(x);
}

static PyObject *
bu_longlong(const char *p, const formatdef *f)
{
#if HAVE_LONG_LONG
	PY_LONG_LONG x = 0;
	int i = f->size;
	do {
		x = (x<<8) | (*p++ & 0xFF);
	} while (--i > 0);
	/* Extend the sign bit. */
	if (SIZEOF_LONG_LONG > f->size)
		x |= -(x & (1L << (8 * f->size - 1)));
#ifdef PY_USE_INT_WHEN_POSSIBLE
	if (x >= INT_MIN && x <= INT_MAX)
		return PyInt_FromLong(Py_SAFE_DOWNCAST(x, PY_LONG_LONG, long));
#endif
	return PyLong_FromLongLong(x);
#else
	return _PyLong_FromByteArray((const unsigned char *)p,
				      8,
				      0, /* little-endian */
				      1  /* signed */);
#endif
}

static PyObject *
bu_ulonglong(const char *p, const formatdef *f)
{
#if HAVE_LONG_LONG
	unsigned PY_LONG_LONG x = 0;
	int i = f->size;
	do {
		x = (x<<8) | (*p++ & 0xFF);
	} while (--i > 0);
#ifdef PY_USE_INT_WHEN_POSSIBLE
	if (x <= INT_MAX)
		return PyInt_FromLong(Py_SAFE_DOWNCAST(x, unsigned PY_LONG_LONG, long));
#endif
	return PyLong_FromUnsignedLongLong(x);
#else
	return _PyLong_FromByteArray((const unsigned char *)p,
				      8,
				      0, /* little-endian */
				      0  /* signed */);
#endif
}

static PyObject *
bu_float(const char *p, const formatdef *f)
{
	return unpack_float(p, 0);
}

static PyObject *
bu_double(const char *p, const formatdef *f)
{
	return unpack_double(p, 0);
}

static int
bp_int(char *p, PyObject *v, const formatdef *f)
{
	long x;
	int i;
	if (get_long(v, &x) < 0)
		return -1;
	i = f->size;
	do {
		p[--i] = (char)x;
		x >>= 8;
	} while (i > 0);
	return 0;
}

static int
bp_uint(char *p, PyObject *v, const formatdef *f)
{
	unsigned long x;
	int i;
	if (get_ulong(v, &x) < 0)
		return -1;
	i = f->size;
	do {
		p[--i] = (char)x;
		x >>= 8;
	} while (i > 0);
	return 0;
}

static int
bp_longlong(char *p, PyObject *v, const formatdef *f)
{
	int res;
	v = get_pylong(v);
	if (v == NULL)
		return -1;
	res = _PyLong_AsByteArray((PyLongObject *)v,
			   	  (unsigned char *)p,
				  8,
				  0, /* little_endian */
				  1  /* signed */);
	Py_DECREF(v);
	return res;
}

static int
bp_ulonglong(char *p, PyObject *v, const formatdef *f)
{
	int res;
	v = get_pylong(v);
	if (v == NULL)
		return -1;
	res = _PyLong_AsByteArray((PyLongObject *)v,
			   	  (unsigned char *)p,
				  8,
				  0, /* little_endian */
				  0  /* signed */);
	Py_DECREF(v);
	return res;
}

static int
bp_float(char *p, PyObject *v, const formatdef *f)
{
	double x = PyFloat_AsDouble(v);
	if (x == -1 && PyErr_Occurred()) {
		PyErr_SetString(StructError,
				"required argument is not a float");
		return -1;
	}
	return _PyFloat_Pack4(x, (unsigned char *)p, 0);
}

static int
bp_double(char *p, PyObject *v, const formatdef *f)
{
	double x = PyFloat_AsDouble(v);
	if (x == -1 && PyErr_Occurred()) {
		PyErr_SetString(StructError,
				"required argument is not a float");
		return -1;
	}
	return _PyFloat_Pack8(x, (unsigned char *)p, 0);
}

static formatdef bigendian_table[] = {
	{'x',	1,		0,		NULL},
	{'b',	1,		0,		bu_int,		bp_int},
	{'B',	1,		0,		bu_uint,	bp_int},
	{'c',	1,		0,		nu_char,	np_char},
	{'s',	1,		0,		NULL},
	{'p',	1,		0,		NULL},
	{'h',	2,		0,		bu_int,		bp_int},
	{'H',	2,		0,		bu_uint,	bp_uint},
	{'i',	4,		0,		bu_int,		bp_int},
	{'I',	4,		0,		bu_uint,	bp_uint},
	{'l',	4,		0,		bu_int,		bp_int},
	{'L',	4,		0,		bu_uint,	bp_uint},
	{'q',	8,		0,		bu_longlong,	bp_longlong},
	{'Q',	8,		0,		bu_ulonglong,	bp_ulonglong},
	{'f',	4,		0,		bu_float,	bp_float},
	{'d',	8,		0,		bu_double,	bp_double},
	{0}
};

/* Little-endian routines. *****************************************************/

static PyObject *
lu_int(const char *p, const formatdef *f)
{
	long x = 0;
	int i = f->size;
	do {
		x = (x<<8) | (p[--i] & 0xFF);
	} while (i > 0);
	/* Extend the sign bit. */
	if (SIZEOF_LONG > f->size)
		x |= -(x & (1L << (8*f->size - 1)));
	return PyInt_FromLong(x);
}

static PyObject *
lu_uint(const char *p, const formatdef *f)
{
	unsigned long x = 0;
	int i = f->size;
	do {
		x = (x<<8) | (p[--i] & 0xFF);
	} while (i > 0);
#ifdef PY_USE_INT_WHEN_POSSIBLE
	if (x <= INT_MAX)
		return PyInt_FromLong((long)x);
#else
	if (SIZEOF_LONG > f->size)
		return PyInt_FromLong((long)x);
#endif
	return PyLong_FromUnsignedLong((long)x);
}

static PyObject *
lu_longlong(const char *p, const formatdef *f)
{
#if HAVE_LONG_LONG
	PY_LONG_LONG x = 0;
	int i = f->size;
	do {
		x = (x<<8) | (p[--i] & 0xFF);
	} while (i > 0);
	/* Extend the sign bit. */
	if (SIZEOF_LONG_LONG > f->size)
		x |= -(x & (1L << (8 * f->size - 1)));
#ifdef PY_USE_INT_WHEN_POSSIBLE
	if (x >= INT_MIN && x <= INT_MAX)
		return PyInt_FromLong(Py_SAFE_DOWNCAST(x, PY_LONG_LONG, long));
#endif
	return PyLong_FromLongLong(x);
#else
	return _PyLong_FromByteArray((const unsigned char *)p,
				      8,
				      1, /* little-endian */
				      1  /* signed */);
#endif
}

static PyObject *
lu_ulonglong(const char *p, const formatdef *f)
{
#if HAVE_LONG_LONG
	unsigned PY_LONG_LONG x = 0;
	int i = f->size;
	do {
		x = (x<<8) | (p[--i] & 0xFF);
	} while (i > 0);
#ifdef PY_USE_INT_WHEN_POSSIBLE
	if (x <= INT_MAX)
		return PyInt_FromLong(Py_SAFE_DOWNCAST(x, unsigned PY_LONG_LONG, long));
#endif
	return PyLong_FromUnsignedLongLong(x);
#else
	return _PyLong_FromByteArray((const unsigned char *)p,
				      8,
				      1, /* little-endian */
				      0  /* signed */);
#endif
}

static PyObject *
lu_float(const char *p, const formatdef *f)
{
	return unpack_float(p, 1);
}

static PyObject *
lu_double(const char *p, const formatdef *f)
{
	return unpack_double(p, 1);
}

static int
lp_int(char *p, PyObject *v, const formatdef *f)
{
	long x;
	int i;
	if (get_long(v, &x) < 0)
		return -1;
	i = f->size;
	do {
		*p++ = (char)x;
		x >>= 8;
	} while (--i > 0);
	return 0;
}

static int
lp_uint(char *p, PyObject *v, const formatdef *f)
{
	unsigned long x;
	int i;
	if (get_ulong(v, &x) < 0)
		return -1;
	i = f->size;
	do {
		*p++ = (char)x;
		x >>= 8;
	} while (--i > 0);
	return 0;
}

static int
lp_longlong(char *p, PyObject *v, const formatdef *f)
{
	int res;
	v = get_pylong(v);
	if (v == NULL)
		return -1;
	res = _PyLong_AsByteArray((PyLongObject*)v,
			   	  (unsigned char *)p,
				  8,
				  1, /* little_endian */
				  1  /* signed */);
	Py_DECREF(v);
	return res;
}

static int
lp_ulonglong(char *p, PyObject *v, const formatdef *f)
{
	int res;
	v = get_pylong(v);
	if (v == NULL)
		return -1;
	res = _PyLong_AsByteArray((PyLongObject*)v,
			   	  (unsigned char *)p,
				  8,
				  1, /* little_endian */
				  0  /* signed */);
	Py_DECREF(v);
	return res;
}

static int
lp_float(char *p, PyObject *v, const formatdef *f)
{
	double x = PyFloat_AsDouble(v);
	if (x == -1 && PyErr_Occurred()) {
		PyErr_SetString(StructError,
				"required argument is not a float");
		return -1;
	}
	return _PyFloat_Pack4(x, (unsigned char *)p, 1);
}

static int
lp_double(char *p, PyObject *v, const formatdef *f)
{
	double x = PyFloat_AsDouble(v);
	if (x == -1 && PyErr_Occurred()) {
		PyErr_SetString(StructError,
				"required argument is not a float");
		return -1;
	}
	return _PyFloat_Pack8(x, (unsigned char *)p, 1);
}

static formatdef lilendian_table[] = {
	{'x',	1,		0,		NULL},
	{'b',	1,		0,		lu_int,		lp_int},
	{'B',	1,		0,		lu_uint,	lp_int},
	{'c',	1,		0,		nu_char,	np_char},
	{'s',	1,		0,		NULL},
	{'p',	1,		0,		NULL},
	{'h',	2,		0,		lu_int,		lp_int},
	{'H',	2,		0,		lu_uint,	lp_uint},
	{'i',	4,		0,		lu_int,		lp_int},
	{'I',	4,		0,		lu_uint,	lp_uint},
	{'l',	4,		0,		lu_int,		lp_int},
	{'L',	4,		0,		lu_uint,	lp_uint},
	{'q',	8,		0,		lu_longlong,	lp_longlong},
	{'Q',	8,		0,		lu_ulonglong,	lp_ulonglong},
	{'f',	4,		0,		lu_float,	lp_float},
	{'d',	8,		0,		lu_double,	lp_double},
	{0}
};


static const formatdef *
whichtable(char **pfmt)
{
	const char *fmt = (*pfmt)++; /* May be backed out of later */
	switch (*fmt) {
	case '<':
		return lilendian_table;
	case '>':
	case '!': /* Network byte order is big-endian */
		return bigendian_table;
	case '=': { /* Host byte order -- different from native in aligment! */
		int n = 1;
		char *p = (char *) &n;
		if (*p == 1)
			return lilendian_table;
		else
			return bigendian_table;
	}
	default:
		--*pfmt; /* Back out of pointer increment */
		/* Fall through */
	case '@':
		return native_table;
	}
}


/* Get the table entry for a format code */

static const formatdef *
getentry(int c, const formatdef *f)
{
	for (; f->format != '\0'; f++) {
		if (f->format == c) {
			return f;
		}
	}
	PyErr_SetString(StructError, "bad char in struct format");
	return NULL;
}


/* Align a size according to a format code */

static int
align(int size, int c, const formatdef *e)
{
	if (e->format == c) {
		if (e->alignment) {
			size = ((size + e->alignment - 1)
				/ e->alignment)
				* e->alignment;
		}
	}
	return size;
}


/* calculate the size of a format string */

static int
prepare_s(PyStructObject *self)
{
	const formatdef *f;
	const formatdef *e;
	formatcode *codes;
	
	const char *s;
	const char *fmt;
	char c;
	int size, len, num, itemsize, x;

	fmt = PyString_AS_STRING(self->s_format);

	f = whichtable((char **)&fmt);
	
	s = fmt;
	size = 0;
	len = 0;
	while ((c = *s++) != '\0') {
		if (isspace(Py_CHARMASK(c)))
			continue;
		if ('0' <= c && c <= '9') {
			num = c - '0';
			while ('0' <= (c = *s++) && c <= '9') {
				x = num*10 + (c - '0');
				if (x/10 != num) {
					PyErr_SetString(
						StructError,
						"overflow in item count");
					return -1;
				}
				num = x;
			}
			if (c == '\0')
				break;
		}
		else
			num = 1;

		e = getentry(c, f);
		if (e == NULL)
			return -1;
		
		switch (c) {
			case 's': /* fall through */
			case 'p': len++; break;
			case 'x': break;
			default: len += num; break;
		}

		itemsize = e->size;
		size = align(size, c, e);
		x = num * itemsize;
		size += x;
		if (x/itemsize != num || size < 0) {
			PyErr_SetString(StructError,
					"total struct size too long");
			return -1;
		}
	}

	self->s_size = size;
	self->s_len = len;
	codes = PyMem_MALLOC((len + 1) * sizeof(formatcode));
	if (codes == NULL) {
		PyErr_NoMemory();
		return -1;
	}
	self->s_codes = codes;
	
	s = fmt;
	size = 0;
	while ((c = *s++) != '\0') {
		if (isspace(Py_CHARMASK(c)))
			continue;
		if ('0' <= c && c <= '9') {
			num = c - '0';
			while ('0' <= (c = *s++) && c <= '9')
				num = num*10 + (c - '0');
			if (c == '\0')
				break;
		}
		else
			num = 1;

		e = getentry(c, f);
		
		size = align(size, c, e);
		if (c == 's' || c == 'p') {
			codes->offset = size;
			codes->size = num;
			codes->fmtdef = e;
			codes++;
			size += num;
		} else if (c == 'x') {
			size += num;
		} else {
			while (--num >= 0) {
				codes->offset = size;
				codes->size = e->size;
				codes->fmtdef = e;
				codes++;
				size += e->size;
			}
		}
	}
	codes->fmtdef = NULL;
	codes->offset = size;
	codes->size = 0;
	
	return 0;
}

static PyObject *
s_new(PyTypeObject *type, PyObject *args, PyObject *kwds)
{
	PyObject *self;

	assert(type != NULL && type->tp_alloc != NULL);

	self = type->tp_alloc(type, 0);
	if (self != NULL) {
		PyStructObject *s = (PyStructObject*)self;
		Py_INCREF(Py_None);
		s->s_format = Py_None;
		s->s_codes = NULL;
		s->s_size = -1;
		s->s_len = -1;
	}
	return self;
}

static int
s_init(PyObject *self, PyObject *args, PyObject *kwds)
{
	PyStructObject *soself = (PyStructObject *)self;
	PyObject *o_format = NULL;
	int ret = 0;
	static char *kwlist[] = {"format", 0};

	assert(PyStruct_Check(self));

	if (!PyArg_ParseTupleAndKeywords(args, kwds, "S:Struct", kwlist,
					 &o_format))
        	return -1;

	Py_INCREF(o_format);
	Py_XDECREF(soself->s_format);
	soself->s_format = o_format;
	
	ret = prepare_s(soself);
	return ret;
}

static void
s_dealloc(PyStructObject *s)
{
	if (s->weakreflist != NULL)
		PyObject_ClearWeakRefs((PyObject *)s);
	if (s->s_codes != NULL) {
		PyMem_FREE(s->s_codes);
	}
	Py_XDECREF(s->s_format);
	s->ob_type->tp_free((PyObject *)s);
}

static PyObject *
s_unpack_internal(PyStructObject *soself, char *startfrom) {
	formatcode *code;
	Py_ssize_t i = 0;
	PyObject *result = PyTuple_New(soself->s_len);
	if (result == NULL)
		return NULL;

	for (code = soself->s_codes; code->fmtdef != NULL; code++) {
		PyObject *v;
		const formatdef *e = code->fmtdef;
		const char *res = startfrom + code->offset;
		if (e->format == 's') {
			v = PyString_FromStringAndSize(res, code->size);
			if (v == NULL)
				goto fail;
			PyTuple_SET_ITEM(result, i++, v);
		} else if (e->format == 'p') {
			Py_ssize_t n = *(unsigned char*)res;
			if (n >= code->size)
				n = code->size - 1;
			v = PyString_FromStringAndSize(res + 1, n);
			if (v == NULL)
				goto fail;
			PyTuple_SET_ITEM(result, i++, v);
		} else {
			v = e->unpack(res, e);
			if (v == NULL)
				goto fail;
			PyTuple_SET_ITEM(result, i++, v);
		}
	}

	return result;
fail:
	Py_DECREF(result);
	return NULL;
};


PyDoc_STRVAR(s_unpack__doc__,
"unpack(str) -> (v1, v2, ...)\n\
\n\
Return tuple containing values unpacked according to this Struct's format.\n\
Requires len(str) == self.size. See struct.__doc__ for more on format\n\
strings.");

static PyObject *
s_unpack(PyObject *self, PyObject *inputstr)
{
	PyStructObject *soself = (PyStructObject *)self;
	assert(PyStruct_Check(self));
	assert(soself->s_codes != NULL);	
	if (inputstr == NULL || !PyString_Check(inputstr) ||
		PyString_GET_SIZE(inputstr) != soself->s_size) {
		PyErr_Format(StructError,
			"unpack requires a string argument of length %d", soself->s_size);
		return NULL;
	}
	return s_unpack_internal(soself, PyString_AS_STRING(inputstr));
}

PyDoc_STRVAR(s_unpack_from__doc__,
"unpack_from(buffer[, offset]) -> (v1, v2, ...)\n\
\n\
Return tuple containing values unpacked according to this Struct's format.\n\
Unlike unpack, unpack_from can unpack values from any object supporting\n\
the buffer API, not just str. Requires len(buffer[offset:]) >= self.size.\n\
See struct.__doc__ for more on format strings.");

static PyObject *
s_unpack_from(PyObject *self, PyObject *args, PyObject *kwds)
{
	static char *kwlist[] = {"buffer", "offset", 0};
#if (PY_VERSION_HEX < 0x02050000)
	static char *fmt = "z#|i:unpack_from";
#else
	static char *fmt = "z#|n:unpack_from";
#endif
	Py_ssize_t buffer_len = 0, offset = 0;
	char *buffer = NULL;
	PyStructObject *soself = (PyStructObject *)self;
	assert(PyStruct_Check(self));
	assert(soself->s_codes != NULL);

	if (!PyArg_ParseTupleAndKeywords(args, kwds, fmt, kwlist,
					 &buffer, &buffer_len, &offset))
        	return NULL;

	if (buffer == NULL) {
		PyErr_Format(StructError,
			"unpack_from requires a buffer argument");
		return NULL;
	}
	
	if (offset < 0)
		offset += buffer_len;

	if (offset < 0 || (buffer_len - offset) < soself->s_size) {
		PyErr_Format(StructError,
			"unpack_from requires a buffer of at least %d bytes",
			soself->s_size);
		return NULL;
	}
	return s_unpack_internal(soself, buffer + offset);
}

PyDoc_STRVAR(s_pack__doc__,
"pack(v1, v2, ...) -> string\n\
\n\
Return a string containing values v1, v2, ... packed according to this\n\
Struct's format. See struct.__doc__ for more on format strings.");

static PyObject *
s_pack(PyObject *self, PyObject *args)
{
	PyStructObject *soself;
	PyObject *result;
	char *restart;
	formatcode *code;
	Py_ssize_t i;
	
	soself = (PyStructObject *)self;
	assert(PyStruct_Check(self));
	assert(soself->s_codes != NULL);
	if (args == NULL || !PyTuple_Check(args) ||
	    PyTuple_GET_SIZE(args) != soself->s_len)
	{
		PyErr_Format(StructError,
			"pack requires exactly %d arguments", soself->s_len);
		return NULL;
	}
	
	result = PyString_FromStringAndSize((char *)NULL, soself->s_size);
	if (result == NULL)
		return NULL;
	
	restart = PyString_AS_STRING(result);
	memset(restart, '\0', soself->s_size);
	i = 0;
	for (code = soself->s_codes; code->fmtdef != NULL; code++) {
		Py_ssize_t n;
		PyObject *v;
		const formatdef *e = code->fmtdef;
		char *res = restart + code->offset;
		if (e->format == 's') {
			v = PyTuple_GET_ITEM(args, i++);
			if (!PyString_Check(v)) {
				PyErr_SetString(StructError,
						"argument for 's' must be a string");
				goto fail;
			}
			n = PyString_GET_SIZE(v);
			if (n > code->size)
				n = code->size;
			if (n > 0)
				memcpy(res, PyString_AS_STRING(v), n);
		} else if (e->format == 'p') {
			v = PyTuple_GET_ITEM(args, i++);
			if (!PyString_Check(v)) {
				PyErr_SetString(StructError,
						"argument for 'p' must be a string");
				goto fail;
			}
			n = PyString_GET_SIZE(v);
			if (n > (code->size - 1))
				n = code->size - 1;
			if (n > 0)
				memcpy(res + 1, PyString_AS_STRING(v), n);
			if (n > 255)
				n = 255;
			*res = Py_SAFE_DOWNCAST(n, Py_ssize_t, unsigned char);
		} else {
			v = PyTuple_GET_ITEM(args, i++);
			if (e->pack(res, v, e) < 0)
				goto fail;
		}
	}
	
	return result;

fail:
	Py_DECREF(result);
	return NULL;
	
}


/* List of functions */

static struct PyMethodDef s_methods[] = {
	{"pack",	(PyCFunction)s_pack,		METH_VARARGS, s_pack__doc__},
	{"unpack",	(PyCFunction)s_unpack,		METH_O, s_unpack__doc__},
	{"unpack_from",	(PyCFunction)s_unpack_from,	METH_KEYWORDS, s_unpack_from__doc__},
	{NULL,	 NULL}		/* sentinel */
};

PyDoc_STRVAR(s__doc__, "Compiled struct object");

#define OFF(x) offsetof(PyStructObject, x)

static PyMemberDef s_memberlist[] = {
	{"format",	T_OBJECT,	OFF(s_format),	RO,
	 "struct format string"},
	{"size",	T_INT,		OFF(s_size),	RO,
	 "struct size in bytes"},
	{"_len",	T_INT,		OFF(s_len),	RO,
	 "number of items expected in tuple"},
	{NULL}	/* Sentinel */
};


static
PyTypeObject PyStructType = {
	PyObject_HEAD_INIT(NULL)
	0,
	"Struct",
	sizeof(PyStructObject),
	0,
	(destructor)s_dealloc,			/* tp_dealloc */
	0,					/* tp_print */
	0,					/* tp_getattr */
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
	PyObject_GenericSetAttr,		/* tp_setattro */
	0,					/* tp_as_buffer */
	Py_TPFLAGS_DEFAULT | Py_TPFLAGS_BASETYPE | Py_TPFLAGS_HAVE_WEAKREFS, /* tp_flags */
	s__doc__,				/* tp_doc */
	0,					/* tp_traverse */
	0,					/* tp_clear */
	0,					/* tp_richcompare */
	offsetof(PyStructObject, weakreflist),	/* tp_weaklistoffset */
	0,					/* tp_iter */
	0,					/* tp_iternext */
	s_methods,				/* tp_methods */
	s_memberlist,				/* tp_members */
	0,					/* tp_getset */
	0,					/* tp_base */
	0,					/* tp_dict */
	0,					/* tp_descr_get */
	0,					/* tp_descr_set */
	0,					/* tp_dictoffset */
	s_init,					/* tp_init */
	PyType_GenericAlloc,			/* tp_alloc */
	s_new,					/* tp_new */
	PyObject_Del,				/* tp_free */
};

/* Module initialization */

PyMODINIT_FUNC
init_struct(void)
{
	PyObject *m = Py_InitModule("_struct", NULL);
	if (m == NULL)
		return;

	PyStructType.ob_type = &PyType_Type;
	if (PyType_Ready(&PyStructType) < 0)
		return;

	/* Add some symbolic constants to the module */
	if (StructError == NULL) {
		StructError = PyErr_NewException("struct.error", NULL, NULL);
		if (StructError == NULL)
			return;
	}
	Py_INCREF(StructError);
	PyModule_AddObject(m, "error", StructError);
	Py_INCREF((PyObject*)&PyStructType);
	PyModule_AddObject(m, "Struct", (PyObject*)&PyStructType);
}
