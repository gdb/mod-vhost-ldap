#ifndef Py_OBJECT_H
#define Py_OBJECT_H
#ifdef __cplusplus
extern "C" {
#endif


/* Object and type object interface */

/*
Objects are structures allocated on the heap.  Special rules apply to
the use of objects to ensure they are properly garbage-collected.
Objects are never allocated statically or on the stack; they must be
accessed through special macros and functions only.  (Type objects are
exceptions to the first rule; the standard types are represented by
statically initialized type objects, although work on type/class unification
for Python 2.2 made it possible to have heap-allocated type objects too).

An object has a 'reference count' that is increased or decreased when a
pointer to the object is copied or deleted; when the reference count
reaches zero there are no references to the object left and it can be
removed from the heap.

An object has a 'type' that determines what it represents and what kind
of data it contains.  An object's type is fixed when it is created.
Types themselves are represented as objects; an object contains a
pointer to the corresponding type object.  The type itself has a type
pointer pointing to the object representing the type 'type', which
contains a pointer to itself!).

Objects do not float around in memory; once allocated an object keeps
the same size and address.  Objects that must hold variable-size data
can contain pointers to variable-size parts of the object.  Not all
objects of the same type have the same size; but the size cannot change
after allocation.  (These restrictions are made so a reference to an
object can be simply a pointer -- moving an object would require
updating all the pointers, and changing an object's size would require
moving it if there was another object right next to it.)

Objects are always accessed through pointers of the type 'PyObject *'.
The type 'PyObject' is a structure that only contains the reference count
and the type pointer.  The actual memory allocated for an object
contains other data that can only be accessed after casting the pointer
to a pointer to a longer structure type.  This longer type must start
with the reference count and type fields; the macro PyObject_HEAD should be
used for this (to accommodate for future changes).  The implementation
of a particular object type can cast the object pointer to the proper
type and back.

A standard interface exists for objects that contain an array of items
whose size is determined when the object is allocated.
*/

#ifdef Py_DEBUG
/* Turn on aggregate reference counting.  This arranges that extern
 * _Py_RefTotal hold a count of all references, the sum of ob_refcnt
 * across all objects.  The value can be gotten programatically via
 * sys.gettotalrefcount() (which exists only if Py_REF_DEBUG is enabled).
 * In a debug-mode build, this is where the "8288" comes from in
 *
 *  >>> 23
 *  23
 *  [8288 refs]
 *  >>>
 *
 * Note that if this count increases when you're not storing away new objects,
 * there's probably a leak.  Remember, though, that in interactive mode the
 * special name "_" holds a reference to the last result displayed!
 * Py_REF_DEBUG also checks after every decref to verify that the refcount
 * hasn't gone negative, and causes an immediate fatal error if it has.
 */
#define Py_REF_DEBUG

/* Turn on heavy reference debugging.  This is major surgery.  Every PyObject
 * grows two more pointers, to maintain a doubly-linked list of all live
 * heap-allocated objects (note that, e.g., most builtin type objects are
 * not in this list, as they're statically allocated).  This list can be
 * materialized into a Python list via sys.getobjects() (which exists only
 * if Py_TRACE_REFS is enabled).  Py_TRACE_REFS implies Py_REF_DEBUG.
 */
#define Py_TRACE_REFS
#endif /* Py_DEBUG */

/* Py_TRACE_REFS implies Py_REF_DEBUG. */
#if defined(Py_TRACE_REFS) && !defined(Py_REF_DEBUG)
#define Py_REF_DEBUG
#endif

#ifdef Py_TRACE_REFS
/* Define pointers to support a doubly-linked list of all live heap objects. */
#define _PyObject_HEAD_EXTRA		\
	struct _object *_ob_next;	\
	struct _object *_ob_prev;

#define _PyObject_EXTRA_INIT 0, 0,

#else
#define _PyObject_HEAD_EXTRA
#define _PyObject_EXTRA_INIT
#endif

/* PyObject_HEAD defines the initial segment of every PyObject. */
#define PyObject_HEAD			\
	_PyObject_HEAD_EXTRA		\
	int ob_refcnt;			\
	struct _typeobject *ob_type;

#define PyObject_HEAD_INIT(type)	\
	_PyObject_EXTRA_INIT		\
	1, type,

/* PyObject_VAR_HEAD defines the initial segment of all variable-size
 * container objects.  These end with a declaration of an array with 1
 * element, but enough space is malloc'ed so that the array actually
 * has room for ob_size elements.  Note that ob_size is an element count,
 * not necessarily a byte count.
 */
#define PyObject_VAR_HEAD		\
	PyObject_HEAD			\
	int ob_size; /* Number of items in variable part */

/* Nothing is actually declared to be a PyObject, but every pointer to
 * a Python object can be cast to a PyObject*.  This is inheritance built
 * by hand.  Similarly every pointer to a variable-size Python object can,
 * in addition, be cast to PyVarObject*.
 */
typedef struct _object {
	PyObject_HEAD
} PyObject;

typedef struct {
	PyObject_VAR_HEAD
} PyVarObject;


/*
Type objects contain a string containing the type name (to help somewhat
in debugging), the allocation parameters (see PyObject_New() and
PyObject_NewVar()),
and methods for accessing objects of the type.  Methods are optional, a
nil pointer meaning that particular kind of access is not available for
this type.  The Py_DECREF() macro uses the tp_dealloc method without
checking for a nil pointer; it should always be implemented except if
the implementation can guarantee that the reference count will never
reach zero (e.g., for statically allocated type objects).

NB: the methods for certain type groups are now contained in separate
method blocks.
*/

typedef PyObject * (*unaryfunc)(PyObject *);
typedef PyObject * (*binaryfunc)(PyObject *, PyObject *);
typedef PyObject * (*ternaryfunc)(PyObject *, PyObject *, PyObject *);
typedef int (*inquiry)(PyObject *);
typedef int (*coercion)(PyObject **, PyObject **);
typedef PyObject *(*intargfunc)(PyObject *, int);
typedef PyObject *(*intintargfunc)(PyObject *, int, int);
typedef int(*intobjargproc)(PyObject *, int, PyObject *);
typedef int(*intintobjargproc)(PyObject *, int, int, PyObject *);
typedef int(*objobjargproc)(PyObject *, PyObject *, PyObject *);
typedef int (*getreadbufferproc)(PyObject *, int, void **);
typedef int (*getwritebufferproc)(PyObject *, int, void **);
typedef int (*getsegcountproc)(PyObject *, int *);
typedef int (*getcharbufferproc)(PyObject *, int, const char **);
typedef int (*objobjproc)(PyObject *, PyObject *);
typedef int (*visitproc)(PyObject *, void *);
typedef int (*traverseproc)(PyObject *, visitproc, void *);

typedef struct {
	/* For numbers without flag bit Py_TPFLAGS_CHECKTYPES set, all
	   arguments are guaranteed to be of the object's type (modulo
	   coercion hacks -- i.e. if the type's coercion function
	   returns other types, then these are allowed as well).  Numbers that
	   have the Py_TPFLAGS_CHECKTYPES flag bit set should check *both*
	   arguments for proper type and implement the necessary conversions
	   in the slot functions themselves. */

	binaryfunc nb_add;
	binaryfunc nb_subtract;
	binaryfunc nb_multiply;
	binaryfunc nb_divide;
	binaryfunc nb_remainder;
	binaryfunc nb_divmod;
	ternaryfunc nb_power;
	unaryfunc nb_negative;
	unaryfunc nb_positive;
	unaryfunc nb_absolute;
	inquiry nb_nonzero;
	unaryfunc nb_invert;
	binaryfunc nb_lshift;
	binaryfunc nb_rshift;
	binaryfunc nb_and;
	binaryfunc nb_xor;
	binaryfunc nb_or;
	coercion nb_coerce;
	unaryfunc nb_int;
	unaryfunc nb_long;
	unaryfunc nb_float;
	unaryfunc nb_oct;
	unaryfunc nb_hex;
	/* Added in release 2.0 */
	binaryfunc nb_inplace_add;
	binaryfunc nb_inplace_subtract;
	binaryfunc nb_inplace_multiply;
	binaryfunc nb_inplace_divide;
	binaryfunc nb_inplace_remainder;
	ternaryfunc nb_inplace_power;
	binaryfunc nb_inplace_lshift;
	binaryfunc nb_inplace_rshift;
	binaryfunc nb_inplace_and;
	binaryfunc nb_inplace_xor;
	binaryfunc nb_inplace_or;

	/* Added in release 2.2 */
	/* The following require the Py_TPFLAGS_HAVE_CLASS flag */
	binaryfunc nb_floor_divide;
	binaryfunc nb_true_divide;
	binaryfunc nb_inplace_floor_divide;
	binaryfunc nb_inplace_true_divide;
} PyNumberMethods;

typedef struct {
	inquiry sq_length;
	binaryfunc sq_concat;
	intargfunc sq_repeat;
	intargfunc sq_item;
	intintargfunc sq_slice;
	intobjargproc sq_ass_item;
	intintobjargproc sq_ass_slice;
	objobjproc sq_contains;
	/* Added in release 2.0 */
	binaryfunc sq_inplace_concat;
	intargfunc sq_inplace_repeat;
} PySequenceMethods;

typedef struct {
	inquiry mp_length;
	binaryfunc mp_subscript;
	objobjargproc mp_ass_subscript;
} PyMappingMethods;

typedef struct {
	getreadbufferproc bf_getreadbuffer;
	getwritebufferproc bf_getwritebuffer;
	getsegcountproc bf_getsegcount;
	getcharbufferproc bf_getcharbuffer;
} PyBufferProcs;


typedef void (*freefunc)(void *);
typedef void (*destructor)(PyObject *);
typedef int (*printfunc)(PyObject *, FILE *, int);
typedef PyObject *(*getattrfunc)(PyObject *, char *);
typedef PyObject *(*getattrofunc)(PyObject *, PyObject *);
typedef int (*setattrfunc)(PyObject *, char *, PyObject *);
typedef int (*setattrofunc)(PyObject *, PyObject *, PyObject *);
typedef int (*cmpfunc)(PyObject *, PyObject *);
typedef PyObject *(*reprfunc)(PyObject *);
typedef long (*hashfunc)(PyObject *);
typedef PyObject *(*richcmpfunc) (PyObject *, PyObject *, int);
typedef PyObject *(*getiterfunc) (PyObject *);
typedef PyObject *(*iternextfunc) (PyObject *);
typedef PyObject *(*descrgetfunc) (PyObject *, PyObject *, PyObject *);
typedef int (*descrsetfunc) (PyObject *, PyObject *, PyObject *);
typedef int (*initproc)(PyObject *, PyObject *, PyObject *);
typedef PyObject *(*newfunc)(struct _typeobject *, PyObject *, PyObject *);
typedef PyObject *(*allocfunc)(struct _typeobject *, int);

typedef struct _typeobject {
	PyObject_VAR_HEAD
	char *tp_name; /* For printing, in format "<module>.<name>" */
	int tp_basicsize, tp_itemsize; /* For allocation */

	/* Methods to implement standard operations */

	destructor tp_dealloc;
	printfunc tp_print;
	getattrfunc tp_getattr;
	setattrfunc tp_setattr;
	cmpfunc tp_compare;
	reprfunc tp_repr;

	/* Method suites for standard classes */

	PyNumberMethods *tp_as_number;
	PySequenceMethods *tp_as_sequence;
	PyMappingMethods *tp_as_mapping;

	/* More standard operations (here for binary compatibility) */

	hashfunc tp_hash;
	ternaryfunc tp_call;
	reprfunc tp_str;
	getattrofunc tp_getattro;
	setattrofunc tp_setattro;

	/* Functions to access object as input/output buffer */
	PyBufferProcs *tp_as_buffer;

	/* Flags to define presence of optional/expanded features */
	long tp_flags;

	char *tp_doc; /* Documentation string */

	/* Assigned meaning in release 2.0 */
	/* call function for all accessible objects */
	traverseproc tp_traverse;

	/* delete references to contained objects */
	inquiry tp_clear;

	/* Assigned meaning in release 2.1 */
	/* rich comparisons */
	richcmpfunc tp_richcompare;

	/* weak reference enabler */
	long tp_weaklistoffset;

	/* Added in release 2.2 */
	/* Iterators */
	getiterfunc tp_iter;
	iternextfunc tp_iternext;

	/* Attribute descriptor and subclassing stuff */
	struct PyMethodDef *tp_methods;
	struct PyMemberDef *tp_members;
	struct PyGetSetDef *tp_getset;
	struct _typeobject *tp_base;
	PyObject *tp_dict;
	descrgetfunc tp_descr_get;
	descrsetfunc tp_descr_set;
	long tp_dictoffset;
	initproc tp_init;
	allocfunc tp_alloc;
	newfunc tp_new;
	freefunc tp_free; /* Low-level free-memory routine */
	inquiry tp_is_gc; /* For PyObject_IS_GC */
	PyObject *tp_bases;
	PyObject *tp_mro; /* method resolution order */
	PyObject *tp_cache;
	PyObject *tp_subclasses;
	PyObject *tp_weaklist;

#ifdef COUNT_ALLOCS
	/* these must be last and never explicitly initialized */
	int tp_allocs;
	int tp_frees;
	int tp_maxalloc;
	struct _typeobject *tp_next;
#endif
} PyTypeObject;


/* Generic type check */
extern DL_IMPORT(int) PyType_IsSubtype(PyTypeObject *, PyTypeObject *);
#define PyObject_TypeCheck(ob, tp) \
	((ob)->ob_type == (tp) || PyType_IsSubtype((ob)->ob_type, (tp)))

extern DL_IMPORT(PyTypeObject) PyType_Type; /* built-in 'type' */
extern DL_IMPORT(PyTypeObject) PyBaseObject_Type; /* built-in 'object' */
extern DL_IMPORT(PyTypeObject) PySuper_Type; /* built-in 'super' */

#define PyType_Check(op) PyObject_TypeCheck(op, &PyType_Type)
#define PyType_CheckExact(op) ((op)->ob_type == &PyType_Type)

extern DL_IMPORT(int) PyType_Ready(PyTypeObject *);
extern DL_IMPORT(PyObject *) PyType_GenericAlloc(PyTypeObject *, int);
extern DL_IMPORT(PyObject *) PyType_GenericNew(PyTypeObject *,
					       PyObject *, PyObject *);
extern DL_IMPORT(PyObject *) _PyType_Lookup(PyTypeObject *, PyObject *);

/* Generic operations on objects */
extern DL_IMPORT(int) PyObject_Print(PyObject *, FILE *, int);
extern DL_IMPORT(void) _PyObject_Dump(PyObject *);
extern DL_IMPORT(PyObject *) PyObject_Repr(PyObject *);
extern DL_IMPORT(PyObject *) PyObject_Str(PyObject *);
#ifdef Py_USING_UNICODE
extern DL_IMPORT(PyObject *) PyObject_Unicode(PyObject *);
#endif
extern DL_IMPORT(int) PyObject_Compare(PyObject *, PyObject *);
extern DL_IMPORT(PyObject *) PyObject_RichCompare(PyObject *, PyObject *, int);
extern DL_IMPORT(int) PyObject_RichCompareBool(PyObject *, PyObject *, int);
extern DL_IMPORT(PyObject *) PyObject_GetAttrString(PyObject *, char *);
extern DL_IMPORT(int) PyObject_SetAttrString(PyObject *, char *, PyObject *);
extern DL_IMPORT(int) PyObject_HasAttrString(PyObject *, char *);
extern DL_IMPORT(PyObject *) PyObject_GetAttr(PyObject *, PyObject *);
extern DL_IMPORT(int) PyObject_SetAttr(PyObject *, PyObject *, PyObject *);
extern DL_IMPORT(int) PyObject_HasAttr(PyObject *, PyObject *);
extern DL_IMPORT(PyObject **) _PyObject_GetDictPtr(PyObject *);
extern DL_IMPORT(PyObject *) PyObject_GenericGetAttr(PyObject *, PyObject *);
extern DL_IMPORT(int) PyObject_GenericSetAttr(PyObject *,
					      PyObject *, PyObject *);
extern DL_IMPORT(long) PyObject_Hash(PyObject *);
extern DL_IMPORT(int) PyObject_IsTrue(PyObject *);
extern DL_IMPORT(int) PyObject_Not(PyObject *);
extern DL_IMPORT(int) PyCallable_Check(PyObject *);
extern DL_IMPORT(int) PyNumber_Coerce(PyObject **, PyObject **);
extern DL_IMPORT(int) PyNumber_CoerceEx(PyObject **, PyObject **);

extern DL_IMPORT(void) PyObject_ClearWeakRefs(PyObject *);

/* A slot function whose address we need to compare */
extern int _PyObject_SlotCompare(PyObject *, PyObject *);


/* PyObject_Dir(obj) acts like Python __builtin__.dir(obj), returning a
   list of strings.  PyObject_Dir(NULL) is like __builtin__.dir(),
   returning the names of the current locals.  In this case, if there are
   no current locals, NULL is returned, and PyErr_Occurred() is false.
*/
extern DL_IMPORT(PyObject *) PyObject_Dir(PyObject *);


/* Helpers for printing recursive container types */
extern DL_IMPORT(int) Py_ReprEnter(PyObject *);
extern DL_IMPORT(void) Py_ReprLeave(PyObject *);

/* Helpers for hash functions */
extern DL_IMPORT(long) _Py_HashDouble(double);
extern DL_IMPORT(long) _Py_HashPointer(void*);

/* Helper for passing objects to printf and the like */
#define PyObject_REPR(obj) PyString_AS_STRING(PyObject_Repr(obj))

/* Flag bits for printing: */
#define Py_PRINT_RAW	1	/* No string quotes etc. */

/*
`Type flags (tp_flags)

These flags are used to extend the type structure in a backwards-compatible
fashion. Extensions can use the flags to indicate (and test) when a given
type structure contains a new feature. The Python core will use these when
introducing new functionality between major revisions (to avoid mid-version
changes in the PYTHON_API_VERSION).

Arbitration of the flag bit positions will need to be coordinated among
all extension writers who publically release their extensions (this will
be fewer than you might expect!)..

Python 1.5.2 introduced the bf_getcharbuffer slot into PyBufferProcs.

Type definitions should use Py_TPFLAGS_DEFAULT for their tp_flags value.

Code can use PyType_HasFeature(type_ob, flag_value) to test whether the
given type object has a specified feature.
*/

/* PyBufferProcs contains bf_getcharbuffer */
#define Py_TPFLAGS_HAVE_GETCHARBUFFER  (1L<<0)

/* PySequenceMethods contains sq_contains */
#define Py_TPFLAGS_HAVE_SEQUENCE_IN (1L<<1)

/* This is here for backwards compatibility.  Extensions that use the old GC
 * API will still compile but the objects will not be tracked by the GC. */
#define Py_TPFLAGS_GC 0 /* used to be (1L<<2) */

/* PySequenceMethods and PyNumberMethods contain in-place operators */
#define Py_TPFLAGS_HAVE_INPLACEOPS (1L<<3)

/* PyNumberMethods do their own coercion */
#define Py_TPFLAGS_CHECKTYPES (1L<<4)

/* tp_richcompare is defined */
#define Py_TPFLAGS_HAVE_RICHCOMPARE (1L<<5)

/* Objects which are weakly referencable if their tp_weaklistoffset is >0 */
#define Py_TPFLAGS_HAVE_WEAKREFS (1L<<6)

/* tp_iter is defined */
#define Py_TPFLAGS_HAVE_ITER (1L<<7)

/* New members introduced by Python 2.2 exist */
#define Py_TPFLAGS_HAVE_CLASS (1L<<8)

/* Set if the type object is dynamically allocated */
#define Py_TPFLAGS_HEAPTYPE (1L<<9)

/* Set if the type allows subclassing */
#define Py_TPFLAGS_BASETYPE (1L<<10)

/* Set if the type is 'ready' -- fully initialized */
#define Py_TPFLAGS_READY (1L<<12)

/* Set while the type is being 'readied', to prevent recursive ready calls */
#define Py_TPFLAGS_READYING (1L<<13)

/* Objects support garbage collection (see objimp.h) */
#define Py_TPFLAGS_HAVE_GC (1L<<14)

#define Py_TPFLAGS_DEFAULT  ( \
                             Py_TPFLAGS_HAVE_GETCHARBUFFER | \
                             Py_TPFLAGS_HAVE_SEQUENCE_IN | \
                             Py_TPFLAGS_HAVE_INPLACEOPS | \
                             Py_TPFLAGS_HAVE_RICHCOMPARE | \
                             Py_TPFLAGS_HAVE_WEAKREFS | \
                             Py_TPFLAGS_HAVE_ITER | \
                             Py_TPFLAGS_HAVE_CLASS | \
                            0)

#define PyType_HasFeature(t,f)  (((t)->tp_flags & (f)) != 0)


/*
The macros Py_INCREF(op) and Py_DECREF(op) are used to increment or decrement
reference counts.  Py_DECREF calls the object's deallocator function when
the refcount falls to 0; for
objects that don't contain references to other objects or heap memory
this can be the standard function free().  Both macros can be used
wherever a void expression is allowed.  The argument must not be a
NIL pointer.  If it may be NIL, use Py_XINCREF/Py_XDECREF instead.
The macro _Py_NewReference(op) initialize reference counts to 1, and
in special builds (Py_REF_DEBUG, Py_TRACE_REFS) performs additional
bookkeeping appropriate to the special build.

We assume that the reference count field can never overflow; this can
be proven when the size of the field is the same as the pointer size, so
we ignore the possibility.  Provided a C int is at least 32 bits (which
is implicitly assumed in many parts of this code), that's enough for
about 2**31 references to an object.

XXX The following became out of date in Python 2.2, but I'm not sure
XXX what the full truth is now.  Certainly, heap-allocated type objects
XXX can and should be deallocated.
Type objects should never be deallocated; the type pointer in an object
is not considered to be a reference to the type object, to save
complications in the deallocation function.  (This is actually a
decision that's up to the implementer of each new type so if you want,
you can count such references to the type object.)

*** WARNING*** The Py_DECREF macro must have a side-effect-free argument
since it may evaluate its argument multiple times.  (The alternative
would be to mace it a proper function or assign it to a global temporary
variable first, both of which are slower; and in a multi-threaded
environment the global variable trick is not safe.)
*/

#ifdef Py_REF_DEBUG
extern DL_IMPORT(long) _Py_RefTotal;
extern DL_IMPORT(void) _Py_NegativeRefcount(const char *fname,
					    int lineno, PyObject *op);
#define _PyMAYBE_BUMP_REFTOTAL		_Py_RefTotal++
#define _PyMAYBE_DROP_REFTOTAL		_Py_RefTotal--
#define _PyMAYBE_REFTOTAL_COMMA		,
#define _PyMAYBE_CHECK_REFCNT(OP)				\
{	if ((OP)->ob_refcnt < 0)				\
		_Py_NegativeRefcount(__FILE__, __LINE__,	\
				     (PyObject *)(OP));		\
}
#else
#define _PyMAYBE_BUMP_REFTOTAL
#define _PyMAYBE_DROP_REFTOTAL
#define _PyMAYBE_REFTOTAL_COMMA
#define _PyMAYBE_CHECK_REFCNT(OP)	;
#endif

#ifdef COUNT_ALLOCS
extern DL_IMPORT(void) inc_count(PyTypeObject *);
#define _PyMAYBE_BUMP_COUNT(OP)		inc_count((OP)->ob_type)
#define _PyMAYBE_BUMP_FREECOUNT(OP)	(OP)->ob_type->tp_frees++
#define _PyMAYBE_BUMP_COUNT_COMMA	,
#define _PyMAYBE_BUMP_FREECOUNT_COMMA	,
#else
#define _PyMAYBE_BUMP_COUNT(OP)
#define _PyMAYBE_BUMP_FREECOUNT(OP)
#define _PyMAYBE_BUMP_COUNT_COMMA
#define _PyMAYBE_BUMP_FREECOUNT_COMMA
#endif

#ifdef Py_TRACE_REFS
/* Py_TRACE_REFS is such major surgery that we call external routines. */
extern DL_IMPORT(void) _Py_NewReference(PyObject *);
extern DL_IMPORT(void) _Py_ForgetReference(PyObject *);
extern DL_IMPORT(void) _Py_Dealloc(PyObject *);
extern DL_IMPORT(void) _Py_PrintReferences(FILE *);
extern DL_IMPORT(void) _Py_ResetReferences(void);

#else
/* Without Py_TRACE_REFS, there's little enough to do that we expand code
 * inline.
 */
#define _Py_NewReference(op) (					\
	_PyMAYBE_BUMP_COUNT(op) _PyMAYBE_BUMP_COUNT_COMMA	\
	_PyMAYBE_BUMP_REFTOTAL _PyMAYBE_REFTOTAL_COMMA		\
	(op)->ob_refcnt = 1)

#define _Py_ForgetReference(op) _PyMAYBE_BUMP_FREECOUNT(op)

#define _Py_Dealloc(op) (						\
	_PyMAYBE_BUMP_FREECOUNT(op) _PyMAYBE_BUMP_FREECOUNT_COMMA	\
	(*(op)->ob_type->tp_dealloc)((PyObject *)(op)))
#endif /* !Py_TRACE_REFS */

#define Py_INCREF(op) (						\
	_PyMAYBE_BUMP_REFTOTAL _PyMAYBE_REFTOTAL_COMMA		\
	(op)->ob_refcnt++)

#define Py_DECREF(op)						\
	if (_PyMAYBE_DROP_REFTOTAL _PyMAYBE_REFTOTAL_COMMA	\
	    --(op)->ob_refcnt != 0)				\
		_PyMAYBE_CHECK_REFCNT(op)			\
	else							\
		_Py_Dealloc((PyObject *)(op))

/* Macros to use in case the object pointer may be NULL: */
#define Py_XINCREF(op) if ((op) == NULL) ; else Py_INCREF(op)
#define Py_XDECREF(op) if ((op) == NULL) ; else Py_DECREF(op)

/*
_Py_NoneStruct is an object of undefined type which can be used in contexts
where NULL (nil) is not suitable (since NULL often means 'error').

Don't forget to apply Py_INCREF() when returning this value!!!
*/
extern DL_IMPORT(PyObject) _Py_NoneStruct; /* Don't use this directly */
#define Py_None (&_Py_NoneStruct)

/*
Py_NotImplemented is a singleton used to signal that an operation is
not implemented for a given type combination.
*/
extern DL_IMPORT(PyObject) _Py_NotImplementedStruct; /* Don't use this directly */
#define Py_NotImplemented (&_Py_NotImplementedStruct)

/* Rich comparison opcodes */
#define Py_LT 0
#define Py_LE 1
#define Py_EQ 2
#define Py_NE 3
#define Py_GT 4
#define Py_GE 5

/*
A common programming style in Python requires the forward declaration
of static, initialized structures, e.g. for a type object that is used
by the functions whose address must be used in the initializer.
Some compilers (notably SCO ODT 3.0, I seem to remember early AIX as
well) botch this if you use the static keyword for both declarations
(they allocate two objects, and use the first, uninitialized one until
the second declaration is encountered).  Therefore, the forward
declaration should use the 'forwardstatic' keyword.  This expands to
static on most systems, but to extern on a few.  The actual storage
and name will still be static because the second declaration is
static, so no linker visible symbols will be generated.  (Standard C
compilers take offense to the extern forward declaration of a static
object, so I can't just put extern in all cases. :-( )
*/

#ifdef BAD_STATIC_FORWARD
#define staticforward extern
#define statichere static
#else /* !BAD_STATIC_FORWARD */
#define staticforward static
#define statichere static
#endif /* !BAD_STATIC_FORWARD */


/*
More conventions
================

Argument Checking
-----------------

Functions that take objects as arguments normally don't check for nil
arguments, but they do check the type of the argument, and return an
error if the function doesn't apply to the type.

Failure Modes
-------------

Functions may fail for a variety of reasons, including running out of
memory.  This is communicated to the caller in two ways: an error string
is set (see errors.h), and the function result differs: functions that
normally return a pointer return NULL for failure, functions returning
an integer return -1 (which could be a legal return value too!), and
other functions return 0 for success and -1 for failure.
Callers should always check for errors before using the result.  If
an error was set, the caller must either explicitly clear it, or pass
the error on to its caller.

Reference Counts
----------------

It takes a while to get used to the proper usage of reference counts.

Functions that create an object set the reference count to 1; such new
objects must be stored somewhere or destroyed again with Py_DECREF().
Functions that 'store' objects such as PyTuple_SetItem() and
PyDict_SetItemString()
don't increment the reference count of the object, since the most
frequent use is to store a fresh object.  Functions that 'retrieve'
objects such as PyTuple_GetItem() and PyDict_GetItemString() also
don't increment
the reference count, since most frequently the object is only looked at
quickly.  Thus, to retrieve an object and store it again, the caller
must call Py_INCREF() explicitly.

NOTE: functions that 'consume' a reference count like
PyList_SetItemString() even consume the reference if the object wasn't
stored, to simplify error handling.

It seems attractive to make other functions that take an object as
argument consume a reference count; however this may quickly get
confusing (even the current practice is already confusing).  Consider
it carefully, it may save lots of calls to Py_INCREF() and Py_DECREF() at
times.
*/


/* Trashcan mechanism, thanks to Christian Tismer.

When deallocating a container object, it's possible to trigger an unbounded
chain of deallocations, as each Py_DECREF in turn drops the refcount on "the
next" object in the chain to 0.  This can easily lead to stack faults, and
especially in threads (which typically have less stack space to work with).

A container object that participates in cyclic gc can avoid this by
bracketing the body of its tp_dealloc function with a pair of macros:

static void
mytype_dealloc(mytype *p)
{
        ... declarations go here ...

 	PyObject_GC_UnTrack(p);	   // must untrack first
	Py_TRASHCAN_SAFE_BEGIN(p)
	... The body of the deallocator goes here, including all calls ...
	... to Py_DECREF on contained objects.                         ...
	Py_TRASHCAN_SAFE_END(p)
}

How it works:  The BEGIN macro increments a call-depth counter.  So long
as this counter is small, the body of the deallocator is run directly without
further ado.  But if the counter gets large, it instead adds p to a list of
objects to be deallocated later, skips the body of the deallocator, and
resumes execution after the END macro.  The tp_dealloc routine then returns
without deallocating anything (and so unbounded call-stack depth is avoided).

When the call stack finishes unwinding again, code generated by the END macro
notices this, and calls another routine to deallocate all the objects that
may have been added to the list of deferred deallocations.  In effect, a
chain of N deallocations is broken into N / PyTrash_UNWIND_LEVEL pieces,
with the call stack never exceeding a depth of PyTrash_UNWIND_LEVEL.
*/

extern DL_IMPORT(void) _PyTrash_deposit_object(PyObject*);
extern DL_IMPORT(void) _PyTrash_destroy_chain(void);
extern DL_IMPORT(int) _PyTrash_delete_nesting;
extern DL_IMPORT(PyObject *) _PyTrash_delete_later;

#define PyTrash_UNWIND_LEVEL 50

#define Py_TRASHCAN_SAFE_BEGIN(op) \
	if (_PyTrash_delete_nesting < PyTrash_UNWIND_LEVEL) { \
		++_PyTrash_delete_nesting;
		/* The body of the deallocator is here. */
#define Py_TRASHCAN_SAFE_END(op) \
		--_PyTrash_delete_nesting; \
		if (_PyTrash_delete_later && _PyTrash_delete_nesting <= 0) \
			_PyTrash_destroy_chain(); \
	} \
	else \
		_PyTrash_deposit_object((PyObject*)op);

#ifdef __cplusplus
}
#endif
#endif /* !Py_OBJECT_H */
