#ifndef Py_MYMALLOC_H
#define Py_MYMALLOC_H
/***********************************************************
Copyright 1991-1995 by Stichting Mathematisch Centrum, Amsterdam,
The Netherlands.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the names of Stichting Mathematisch
Centrum or CWI or Corporation for National Research Initiatives or
CNRI not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior
permission.

While CWI is the initial source for this software, a modified version
is made available by the Corporation for National Research Initiatives
(CNRI) at the Internet address ftp://ftp.python.org.

STICHTING MATHEMATISCH CENTRUM AND CNRI DISCLAIM ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH
CENTRUM OR CNRI BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL
DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

******************************************************************/

/* Lowest-level memory allocation interface */

#ifdef macintosh
#define ANY void
#endif

#ifdef __STDC__
#define ANY void
#endif

#ifdef __TURBOC__
#define ANY void
#endif

#ifdef __GNUC__
#define ANY void
#endif

#ifndef ANY
#define ANY char
#endif

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "myproto.h"

#ifdef __cplusplus
/* Move this down here since some C++ #include's don't like to be included
   inside an extern "C" */
extern "C" {
#endif

#ifdef SYMANTEC__CFM68K__
#pragma lib_export on
#endif

#ifndef DL_IMPORT       /* declarations for DLL import */
#define DL_IMPORT(RTYPE) RTYPE
#endif

#ifndef NULL
#define NULL ((ANY *)0)
#endif

#ifdef MALLOC_ZERO_RETURNS_NULL
/* XXX Always allocate one extra byte, since some malloc's return NULL
   XXX for malloc(0) or realloc(p, 0). */
#define _PyMem_EXTRA 1
#else
#define _PyMem_EXTRA 0
#endif

/*
 * Core memory allocator
 * =====================
 */

/* To make sure the interpreter is user-malloc friendly, all memory
   APIs are implemented on top of this one.

   The PyCore_* macros can be defined to make the interpreter use a
   custom allocator. Note that they are for internal use only. Both
   the core and extension modules should use the PyMem_* API. */

#ifndef PyCore_MALLOC_FUNC
#undef PyCore_REALLOC_FUNC
#undef PyCore_FREE_FUNC
#define PyCore_MALLOC_FUNC      malloc
#define PyCore_REALLOC_FUNC     realloc
#define PyCore_FREE_FUNC        free
#endif

#ifndef PyCore_MALLOC_PROTO
#undef PyCore_REALLOC_PROTO
#undef PyCore_FREE_PROTO
#define PyCore_MALLOC_PROTO     Py_PROTO((size_t))
#define PyCore_REALLOC_PROTO    Py_PROTO((ANY *, size_t))
#define PyCore_FREE_PROTO       Py_PROTO((ANY *))
#endif

#ifdef NEED_TO_DECLARE_MALLOC_AND_FRIEND
extern ANY *PyCore_MALLOC_FUNC PyCore_MALLOC_PROTO;
extern ANY *PyCore_REALLOC_FUNC PyCore_REALLOC_PROTO;
extern void PyCore_FREE_FUNC PyCore_FREE_PROTO;
#endif

#ifndef PyCore_MALLOC
#undef PyCore_REALLOC
#undef PyCore_FREE
#define PyCore_MALLOC(n)        PyCore_MALLOC_FUNC(n)
#define PyCore_REALLOC(p, n)    PyCore_REALLOC_FUNC((p), (n))
#define PyCore_FREE(p)          PyCore_FREE_FUNC(p)
#endif

/* BEWARE:

   Each interface exports both functions and macros. Extension modules
   should normally use the functions for ensuring binary compatibility
   of the user's code across Python versions. Subsequently, if the
   Python runtime switches to its own malloc (different from standard
   malloc), no recompilation is required for the extensions.

   The macro versions trade compatibility for speed. They can be used
   whenever there is a performance problem, but their use implies
   recompilation of the code for each new Python release. The Python
   core uses the macros because it *is* compiled on every upgrade.
   This might not be the case with 3rd party extensions in a custom
   setup (for example, a customer does not always have access to the
   source of 3rd party deliverables). You have been warned! */

/*
 * Raw memory interface
 * ====================
 */

/* Functions */

/* Function wrappers around PyCore_MALLOC and friends; useful if you
   need to be sure that you are using the same memory allocator as
   Python.  Note that the wrappers make sure that allocating 0 bytes
   returns a non-NULL pointer, even if the underlying malloc
   doesn't. Returned pointers must be checked for NULL explicitly.
   No action is performed on failure. */
extern DL_IMPORT(ANY *) PyMem_Malloc Py_PROTO((size_t));
extern DL_IMPORT(ANY *) PyMem_Realloc Py_PROTO((ANY *, size_t));
extern DL_IMPORT(void) PyMem_Free Py_PROTO((ANY *));

/* Starting from Python 1.6, the wrappers Py_{Malloc,Realloc,Free} are
   no longer supported. They used to call PyErr_NoMemory() on failure. */

/* Macros */
#define PyMem_MALLOC(n)         PyCore_MALLOC(n)
#define PyMem_REALLOC(p, n)     PyCore_REALLOC((ANY *)(p), (n))
#define PyMem_FREE(p)           PyCore_FREE((ANY *)(p))

/*
 * Type-oriented memory interface
 * ==============================
 */

/* Functions */
#define PyMem_New(type, n) \
	( (type *) PyMem_Malloc((n) * sizeof(type)) )
#define PyMem_Resize(p, type, n) \
	( (p) = (type *) PyMem_Realloc((n) * sizeof(type)) )
#define PyMem_Del(p) PyMem_Free(p)

/* Macros */
#define PyMem_NEW(type, n) \
	( (type *) PyMem_MALLOC(_PyMem_EXTRA + (n) * sizeof(type)) )
#define PyMem_RESIZE(p, type, n) \
	if ((p) == NULL) \
		(p) = (type *)(PyMem_MALLOC( \
				    _PyMem_EXTRA + (n) * sizeof(type))); \
	else \
		(p) = (type *)(PyMem_REALLOC((p), \
				    _PyMem_EXTRA + (n) * sizeof(type)))
#define PyMem_DEL(p) PyMem_FREE(p)

/* PyMem_XDEL is deprecated. To avoid the call when p is NULL,
   it is recommended to write the test explicitly in the code.
   Note that according to ANSI C, free(NULL) has no effect. */

#ifdef __cplusplus
}
#endif

#endif /* !Py_MYMALLOC_H */
