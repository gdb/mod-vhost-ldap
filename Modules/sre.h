/*
 * Secret Labs' Regular Expression Engine
 * $Id$
 *
 * simple regular expression matching engine
 *
 * Copyright (c) 1997-2000 by Secret Labs AB.  All rights reserved.
 *
 * See the _sre.c file for information on usage and redistribution.
 */

#ifndef SRE_INCLUDED
#define SRE_INCLUDED

#include "sre_constants.h"

/* size of a code word (must be unsigned short or larger) */
#define SRE_CODE unsigned short

typedef struct {
    PyObject_HEAD
    PyObject* code; /* link to the code string object */
    int groups;
    PyObject* groupindex;
    /* compatibility */
    PyObject* pattern; /* pattern source (or None) */
    int flags; /* flags used when compiling pattern source */
} PatternObject;

#define PatternObject_GetCode(o)\
    ((void*) PyString_AS_STRING(((PatternObject*)(o))->code))

typedef struct {
    PyObject_HEAD
    PyObject* string; /* link to the target string */
    PatternObject* pattern; /* link to the regex (pattern) object */
    int groups; /* number of groups (start/end marks) */
    int mark[2];
} MatchObject;

typedef unsigned int (*SRE_TOLOWER_HOOK)(unsigned int ch);

typedef struct {
    /* stack elements */
    SRE_CODE* pattern;
    void* ptr;
} SRE_STACK;

typedef struct {
    /* string pointers */
    void* ptr; /* current position (also end of current slice) */
    void* beginning; /* start of original string */
    void* start; /* start of current slice */
    void* end; /* end of original string */
    /* character size */
    int charsize;
    /* registers */
    int lastmark;
    void* mark[64]; /* FIXME: <fl> should be dynamically allocated! */
    /* backtracking stack */
    SRE_STACK* stack;
    int stacksize;
    int stackbase;
    /* hooks */
    SRE_TOLOWER_HOOK tolower;
} SRE_STATE;

typedef struct {
    /* search helper */
    PyObject_HEAD
    PyObject* pattern;
    PyObject* string;
    SRE_STATE state;
} CursorObject;

#endif
