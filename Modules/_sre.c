/*
 * Secret Labs' Regular Expression Engine
 *
 * regular expression matching engine
 *
 * partial history:
 * 99-10-24 fl  created (based on existing template matcher code)
 * 00-03-06 fl  first alpha, sort of (0.5)
 * 00-06-30 fl  added fast search optimization (0.9.3)
 * 00-06-30 fl  added assert (lookahead) primitives, etc (0.9.4)
 * 00-07-02 fl  added charset optimizations, etc (0.9.5)
 * 00-07-03 fl  store code in pattern object, lookbehind, etc
 * 00-07-08 fl  added regs attribute
 * 00-07-21 fl  reset lastindex in scanner methods (0.9.6)
 * 00-08-01 fl  fixes for 1.6b1 (0.9.8)
 *
 * Copyright (c) 1997-2000 by Secret Labs AB.  All rights reserved.
 *
 * This version of the SRE library can be redistributed under CNRI's
 * Python 1.6 license.  For any other use, please contact Secret Labs
 * AB (info@pythonware.com).
 *
 * Portions of this engine have been developed in cooperation with
 * CNRI.  Hewlett-Packard provided funding for 1.6 integration and
 * other compatibility work.
 */

#ifndef SRE_RECURSIVE

char copyright[] = " SRE 0.9.8 Copyright (c) 1997-2000 by Secret Labs AB ";

#include "Python.h"

#include "sre.h"

#if defined(HAVE_LIMITS_H)
#include <limits.h>
#else
#define INT_MAX 2147483647
#endif

#include <ctype.h>

/* name of this module, minus the leading underscore */
#define MODULE "sre"

/* defining this one enables tracing */
#undef VERBOSE

#if PY_VERSION_HEX >= 0x01060000
/* defining this enables unicode support (default under 1.6a1 and later) */
#define HAVE_UNICODE
#endif

/* -------------------------------------------------------------------- */
/* optional features */

/* enables fast searching */
#define USE_FAST_SEARCH

/* enables aggressive inlining (always on for Visual C) */
#undef USE_INLINE

/* -------------------------------------------------------------------- */

#if defined(_MSC_VER)
#pragma optimize("agtw", on) /* doesn't seem to make much difference... */
#pragma warning(disable: 4710) /* who cares if functions are not inlined ;-) */
/* fastest possible local call under MSVC */
#define LOCAL(type) static __inline type __fastcall
#elif defined(USE_INLINE)
#define LOCAL(type) static inline type
#else
#define LOCAL(type) static type
#endif

/* error codes */
#define SRE_ERROR_ILLEGAL -1 /* illegal opcode */
#define SRE_ERROR_STATE -2 /* illegal state */
#define SRE_ERROR_MEMORY -9 /* out of memory */

#if defined(VERBOSE)
#define TRACE(v) printf v
#else
#define TRACE(v)
#endif

#define PTR(ptr) ((SRE_CHAR*) (ptr) - (SRE_CHAR*) state->beginning)

/* -------------------------------------------------------------------- */
/* search engine state */

/* default character predicates (run sre_chars.py to regenerate tables) */

#define SRE_DIGIT_MASK 1
#define SRE_SPACE_MASK 2
#define SRE_LINEBREAK_MASK 4
#define SRE_ALNUM_MASK 8
#define SRE_WORD_MASK 16

static char sre_char_info[128] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 6, 2,
2, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0,
0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 25, 25, 25, 25, 25, 25, 25, 25,
25, 25, 0, 0, 0, 0, 0, 0, 0, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 0, 0,
0, 0, 16, 0, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24,
24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 24, 0, 0, 0, 0, 0 };

static char sre_char_lower[128] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,
10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43,
44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60,
61, 62, 63, 64, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107,
108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
122, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105,
106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119,
120, 121, 122, 123, 124, 125, 126, 127 };

static unsigned int sre_lower(unsigned int ch)
{
    return ((ch) < 128 ? sre_char_lower[ch] : ch);
}

#define SRE_IS_DIGIT(ch)\
    ((ch) < 128 ? (sre_char_info[(ch)] & SRE_DIGIT_MASK) : 0)
#define SRE_IS_SPACE(ch)\
    ((ch) < 128 ? (sre_char_info[(ch)] & SRE_SPACE_MASK) : 0)
#define SRE_IS_LINEBREAK(ch)\
    ((ch) < 128 ? (sre_char_info[(ch)] & SRE_LINEBREAK_MASK) : 0)
#define SRE_IS_ALNUM(ch)\
    ((ch) < 128 ? (sre_char_info[(ch)] & SRE_ALNUM_MASK) : 0)
#define SRE_IS_WORD(ch)\
    ((ch) < 128 ? (sre_char_info[(ch)] & SRE_WORD_MASK) : 0)

/* locale-specific character predicates */

static unsigned int sre_lower_locale(unsigned int ch)
{
    return ((ch) < 256 ? tolower((ch)) : ch);
}
#define SRE_LOC_IS_DIGIT(ch) ((ch) < 256 ? isdigit((ch)) : 0)
#define SRE_LOC_IS_SPACE(ch) ((ch) < 256 ? isspace((ch)) : 0)
#define SRE_LOC_IS_LINEBREAK(ch) ((ch) == '\n')
#define SRE_LOC_IS_ALNUM(ch) ((ch) < 256 ? isalnum((ch)) : 0)
#define SRE_LOC_IS_WORD(ch) (SRE_LOC_IS_ALNUM((ch)) || (ch) == '_')

/* unicode-specific character predicates */

#if defined(HAVE_UNICODE)
static unsigned int sre_lower_unicode(unsigned int ch)
{
    return (unsigned int) Py_UNICODE_TOLOWER((Py_UNICODE)(ch));
}
#define SRE_UNI_IS_DIGIT(ch) Py_UNICODE_ISDIGIT((Py_UNICODE)(ch))
#define SRE_UNI_IS_SPACE(ch) Py_UNICODE_ISSPACE((Py_UNICODE)(ch))
#define SRE_UNI_IS_LINEBREAK(ch) Py_UNICODE_ISLINEBREAK((Py_UNICODE)(ch))
#define SRE_UNI_IS_ALNUM(ch) Py_UNICODE_ISALNUM((Py_UNICODE)(ch))
#define SRE_UNI_IS_WORD(ch) (SRE_UNI_IS_ALNUM((ch)) || (ch) == '_')
#endif

LOCAL(int)
sre_category(SRE_CODE category, unsigned int ch)
{
    switch (category) {

    case SRE_CATEGORY_DIGIT:
        return SRE_IS_DIGIT(ch);
    case SRE_CATEGORY_NOT_DIGIT:
        return !SRE_IS_DIGIT(ch);
    case SRE_CATEGORY_SPACE:
        return SRE_IS_SPACE(ch);
    case SRE_CATEGORY_NOT_SPACE:
        return !SRE_IS_SPACE(ch);
    case SRE_CATEGORY_WORD:
        return SRE_IS_WORD(ch);
    case SRE_CATEGORY_NOT_WORD:
        return !SRE_IS_WORD(ch);
    case SRE_CATEGORY_LINEBREAK:
        return SRE_IS_LINEBREAK(ch);
    case SRE_CATEGORY_NOT_LINEBREAK:
        return !SRE_IS_LINEBREAK(ch);

    case SRE_CATEGORY_LOC_WORD:
        return SRE_LOC_IS_WORD(ch);
    case SRE_CATEGORY_LOC_NOT_WORD:
        return !SRE_LOC_IS_WORD(ch);

#if defined(HAVE_UNICODE)
    case SRE_CATEGORY_UNI_DIGIT:
        return SRE_UNI_IS_DIGIT(ch);
    case SRE_CATEGORY_UNI_NOT_DIGIT:
        return !SRE_UNI_IS_DIGIT(ch);
    case SRE_CATEGORY_UNI_SPACE:
        return SRE_UNI_IS_SPACE(ch);
    case SRE_CATEGORY_UNI_NOT_SPACE:
        return !SRE_UNI_IS_SPACE(ch);
    case SRE_CATEGORY_UNI_WORD:
        return SRE_UNI_IS_WORD(ch);
    case SRE_CATEGORY_UNI_NOT_WORD:
        return !SRE_UNI_IS_WORD(ch);
    case SRE_CATEGORY_UNI_LINEBREAK:
        return SRE_UNI_IS_LINEBREAK(ch);
    case SRE_CATEGORY_UNI_NOT_LINEBREAK:
        return !SRE_UNI_IS_LINEBREAK(ch);
#endif
    }
    return 0;
}

/* helpers */

static void
mark_init(SRE_STATE* state)
{
    state->mark_stack = NULL;
    state->mark_stack_size = state->mark_stack_base = 0;
}

static void
mark_fini(SRE_STATE* state)
{
#if 0
    /* FIXME: debugging */
    if (state->maxlevel > 0)
        printf("max %d\n", state->maxlevel);
    if (state->mark_stack_base > 0)
        printf("mark stack %d\n", state->mark_stack_base);
#endif

    if (state->mark_stack)
        free(state->mark_stack);
    mark_init(state);
}

static int
mark_save(SRE_STATE* state, int lo, int hi)
{
    void* stack;
    int size;
    int minsize, newsize;

    if (hi <= lo)
        return 0;

    size = (hi - lo) + 1;

    newsize = state->mark_stack_size;
    minsize = state->mark_stack_base + size;

    if (newsize < minsize) {
        /* create new stack */
        if (!newsize) {
            newsize = 512;
            if (newsize < minsize)
                newsize = minsize;
            TRACE(("allocate stack %d\n", newsize));
            stack = malloc(sizeof(void*) * newsize);
        } else {
            /* grow the stack */
            while (newsize < minsize)
                newsize += newsize;
            TRACE(("grow stack to %d\n", newsize));
            stack = realloc(state->mark_stack, sizeof(void*) * newsize);
        }
        if (!stack) {
            mark_fini(state);
            return SRE_ERROR_MEMORY;
        }
        state->mark_stack = stack;
        state->mark_stack_size = newsize;
    }

    TRACE(("copy %d:%d to %d\n", lo, hi, state->mark_stack_base));

    memcpy(state->mark_stack + state->mark_stack_base, state->mark + lo,
           size * sizeof(void*));

    state->mark_stack_base += size;

    return 0;
}

static int
mark_restore(SRE_STATE* state, int lo, int hi)
{
    int size;

    if (hi <= lo)
        return 0;

    size = (hi - lo) + 1;

    state->mark_stack_base -= size;

    TRACE(("copy %d:%d from %d\n", lo, hi, state->mark_stack_base));

    memcpy(state->mark + lo, state->mark_stack + state->mark_stack_base,
           size * sizeof(void*));

    return 0;
}

/* generate 8-bit version */

#define SRE_CHAR unsigned char
#define SRE_AT sre_at
#define SRE_MEMBER sre_member
#define SRE_MATCH sre_match
#define SRE_SEARCH sre_search

#if defined(HAVE_UNICODE)

#define SRE_RECURSIVE
#include "_sre.c"
#undef SRE_RECURSIVE

#undef SRE_SEARCH
#undef SRE_MATCH
#undef SRE_MEMBER
#undef SRE_AT
#undef SRE_CHAR

/* generate 16-bit unicode version */

#define SRE_CHAR Py_UNICODE
#define SRE_AT sre_uat
#define SRE_MEMBER sre_umember
#define SRE_MATCH sre_umatch
#define SRE_SEARCH sre_usearch
#endif

#endif /* SRE_RECURSIVE */

/* -------------------------------------------------------------------- */
/* String matching engine */

/* the following section is compiled twice, with different character
   settings */

LOCAL(int)
SRE_AT(SRE_STATE* state, SRE_CHAR* ptr, SRE_CODE at)
{
    /* check if pointer is at given position */

    int this, that;

    switch (at) {

    case SRE_AT_BEGINNING:
        return ((void*) ptr == state->beginning);

    case SRE_AT_BEGINNING_LINE:
        return ((void*) ptr == state->beginning ||
                SRE_IS_LINEBREAK((int) ptr[-1]));

    case SRE_AT_END:
        return (((void*) (ptr+1) == state->end &&
                 SRE_IS_LINEBREAK((int) ptr[0])) ||
                ((void*) ptr == state->end));

    case SRE_AT_END_LINE:
        return ((void*) ptr == state->end ||
                SRE_IS_LINEBREAK((int) ptr[0]));

    case SRE_AT_BOUNDARY:
        if (state->beginning == state->end)
            return 0;
        that = ((void*) ptr > state->beginning) ?
            SRE_IS_WORD((int) ptr[-1]) : 0;
        this = ((void*) ptr < state->end) ?
            SRE_IS_WORD((int) ptr[0]) : 0;
        return this != that;

    case SRE_AT_NON_BOUNDARY:
        if (state->beginning == state->end)
            return 0;
        that = ((void*) ptr > state->beginning) ?
            SRE_IS_WORD((int) ptr[-1]) : 0;
        this = ((void*) ptr < state->end) ?
            SRE_IS_WORD((int) ptr[0]) : 0;
        return this == that;
    }

    return 0;
}

LOCAL(int)
SRE_MEMBER(SRE_CODE* set, SRE_CODE ch)
{
    /* check if character is a member of the given set */

    int ok = 1;

    for (;;) {
        switch (*set++) {

        case SRE_OP_NEGATE:
            ok = !ok;
            break;

        case SRE_OP_FAILURE:
            return !ok;

        case SRE_OP_LITERAL:
            /* <LITERAL> <code> */
            if (ch == set[0])
                return ok;
            set++;
            break;

        case SRE_OP_RANGE:
            /* <RANGE> <lower> <upper> */
            if (set[0] <= ch && ch <= set[1])
                return ok;
            set += 2;
            break;

        case SRE_OP_CHARSET:
            /* <CHARSET> <bitmap> (16 bits per code word) */
            if (ch < 256 && (set[ch >> 4] & (1 << (ch & 15))))
                return ok;
            set += 16;
            break;

        case SRE_OP_CATEGORY:
            /* <CATEGORY> <code> */
            if (sre_category(set[0], (int) ch))
                return ok;
            set += 1;
            break;

        default:
            /* internal error -- there's not much we can do about it
               here, so let's just pretend it didn't match... */
            return 0;
        }
    }
}

LOCAL(int)
SRE_MATCH(SRE_STATE* state, SRE_CODE* pattern, int level)
{
    /* check if string matches the given pattern.  returns -1 for
       error, 0 for failure, and 1 for success */

    SRE_CHAR* end = state->end;
    SRE_CHAR* ptr = state->ptr;
    int i, count;
    SRE_REPEAT* rp;
    int lastmark;

    SRE_REPEAT rep; /* FIXME: <fl> allocate in STATE instead */

    TRACE(("%8d: enter %d\n", PTR(ptr), level));

    if (pattern[0] == SRE_OP_INFO) {
        /* optimization info block */
        /* <INFO> <1=skip> <2=flags> <3=min> ... */
        if (pattern[3] && (end - ptr) < pattern[3]) {
            TRACE(("reject (got %d chars, need %d)\n",
                   (end - ptr), pattern[3]));
            return 0;
        }
        pattern += pattern[1] + 1;
    }

    /* FIXME: debugging */
    if (level > state->maxlevel)
        state->maxlevel = level;

    for (;;) {

        switch (*pattern++) {

        case SRE_OP_FAILURE:
            /* immediate failure */
            TRACE(("%8d: failure\n", PTR(ptr)));
            return 0;

        case SRE_OP_SUCCESS:
            /* end of pattern */
            TRACE(("%8d: success\n", PTR(ptr)));
            state->ptr = ptr;
            return 1;

        case SRE_OP_AT:
            /* match at given position */
            /* <AT> <code> */
            TRACE(("%8d: position %d\n", PTR(ptr), *pattern));
            if (!SRE_AT(state, ptr, *pattern))
                return 0;
            pattern++;
            break;

        case SRE_OP_CATEGORY:
            /* match at given category */
            /* <CATEGORY> <code> */
            TRACE(("%8d: category %d [category %d]\n", PTR(ptr),
                   *ptr, *pattern));
            if (ptr >= end || !sre_category(pattern[0], ptr[0]))
                return 0;
            TRACE(("%8d: category ok\n", PTR(ptr)));
            pattern++;
            ptr++;
            break;

        case SRE_OP_LITERAL:
            /* match literal string */
            /* <LITERAL> <code> */
            TRACE(("%8d: literal %c\n", PTR(ptr), pattern[0]));
            if (ptr >= end || (SRE_CODE) ptr[0] != pattern[0])
                return 0;
            pattern++;
            ptr++;
            break;

        case SRE_OP_NOT_LITERAL:
            /* match anything that is not literal character */
            /* <NOT_LITERAL> <code> */
            TRACE(("%8d: literal not %c\n", PTR(ptr), pattern[0]));
            if (ptr >= end || (SRE_CODE) ptr[0] == pattern[0])
                return 0;
            pattern++;
            ptr++;
            break;

        case SRE_OP_ANY:
            /* match anything */
            /* <ANY> */
            TRACE(("%8d: anything\n", PTR(ptr)));
            if (ptr >= end)
                return 0;
            ptr++;
            break;

        case SRE_OP_IN:
            /* match set member (or non_member) */
            /* <IN> <skip> <set> */
            TRACE(("%8d: set %c\n", PTR(ptr), *ptr));
            if (ptr >= end || !SRE_MEMBER(pattern + 1, *ptr))
                return 0;
            pattern += pattern[0];
            ptr++;
            break;

        case SRE_OP_GROUPREF:
            /* match backreference */
            TRACE(("%8d: group %d\n", PTR(ptr), pattern[0]));
            i = pattern[0];
            {
                SRE_CHAR* p = (SRE_CHAR*) state->mark[i+i];
                SRE_CHAR* e = (SRE_CHAR*) state->mark[i+i+1];
                if (!p || !e || e < p)
                    return 0;
                while (p < e) {
                    if (ptr >= end || *ptr != *p)
                        return 0;
                    p++; ptr++;
                }
            }
            pattern++;
            break;

        case SRE_OP_GROUPREF_IGNORE:
            /* match backreference */
            TRACE(("%8d: group ignore %d\n", PTR(ptr), pattern[0]));
            i = pattern[0];
            {
                SRE_CHAR* p = (SRE_CHAR*) state->mark[i+i];
                SRE_CHAR* e = (SRE_CHAR*) state->mark[i+i+1];
                if (!p || !e || e < p)
                    return 0;
                while (p < e) {
                    if (ptr >= end ||
                        state->lower(*ptr) != state->lower(*p))
                        return 0;
                    p++; ptr++;
                }
            }
            pattern++;
            break;

        case SRE_OP_LITERAL_IGNORE:
            TRACE(("%8d: literal lower(%c)\n", PTR(ptr), pattern[0]));
            if (ptr >= end ||
                state->lower(*ptr) != state->lower(*pattern))
                return 0;
            pattern++;
            ptr++;
            break;

        case SRE_OP_NOT_LITERAL_IGNORE:
            TRACE(("%8d: literal not lower(%c)\n", PTR(ptr), pattern[0]));
            if (ptr >= end ||
                state->lower(*ptr) == state->lower(*pattern))
                return 0;
            pattern++;
            ptr++;
            break;

        case SRE_OP_IN_IGNORE:
            TRACE(("%8d: set lower(%c)\n", PTR(ptr), *ptr));
            if (ptr >= end
                || !SRE_MEMBER(pattern+1, (SRE_CODE) state->lower(*ptr)))
                return 0;
            pattern += pattern[0];
            ptr++;
            break;

        case SRE_OP_MARK:
            /* set mark */
            /* <MARK> <gid> */
            TRACE(("%8d: set mark %d\n", PTR(ptr), pattern[0]));
            i = pattern[0];
            if (i & 1)
                state->lastindex = i/2 + 1;
            if (i > state->lastmark)
                state->lastmark = i;
            state->mark[i] = ptr;
            pattern++;
            break;

        case SRE_OP_JUMP:
        case SRE_OP_INFO:
            /* jump forward */
            /* <JUMP> <offset> */
            TRACE(("%8d: jump +%d\n", PTR(ptr), pattern[0]));
            pattern += pattern[0];
            break;

        case SRE_OP_ASSERT:
            /* assert subpattern */
            /* <ASSERT> <skip> <back> <pattern> */
            TRACE(("%8d: assert subpattern %d\n", PTR(ptr), pattern[1]));
            state->ptr = ptr - pattern[1];
            if (state->ptr < state->beginning)
                return 0;
            i = SRE_MATCH(state, pattern + 2, level + 1);
            if (i <= 0)
                return i;
            if (pattern[1] > 0 && state->ptr != ptr)
                return SRE_ERROR_STATE;
            pattern += pattern[0];
            break;

        case SRE_OP_ASSERT_NOT:
            /* assert not subpattern */
            /* <ASSERT_NOT> <skip> <back> <pattern> */
            TRACE(("%8d: assert not subpattern %d\n", PTR(ptr), pattern[1]));
            state->ptr = ptr - pattern[1];
            if (state->ptr < state->beginning)
                return 0;
            i = SRE_MATCH(state, pattern + 2, level + 1);
            if (i < 0)
                return i;
            if (i)
                return 0;
            if (pattern[1] > 0 && state->ptr != ptr)
                return SRE_ERROR_STATE;
            pattern += pattern[0];
            break;

        case SRE_OP_BRANCH:
            /* alternation */
            /* <BRANCH> <0=skip> code <JUMP> ... <NULL> */
            TRACE(("%8d: branch\n", PTR(ptr)));
            {
                lastmark = state->lastmark;
                while (pattern[0]) {
                    TRACE(("%8d: try branch\n", PTR(ptr)));
                    if (pattern[1] != SRE_OP_LITERAL ||
                        (ptr < end && (SRE_CODE) ptr[0] == pattern[2])) {
                        state->ptr = ptr;
                        i = SRE_MATCH(state, pattern + 1, level + 1);
                        if (i)
                            return i;
                    }
                    while (state->lastmark > lastmark)
                        state->mark[state->lastmark--] = NULL;
                    pattern += pattern[0];
                }
            }
            return 0;

        case SRE_OP_REPEAT_ONE:
            /* match repeated sequence (maximizing regexp) */

            /* this operator only works if the repeated item is
               exactly one character wide, and we're not already
               collecting backtracking points.  for other cases,
               use the MAX_REPEAT operator instead */

            /* <REPEAT_ONE> <skip> <1=min> <2=max> item <SUCCESS> tail */

            TRACE(("%8d: max repeat one {%d,%d}\n", PTR(ptr),
                   pattern[1], pattern[2]));

            count = 0;

            if (pattern[3] == SRE_OP_ANY) {
                /* repeated wildcard.  skip to the end of the target
                   string, and backtrack from there */
                /* FIXME: must look for line endings */
                if (ptr + pattern[1] > end)
                    return 0; /* cannot match */
                count = pattern[2];
                if (count > end - ptr)
                    count = end - ptr;
                ptr += count;

            } else if (pattern[3] == SRE_OP_LITERAL) {
                /* repeated literal */
                SRE_CODE chr = pattern[4];
                while (count < (int) pattern[2]) {
                    if (ptr >= end || (SRE_CODE) ptr[0] != chr)
                        break;
                    ptr++;
                    count++;
                }

            } else if (pattern[3] == SRE_OP_LITERAL_IGNORE) {
                /* repeated literal */
                SRE_CODE chr = pattern[4];
                while (count < (int) pattern[2]) {
                    if (ptr >= end || (SRE_CODE) state->lower(*ptr) != chr)
                        break;
                    ptr++;
                    count++;
                }

            } else if (pattern[3] == SRE_OP_NOT_LITERAL) {
                /* repeated non-literal */
                SRE_CODE chr = pattern[4];
                while (count < (int) pattern[2]) {
                    if (ptr >= end || (SRE_CODE) ptr[0] == chr)
                        break;
                    ptr++;
                    count++;
                }

            } else if (pattern[3] == SRE_OP_NOT_LITERAL_IGNORE) {
                /* repeated non-literal */
                SRE_CODE chr = pattern[4];
                while (count < (int) pattern[2]) {
                    if (ptr >= end || (SRE_CODE) state->lower(ptr[0]) == chr)
                        break;
                    ptr++;
                    count++;
                }

            } else if (pattern[3] == SRE_OP_IN) {
                /* repeated set */
                while (count < (int) pattern[2]) {
                    if (ptr >= end || !SRE_MEMBER(pattern + 5, *ptr))
                        break;
                    ptr++;
                    count++;
                }

            } else {
                /* repeated single character pattern */
                state->ptr = ptr;
                while (count < (int) pattern[2]) {
                    i = SRE_MATCH(state, pattern + 3, level + 1);
                    if (i < 0)
                        return i;
                    if (!i)
                        break;
                    count++;
                }
                state->ptr = ptr;
                ptr += count;
            }

            /* when we arrive here, count contains the number of
               matches, and ptr points to the tail of the target
               string.  check if the rest of the pattern matches,
               and backtrack if not. */

            TRACE(("%8d: repeat %d found\n", PTR(ptr), count));

            if (count < (int) pattern[1])
                return 0;

            if (pattern[pattern[0]] == SRE_OP_SUCCESS) {
                /* tail is empty.  we're finished */
                TRACE(("%8d: tail is empty\n", PTR(ptr)));
                state->ptr = ptr;
                return 1;

            } else if (pattern[pattern[0]] == SRE_OP_LITERAL) {
                /* tail starts with a literal. skip positions where
                   the rest of the pattern cannot possibly match */
                SRE_CODE chr = pattern[pattern[0]+1];
                TRACE(("%8d: tail is literal %d\n", PTR(ptr), chr));
                for (;;) {
                    TRACE(("%8d: scan for tail match\n", PTR(ptr)));
                    while (count >= (int) pattern[1] &&
                           (ptr >= end || *ptr != chr)) {
                        ptr--;
                        count--;
                    }
                    TRACE(("%8d: check tail\n", PTR(ptr)));
                    if (count < (int) pattern[1])
                        break;
                    state->ptr = ptr;
                    i = SRE_MATCH(state, pattern + pattern[0], level + 1);
                    if (i > 0) {
                        TRACE(("%8d: repeat %d picked\n", PTR(ptr), count));
                        return 1;
                    }
                    ptr--;
                    count--;
                }

            } else {
                /* general case */
                TRACE(("%8d: tail is pattern\n", PTR(ptr)));
                while (count >= (int) pattern[1]) {
                    state->ptr = ptr;
                    i = SRE_MATCH(state, pattern + pattern[0], level + 1);
                    if (i < 0)
                        return i;
                    if (i) {
                        TRACE(("%8d: repeat %d picked\n", PTR(ptr), count));
                        return 1;
                    }
                    ptr--;
                    count--;
                }
            }
            return 0;

        case SRE_OP_REPEAT:
            /* create repeat context.  all the hard work is done
               by the UNTIL operator */
            /* <REPEAT> <skip> <1=min> <2=max> item <UNTIL> tail */
            TRACE(("%8d: repeat {%d,%d}\n", PTR(ptr),
                   pattern[1], pattern[2]));

            rep.count = -1;
            rep.pattern = pattern;

            /* install new repeat context */
            rep.prev = state->repeat;
            state->repeat = &rep;

            state->ptr = ptr;
            i = SRE_MATCH(state, pattern + pattern[0], level + 1);

            state->repeat = rep.prev;

            return i;

        case SRE_OP_MAX_UNTIL:
            /* maximizing repeat */
            /* <REPEAT> <skip> <1=min> <2=max> item <MAX_UNTIL> tail */

            /* FIXME: we probably need to deal with zero-width
               matches in here... */

            rp = state->repeat;
            if (!rp)
                return SRE_ERROR_STATE;

            state->ptr = ptr;

            count = rp->count + 1;

            TRACE(("%8d: max until %d\n", PTR(ptr), count));

            if (count < rp->pattern[1]) {
                /* not enough matches */
                TRACE(("%8d: match item (required)\n", PTR(ptr)));
                rp->count = count;
                i = SRE_MATCH(state, rp->pattern + 3, level + 1);
                if (i)
                    return i;
                rp->count = count - 1;
                state->ptr = ptr;
                return 0;
            }

            if (count < rp->pattern[2] || rp->pattern[2] == 65535) {
                TRACE(("%8d: match item (optional)\n", PTR(ptr)));
                /* we may have enough matches, but if we can
                   match another item, do so */
                rp->count = count;
                lastmark = state->lastmark;
                mark_save(state, 0, lastmark);
                i = SRE_MATCH(state, rp->pattern + 3, level + 1);
                if (i)
                    return i;
                mark_restore(state, 0, lastmark);
                rp->count = count - 1;
                state->ptr = ptr;
            }

            /* cannot match more repeated items here.  make sure the
               tail matches */
            TRACE(("%8d: match tail\n", PTR(ptr)));
            state->repeat = rp->prev;
            i = SRE_MATCH(state, pattern, level + 1);
            if (i)
                return i;
            state->repeat = rp;
            return 0;

        case SRE_OP_MIN_UNTIL:
            /* minimizing repeat */
            /* <REPEAT> <skip> <1=min> <2=max> item <MIN_UNTIL> tail */

            rp = state->repeat;
            if (!rp)
                return SRE_ERROR_STATE;

            count = rp->count + 1;

            TRACE(("%8d: min until %d\n", PTR(ptr), count));

            state->ptr = ptr;

            if (count < rp->pattern[1]) {
                /* not enough matches */
                TRACE(("%8d: match item (required)\n", PTR(ptr)));
                rp->count = count;
                i = SRE_MATCH(state, rp->pattern + 3, level + 1);
                if (i)
                    return i;
                rp->count = count-1;
                state->ptr = ptr;
                return 0;
            }

            /* see if the tail matches */
            TRACE(("%8d: match tail\n", PTR(ptr)));
            state->repeat = rp->prev;
            i = SRE_MATCH(state, pattern, level + 1);
            if (i) {
                /* free(rp); */
                return i;
            }
            state->repeat = rp;

            if (count >= rp->pattern[2] && rp->pattern[2] != 65535)
                return 0;

            TRACE(("%8d: match item (optional)\n", PTR(ptr)));
            rp->count = count;
            i = SRE_MATCH(state, rp->pattern + 3, level + 1);
            if (i)
                return i;
            rp->count = count - 1;
            return 0;

        default:
            TRACE(("%8d: unknown opcode %d\n", PTR(ptr), pattern[-1]));
            return SRE_ERROR_ILLEGAL;
        }
    }

    /* shouldn't end up here */
    return SRE_ERROR_ILLEGAL;
}

static int
SRE_SEARCH(SRE_STATE* state, SRE_CODE* pattern)
{
    SRE_CHAR* ptr = state->start;
    SRE_CHAR* end = state->end;
    int status = 0;
    int prefix_len = 0;
    SRE_CODE* prefix = NULL;
    SRE_CODE* charset = NULL;
    SRE_CODE* overlap = NULL;
    int flags = 0;

    if (pattern[0] == SRE_OP_INFO) {
        /* optimization info block */
        /* <INFO> <1=skip> <2=flags> <3=min> <4=max> <5=prefix info>  */

        flags = pattern[2];

        if (pattern[3] > 0) {
            /* adjust end point (but make sure we leave at least one
               character in there, so literal search will work) */
            end -= pattern[3]-1;
            if (end <= ptr)
                end = ptr+1;
        }

        if (flags & SRE_INFO_PREFIX) {
            /* pattern starts with a known prefix */
            prefix_len = pattern[5];
            prefix = pattern + 6;
            overlap = prefix + prefix_len - 1;
        } else if (flags & SRE_INFO_CHARSET)
            /* pattern starts with a character from a known set */
            charset = pattern + 5;

        pattern += 1 + pattern[1];
    }

#if defined(USE_FAST_SEARCH)
    if (prefix_len > 1) {
        /* pattern starts with a known prefix.  use the overlap
           table to skip forward as fast as we possibly can */
        int i = 0;
        end = state->end;
        while (ptr < end) {
            for (;;) {
                if ((SRE_CODE) ptr[0] != prefix[i]) {
                    if (!i)
                        break;
                    else
                        i = overlap[i];
                } else {
                    if (++i == prefix_len) {
                        /* found a potential match */
                        TRACE(("%8d: === SEARCH === hit\n", PTR(ptr)));
                        state->start = ptr - prefix_len + 1;
                        state->ptr = ptr + 1;
                        if (flags & SRE_INFO_LITERAL)
                            return 1; /* we got all of it */
                        status = SRE_MATCH(state, pattern + 2*prefix_len, 1);
                        if (status != 0)
                            return status;
                        /* close but no cigar -- try again */
                        i = overlap[i];
                    }
                    break;
                }
                
            }
            ptr++;
        }
        return 0;
    }
#endif

    if (pattern[0] == SRE_OP_LITERAL) {
        /* pattern starts with a literal character.  this is used
           for short prefixes, and if fast search is disabled */
        SRE_CODE chr = pattern[1];
        for (;;) {
            while (ptr < end && (SRE_CODE) ptr[0] != chr)
                ptr++;
            if (ptr == end)
                return 0;
            TRACE(("%8d: === SEARCH === literal\n", PTR(ptr)));
            state->start = ptr;
            state->ptr = ++ptr;
            status = SRE_MATCH(state, pattern + 2, 1);
            if (status != 0)
                break;
        }
    } else if (charset) {
        /* pattern starts with a character from a known set */
        for (;;) {
            while (ptr < end && !SRE_MEMBER(charset, ptr[0]))
                ptr++;
            if (ptr == end)
                return 0;
            TRACE(("%8d: === SEARCH === charset\n", PTR(ptr)));
            state->start = ptr;
            state->ptr = ptr;
            status = SRE_MATCH(state, pattern, 1);
            if (status != 0)
                break;
        }
    } else
        /* general case */
        while (ptr <= end) {
            TRACE(("%8d: === SEARCH ===\n", PTR(ptr))); 
            state->start = state->ptr = ptr++;
            status = SRE_MATCH(state, pattern, 1);
            if (status != 0)
                break;
        }

    return status;
}
    

#if !defined(SRE_RECURSIVE)

/* -------------------------------------------------------------------- */
/* factories and destructors */

/* see sre.h for object declarations */

staticforward PyTypeObject Pattern_Type;
staticforward PyTypeObject Match_Type;
staticforward PyTypeObject Scanner_Type;

static PyObject *
_compile(PyObject* self_, PyObject* args)
{
    /* "compile" pattern descriptor to pattern object */

    PatternObject* self;
    int i, n;

    PyObject* pattern;
    int flags = 0;
    PyObject* code;
    int groups = 0;
    PyObject* groupindex = NULL;
    PyObject* indexgroup = NULL;
    if (!PyArg_ParseTuple(args, "OiO|iOO", &pattern, &flags, &code,
                          &groups, &groupindex, &indexgroup))
        return NULL;

    code = PySequence_Fast(code, "code argument must be a sequence");
    if (!code)
        return NULL;

#if PY_VERSION_HEX >= 0x01060000
    n = PySequence_Size(code);
#else
    n = PySequence_Length(code);
#endif

    self = PyObject_NEW_VAR(PatternObject, &Pattern_Type, 100*n);
    if (!self) {
        Py_DECREF(code);
        return NULL;
    }

    for (i = 0; i < n; i++) {
        PyObject *o = PySequence_Fast_GET_ITEM(code, i);
        self->code[i] = (SRE_CODE) PyInt_AsLong(o);
    }

    Py_DECREF(code);

    if (PyErr_Occurred())
        return NULL;

    Py_INCREF(pattern);
    self->pattern = pattern;

    self->flags = flags;

    self->groups = groups;

    Py_XINCREF(groupindex);
    self->groupindex = groupindex;

    Py_XINCREF(indexgroup);
    self->indexgroup = indexgroup;

    return (PyObject*) self;
}

static PyObject *
sre_codesize(PyObject* self, PyObject* args)
{
    return Py_BuildValue("i", sizeof(SRE_CODE));
}

static PyObject *
sre_getlower(PyObject* self, PyObject* args)
{
    int character, flags;
    if (!PyArg_ParseTuple(args, "ii", &character, &flags))
        return NULL;
    if (flags & SRE_FLAG_LOCALE)
        return Py_BuildValue("i", sre_lower_locale(character));
#if defined(HAVE_UNICODE)
    if (flags & SRE_FLAG_UNICODE)
        return Py_BuildValue("i", sre_lower_unicode(character));
#endif
    return Py_BuildValue("i", sre_lower(character));
}

LOCAL(void)
state_reset(SRE_STATE* state)
{
    int i;

    state->lastmark = 0;

    /* FIXME: dynamic! */
    for (i = 0; i < SRE_MARK_SIZE; i++)
        state->mark[i] = NULL;

    state->lastindex = -1;

    state->repeat = NULL;

    /* FIXME: debugging */
    state->maxlevel = 0;

    mark_fini(state);
}

LOCAL(PyObject*)
state_init(SRE_STATE* state, PatternObject* pattern, PyObject* string,
           int start, int end)
{
    /* prepare state object */

    PyBufferProcs *buffer;
    int size, bytes;
    void* ptr;

    /* get pointer to string buffer */
    buffer = string->ob_type->tp_as_buffer;
    if (!buffer || !buffer->bf_getreadbuffer || !buffer->bf_getsegcount ||
        buffer->bf_getsegcount(string, NULL) != 1) {
        PyErr_SetString(PyExc_TypeError, "expected string or buffer");
        return NULL;
    }

    /* determine buffer size */
    bytes = buffer->bf_getreadbuffer(string, 0, &ptr);
    if (bytes < 0) {
        PyErr_SetString(PyExc_TypeError, "buffer has negative size");
        return NULL;
    }

    /* determine character size */

#if PY_VERSION_HEX >= 0x01060000
    size = PyObject_Size(string);
#else
    size = PyObject_Length(string);
#endif

    if (PyString_Check(string) || bytes == size)
        state->charsize = 1;
#if defined(HAVE_UNICODE)
    else if (bytes == (int) (size * sizeof(Py_UNICODE)))
        state->charsize = sizeof(Py_UNICODE);
#endif
    else {
        PyErr_SetString(PyExc_TypeError, "buffer size mismatch");
        return NULL;
    }

    /* adjust boundaries */
    if (start < 0)
        start = 0;
    else if (start > size)
        start = size;

    if (end < 0)
        end = 0;
    else if (end > size)
        end = size;

    state->beginning = ptr;

    state->start = (void*) ((char*) ptr + start * state->charsize);
    state->end = (void*) ((char*) ptr + end * state->charsize);

    Py_INCREF(string);
    state->string = string;
    state->pos = start;
    state->endpos = end;

    if (pattern->flags & SRE_FLAG_LOCALE)
        state->lower = sre_lower_locale;
#if defined(HAVE_UNICODE)
    else if (pattern->flags & SRE_FLAG_UNICODE)
        state->lower = sre_lower_unicode;
#endif
    else
        state->lower = sre_lower;

    state->mark_stack = NULL;
    state->mark_stack_base = 0;

    state_reset(state);

    return string;
}

LOCAL(void)
state_fini(SRE_STATE* state)
{
    Py_XDECREF(state->string);
    mark_fini(state);
}

LOCAL(PyObject*)
state_getslice(SRE_STATE* state, int index, PyObject* string)
{
    index = (index - 1) * 2;

    if (string == Py_None || !state->mark[index] || !state->mark[index+1]) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return PySequence_GetSlice(
        string,
        ((char*)state->mark[index] - (char*)state->beginning) /
        state->charsize,
        ((char*)state->mark[index+1] - (char*)state->beginning) /
        state->charsize
        );
}

static PyObject*
pattern_new_match(PatternObject* pattern, SRE_STATE* state, int status)
{
    /* create match object (from state object) */

    MatchObject* match;
    int i, j;
    char* base;
    int n;

    if (status > 0) {

        /* create match object (with room for extra group marks) */
        match = PyObject_NEW_VAR(MatchObject, &Match_Type,
                                 2*(pattern->groups+1));
        if (!match)
            return NULL;

        Py_INCREF(pattern);
        match->pattern = pattern;

        Py_INCREF(state->string);
        match->string = state->string;

        match->regs = NULL;
        match->groups = pattern->groups+1;

        /* fill in group slices */

        base = (char*) state->beginning;
        n = state->charsize;

        match->mark[0] = ((char*) state->start - base) / n;
        match->mark[1] = ((char*) state->ptr - base) / n;

        for (i = j = 0; i < pattern->groups; i++, j+=2)
            if (j+1 <= state->lastmark && state->mark[j] && state->mark[j+1]) {
                match->mark[j+2] = ((char*) state->mark[j] - base) / n;
                match->mark[j+3] = ((char*) state->mark[j+1] - base) / n;
            } else
                match->mark[j+2] = match->mark[j+3] = -1; /* undefined */

        match->pos = state->pos;
        match->endpos = state->endpos;

        match->lastindex = state->lastindex;

        return (PyObject*) match;

    } else if (status < 0) {

        /* internal error */
        PyErr_SetString(
            PyExc_RuntimeError, "internal error in regular expression engine"
            );
        return NULL;

    }

    Py_INCREF(Py_None);
    return Py_None;
}

static PyObject*
pattern_scanner(PatternObject* pattern, PyObject* args)
{
    /* create search state object */

    ScannerObject* self;

    PyObject* string;
    int start = 0;
    int end = INT_MAX;
    if (!PyArg_ParseTuple(args, "O|ii:scanner", &string, &start, &end))
        return NULL;

    /* create scanner object */
    self = PyObject_NEW(ScannerObject, &Scanner_Type);
    if (!self)
        return NULL;

    string = state_init(&self->state, pattern, string, start, end);
    if (!string) {
        PyObject_Del(self);
        return NULL;
    }

    Py_INCREF(pattern);
    self->pattern = (PyObject*) pattern;

    return (PyObject*) self;
}

static void
pattern_dealloc(PatternObject* self)
{
    Py_XDECREF(self->pattern);
    Py_XDECREF(self->groupindex);
    PyObject_DEL(self);
}

static PyObject*
pattern_match(PatternObject* self, PyObject* args)
{
    SRE_STATE state;
    int status;

    PyObject* string;
    int start = 0;
    int end = INT_MAX;
    if (!PyArg_ParseTuple(args, "O|ii:match", &string, &start, &end))
        return NULL;

    string = state_init(&state, self, string, start, end);
    if (!string)
        return NULL;

    state.ptr = state.start;

    if (state.charsize == 1) {
        status = sre_match(&state, PatternObject_GetCode(self), 1);
    } else {
#if defined(HAVE_UNICODE)
        status = sre_umatch(&state, PatternObject_GetCode(self), 1);
#endif
    }

    state_fini(&state);

    return pattern_new_match(self, &state, status);
}

static PyObject*
pattern_search(PatternObject* self, PyObject* args)
{
    SRE_STATE state;
    int status;

    PyObject* string;
    int start = 0;
    int end = INT_MAX;
    if (!PyArg_ParseTuple(args, "O|ii:search", &string, &start, &end))
        return NULL;

    string = state_init(&state, self, string, start, end);
    if (!string)
        return NULL;

    if (state.charsize == 1) {
        status = sre_search(&state, PatternObject_GetCode(self));
    } else {
#if defined(HAVE_UNICODE)
        status = sre_usearch(&state, PatternObject_GetCode(self));
#endif
    }

    state_fini(&state);

    return pattern_new_match(self, &state, status);
}

static PyObject*
call(char* function, PyObject* args)
{
    PyObject* name;
    PyObject* module;
    PyObject* func;
    PyObject* result;

    name = PyString_FromString(MODULE);
    if (!name)
        return NULL;
    module = PyImport_Import(name);
    Py_DECREF(name);
    if (!module)
        return NULL;
    func = PyObject_GetAttrString(module, function);
    Py_DECREF(module);
    if (!func)
        return NULL;
    result = PyObject_CallObject(func, args);
    Py_DECREF(func);
    Py_DECREF(args);
    return result;
}

static PyObject*
pattern_sub(PatternObject* self, PyObject* args)
{
    PyObject* template;
    PyObject* string;
    PyObject* count = Py_False; /* zero */
    if (!PyArg_ParseTuple(args, "OO|O:sub", &template, &string, &count))
        return NULL;

    /* delegate to Python code */
    return call("_sub", Py_BuildValue("OOOO", self, template, string, count));
}

static PyObject*
pattern_subn(PatternObject* self, PyObject* args)
{
    PyObject* template;
    PyObject* string;
    PyObject* count = Py_False; /* zero */
    if (!PyArg_ParseTuple(args, "OO|O:subn", &template, &string, &count))
        return NULL;

    /* delegate to Python code */
    return call("_subn", Py_BuildValue("OOOO", self, template, string, count));
}

static PyObject*
pattern_split(PatternObject* self, PyObject* args)
{
    PyObject* string;
    PyObject* maxsplit = Py_False; /* zero */
    if (!PyArg_ParseTuple(args, "O|O:split", &string, &maxsplit))
        return NULL;

    /* delegate to Python code */
    return call("_split", Py_BuildValue("OOO", self, string, maxsplit));
}

static PyObject*
pattern_findall(PatternObject* self, PyObject* args)
{
    SRE_STATE state;
    PyObject* list;
    int status;
    int i;

    PyObject* string;
    int start = 0;
    int end = INT_MAX;
    if (!PyArg_ParseTuple(args, "O|ii:findall", &string, &start, &end))
        return NULL;

    string = state_init(&state, self, string, start, end);
    if (!string)
        return NULL;

    list = PyList_New(0);

    while (state.start <= state.end) {

        PyObject* item;
        
        state.ptr = state.start;

        if (state.charsize == 1) {
            status = sre_search(&state, PatternObject_GetCode(self));
        } else {
#if defined(HAVE_UNICODE)
            status = sre_usearch(&state, PatternObject_GetCode(self));
#endif
        }

        if (status > 0) {

            /* don't bother to build a match object */
            switch (self->groups) {
            case 0:
                item = PySequence_GetSlice(
                    string,
                    ((char*) state.start - (char*) state.beginning) /
                    state.charsize,
                    ((char*) state.ptr - (char*) state.beginning) /
                    state.charsize);
                if (!item)
                    goto error;
                break;
            case 1:
                item = state_getslice(&state, 1, string);
                if (!item)
                    goto error;
                break;
            default:
                item = PyTuple_New(self->groups);
                if (!item)
                    goto error;
                for (i = 0; i < self->groups; i++) {
                    PyObject* o = state_getslice(&state, i+1, string);
                    if (!o) {
                        Py_DECREF(item);
                        goto error;
                    }
                    PyTuple_SET_ITEM(item, i, o);
                }
                break;
            }

            if (PyList_Append(list, item) < 0) {
                Py_DECREF(item);
                goto error;
            }

            if (state.ptr == state.start)
                state.start = (void*) ((char*) state.ptr + state.charsize);
            else
                state.start = state.ptr;

        } else {

            if (status == 0)
                break;

            /* internal error */
            PyErr_SetString(
                PyExc_RuntimeError,
                "internal error in regular expression engine"
                );
            goto error;

        }
    }

    state_fini(&state);
    return list;

error:
    Py_DECREF(list);
    state_fini(&state);
    return NULL;
    
}

static PyMethodDef pattern_methods[] = {
    {"match", (PyCFunction) pattern_match, 1},
    {"search", (PyCFunction) pattern_search, 1},
    {"sub", (PyCFunction) pattern_sub, 1},
    {"subn", (PyCFunction) pattern_subn, 1},
    {"split", (PyCFunction) pattern_split, 1},
    {"findall", (PyCFunction) pattern_findall, 1},
    /* experimental */
    {"scanner", (PyCFunction) pattern_scanner, 1},
    {NULL, NULL}
};

static PyObject*  
pattern_getattr(PatternObject* self, char* name)
{
    PyObject* res;

    res = Py_FindMethod(pattern_methods, (PyObject*) self, name);

    if (res)
        return res;

    PyErr_Clear();

    /* attributes */
    if (!strcmp(name, "pattern")) {
        Py_INCREF(self->pattern);
        return self->pattern;
    }

    if (!strcmp(name, "flags"))
        return Py_BuildValue("i", self->flags);

    if (!strcmp(name, "groups"))
        return Py_BuildValue("i", self->groups);

    if (!strcmp(name, "groupindex") && self->groupindex) {
        Py_INCREF(self->groupindex);
        return self->groupindex;
    }

    PyErr_SetString(PyExc_AttributeError, name);
    return NULL;
}

statichere PyTypeObject Pattern_Type = {
    PyObject_HEAD_INIT(NULL)
    0, "SRE_Pattern",
    sizeof(PatternObject), sizeof(SRE_CODE),
    (destructor)pattern_dealloc, /*tp_dealloc*/
    0, /*tp_print*/
    (getattrfunc)pattern_getattr /*tp_getattr*/
};

/* -------------------------------------------------------------------- */
/* match methods */

static void
match_dealloc(MatchObject* self)
{
    Py_XDECREF(self->regs);
    Py_XDECREF(self->string);
    Py_DECREF(self->pattern);
    PyObject_DEL(self);
}

static PyObject*
match_getslice_by_index(MatchObject* self, int index, PyObject* def)
{
    if (index < 0 || index >= self->groups) {
        /* raise IndexError if we were given a bad group number */
        PyErr_SetString(
            PyExc_IndexError,
            "no such group"
            );
        return NULL;
    }

    index *= 2;

    if (self->string == Py_None || self->mark[index] < 0) {
        /* return default value if the string or group is undefined */
        Py_INCREF(def);
        return def;
    }

    return PySequence_GetSlice(
        self->string, self->mark[index], self->mark[index+1]
        );
}

static int
match_getindex(MatchObject* self, PyObject* index)
{
    int i;

    if (PyInt_Check(index))
        return (int) PyInt_AS_LONG(index);

    i = -1;

    if (self->pattern->groupindex) {
        index = PyObject_GetItem(self->pattern->groupindex, index);
        if (index) {
            if (PyInt_Check(index))
                i = (int) PyInt_AS_LONG(index);
            Py_DECREF(index);
        } else
            PyErr_Clear();
    }

    return i;
}

static PyObject*
match_getslice(MatchObject* self, PyObject* index, PyObject* def)
{
    return match_getslice_by_index(self, match_getindex(self, index), def);
}

static PyObject*
match_group(MatchObject* self, PyObject* args)
{
    PyObject* result;
    int i, size;

    size = PyTuple_GET_SIZE(args);

    switch (size) {
    case 0:
        result = match_getslice(self, Py_False, Py_None);
        break;
    case 1:
        result = match_getslice(self, PyTuple_GET_ITEM(args, 0), Py_None);
        break;
    default:
        /* fetch multiple items */
        result = PyTuple_New(size);
        if (!result)
            return NULL;
        for (i = 0; i < size; i++) {
            PyObject* item = match_getslice(
                self, PyTuple_GET_ITEM(args, i), Py_None
                );
            if (!item) {
                Py_DECREF(result);
                return NULL;
            }
            PyTuple_SET_ITEM(result, i, item);
        }
        break;
    }
    return result;
}

static PyObject*
match_groups(MatchObject* self, PyObject* args)
{
    PyObject* result;
    int index;

    PyObject* def = Py_None;
    if (!PyArg_ParseTuple(args, "|O:groups", &def))
        return NULL;

    result = PyTuple_New(self->groups-1);
    if (!result)
        return NULL;

    for (index = 1; index < self->groups; index++) {
        PyObject* item;
        item = match_getslice_by_index(self, index, def);
        if (!item) {
            Py_DECREF(result);
            return NULL;
        }
        PyTuple_SET_ITEM(result, index-1, item);
    }

    return result;
}

static PyObject*
match_groupdict(MatchObject* self, PyObject* args)
{
    PyObject* result;
    PyObject* keys;
    int index;

    PyObject* def = Py_None;
    if (!PyArg_ParseTuple(args, "|O:groupdict", &def))
        return NULL;

    result = PyDict_New();
    if (!result || !self->pattern->groupindex)
        return result;

    keys = PyMapping_Keys(self->pattern->groupindex);
    if (!keys) {
        Py_DECREF(result);
        return NULL;
    }

    for (index = 0; index < PyList_GET_SIZE(keys); index++) {
        PyObject* key;
        PyObject* item;
        key = PyList_GET_ITEM(keys, index);
        if (!key) {
            Py_DECREF(keys);
            Py_DECREF(result);
            return NULL;
        }
        item = match_getslice(self, key, def);
        if (!item) {
            Py_DECREF(key);
            Py_DECREF(keys);
            Py_DECREF(result);
            return NULL;
        }
        /* FIXME: <fl> this can fail, right? */
        PyDict_SetItem(result, key, item);
    }

    Py_DECREF(keys);

    return result;
}

static PyObject*
match_start(MatchObject* self, PyObject* args)
{
    int index;

    PyObject* index_ = Py_False; /* zero */
    if (!PyArg_ParseTuple(args, "|O:start", &index_))
        return NULL;

    index = match_getindex(self, index_);

    if (index < 0 || index >= self->groups) {
        PyErr_SetString(
            PyExc_IndexError,
            "no such group"
            );
        return NULL;
    }

    if (self->mark[index*2] < 0) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return Py_BuildValue("i", self->mark[index*2]);
}

static PyObject*
match_end(MatchObject* self, PyObject* args)
{
    int index;

    PyObject* index_ = Py_False; /* zero */
    if (!PyArg_ParseTuple(args, "|O:end", &index_))
        return NULL;

    index = match_getindex(self, index_);

    if (index < 0 || index >= self->groups) {
        PyErr_SetString(
            PyExc_IndexError,
            "no such group"
            );
        return NULL;
    }

    if (self->mark[index*2] < 0) {
        Py_INCREF(Py_None);
        return Py_None;
    }

    return Py_BuildValue("i", self->mark[index*2+1]);
}

LOCAL(PyObject*)
_pair(int i1, int i2)
{
    PyObject* pair;
    PyObject* item;

    pair = PyTuple_New(2);
    if (!pair)
        return NULL;

    item = PyInt_FromLong(i1);
    if (!item)
        goto error;
    PyTuple_SET_ITEM(pair, 0, item);

    item = PyInt_FromLong(i2);
    if (!item)
        goto error;
    PyTuple_SET_ITEM(pair, 1, item);

    return pair;

  error:
    Py_DECREF(pair);
    return NULL;
}

static PyObject*
match_span(MatchObject* self, PyObject* args)
{
    int index;

    PyObject* index_ = Py_False; /* zero */
    if (!PyArg_ParseTuple(args, "|O:span", &index_))
        return NULL;

    index = match_getindex(self, index_);

    if (index < 0 || index >= self->groups) {
        PyErr_SetString(
            PyExc_IndexError,
            "no such group"
            );
        return NULL;
    }

    if (self->mark[index*2] < 0) {
        Py_INCREF(Py_None);
        Py_INCREF(Py_None);
        return Py_BuildValue("OO", Py_None, Py_None);
    }

    return _pair(self->mark[index*2], self->mark[index*2+1]);
}

static PyObject*
match_regs(MatchObject* self)
{
    PyObject* regs;
    PyObject* item;
    int index;

    regs = PyTuple_New(self->groups);
    if (!regs)
        return NULL;

    for (index = 0; index < self->groups; index++) {
        item = _pair(self->mark[index*2], self->mark[index*2+1]);
        if (!item) {
            Py_DECREF(regs);
            return NULL;
        }
        PyTuple_SET_ITEM(regs, index, item);
    }

    Py_INCREF(regs);
    self->regs = regs;

    return regs;
}

static PyMethodDef match_methods[] = {
    {"group", (PyCFunction) match_group, 1},
    {"start", (PyCFunction) match_start, 1},
    {"end", (PyCFunction) match_end, 1},
    {"span", (PyCFunction) match_span, 1},
    {"groups", (PyCFunction) match_groups, 1},
    {"groupdict", (PyCFunction) match_groupdict, 1},
    {NULL, NULL}
};

static PyObject*  
match_getattr(MatchObject* self, char* name)
{
    PyObject* res;

    res = Py_FindMethod(match_methods, (PyObject*) self, name);
    if (res)
        return res;

    PyErr_Clear();

    if (!strcmp(name, "lastindex")) {
        if (self->lastindex >= 0)
            return Py_BuildValue("i", self->lastindex);
        Py_INCREF(Py_None);
        return Py_None;
    }

    if (!strcmp(name, "lastgroup")) {
        if (self->pattern->indexgroup && self->lastindex >= 0) {
            PyObject* result = PySequence_GetItem(
                self->pattern->indexgroup, self->lastindex
                );
            if (result)
                return result;
            PyErr_Clear();
        }
        Py_INCREF(Py_None);
        return Py_None;
    }

    if (!strcmp(name, "string")) {
        if (self->string) {
            Py_INCREF(self->string);
            return self->string;
        } else {
            Py_INCREF(Py_None);
            return Py_None;
        }
    }

    if (!strcmp(name, "regs")) {
        if (self->regs) {
            Py_INCREF(self->regs);
            return self->regs;
        } else
            return match_regs(self);
    }

    if (!strcmp(name, "re")) {
        Py_INCREF(self->pattern);
        return (PyObject*) self->pattern;
    }

    if (!strcmp(name, "pos"))
        return Py_BuildValue("i", self->pos);

    if (!strcmp(name, "endpos"))
        return Py_BuildValue("i", self->endpos);

    PyErr_SetString(PyExc_AttributeError, name);
    return NULL;
}

/* FIXME: implement setattr("string", None) as a special case (to
   detach the associated string, if any */

statichere PyTypeObject Match_Type = {
    PyObject_HEAD_INIT(NULL)
    0, "SRE_Match",
    sizeof(MatchObject), sizeof(int),
    (destructor)match_dealloc, /*tp_dealloc*/
    0, /*tp_print*/
    (getattrfunc)match_getattr /*tp_getattr*/
};

/* -------------------------------------------------------------------- */
/* scanner methods (experimental) */

static void
scanner_dealloc(ScannerObject* self)
{
    state_fini(&self->state);
    Py_DECREF(self->pattern);
    PyObject_DEL(self);
}

static PyObject*
scanner_match(ScannerObject* self, PyObject* args)
{
    SRE_STATE* state = &self->state;
    PyObject* match;
    int status;

    state_reset(state);

    state->ptr = state->start;

    if (state->charsize == 1) {
        status = sre_match(state, PatternObject_GetCode(self->pattern), 1);
    } else {
#if defined(HAVE_UNICODE)
        status = sre_umatch(state, PatternObject_GetCode(self->pattern), 1);
#endif
    }

    match = pattern_new_match((PatternObject*) self->pattern,
                               state, status);

    if (status == 0 || state->ptr == state->start)
        state->start = (void*) ((char*) state->ptr + state->charsize);
    else
        state->start = state->ptr;

    return match;
}


static PyObject*
scanner_search(ScannerObject* self, PyObject* args)
{
    SRE_STATE* state = &self->state;
    PyObject* match;
    int status;

    state_reset(state);

    state->ptr = state->start;

    if (state->charsize == 1) {
        status = sre_search(state, PatternObject_GetCode(self->pattern));
    } else {
#if defined(HAVE_UNICODE)
        status = sre_usearch(state, PatternObject_GetCode(self->pattern));
#endif
    }

    match = pattern_new_match((PatternObject*) self->pattern,
                               state, status);

    if (status == 0 || state->ptr == state->start)
        state->start = (void*) ((char*) state->ptr + state->charsize);
    else
        state->start = state->ptr;

    return match;
}

static PyMethodDef scanner_methods[] = {
    {"match", (PyCFunction) scanner_match, 0},
    {"search", (PyCFunction) scanner_search, 0},
    {NULL, NULL}
};

static PyObject*  
scanner_getattr(ScannerObject* self, char* name)
{
    PyObject* res;

    res = Py_FindMethod(scanner_methods, (PyObject*) self, name);
    if (res)
        return res;

    PyErr_Clear();

    /* attributes */
    if (!strcmp(name, "pattern")) {
        Py_INCREF(self->pattern);
        return self->pattern;
    }

    PyErr_SetString(PyExc_AttributeError, name);
    return NULL;
}

statichere PyTypeObject Scanner_Type = {
    PyObject_HEAD_INIT(NULL)
    0, "SRE_Scanner",
    sizeof(ScannerObject), 0,
    (destructor)scanner_dealloc, /*tp_dealloc*/
    0, /*tp_print*/
    (getattrfunc)scanner_getattr, /*tp_getattr*/
};

static PyMethodDef _functions[] = {
    {"compile", _compile, 1},
    {"getcodesize", sre_codesize, 1},
    {"getlower", sre_getlower, 1},
    {NULL, NULL}
};

void
#if defined(WIN32)
__declspec(dllexport)
#endif
init_sre(void)
{
    /* Patch object types */
    Pattern_Type.ob_type = Match_Type.ob_type =
        Scanner_Type.ob_type = &PyType_Type;

    Py_InitModule("_" MODULE, _functions);
}

#endif /* !defined(SRE_RECURSIVE) */
