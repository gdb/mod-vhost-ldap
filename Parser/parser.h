#ifndef Py_PARSER_H
#define Py_PARSER_H
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

/* Parser interface */

#define MAXSTACK 500

typedef struct {
	int		 s_state;	/* State in current DFA */
	dfa		*s_dfa;		/* Current DFA */
	struct _node	*s_parent;	/* Where to add next node */
} stackentry;

typedef struct {
	stackentry	*s_top;		/* Top entry */
	stackentry	 s_base[MAXSTACK];/* Array of stack entries */
					/* NB The stack grows down */
} stack;

typedef struct {
	stack	 	p_stack;	/* Stack of parser states */
	grammar		*p_grammar;	/* Grammar to use */
	node		*p_tree;	/* Top of parse tree */
} parser_state;

parser_state *PyParser_New Py_PROTO((grammar *g, int start));
void PyParser_Delete Py_PROTO((parser_state *ps));
int PyParser_AddToken
	Py_PROTO((parser_state *ps, int type, char *str, int lineno));
void PyGrammar_AddAccelerators Py_PROTO((grammar *g));

#ifdef __cplusplus
}
#endif
#endif /* !Py_PARSER_H */
