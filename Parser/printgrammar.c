/***********************************************************
Copyright 1991-1995 by Stichting Mathematisch Centrum, Amsterdam,
The Netherlands.

                        All Rights Reserved

Copyright (c) 2000, BeOpen.com.
Copyright (c) 1995-2000, Corporation for National Research Initiatives.
Copyright (c) 1990-1995, Stichting Mathematisch Centrum.
All rights reserved.

See the file "Misc/COPYRIGHT" for information on usage and
redistribution of this file, and for a DISCLAIMER OF ALL WARRANTIES.

******************************************************************/

/* Print a bunch of C initializers that represent a grammar */

#include "pgenheaders.h"
#include "grammar.h"

/* Forward */
static void printarcs Py_PROTO((int, dfa *, FILE *));
static void printstates Py_PROTO((grammar *, FILE *));
static void printdfas Py_PROTO((grammar *, FILE *));
static void printlabels Py_PROTO((grammar *, FILE *));

void
printgrammar(g, fp)
	grammar *g;
	FILE *fp;
{
	fprintf(fp, "#include \"pgenheaders.h\"\n");
	fprintf(fp, "#include \"grammar.h\"\n");
	printdfas(g, fp);
	printlabels(g, fp);
	fprintf(fp, "grammar _PyParser_Grammar = {\n");
	fprintf(fp, "\t%d,\n", g->g_ndfas);
	fprintf(fp, "\tdfas,\n");
	fprintf(fp, "\t{%d, labels},\n", g->g_ll.ll_nlabels);
	fprintf(fp, "\t%d\n", g->g_start);
	fprintf(fp, "};\n");
}

void
printnonterminals(g, fp)
	grammar *g;
	FILE *fp;
{
	dfa *d;
	int i;
	
	d = g->g_dfa;
	for (i = g->g_ndfas; --i >= 0; d++)
		fprintf(fp, "#define %s %d\n", d->d_name, d->d_type);
}

static void
printarcs(i, d, fp)
	int i;
	dfa *d;
	FILE *fp;
{
	arc *a;
	state *s;
	int j, k;
	
	s = d->d_state;
	for (j = 0; j < d->d_nstates; j++, s++) {
		fprintf(fp, "static arc arcs_%d_%d[%d] = {\n",
			i, j, s->s_narcs);
		a = s->s_arc;
		for (k = 0; k < s->s_narcs; k++, a++)
			fprintf(fp, "\t{%d, %d},\n", a->a_lbl, a->a_arrow);
		fprintf(fp, "};\n");
	}
}

static void
printstates(g, fp)
	grammar *g;
	FILE *fp;
{
	state *s;
	dfa *d;
	int i, j;
	
	d = g->g_dfa;
	for (i = 0; i < g->g_ndfas; i++, d++) {
		printarcs(i, d, fp);
		fprintf(fp, "static state states_%d[%d] = {\n",
			i, d->d_nstates);
		s = d->d_state;
		for (j = 0; j < d->d_nstates; j++, s++)
			fprintf(fp, "\t{%d, arcs_%d_%d},\n",
				s->s_narcs, i, j);
		fprintf(fp, "};\n");
	}
}

static void
printdfas(g, fp)
	grammar *g;
	FILE *fp;
{
	dfa *d;
	int i, j;
	
	printstates(g, fp);
	fprintf(fp, "static dfa dfas[%d] = {\n", g->g_ndfas);
	d = g->g_dfa;
	for (i = 0; i < g->g_ndfas; i++, d++) {
		fprintf(fp, "\t{%d, \"%s\", %d, %d, states_%d,\n",
			d->d_type, d->d_name, d->d_initial, d->d_nstates, i);
		fprintf(fp, "\t \"");
		for (j = 0; j < NBYTES(g->g_ll.ll_nlabels); j++)
			fprintf(fp, "\\%03o", d->d_first[j] & 0xff);
		fprintf(fp, "\"},\n");
	}
	fprintf(fp, "};\n");
}

static void
printlabels(g, fp)
	grammar *g;
	FILE *fp;
{
	label *l;
	int i;
	
	fprintf(fp, "static label labels[%d] = {\n", g->g_ll.ll_nlabels);
	l = g->g_ll.ll_label;
	for (i = g->g_ll.ll_nlabels; --i >= 0; l++) {
		if (l->lb_str == NULL)
			fprintf(fp, "\t{%d, 0},\n", l->lb_type);
		else
			fprintf(fp, "\t{%d, \"%s\"},\n",
				l->lb_type, l->lb_str);
	}
	fprintf(fp, "};\n");
}
