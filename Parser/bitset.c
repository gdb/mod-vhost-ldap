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

/* Bitset primitives used by the parser generator */

#include "pgenheaders.h"
#include "bitset.h"

bitset
newbitset(nbits)
	int nbits;
{
	int nbytes = NBYTES(nbits);
	bitset ss = PyMem_NEW(BYTE, nbytes);
	
	if (ss == NULL)
		Py_FatalError("no mem for bitset");
	
	ss += nbytes;
	while (--nbytes >= 0)
		*--ss = 0;
	return ss;
}

void
delbitset(ss)
	bitset ss;
{
	PyMem_DEL(ss);
}

int
addbit(ss, ibit)
	bitset ss;
	int ibit;
{
	int ibyte = BIT2BYTE(ibit);
	BYTE mask = BIT2MASK(ibit);
	
	if (ss[ibyte] & mask)
		return 0; /* Bit already set */
	ss[ibyte] |= mask;
	return 1;
}

#if 0 /* Now a macro */
int
testbit(ss, ibit)
	bitset ss;
	int ibit;
{
	return (ss[BIT2BYTE(ibit)] & BIT2MASK(ibit)) != 0;
}
#endif

int
samebitset(ss1, ss2, nbits)
	bitset ss1, ss2;
	int nbits;
{
	int i;
	
	for (i = NBYTES(nbits); --i >= 0; )
		if (*ss1++ != *ss2++)
			return 0;
	return 1;
}

void
mergebitset(ss1, ss2, nbits)
	bitset ss1, ss2;
	int nbits;
{
	int i;
	
	for (i = NBYTES(nbits); --i >= 0; )
		*ss1++ |= *ss2++;
}
