#ifndef Py_ERRCODE_H
#define Py_ERRCODE_H
#ifdef __cplusplus
extern "C" {
#endif

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

/* Error codes passed around between file input, tokenizer, parser and
   interpreter.  This is necessary so we can turn them into Python
   exceptions at a higher level.  Note that some errors have a
   slightly different meaning when passed from the tokenizer to the
   parser than when passed from the parser to the interpreter; e.g.
   the parser only returns E_EOF when it hits EOF immediately, and it
   never returns E_OK. */

#define E_OK		10	/* No error */
#define E_EOF		11	/* End Of File */
#define E_INTR		12	/* Interrupted */
#define E_TOKEN		13	/* Bad token */
#define E_SYNTAX	14	/* Syntax error */
#define E_NOMEM		15	/* Ran out of memory */
#define E_DONE		16	/* Parsing complete */
#define E_ERROR		17	/* Execution error */
#define E_INDENT	18	/* Invalid indentation detected */
#define E_OVERFLOW      19      /* Node had too many children */

#ifdef __cplusplus
}
#endif
#endif /* !Py_ERRCODE_H */
