#ifndef Py_ASSERT_H
#define Py_ASSERT_H
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

#ifdef MPW /* This is for MPW's File command */

#define assert(e) { if (!(e)) { printf("### Python: Assertion failed:\n\
    File %s; Line %d\n", __FILE__, __LINE__); abort(); } }
#else
#define assert(e) { if (!(e)) { printf("Assertion failed\n"); abort(); } }
#endif

#ifdef __cplusplus
}
#endif
#endif /* !Py_ASSERT_H */
