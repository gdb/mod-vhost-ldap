/* Useful #includes and #defines for programming a set of Unix
   look-alike file system access functions on the Macintosh.
   Public domain by Guido van Rossum, CWI, Amsterdam (July 1987).
*/

#include <Types.h>
#include <Files.h>
#include <OSUtils.h>

#ifdef THINK_C
#include <pascal.h>
#endif

#include <errno.h>
#include <string.h>

/* Macro to find out whether we can do HFS-only calls: */
#define FSFCBLen (* (short *) 0x3f6)
#define hfsrunning() (FSFCBLen > 0)

/* Universal constants: */
#define MAXPATH 256
#define TRUE 1
#define FALSE 0
#ifndef NULL
#define NULL 0
#endif
#define EOS '\0'
#define SEP ':'
