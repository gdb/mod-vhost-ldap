/*
** Config file for dynamically-loaded ppc/cfm68k plugin modules.
*/

#define USE_GUSI1		/* Stdio implemented with GUSI */
/* #define USE_GUSI2		/* Stdio implemented with GUSI */
#define WITH_THREAD		/* Use thread support (needs GUSI 2, not GUSI 1) */
#define USE_MSL			/* Use MSL libraries */
#ifdef USE_MSL
#define MSL_USE_PRECOMPILED_HEADERS 0	/* Don't use precomp headers: we include our own */
#include <ansi_prefix.mac.h>
#endif
