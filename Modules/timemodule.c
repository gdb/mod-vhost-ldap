/***********************************************************
Copyright 1991, 1992, 1993 by Stichting Mathematisch Centrum,
Amsterdam, The Netherlands.

                        All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the names of Stichting Mathematisch
Centrum or CWI not be used in advertising or publicity pertaining to
distribution of the software without specific, written prior permission.

STICHTING MATHEMATISCH CENTRUM DISCLAIMS ALL WARRANTIES WITH REGARD TO
THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS, IN NO EVENT SHALL STICHTING MATHEMATISCH CENTRUM BE LIABLE
FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT
OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

******************************************************************/

/* Time module */

#include "allobjects.h"
#include "modsupport.h"
#include "ceval.h"

#include "sigtype.h"

#include <signal.h>
#include <setjmp.h>

#ifdef BSD_TIME
#define HAVE_GETTIMEOFDAY
#include "myselect.h" /* Implies <sys/types.h>, <sys/time.h>, <sys/param.h> */
#endif

#ifdef macintosh
#define NO_UNISTD
#endif

#ifndef NO_UNISTD
#include <unistd.h>
#endif

/* What happens here is not trivial.
   The BSD_TIME code needs <sys/time.h> (for struct timeval).
   The rest of the code needs only time_t, except some MS-DOS
   code which needs clock_t as well.
   Standard C says that time_t is defined in <time.h>, and
   does not have <sys/types.h>; THINK C agrees (MS-DOS too?).
   What's worse, in pure 4.3 BSD, older SunOS versions, and
   probably everything derived from BSD, you can't #include
   both <time.h> and <sys/time.h> in the same file, since
   <sys/time.h> includes <time.h> without any protection,
   and <time.h> contains a typedef, which can't be parsed twice!
   So on traditional UNIX systems we include <sys/types.h>
   and <sys/time.h> and hope this implies <time.h> and time_t,
   while on other systems, including conforming Standard C
   systems (where 'unix' can't be defined), we rely on <time.h>.
   Still one problem: BSD_TIME won't work with strict Standard C...
*/

#ifdef unix
#include <sys/types.h>
#include <sys/time.h> /* Implies <time.h> everywhere, as far as I know */
#else /* !unix */
#include <time.h>
#endif /* !unix */

/* XXX This is bogus -- times() is defined in posixmodule.c */
#ifdef DO_TIMES
#include <sys/times.h>
#include <sys/param.h>
#include <errno.h>
#endif

#ifdef SYSV
/* Access timezone stuff */
#ifdef OLDTZ				/* ANSI prepends underscore to these */
#define _timezone	timezone	/* seconds to be added to GMT */
#define _altzone	0		/* _timezone if daylight saving time */
#define _daylight	0		/* if zero, _altzone is not available*/
#define _tzname		tzname		/* Name of timezone and altzone */
#endif
#ifdef NOALTTZ				/* if system doesn't support alt tz */
#undef _daylight
#undef _altzone
#define _daylight	0
#define _altzone 	0
#endif
#endif /* SYSV */

/* Forward declarations */
static void floatsleep PROTO((double));
static long millitimer PROTO((void)); 

/* Time methods */

static object *
time_time(self, args)
	object *self;
	object *args;
{
#ifdef HAVE_GETTIMEOFDAY
	struct timeval t;
	struct timezone tz;
	if (!getnoarg(args))
		return NULL;
	if (gettimeofday(&t, &tz) != 0) {
		err_errno(IOError);
		return NULL;
	}
	return newfloatobject(t.tv_sec*1.0 + t.tv_usec*0.000001);
#else /* !HAVE_GETTIMEOFDAY */
	time_t secs;
	if (!getnoarg(args))
		return NULL;
	time(&secs);
#ifdef macintosh
/* The Mac epoch is 1904, while UNIX uses 1970; Python prefers 1970 */
/* Moreover, the Mac returns local time.  This we cannot fix... */
#define TIMEDIFF ((time_t) \
	(((1970-1904)*365L + (1970-1904)/4) * 24 * 3600))
	secs -= TIMEDIFF;
#endif
	return newfloatobject((double)secs);
#endif /* !HAVE_GETTIMEOFDAY */
}

static jmp_buf sleep_intr;

/* ARGSUSED */
static void
sleep_catcher(sig)
	int sig; /* Not used but required by interface */
{
	longjmp(sleep_intr, 1);
}

static object *
time_sleep(self, args)
	object *self;
	object *args;
{
	double secs;
	SIGTYPE (*sigsave)() = 0; /* Initialized to shut lint up */
	if (!getargs(args, "d", &secs))
		return NULL;
	BGN_SAVE
	if (setjmp(sleep_intr)) {
		RET_SAVE
		signal(SIGINT, sigsave);
		err_set(KeyboardInterrupt);
		return NULL;
	}
	sigsave = signal(SIGINT, SIG_IGN);
	if (sigsave != (SIGTYPE (*)()) SIG_IGN)
		signal(SIGINT, sleep_catcher);
	floatsleep(secs);
	END_SAVE
	signal(SIGINT, sigsave);
	INCREF(None);
	return None;
}

#ifdef macintosh
#define DO_MILLI
#endif

#ifdef AMOEBA
#define DO_MILLI
extern long sys_milli();
#define millitimer sys_milli
#endif /* AMOEBA */

#ifdef BSD_TIME
#define DO_MILLI
#endif /* BSD_TIME */

#ifdef TURBO_C
#define DO_MILLI
#endif

#ifdef DO_MILLI

static object *
time_millisleep(self, args)
	object *self;
	object *args;
{
	long msecs;
	SIGTYPE (*sigsave)();
	if (!getlongarg(args, &msecs))
		return NULL;
	BGN_SAVE
	if (setjmp(sleep_intr)) {
		RET_SAVE
		signal(SIGINT, sigsave);
		err_set(KeyboardInterrupt);
		return NULL;
	}
	sigsave = signal(SIGINT, SIG_IGN);
	if (sigsave != (SIGTYPE (*)()) SIG_IGN)
		signal(SIGINT, sleep_catcher);
	floatsleep(msecs / 1000.0);
	END_SAVE
	signal(SIGINT, sigsave);
	INCREF(None);
	return None;
}

static object *
time_millitimer(self, args)
	object *self;
	object *args;
{
	long msecs;
	if (!getnoarg(args))
		return NULL;
	msecs = millitimer();
	return newintobject(msecs);
}

#endif /* DO_MILLI */

#ifdef DO_TIMES

static object *
time_times(self, args)
	object *self;
	object *args;
{
	struct tms t;
	clock_t c;
	if (!getnoarg(args))
		return NULL;
	errno = 0;
	c = times(&t);
	if (c == (clock_t) -1) {
		err_errno(IOError);
		return NULL;
	}
	return mkvalue("(dddd)",
		       (double)t.tms_utime / HZ,
		       (double)t.tms_stime / HZ,
		       (double)t.tms_cutime / HZ,
		       (double)t.tms_cstime / HZ);
}

#endif


static object *
time_convert(when, function)
	time_t when;
	struct tm * (*function) PROTO((time_t *));
{
	struct tm *p = function(&when);
	return mkvalue("(iiiiiiiii)",
		       p->tm_year + 1900,
		       p->tm_mon + 1, /* Want January == 1 */
		       p->tm_mday,
		       p->tm_hour,
		       p->tm_min,
		       p->tm_sec,
		       (p->tm_wday + 6) % 7, /* Want Monday == 0 */
		       p->tm_yday,
		       p->tm_isdst);
}

static object *
time_gmtime(self, args)
	object *self;
	object *args;
{
	double when;
	if (!getargs(args, "d", &when))
		return NULL;
	return time_convert((time_t)when, gmtime);
}

static object *
time_localtime(self, args)
	object *self;
	object *args;
{
	double when;
	if (!getargs(args, "d", &when))
		return NULL;
	return time_convert((time_t)when, localtime);
}

/* Some very old systems may not have mktime().  Comment it out then! */

static object *
time_mktime(self, args)
	object *self;
	object *args;
{
	struct tm buf;
	if (!getargs(args, "(iiiiiiiii)",
		     &buf.tm_year,
		     &buf.tm_mon,
		     &buf.tm_mday,
		     &buf.tm_hour,
		     &buf.tm_min,
		     &buf.tm_sec,
		     &buf.tm_wday,
		     &buf.tm_yday,
		     &buf.tm_isdst))
		return NULL;
	if (buf.tm_year >= 1900)
		buf.tm_year -= 1900;
	buf.tm_mon--;
	return newintobject((long)mktime(&buf));
}

static struct methodlist time_methods[] = {
#ifdef DO_MILLI
	{"millisleep",	time_millisleep},
	{"millitimer",	time_millitimer},
#endif /* DO_MILLI */
#ifdef DO_TIMES
	{"times",	time_times},
#endif
	{"sleep",	time_sleep},
	{"time",	time_time},
	{"gmtime",	time_gmtime},
	{"localtime",	time_localtime},
	{"mktime",	time_mktime},
	{NULL,		NULL}		/* sentinel */
};


void
inittime()
{
	object *m, *d;
	m = initmodule("time", time_methods);
	d = getmoduledict(m);
#ifdef SYSV
	tzset();
	dictinsert(d, "timezone", newintobject((long)_timezone));
	dictinsert(d, "altzone", newintobject((long)_altzone));
	dictinsert(d, "daylight", newintobject((long)_daylight));
	dictinsert(d, "tzname", mkvalue("(zz)", _tzname[0], _tzname[1]));
#else /* !SYSV */
	{
#define YEAR ((time_t)((365 * 24 + 6) * 3600))
		time_t t;
		struct tm *p;
		long winterzone, summerzone;
		char wintername[10], summername[10];
		t = (time((time_t *)0) / YEAR) * YEAR;
		p = localtime(&t);
		winterzone = -p->tm_gmtoff;
		strncpy(wintername, p->tm_zone ? p->tm_zone : "   ", 9);
		wintername[9] = '\0';
		t += YEAR/2;
		p = localtime(&t);
		summerzone = -p->tm_gmtoff;
		strncpy(summername, p->tm_zone ? p->tm_zone : "   ", 9);
		summername[9] = '\0';
		dictinsert(d, "timezone", newintobject(winterzone));
		dictinsert(d, "altzone", newintobject(summerzone));
		dictinsert(d, "daylight",
			   newintobject((long)(winterzone != summerzone)));
		dictinsert(d, "tzname",
			   mkvalue("(zz)", wintername, summername));
	}
#endif /* !SYSV */
}


#ifdef macintosh

#define MacTicks	(* (long *)0x16A)

#ifdef THINK_C_3_0
sleep(secs)
	int secs;
{
	register long deadline;
	
	deadline = MacTicks + mecs * 60;
	while (MacTicks < deadline) {
		if (intrcheck())
			sleep_catcher(SIGINT);
	}
}
#endif

static void
floatsleep(secs)
	double secs;
{
	register long deadline;
	
	deadline = MacTicks + (long)(secs * 60.0);
	while (MacTicks < deadline) {
		if (intrcheck())
			sleep_catcher(SIGINT);
	}
}

static long
millitimer()
{
	return MacTicks * 50 / 3; /* MacTicks * 1000 / 60 */
}

#endif /* macintosh */


#ifdef unix

#ifdef BSD_TIME

static long
millitimer()
{
	struct timeval t;
	struct timezone tz;
	if (gettimeofday(&t, &tz) != 0)
		return -1;
	return t.tv_sec*1000 + t.tv_usec/1000;
}

static void
floatsleep(secs)
	double secs;
{
	struct timeval t;
	double frac;
	extern double fmod PROTO((double, double));
	extern double floor PROTO((double));
	frac = fmod(secs, 1.0);
	secs = floor(secs);
	t.tv_sec = (long)secs;
	t.tv_usec = (long)(frac*1000000.0);
	(void) select(0, (fd_set *)0, (fd_set *)0, (fd_set *)0, &t);
}

#else /* !BSD_TIME */

static void
floatsleep(secs)
	double secs;
{
	sleep((int)secs);
}

#endif /* !BSD_TIME */

#endif /* unix */


#ifdef TURBO_C /* Maybe also for MS-DOS? */

#ifndef CLOCKS_PER_SEC
#define CLOCKS_PER_SEC 55	/* 54.945 msec per tick (18.2 HZ clock) */
#endif

static void
floatsleep(secs)
	double secs;
{
	delay(long(secs/1000.0));
}

static long
millitimer()
{
	clock_t ticks;

	ticks = clock();	/* ticks since program start */
	return ticks * CLOCKS_PER_SEC;/* XXX shouldn't this be different? */
}

#endif /* TURBO_C */
