/* Time module */

#include "allobjects.h"

#include "modsupport.h"

#include "sigtype.h"

#include <signal.h>
#include <setjmp.h>

#ifdef __STDC__
#include <time.h>
#else /* !__STDC__ */
typedef unsigned long time_t;
extern time_t time();
#endif /* !__STDC__ */


/* Time methods */

static object *
time_time(self, args)
	object *self;
	object *args;
{
	long secs;
	if (!getnoarg(args))
		return NULL;
	secs = time((time_t *)NULL);
	return newintobject(secs);
}

static jmp_buf sleep_intr;

static void
sleep_catcher(sig)
	int sig;
{
	longjmp(sleep_intr, 1);
}

static object *
time_sleep(self, args)
	object *self;
	object *args;
{
	int secs;
	SIGTYPE (*sigsave)();
	if (!getintarg(args, &secs))
		return NULL;
	if (setjmp(sleep_intr)) {
		signal(SIGINT, sigsave);
		err_set(KeyboardInterrupt);
		return NULL;
	}
	sigsave = signal(SIGINT, SIG_IGN);
	if (sigsave != (SIGTYPE (*)()) SIG_IGN)
		signal(SIGINT, sleep_catcher);
	sleep(secs);
	signal(SIGINT, sigsave);
	INCREF(None);
	return None;
}

#ifdef THINK_C
#define DO_MILLI
#endif /* THINK_C */

#ifdef AMOEBA
#define DO_MILLI
extern long sys_milli();
#define millitimer sys_milli
#endif /* AMOEBA */

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
	if (setjmp(sleep_intr)) {
		signal(SIGINT, sigsave);
		err_set(KeyboardInterrupt);
		return NULL;
	}
	sigsave = signal(SIGINT, SIG_IGN);
	if (sigsave != (SIGTYPE (*)()) SIG_IGN)
		signal(SIGINT, sleep_catcher);
	millisleep(msecs);
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
	extern long millitimer();
	if (!getnoarg(args))
		return NULL;
	msecs = millitimer();
	return newintobject(msecs);
}

#endif /* DO_MILLI */


static struct methodlist time_methods[] = {
#ifdef DO_MILLI
	{"millisleep",	time_millisleep},
	{"millitimer",	time_millitimer},
#endif /* DO_MILLI */
	{"sleep",	time_sleep},
	{"time",	time_time},
	{NULL,		NULL}		/* sentinel */
};


void
inittime()
{
	initmodule("time", time_methods);
}


#ifdef THINK_C

#define MacTicks	(* (long *)0x16A)

static
sleep(msecs)
	int msecs;
{
	register long deadline;
	
	deadline = MacTicks + msecs * 60;
	while (MacTicks < deadline) {
		if (intrcheck())
			sleep_catcher(SIGINT);
	}
}

static
millisleep(msecs)
	long msecs;
{
	register long deadline;
	
	deadline = MacTicks + msecs * 3 / 50; /* msecs * 60 / 1000 */
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

#endif /* THINK_C */
