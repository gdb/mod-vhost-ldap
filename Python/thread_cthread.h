/***********************************************************
Copyright 1991-1995 by Stichting Mathematisch Centrum, Amsterdam,
The Netherlands.

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

#include <mach/cthreads.h>


/*
 * Initialization.
 */
static void _init_thread _P0()
{
	cthread_init();
}

/*
 * Thread support.
 */
int start_new_thread _P2(func, void (*func) _P((void *)), arg, void *arg)
{
	int success = 0;	/* init not needed when SOLARIS_THREADS and */
				/* C_THREADS implemented properly */

	dprintf(("start_new_thread called\n"));
	if (!initialized)
		init_thread();
	/* looks like solaris detaches the thread to never rejoin
	 * so well do it here
	 */
	cthread_detach(cthread_fork((cthread_fn_t) func, arg));
	return success < 0 ? 0 : 1;
}

long get_thread_ident _P0()
{
	if (!initialized)
		init_thread();
	return (long) cthread_self();
}

static void do_exit_thread _P1(no_cleanup, int no_cleanup)
{
	dprintf(("exit_thread called\n"));
	if (!initialized)
		if (no_cleanup)
			_exit(0);
		else
			exit(0);
	cthread_exit(0);
}

void exit_thread _P0()
{
	do_exit_thread(0);
}

void _exit_thread _P0()
{
	do_exit_thread(1);
}

#ifndef NO_EXIT_PROG
static void do_exit_prog _P2(status, int status, no_cleanup, int no_cleanup)
{
	dprintf(("exit_prog(%d) called\n", status));
	if (!initialized)
		if (no_cleanup)
			_exit(status);
		else
			exit(status);
	if (no_cleanup)
		_exit(status);
	else
		exit(status);
}

void exit_prog _P1(status, int status)
{
	do_exit_prog(status, 0);
}

void _exit_prog _P1(status, int status)
{
	do_exit_prog(status, 1);
}
#endif /* NO_EXIT_PROG */

/*
 * Lock support.
 */
type_lock allocate_lock _P0()
{
	mutex_t lock;

	dprintf(("allocate_lock called\n"));
	if (!initialized)
		init_thread();

	lock = mutex_alloc();
	if (mutex_init(lock)) {
		perror("mutex_init");
		free((void *) lock);
		lock = 0;
	}
	dprintf(("allocate_lock() -> %lx\n", (long)lock));
	return (type_lock) lock;
}

void free_lock _P1(lock, type_lock lock)
{
	dprintf(("free_lock(%lx) called\n", (long)lock));
	mutex_free(lock);
}

int acquire_lock _P2(lock, type_lock lock, waitflag, int waitflag)
{
	int success = FALSE;

	dprintf(("acquire_lock(%lx, %d) called\n", (long)lock, waitflag));
	if (waitflag) { 	/* blocking */
		mutex_lock(lock);
		success = TRUE;
	} else {		/* non blocking */
		success = mutex_try_lock(lock);
	}
	dprintf(("acquire_lock(%lx, %d) -> %d\n", (long)lock, waitflag, success));
	return success;
}

void release_lock _P1(lock, type_lock lock)
{
	dprintf(("release_lock(%lx) called\n", (long)lock));
	mutex_unlock((mutex_t )lock);
}

/*
 * Semaphore support.
 *
 * This implementation is ripped directly from the pthreads implementation.
 * Which is to say that it is 100% non-functional at this time.
 *
 * Assuming the page is still up, documentation can be found at:
 *
 * http://www.doc.ic.ac.uk/~mac/manuals/solaris-manual-pages/solaris/usr/man/man2/_lwp_sema_wait.2.html
 *
 * Looking at the man page, it seems that one could easily implement a
 * semaphore using a condition.
 *
 */
type_sema allocate_sema _P1(value, int value)
{
	char *sema = 0;
	dprintf(("allocate_sema called\n"));
	if (!initialized)
		init_thread();

	dprintf(("allocate_sema() -> %lx\n", (long) sema));
	return (type_sema) sema;
}

void free_sema _P1(sema, type_sema sema)
{
	dprintf(("free_sema(%lx) called\n", (long) sema));
}

int down_sema _P2(sema, type_sema sema, waitflag, int waitflag)
{
	dprintf(("down_sema(%lx, %d) called\n", (long) sema, waitflag));
	dprintf(("down_sema(%lx) return\n", (long) sema));
	return -1;
}

void up_sema _P1(sema, type_sema sema)
{
	dprintf(("up_sema(%lx)\n", (long) sema));
}
