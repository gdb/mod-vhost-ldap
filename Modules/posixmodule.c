/***********************************************************
Copyright 1991 by Stichting Mathematisch Centrum, Amsterdam, The
Netherlands.

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

/* POSIX module implementation */

#ifdef AMOEBA
#define NO_LSTAT
#define SYSV
#endif

#ifdef MSDOS
#define NO_LSTAT
#define NO_UNAME
#endif

#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef SYSV

#define UTIME_STRUCT
#include <dirent.h>
#define direct dirent
#ifdef i386
#define mode_t int
#endif

#else /* !SYSV */

#ifndef MSDOS
#include <sys/dir.h>
#endif

#endif /* !SYSV */

#include "allobjects.h"
#include "modsupport.h"

extern char *strerror PROTO((int));


/* Return a dictionary corresponding to the POSIX environment table */

extern char **environ;

static object *
convertenviron()
{
	object *d;
	char **e;
	d = newdictobject();
	if (d == NULL)
		return NULL;
	if (environ == NULL)
		return d;
	/* XXX This part ignores errors */
	for (e = environ; *e != NULL; e++) {
		object *v;
		char *p = strchr(*e, '=');
		if (p == NULL)
			continue;
		v = newstringobject(p+1);
		if (v == NULL)
			continue;
		*p = '\0';
		(void) dictinsert(d, *e, v);
		*p = '=';
		DECREF(v);
	}
	return d;
}


static object *PosixError; /* Exception posix.error */

/* Set a POSIX-specific error from errno, and return NULL */

static object *
posix_error()
{
	return err_errno(PosixError);
}


/* POSIX generic methods */

static object *
posix_1str(args, func)
	object *args;
	int (*func) FPROTO((const char *));
{
	char *path1;
	if (!getstrarg(args, &path1))
		return NULL;
	if ((*func)(path1) < 0)
		return posix_error();
	INCREF(None);
	return None;
}

static object *
posix_2str(args, func)
	object *args;
	int (*func) FPROTO((const char *, const char *));
{
	char *path1, *path2;
	if (!getstrstrarg(args, &path1, &path2))
		return NULL;
	if ((*func)(path1, path2) < 0)
		return posix_error();
	INCREF(None);
	return None;
}

static object *
posix_strint(args, func)
	object *args;
	int (*func) FPROTO((const char *, int));
{
	char *path;
	int i;
	if (!getstrintarg(args, &path, &i))
		return NULL;
	if ((*func)(path, i) < 0)
		return posix_error();
	INCREF(None);
	return None;
}

static object *
posix_do_stat(self, args, statfunc)
	object *self;
	object *args;
	int (*statfunc) FPROTO((const char *, struct stat *));
{
	struct stat st;
	char *path;
	object *v;
	if (!getstrarg(args, &path))
		return NULL;
	if ((*statfunc)(path, &st) != 0)
		return posix_error();
	v = newtupleobject(10);
	if (v == NULL)
		return NULL;
#define SET(i, st_member) settupleitem(v, i, newintobject((long)st.st_member))
	SET(0, st_mode);
	SET(1, st_ino);
	SET(2, st_dev);
	SET(3, st_nlink);
	SET(4, st_uid);
	SET(5, st_gid);
	SET(6, st_size);
	SET(7, st_atime);
	SET(8, st_mtime);
	SET(9, st_ctime);
#undef SET
	if (err_occurred()) {
		DECREF(v);
		return NULL;
	}
	return v;
}


/* POSIX methods */

static object *
posix_chdir(self, args)
	object *self;
	object *args;
{
	extern int chdir PROTO((const char *));
	return posix_1str(args, chdir);
}

static object *
posix_chmod(self, args)
	object *self;
	object *args;
{
	extern int chmod PROTO((const char *, mode_t));
	return posix_strint(args, chmod);
}

static object *
posix_getcwd(self, args)
	object *self;
	object *args;
{
	char buf[1026];
	extern char *getcwd PROTO((char *, int));
	if (!getnoarg(args))
		return NULL;
	if (getcwd(buf, sizeof buf) == NULL)
		return posix_error();
	return newstringobject(buf);
}

#ifndef MSDOS
static object *
posix_link(self, args)
	object *self;
	object *args;
{
	extern int link PROTO((const char *, const char *));
	return posix_2str(args, link);
}
#endif /* !MSDOS */

static object *
posix_listdir(self, args)
	object *self;
	object *args;
{
	char *name;
	object *d, *v;

#ifdef MSDOS
	struct ffblk ep;
	int rv;
	if (!getstrarg(args, &name))
		return NULL;

	if (findfirst(name, &ep, 0) == -1)
		return posix_error();
	if ((d = newlistobject(0)) == NULL)
		return NULL;
	do {
		v = newstringobject(ep.ff_name);
		if (v == NULL) {
			DECREF(d);
			d = NULL;
			break;
		}
		if (addlistitem(d, v) != 0) {
			DECREF(v);
			DECREF(d);
			d = NULL;
			break;
		}
		DECREF(v);
	} while ((rv = findnext(&ep)) == 0);
#else /* !MSDOS */
	DIR *dirp;
	struct direct *ep;
	if (!getstrarg(args, &name))
		return NULL;
	if ((dirp = opendir(name)) == NULL)
		return posix_error();
	if ((d = newlistobject(0)) == NULL) {
		closedir(dirp);
		return NULL;
	}
	while ((ep = readdir(dirp)) != NULL) {
		v = newstringobject(ep->d_name);
		if (v == NULL) {
			DECREF(d);
			d = NULL;
			break;
		}
		if (addlistitem(d, v) != 0) {
			DECREF(v);
			DECREF(d);
			d = NULL;
			break;
		}
		DECREF(v);
	}
	closedir(dirp);
#endif /* !MSDOS */

	return d;
}

static object *
posix_mkdir(self, args)
	object *self;
	object *args;
{
	extern int mkdir PROTO((const char *, mode_t));
	return posix_strint(args, mkdir);
}

#ifdef i386
int
rename(from, to)
	char *from;
	char *to;
{
	int status;
	/* XXX Shouldn't this unlink the destination first? */
	status = link(from, to);
	if (status != 0)
		return status;
	return unlink(from);
}
#endif /* i386 */

static object *
posix_rename(self, args)
	object *self;
	object *args;
{
	extern int rename PROTO((const char *, const char *));
	return posix_2str(args, rename);
}

static object *
posix_rmdir(self, args)
	object *self;
	object *args;
{
	extern int rmdir PROTO((const char *));
	return posix_1str(args, rmdir);
}

static object *
posix_stat(self, args)
	object *self;
	object *args;
{
	extern int stat PROTO((const char *, struct stat *));
	return posix_do_stat(self, args, stat);
}

static object *
posix_system(self, args)
	object *self;
	object *args;
{
	char *command;
	int sts;
	if (!getstrarg(args, &command))
		return NULL;
	sts = system(command);
	return newintobject((long)sts);
}

#ifndef MSDOS
static object *
posix_umask(self, args)
	object *self;
	object *args;
{
	int i;
	if (!getintarg(args, &i))
		return NULL;
	i = umask(i);
	if (i < 0)
		return posix_error();
	return newintobject((long)i);
}
#endif /* !MSDOS */

static object *
posix_unlink(self, args)
	object *self;
	object *args;
{
	extern int unlink PROTO((const char *));
	return posix_1str(args, unlink);
}

#ifndef NO_UNAME
#include <sys/utsname.h>

static object *
posix_uname(self, args)
	object *self;
	object *args;
{
	extern int uname PROTO((struct utsname *));
	struct utsname u;
	object *v;
	if (uname(&u) < 0)
		return posix_error();
	v = newtupleobject(5);
	if (v == NULL)
		return NULL;
#define SET(i, member) settupleitem(v, i, newstringobject(u.member))
	SET(0, sysname);
	SET(1, nodename);
	SET(2, release);
	SET(3, version);
	SET(4, machine);
#undef SET
	if (err_occurred()) {
		DECREF(v);
		return NULL;
	}
	return v;
}
#endif /* NO_UNAME */

#ifdef UTIME_STRUCT
#include <utime.h>
#endif

static object *
posix_utime(self, args)
	object *self;
	object *args;
{
	char *path;

#ifdef UTIME_STRUCT
	struct utimbuf buf;
#define ATIME buf.actime
#define MTIME buf.modtime
#define UTIME_ARG &buf

#else
	time_t buf[2];
#define ATIME buf[0]
#define MTIME buf[1]
#define UTIME_ARG buf
#endif

	if (!getargs(args, "(s(ll))", &path, &ATIME, &MTIME))
		return NULL;
	if (utime(path, UTIME_ARG) < 0)
		return posix_error();
	INCREF(None);
	return None;
#undef UTIME_ARG
#undef ATIME
#undef MTIME
}


#ifndef MSDOS

/* Process operations */

static object *
posix__exit(self, args)
	object *self;
	object *args;
{
	int sts;
	if (!getintarg(args, &sts))
		return NULL;
	_exit(sts);
	/* NOTREACHED */
}

/* XXX To do: exece, execp */

static object *
posix_exec(self, args)
	object *self;
	object *args;
{
	char *path;
	object *argv;
	char **argvlist;
	int i, argc;
	object *(*getitem) PROTO((object *, int));

	/* exec has two arguments: (path, argv), where
	   argv is a list or tuple of strings. */

	if (!getargs(args, "(sO)", &path, &argv))
		return NULL;
	if (is_listobject(argv)) {
		argc = getlistsize(argv);
		getitem = getlistitem;
	}
	else if (is_tupleobject(argv)) {
		argc = gettuplesize(argv);
		getitem = gettupleitem;
	}
	else {
 badarg:
		err_badarg();
		return NULL;
	}

	argvlist = NEW(char *, argc+1);
	if (argvlist == NULL)
		return NULL;
	for (i = 0; i < argc; i++) {
		if (!getstrarg((*getitem)(argv, i), &argvlist[i])) {
			DEL(argvlist);
			goto badarg;
		}
	}
	argvlist[argc] = NULL;

	execv(path, argvlist);
	
	/* If we get here it's definitely an error */

	DEL(argvlist);
	return posix_error();
}

static object *
posix_fork(self, args)
	object *self;
	object *args;
{
	int pid;
	pid = fork();
	if (pid == -1)
		return posix_error();
	return newintobject((long)pid);
}

static object *
posix_getpid(self, args)
	object *self;
	object *args;
{
	if (!getnoarg(args))
		return NULL;
	return newintobject((long)getpid());
}

static object *
posix_getpgrp(self, args)
	object *self;
	object *args;
{
	if (!getnoarg(args))
		return NULL;
	return newintobject((long)getpgrp(0));
}

static object *
posix_getppid(self, args)
	object *self;
	object *args;
{
	if (!getnoarg(args))
		return NULL;
	return newintobject((long)getppid());
}

static object *
posix_kill(self, args)
	object *self;
	object *args;
{
	int pid, sig;
	if (!getintintarg(args, &pid, &sig))
		return NULL;
	if (kill(pid, sig) == -1)
		return posix_error();
	INCREF(None);
	return None;
}

static object *
posix_popen(self, args)
	object *self;
	object *args;
{
	extern int pclose PROTO((FILE *));
	char *name, *mode;
	FILE *fp;
	if (!getargs(args, "(ss)", &name, &mode))
		return NULL;
	fp = popen(name, mode);
	if (fp == NULL)
		return posix_error();
	/* From now on, ignore SIGPIPE and let the error checking
	   do the work. */
	(void) signal(SIGPIPE, SIG_IGN);
	return newopenfileobject(fp, name, mode, pclose);
}

static object *
posix_wait(self, args) /* Also waitpid() */
	object *self;
	object *args;
{
	object *v;
	int pid, sts;
	if (args == NULL)
		pid = wait(&sts);
	else {
#ifdef NO_WAITPID
		err_setstr(PosixError,
		"posix.wait(pid, options) not supported on this system");
#else
		int options;
		if (!getintintarg(args, &pid, &options))
			return NULL;
		pid = waitpid(pid, &sts, options);
#endif
	}
	if (pid == -1)
		return posix_error();
	v = newtupleobject(2);
	if (v != NULL) {
		settupleitem(v, 0, newintobject((long)pid));
		settupleitem(v, 1, newintobject((long)sts));
		if (err_occurred()) {
			DECREF(v);
			v = NULL;
		}
	}
	return v;
}

#endif /* MSDOS */

static object *
posix_lstat(self, args)
	object *self;
	object *args;
{
#ifdef NO_LSTAT
#define lstat stat
#endif
	extern int lstat PROTO((const char *, struct stat *));
	return posix_do_stat(self, args, lstat);
}

static object *
posix_readlink(self, args)
	object *self;
	object *args;
{
#ifdef NO_LSTAT
	err_setstr(PosixError, "readlink not implemented on this system");
	return NULL;
#else
	char buf[1024]; /* XXX Should use MAXPATHLEN */
	char *path;
	int n;
	if (!getstrarg(args, &path))
		return NULL;
	n = readlink(path, buf, sizeof buf);
	if (n < 0)
		return posix_error();
	return newsizedstringobject(buf, n);
#endif
}

static object *
posix_symlink(self, args)
	object *self;
	object *args;
{
#ifdef NO_LSTAT
	err_setstr(PosixError, "symlink not implemented on this system");
	return NULL;
#else
	extern int symlink PROTO((const char *, const char *));
	return posix_2str(args, symlink);
#endif
}


static struct methodlist posix_methods[] = {
	{"chdir",	posix_chdir},
	{"chmod",	posix_chmod},
	{"getcwd",	posix_getcwd},
#ifndef MSDOS
	{"link",	posix_link},
#endif
	{"listdir",	posix_listdir},
	{"lstat",	posix_lstat},
	{"mkdir",	posix_mkdir},
	{"readlink",	posix_readlink},
	{"rename",	posix_rename},
	{"rmdir",	posix_rmdir},
	{"stat",	posix_stat},
	{"symlink",	posix_symlink},
	{"system",	posix_system},
#ifndef MSDOS
	{"umask",	posix_umask},
#endif
#ifndef NO_UNAME
	{"uname",	posix_uname},
#endif
	{"unlink",	posix_unlink},
	{"utime",	posix_utime},

#ifndef MSDOS
	{"_exit",	posix__exit},
	{"exec",	posix_exec},
	{"fork",	posix_fork},
	{"getpid",	posix_getpid},
	{"getpgrp",	posix_getpgrp},
	{"getppid",	posix_getppid},
	{"kill",	posix_kill},
	{"popen",	posix_popen},
	{"wait",	posix_wait},
#endif

	{NULL,		NULL}		 /* Sentinel */
};


void
initposix()
{
	object *m, *d, *v;
	
	m = initmodule("posix", posix_methods);
	d = getmoduledict(m);
	
	/* Initialize posix.environ dictionary */
	v = convertenviron();
	if (v == NULL || dictinsert(d, "environ", v) != 0)
		fatal("can't define posix.environ");
	DECREF(v);
	
	/* Initialize posix.error exception */
	PosixError = newstringobject("posix.error");
	if (PosixError == NULL || dictinsert(d, "error", PosixError) != 0)
		fatal("can't define posix.error");
}


/* Function used elsewhere to get a file's modification time */

long
getmtime(path)
	char *path;
{
	struct stat st;
	if (stat(path, &st) != 0)
		return -1;
	else
		return st.st_mtime;
}


#ifdef MSDOS

/* A small "compatibility library" for TurboC under MS-DOS */

#include <sir.h>
#include <io.h>
#include <dos.h>
#include <fcntl.h>

int
chmod(path, mode)
	char *path;
	int mode;
{
	return _chmod(path, 1, mode);
}

int
utime(path, times)
	char *path;
	time_t times[2];
{
	struct date dt;
	struct time tm;
	struct ftime dft;
	int	fh;
	unixtodos(tv[0].tv_sec,&dt,&tm);
	dft.ft_tsec = tm.ti_sec; dft.ft_min = tm.ti_min;
	dft.ft_hour = tm.ti_hour; dft.ft_day = dt.da_day;
	dft.ft_month = dt.da_mon;
	dft.ft_year = (dt.da_year - 1980);	/* this is for TC library */

	if ((fh = open(path,O_RDWR)) < 0)
		return posix_error();	/* can't open file to set time */
	if (setftime(fh,&dft) < 0)
	{
		close(fh);
		return posix_error();
	}
	close(fh);				/* close the temp handle */
}

#endif /* MSDOS */
