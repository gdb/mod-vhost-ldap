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

/* POSIX module implementation */

#ifdef AMOEBA
#define NO_LSTAT
#define SYSV
#endif

#ifdef __sgi
#define DO_PG
#endif

#ifdef _NEXT_SOURCE
#define mode_t int
#define NO_UNAME
#endif

#include <signal.h>
#include <string.h>
#include <setjmp.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef DO_TIMES
#include <sys/times.h>
#include <sys/param.h>
#include <errno.h>
#endif

#ifdef SYSV

#define UTIME_STRUCT 1
#include <dirent.h>
#define direct dirent
#ifdef i386
#define mode_t int
#endif

#else /* !SYSV */

#include <sys/dir.h>

#endif /* !SYSV */

#ifndef NO_UNISTD
#include <unistd.h> /* Take this out and hope the best if it doesn't exist */
#endif

#include "allobjects.h"
#include "modsupport.h"
#include "ceval.h"

#ifdef _SEQUENT_
#include <unistd.h>
#else /* _SEQUENT_ */
/* XXX Aren't these always declared in unistd.h? */
extern int mkdir PROTO((const char *, mode_t));
extern int chdir PROTO((const char *));
extern int rmdir PROTO((const char *));
extern int chmod PROTO((const char *, mode_t));
extern char *getcwd(); /* No PROTO((char *, int)) -- non portable */
extern char *strerror PROTO((int));
extern int link PROTO((const char *, const char *));
extern int rename PROTO((const char *, const char *));
extern int stat PROTO((const char *, struct stat *));
extern int unlink PROTO((const char *));
extern int pclose PROTO((FILE *));
#endif /* !_SEQUENT_ */
#ifdef NO_LSTAT
#define lstat stat
#else
extern int lstat PROTO((const char *, struct stat *));
extern int symlink PROTO((const char *, const char *));
#endif


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

static object * posix_error() { 	return err_errno(PosixError);
}


/* POSIX generic methods */

static object *
posix_1str(args, func)
	object *args;
	int (*func) FPROTO((const char *));
{
	char *path1;
	int res;
	if (!getargs(args, "s", &path1))
		return NULL;
	BGN_SAVE
	res = (*func)(path1);
	END_SAVE
	if (res < 0)
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
	int res;
	if (!getargs(args, "(ss)", &path1, &path2))
		return NULL;
	BGN_SAVE
	res = (*func)(path1, path2);
	END_SAVE
	if (res < 0)
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
	int res;
	if (!getargs(args, "(si)", &path, &i))
		return NULL;
	BGN_SAVE
	res = (*func)(path, i);
	END_SAVE
	if (res < 0)
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
	int res;
	if (!getargs(args, "s", &path))
		return NULL;
	BGN_SAVE
	res = (*statfunc)(path, &st);
	END_SAVE
	if (res != 0)
		return posix_error();
	return mkvalue("(llllllllll)",
		    (long)st.st_mode,
		    (long)st.st_ino,
		    (long)st.st_dev,
		    (long)st.st_nlink,
		    (long)st.st_uid,
		    (long)st.st_gid,
		    (long)st.st_size,
		    (long)st.st_atime,
		    (long)st.st_mtime,
		    (long)st.st_ctime);
}


/* POSIX methods */

static object *
posix_chdir(self, args)
	object *self;
	object *args;
{
	return posix_1str(args, chdir);
}

static object *
posix_chmod(self, args)
	object *self;
	object *args;
{
	return posix_strint(args, chmod);
}

static object *
posix_getcwd(self, args)
	object *self;
	object *args;
{
	char buf[1026];
	char *res;
	if (!getnoarg(args))
		return NULL;
	BGN_SAVE
	res = getcwd(buf, sizeof buf);
	END_SAVE
	if (res == NULL)
		return posix_error();
	return newstringobject(buf);
}

static object *
posix_link(self, args)
	object *self;
	object *args;
{
	return posix_2str(args, link);
}

static object *
posix_listdir(self, args)
	object *self;
	object *args;
{
	char *name;
	object *d, *v;
	DIR *dirp;
	struct direct *ep;
	if (!getargs(args, "s", &name))
		return NULL;
	BGN_SAVE
	if ((dirp = opendir(name)) == NULL) {
		RET_SAVE
		return posix_error();
	}
	if ((d = newlistobject(0)) == NULL) {
		closedir(dirp);
		RET_SAVE
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
	END_SAVE

	return d;
}

static object *
posix_mkdir(self, args)
	object *self;
	object *args;
{
	return posix_strint(args, mkdir);
}

static object *
posix_nice(self, args)
	object *self;
	object *args;
{
	int increment, value;

	if (!getargs(args, "i", &increment))
		return NULL;
	value = nice(increment);
	if (value == -1)
		return posix_error();
	return newintobject((long) value);
}

#if i386 && ! _SEQUENT_
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
#endif /* i386 && ! _SEQUENT_ */

static object *
posix_rename(self, args)
	object *self;
	object *args;
{
	return posix_2str(args, rename);
}

static object *
posix_rmdir(self, args)
	object *self;
	object *args;
{
	return posix_1str(args, rmdir);
}

static object *
posix_stat(self, args)
	object *self;
	object *args;
{
	return posix_do_stat(self, args, stat);
}

static object *
posix_system(self, args)
	object *self;
	object *args;
{
	char *command;
	long sts;
	if (!getargs(args, "s", &command))
		return NULL;
	BGN_SAVE
	sts = system(command);
	END_SAVE
	return newintobject(sts);
}

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

static object *
posix_unlink(self, args)
	object *self;
	object *args;
{
	return posix_1str(args, unlink);
}

#ifndef NO_UNAME
#include <sys/utsname.h>

extern int uname PROTO((struct utsname *));

static object *
posix_uname(self, args)
	object *self;
	object *args;
{
	struct utsname u;
	object *v;
	int res;
	if (!getnoarg(args))
		return NULL;
	BGN_SAVE
	res = uname(&u);
	END_SAVE
	if (res < 0)
		return posix_error();
	return mkvalue("(sssss)",
		       u.sysname,
		       u.nodename,
		       u.release,
		       u.version,
		       u.machine);
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
	int res;

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
	BGN_SAVE
	res = utime(path, UTIME_ARG);
	END_SAVE
	if (res < 0)
		return posix_error();
	INCREF(None);
	return None;
#undef UTIME_ARG
#undef ATIME
#undef MTIME
}


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

static object *
posix_execv(self, args)
	object *self;
	object *args;
{
	char *path;
	object *argv;
	char **argvlist;
	int i, argc;
	object *(*getitem) PROTO((object *, int));

	/* execv has two arguments: (path, argv), where
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
		if (!getargs((*getitem)(argv, i), "s", &argvlist[i])) {
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
posix_execve(self, args)
	object *self;
	object *args;
{
	char *path;
	object *argv, *env;
	char **argvlist;
	char **envlist;
	object *key, *val;
	int i, pos, argc, envc;
	object *(*getitem) PROTO((object *, int));

	/* execve has three arguments: (path, argv, env), where
	   argv is a list or tuple of strings and env is a dictionary
	   like posix.environ. */

	if (!getargs(args, "(sOO)", &path, &argv, &env))
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
		err_setstr(TypeError, "argv must be tuple or list");
		return NULL;
	}
	if (!is_dictobject(env)) {
		err_setstr(TypeError, "env must be dictionary");
		return NULL;
	}

	argvlist = NEW(char *, argc+1);
	if (argvlist == NULL) {
		err_nomem();
		return NULL;
	}
	for (i = 0; i < argc; i++) {
		if (!getargs((*getitem)(argv, i),
			     "s;argv must be list of strings",
			     &argvlist[i])) {
			goto fail_1;
		}
	}
	argvlist[argc] = NULL;

	i = getmappingsize(env);
	envlist = NEW(char *, i + 1);
	if (envlist == NULL) {
		err_nomem();
		goto fail_1;
	}
	pos = 0;
	envc = 0;
	while (mappinggetnext(env, &pos, &key, &val)) {
		char *p, *k, *v;
		if (!getargs(key, "s;non-string key in env", &k) ||
		    !getargs(val, "s;non-string value in env", &v)) {
			goto fail_2;
		}
		p = NEW(char, getstringsize(key) + getstringsize(val) + 2);
		if (p == NULL) {
			err_nomem();
			goto fail_2;
		}
		sprintf(p, "%s=%s", k, v);
		envlist[envc++] = p;
	}
	envlist[envc] = 0;

	execve(path, argvlist, envlist);
	
	/* If we get here it's definitely an error */

	(void) posix_error();

 fail_2:
	while (--envc >= 0)
		DEL(envlist[envc]);
	DEL(envlist);
 fail_1:
	DEL(argvlist);

	return NULL;
}

static object *
posix_fork(self, args)
	object *self;
	object *args;
{
	int pid;
	if (!getnoarg(args))
		return NULL;
	pid = fork();
	if (pid == -1)
		return posix_error();
	return newintobject((long)pid);
}

static object *
posix_getegid(self, args)
	object *self;
	object *args;
{
	if (!getnoarg(args))
		return NULL;
	return newintobject((long)getegid());
}

static object *
posix_geteuid(self, args)
	object *self;
	object *args;
{
	if (!getnoarg(args))
		return NULL;
	return newintobject((long)geteuid());
}

static object *
posix_getgid(self, args)
	object *self;
	object *args;
{
	if (!getnoarg(args))
		return NULL;
	return newintobject((long)getgid());
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
#ifdef SYSV
	return newintobject((long)getpgrp());
#else
	return newintobject((long)getpgrp(0));
#endif
}

static object *
posix_setpgrp(self, args)
	object *self;
	object *args;
{
	if (!getnoarg(args))
		return NULL;
#ifdef SYSV
	if (setpgrp() < 0)
#else
	if (setpgrp(0, 0) < 0)
#endif
		return posix_error();
	INCREF(None);
	return None;
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
posix_getuid(self, args)
	object *self;
	object *args;
{
	if (!getnoarg(args))
		return NULL;
	return newintobject((long)getuid());
}

static object *
posix_kill(self, args)
	object *self;
	object *args;
{
	int pid, sig;
	if (!getargs(args, "(ii)", &pid, &sig))
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
	char *name, *mode;
	FILE *fp;
	if (!getargs(args, "(ss)", &name, &mode))
		return NULL;
	BGN_SAVE
	fp = popen(name, mode);
	END_SAVE
	if (fp == NULL)
		return posix_error();
	/* From now on, ignore SIGPIPE and let the error checking
	   do the work. */
	(void) signal(SIGPIPE, SIG_IGN);
	return newopenfileobject(fp, name, mode, pclose);
}

static object *
posix_setuid(self, args)
	object *self;
	object *args;
{
	int uid;
	if (!getargs(args, "i", &uid))
		return NULL;
	if (setuid(uid) < 0)
		return posix_error();
	INCREF(None);
	return None;
}

static object *
posix_setgid(self, args)
	object *self;
	object *args;
{
	int gid;
	if (!getargs(args, "i", &gid))
		return NULL;
	if (setgid(gid) < 0)
		return posix_error();
	INCREF(None);
	return None;
}

static object *
posix_waitpid(self, args)
	object *self;
	object *args;
{
#ifdef NO_WAITPID
	err_setstr(PosixError,
		   "posix.waitpid() not supported on this system");
	return NULL;
#else
	int pid, options, sts;
	if (!getargs(args, "(ii)", &pid, &options))
		return NULL;
	BGN_SAVE
	pid = waitpid(pid, &sts, options);
	END_SAVE
	if (pid == -1)
		return posix_error();
	else
		return mkvalue("ii", pid, sts);
#endif
}

static object *
posix_wait(self, args)
	object *self;
	object *args;
{
	int pid, sts;
	if (args != NULL)
		return posix_waitpid(self, args); /* BW compat */
	BGN_SAVE
	pid = wait(&sts);
	END_SAVE
	if (pid == -1)
		return posix_error();
	else
		return mkvalue("ii", pid, sts);
}

static object *
posix_lstat(self, args)
	object *self;
	object *args;
{
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
	if (!getargs(args, "s", &path))
		return NULL;
	BGN_SAVE
	n = readlink(path, buf, (int) sizeof buf);
	END_SAVE
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
	return posix_2str(args, symlink);
#endif
}


#ifdef DO_TIMES

static object *
posix_times(self, args)
	object *self;
	object *args;
{
	struct tms t;
	clock_t c;
	if (!getnoarg(args))
		return NULL;
	errno = 0;
	c = times(&t);
	if (c == (clock_t) -1)
		return posix_error();
	return mkvalue("dddd",
		       (double)t.tms_utime / HZ,
		       (double)t.tms_stime / HZ,
		       (double)t.tms_cutime / HZ,
		       (double)t.tms_cstime / HZ);
}

#endif /* DO_TIMES */

#ifdef DO_PG

static object *
posix_setsid(self, args)
	object *self;
	object *args;
{
	if (!getnoarg(args))
		return NULL;
	if (setsid() < 0)
		return posix_error();
	INCREF(None);
	return None;
}

static object *
posix_setpgid(self, args)
	object *self;
	object *args;
{
	int pid, pgrp;
	if (!getargs(args, "(ii)", &pid, &pgrp))
		return NULL;
	if (setpgid(pid, pgrp) < 0)
		return posix_error();
	INCREF(None);
	return None;
}

static object *
posix_tcgetpgrp(self, args)
	object *self;
	object *args;
{
	int fd, pgid;
	if (!getargs(args, "i", &fd))
		return NULL;
	pgid = tcgetpgrp(fd);
	if (pgid < 0)
		return posix_error();
	return newintobject((long)pgid);
}

static object *
posix_tcsetpgrp(self, args)
	object *self;
	object *args;
{
	int fd, pgid;
	if (!getargs(args, "(ii)", &fd, &pgid))
		return NULL;
	if (tcsetpgrp(fd, pgid) < 0)
		return posix_error();
       INCREF(None);
	return None;
}

#endif /* DO_PG */

/* Functions acting on file descriptors */

static object *
posix_open(self, args)
	object *self;
	object *args;
{
	char *file;
	int flag;
	int mode = 0777;
	int fd;
	if (!getargs(args, "(si)", &file, &flag)) {
		err_clear();
		if (!getargs(args, "(sii)", &file, &flag, &mode))
			return NULL;
	}
	BGN_SAVE
	fd = open(file, flag, mode);
	END_SAVE
	if (fd < 0)
		return posix_error();
	return newintobject((long)fd);
}

static object *
posix_close(self, args)
	object *self;
	object *args;
{
	int fd, res;
	if (!getargs(args, "i", &fd))
		return NULL;
	BGN_SAVE
	res = close(fd);
	END_SAVE
	if (res < 0)
		return posix_error();
	INCREF(None);
	return None;
}

static object *
posix_dup(self, args)
	object *self;
	object *args;
{
	int fd;
	if (!getargs(args, "i", &fd))
		return NULL;
	BGN_SAVE
	fd = dup(fd);
	END_SAVE
	if (fd < 0)
		return posix_error();
	return newintobject((long)fd);
}

static object *
posix_dup2(self, args)
	object *self;
	object *args;
{
	int fd, fd2, res;
	if (!getargs(args, "(ii)", &fd, &fd2))
		return NULL;
	BGN_SAVE
	res = dup2(fd, fd2);
	END_SAVE
	if (res < 0)
		return posix_error();
	INCREF(None);
	return None;
}

static object *
posix_lseek(self, args)
	object *self;
	object *args;
{
	int fd, how;
	long pos, res;
	if (!getargs(args, "(ili)", &fd, &pos, &how))
		return NULL;
#ifdef SEEK_SET
	/* Turn 0, 1, 2 into SEEK_{SET,CUR,END} */
	switch (how) {
	case 0: how = SEEK_SET; break;
	case 1: how = SEEK_CUR; break;
	case 2: how = SEEK_END; break;
	}
#endif
	BGN_SAVE
	res = lseek(fd, pos, how);
	END_SAVE
	if (res < 0)
		return posix_error();
	return newintobject(res);
}

static object *
posix_read(self, args)
	object *self;
	object *args;
{
	int fd, size;
	object *buffer;
	if (!getargs(args, "(ii)", &fd, &size))
		return NULL;
	buffer = newsizedstringobject((char *)NULL, size);
	if (buffer == NULL)
		return NULL;
	BGN_SAVE
	size = read(fd, getstringvalue(buffer), size);
	END_SAVE
	if (size < 0) {
		DECREF(buffer);
		return posix_error();
	}
	resizestring(&buffer, size);
	return buffer;
}

static object *
posix_write(self, args)
	object *self;
	object *args;
{
	int fd, size;
	char *buffer;
	if (!getargs(args, "(is#)", &fd, &buffer, &size))
		return NULL;
	BGN_SAVE
	size = write(fd, buffer, size);
	END_SAVE
	if (size < 0)
		return posix_error();
	return newintobject((long)size);
}

static object *
posix_fstat(self, args)
	object *self;
	object *args;
{
	int fd;
	struct stat st;
	int res;
	if (!getargs(args, "i", &fd))
		return NULL;
	BGN_SAVE
	res = fstat(fd, &st);
	END_SAVE
	if (res != 0)
		return posix_error();
	return mkvalue("(llllllllll)",
		    (long)st.st_mode,
		    (long)st.st_ino,
		    (long)st.st_dev,
		    (long)st.st_nlink,
		    (long)st.st_uid,
		    (long)st.st_gid,
		    (long)st.st_size,
		    (long)st.st_atime,
		    (long)st.st_mtime,
		    (long)st.st_ctime);
}

static object *
posix_fdopen(self, args)
	object *self;
	object *args;
{
	extern int fclose PROTO((FILE *));
	int fd;
	char *mode;
	FILE *fp;
	if (!getargs(args, "(is)", &fd, &mode))
		return NULL;
	BGN_SAVE
	fp = fdopen(fd, mode);
	END_SAVE
	if (fp == NULL)
		return posix_error();
	/* From now on, ignore SIGPIPE and let the error checking
	   do the work. */
	(void) signal(SIGPIPE, SIG_IGN);
	return newopenfileobject(fp, "(fdopen)", mode, fclose);
}

static object *
posix_pipe(self, args)
	object *self;
	object *args;
{
	int fds[2];
	int res;
	if (!getargs(args, ""))
		return NULL;
	BGN_SAVE
	res = pipe(fds);
	END_SAVE
	if (res != 0)
		return posix_error();
	return mkvalue("(ii)", fds[0], fds[1]);
}

static struct methodlist posix_methods[] = {
	{"chdir",	posix_chdir},
	{"chmod",	posix_chmod},
	{"getcwd",	posix_getcwd},
	{"link",	posix_link},
	{"listdir",	posix_listdir},
	{"lstat",	posix_lstat},
	{"mkdir",	posix_mkdir},
	{"nice",	posix_nice},
	{"readlink",	posix_readlink},
	{"rename",	posix_rename},
	{"rmdir",	posix_rmdir},
	{"stat",	posix_stat},
	{"symlink",	posix_symlink},
	{"system",	posix_system},
	{"umask",	posix_umask},
#ifndef NO_UNAME
	{"uname",	posix_uname},
#endif
	{"unlink",	posix_unlink},
	{"utime",	posix_utime},
#ifdef DO_TIMES
	{"times",	posix_times},
#endif
	{"_exit",	posix__exit},
	{"execv",	posix_execv},
	{"execve",	posix_execve},
	{"fork",	posix_fork},
	{"getegid",	posix_getegid},
	{"geteuid",	posix_geteuid},
	{"getgid",	posix_getgid},
	{"getpid",	posix_getpid},
	{"getpgrp",	posix_getpgrp},
	{"getppid",	posix_getppid},
	{"getuid",	posix_getuid},
	{"kill",	posix_kill},
	{"popen",	posix_popen},
	{"setuid",	posix_setuid},
	{"setgid",	posix_setgid},
	{"setpgrp",	posix_setpgrp},
	{"wait",	posix_wait},
	{"waitpid",	posix_waitpid},
#ifdef DO_PG
	{"setsid",	posix_setsid},
	{"setpgid",	posix_setpgid},
	{"tcgetpgrp",	posix_tcgetpgrp},
	{"tcsetpgrp",	posix_tcsetpgrp},
#endif
	{"open",	posix_open},
	{"close",	posix_close},
	{"dup",		posix_dup},
	{"dup2",	posix_dup2},
	{"lseek",	posix_lseek},
	{"read",	posix_read},
	{"write",	posix_write},
	{"fstat",	posix_fstat},
	{"fdopen",	posix_fdopen},
	{"pipe",	posix_pipe},

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
