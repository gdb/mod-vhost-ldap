# os.py -- either mac, dos or posix depending on what system we're on.

# This exports:
# - all functions from either posix or mac, e.g., os.unlink, os.stat, etc.
# - os.path is either module posixpath or macpath
# - os.name is either 'posix' or 'mac'
# - os.curdir is a string representing the current directory ('.' or ':')
# - os.pardir is a string representing the parent directory ('..' or '::')
# - os.sep is the (or a most common) pathname separator ('/' or ':' or '\\')
# - os.altsep is the alternatte pathname separator (None or '/')
# - os.pathsep is the component separator used in $PATH etc
# - os.defpath is the default search path for executables

# Programs that import and use 'os' stand a better chance of being
# portable between different platforms.  Of course, they must then
# only use functions that are defined by all platforms (e.g., unlink
# and opendir), and leave all pathname manipulation to os.path
# (e.g., split and join).

import sys

_names = sys.builtin_module_names

altsep = None

if 'posix' in _names:
    name = 'posix'
    linesep = '\n'
    curdir = '.'; pardir = '..'; sep = '/'; pathsep = ':'
    defpath = ':/bin:/usr/bin'
    from posix import *
    try:
        from posix import _exit
    except ImportError:
        pass
    import posixpath
    path = posixpath
    del posixpath
elif 'nt' in _names:
    name = 'nt'
    linesep = '\r\n'
    curdir = '.'; pardir = '..'; sep = '\\'; pathsep = ';'
    defpath = '.;C:\\bin'
    from nt import *
    for i in ['_exit']:
        try:
            exec "from nt import " + i
        except ImportError:
            pass
    import ntpath
    path = ntpath
    del ntpath
elif 'dos' in _names:
    name = 'dos'
    linesep = '\r\n'
    curdir = '.'; pardir = '..'; sep = '\\'; pathsep = ';'
    defpath = '.;C:\\bin'
    from dos import *
    try:
        from dos import _exit
    except ImportError:
        pass
    import dospath
    path = dospath
    del dospath
elif 'os2' in _names:
    name = 'os2'
    linesep = '\r\n'
    curdir = '.'; pardir = '..'; sep = '\\'; pathsep = ';'
    defpath = '.;C:\\bin'
    from os2 import *
    try:
        from os2 import _exit
    except ImportError:
        pass
    import ntpath
    path = ntpath
    del ntpath
elif 'mac' in _names:
    name = 'mac'
    linesep = '\r'
    curdir = ':'; pardir = '::'; sep = ':'; pathsep = '\n'
    defpath = ':'
    from mac import *
    try:
        from mac import _exit
    except ImportError:
        pass
    import macpath
    path = macpath
    del macpath
elif 'ce' in _names:
    name = 'ce'
    linesep = '\r\n'
    curdir = '.'; pardir = '..'; sep = '\\'; pathsep = ';'
    defpath = '\\Windows'
    from ce import *
    for i in ['_exit']:
        try:
            exec "from ce import " + i
        except ImportError:
            pass
    # We can use the standard Windows path.
    import ntpath
    path = ntpath
    del ntpath
else:
    raise ImportError, 'no os specific module found'

del _names

sys.modules['os.path'] = path

# Super directory utilities.
# (Inspired by Eric Raymond; the doc strings are mostly his)

def makedirs(name, mode=0777):
    """makedirs(path [, mode=0777]) -> None

    Super-mkdir; create a leaf directory and all intermediate ones.
    Works like mkdir, except that any intermediate path segment (not
    just the rightmost) will be created if it does not exist.  This is
    recursive.

    """
    head, tail = path.split(name)
    if head and tail and not path.exists(head):
        makedirs(head, mode)
    mkdir(name, mode)

def removedirs(name):
    """removedirs(path) -> None

    Super-rmdir; remove a leaf directory and empty all intermediate
    ones.  Works like rmdir except that, if the leaf directory is
    successfully removed, directories corresponding to rightmost path
    segments will be pruned way until either the whole path is
    consumed or an error occurs.  Errors during this latter phase are
    ignored -- they generally mean that a directory was not empty.

    """
    rmdir(name)
    head, tail = path.split(name)
    while head and tail:
        try:
            rmdir(head)
        except error:
            break
        head, tail = path.split(head)

def renames(old, new):
    """renames(old, new) -> None

    Super-rename; create directories as necessary and delete any left
    empty.  Works like rename, except creation of any intermediate
    directories needed to make the new pathname good is attempted
    first.  After the rename, directories corresponding to rightmost
    path segments of the old name will be pruned way until either the
    whole path is consumed or a nonempty directory is found.

    Note: this function can fail with the new directory structure made
    if you lack permissions needed to unlink the leaf directory or
    file.

    """
    head, tail = path.split(new)
    if head and tail and not path.exists(head):
        makedirs(head)
    rename(old, new)
    head, tail = path.split(old)
    if head and tail:
        try:
            removedirs(head)
        except error:
            pass

# Make sure os.environ exists, at least
try:
    environ
except NameError:
    environ = {}

def execl(file, *args):
    execv(file, args)

def execle(file, *args):
    env = args[-1]
    execve(file, args[:-1], env)

def execlp(file, *args):
    execvp(file, args)

def execlpe(file, *args):
    env = args[-1]
    execvpe(file, args[:-1], env)

def execvp(file, args):
    _execvpe(file, args)

def execvpe(file, args, env):
    _execvpe(file, args, env)

_notfound = None
def _execvpe(file, args, env=None):
    if env is not None:
        func = execve
        argrest = (args, env)
    else:
        func = execv
        argrest = (args,)
        env = environ
    global _notfound
    head, tail = path.split(file)
    if head:
        apply(func, (file,) + argrest)
        return
    if env.has_key('PATH'):
        envpath = env['PATH']
    else:
        envpath = defpath
    import string
    PATH = string.splitfields(envpath, pathsep)
    if not _notfound:
        import tempfile
        # Exec a file that is guaranteed not to exist
        try: execv(tempfile.mktemp(), ())
        except error, _notfound: pass
    exc, arg = error, _notfound
    for dir in PATH:
        fullname = path.join(dir, file)
        try:
            apply(func, (fullname,) + argrest)
        except error, (errno, msg):
            if errno != arg[0]:
                exc, arg = error, (errno, msg)
    raise exc, arg

# Change environ to automatically call putenv() if it exists
try:
    # This will fail if there's no putenv
    putenv
except NameError:
    pass
else:
    import UserDict

    if name in ('os2', 'nt', 'dos'):  # Where Env Var Names Must Be UPPERCASE
        # But we store them as upper case
        import string
        class _Environ(UserDict.UserDict):
            def __init__(self, environ):
                UserDict.UserDict.__init__(self)
                data = self.data
                upper = string.upper
                for k, v in environ.items():
                    data[upper(k)] = v
            def __setitem__(self, key, item):
                putenv(key, item)
                key = string.upper(key)
                self.data[key] = item
            def __getitem__(self, key):
                return self.data[string.upper(key)]
            def has_key(self, key):
                return self.data.has_key(string.upper(key))

    else:  # Where Env Var Names Can Be Mixed Case
        class _Environ(UserDict.UserDict):
            def __init__(self, environ):
                UserDict.UserDict.__init__(self)
                self.data = environ
            def __setitem__(self, key, item):
                putenv(key, item)
                self.data[key] = item

    environ = _Environ(environ)

def getenv(key, default=None):
    """Get an environment variable, return None if it doesn't exist.

    The optional second argument can specify an alternative default."""
    return environ.get(key, default)

def _exists(name):
    try:
        eval(name)
        return 1
    except NameError:
        return 0

# Supply spawn*() (probably only for Unix)
if _exists("fork") and not _exists("spawnv") and _exists("execv"):

    P_WAIT = 0
    P_NOWAIT = P_NOWAITO = 1

    # XXX Should we support P_DETACH?  I suppose it could fork()**2
    # and close the std I/O streams.  Also, P_OVERLAY is the same
    # as execv*()?

    def _spawnvef(mode, file, args, env, func):
        # Internal helper; func is the exec*() function to use
        pid = fork()
        if not pid:
            # Child
            try:
                if env is None:
                    func(file, args)
                else:
                    func(file, args, env)
            except:
                _exit(127)
        else:
            # Parent
            if mode == P_NOWAIT:
                return pid # Caller is responsible for waiting!
            while 1:
                wpid, sts = waitpid(pid, 0)
                if WIFSTOPPED(sts):
                    continue
                elif WIFSIGNALED(sts):
                    return -WTERMSIG(sts)
                elif WIFEXITED(sts):
                    return WEXITSTATUS(sts)
                else:
                    raise error, "Not stopped, signaled or exited???"

    def spawnv(mode, file, args):
        return _spawnvef(mode, file, args, None, execv)

    def spawnve(mode, file, args, env):
        return _spawnvef(mode, file, args, env, execve)

    # Note: spawnvp[e] is't currently supported on Windows

    def spawnvp(mode, file, args):
        return _spawnvef(mode, file, args, None, execvp)

    def spawnvpe(mode, file, args, env):
        return _spawnvef(mode, file, args, env, execvpe)

if _exists("spawnv"):
    # These aren't supplied by the basic Windows code
    # but can be easily implemented in Python

    def spawnl(mode, file, *args):
        return spawnv(mode, file, args)

    def spawnle(mode, file, *args):
        env = args[-1]
        return spawnve(mode, file, args[:-1], env)

if _exists("spawnvp"):
    # At the moment, Windows doesn't implement spawnvp[e],
    # so it won't have spawnlp[e] either.
    def spawnlp(mode, file, *args):
        return spawnvp(mode, file, args)

    def spawnlpe(mode, file, *args):
        env = args[-1]
        return spawnvpe(mode, file, args[:-1], env)
