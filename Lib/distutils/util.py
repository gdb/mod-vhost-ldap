"""distutils.util

Miscellaneous utility functions -- anything that doesn't fit into
one of the other *util.py modules.
"""

__revision__ = "$Id$"

import sys, os, string, re

from distutils.errors import DistutilsPlatformError
from distutils.dep_util import newer
from distutils.spawn import spawn, find_executable
from distutils import log
from distutils.version import LooseVersion
from distutils.errors import DistutilsByteCompileError

_sysconfig = __import__('sysconfig')

def convert_path(pathname):
    """Return 'pathname' as a name that will work on the native filesystem.

    i.e. split it on '/' and put it back together again using the current
    directory separator.  Needed because filenames in the setup script are
    always supplied in Unix style, and have to be converted to the local
    convention before we can actually use them in the filesystem.  Raises
    ValueError on non-Unix-ish systems if 'pathname' either starts or
    ends with a slash.
    """
    if os.sep == '/':
        return pathname
    if not pathname:
        return pathname
    if pathname[0] == '/':
        raise ValueError("path '%s' cannot be absolute" % pathname)
    if pathname[-1] == '/':
        raise ValueError("path '%s' cannot end with '/'" % pathname)

    paths = pathname.split('/')
    while '.' in paths:
        paths.remove('.')
    if not paths:
        return os.curdir
    return os.path.join(*paths)


def change_root(new_root, pathname):
    """Return 'pathname' with 'new_root' prepended.

    If 'pathname' is relative, this is equivalent to
    "os.path.join(new_root,pathname)".
    Otherwise, it requires making 'pathname' relative and then joining the
    two, which is tricky on DOS/Windows and Mac OS.
    """
    if os.name == 'posix':
        if not os.path.isabs(pathname):
            return os.path.join(new_root, pathname)
        else:
            return os.path.join(new_root, pathname[1:])

    elif os.name == 'nt':
        (drive, path) = os.path.splitdrive(pathname)
        if path[0] == '\\':
            path = path[1:]
        return os.path.join(new_root, path)

    elif os.name == 'os2':
        (drive, path) = os.path.splitdrive(pathname)
        if path[0] == os.sep:
            path = path[1:]
        return os.path.join(new_root, path)

    elif os.name == 'mac':
        if not os.path.isabs(pathname):
            return os.path.join(new_root, pathname)
        else:
            # Chop off volume name from start of path
            elements = pathname.split(":", 1)
            pathname = ":" + elements[1]
            return os.path.join(new_root, pathname)

    else:
        raise DistutilsPlatformError("nothing known about "
                                     "platform '%s'" % os.name)

_environ_checked = 0

def check_environ():
    """Ensure that 'os.environ' has all the environment variables needed.

    We guarantee that users can use in config files, command-line options,
    etc.  Currently this includes:
      HOME - user's home directory (Unix only)
      PLAT - description of the current platform, including hardware
             and OS (see 'get_platform()')
    """
    global _environ_checked
    if _environ_checked:
        return

    if os.name == 'posix' and 'HOME' not in os.environ:
        import pwd
        os.environ['HOME'] = pwd.getpwuid(os.getuid())[5]

    if 'PLAT' not in os.environ:
        os.environ['PLAT'] = _sysconfig.get_platform()

    _environ_checked = 1

def subst_vars(s, local_vars):
    """Perform shell/Perl-style variable substitution on 'string'.

    Every occurrence of '$' followed by a name is considered a variable, and
    variable is substituted by the value found in the 'local_vars'
    dictionary, or in 'os.environ' if it's not in 'local_vars'.
    'os.environ' is first checked/augmented to guarantee that it contains
    certain values: see 'check_environ()'.  Raise ValueError for any
    variables not found in either 'local_vars' or 'os.environ'.
    """
    check_environ()
    def _subst (match, local_vars=local_vars):
        var_name = match.group(1)
        if var_name in local_vars:
            return str(local_vars[var_name])
        else:
            return os.environ[var_name]

    try:
        return re.sub(r'\$([a-zA-Z_][a-zA-Z_0-9]*)', _subst, s)
    except KeyError, var:
        raise ValueError("invalid variable '$%s'" % var)

def grok_environment_error(exc, prefix="error: "):
    """Generate a useful error message from an EnvironmentError.

    This will generate an IOError or an OSError exception object.
    Handles Python 1.5.1 and 1.5.2 styles, and
    does what it can to deal with exception objects that don't have a
    filename (which happens when the error is due to a two-file operation,
    such as 'rename()' or 'link()'.  Returns the error message as a string
    prefixed with 'prefix'.
    """
    # check for Python 1.5.2-style {IO,OS}Error exception objects
    if hasattr(exc, 'filename') and hasattr(exc, 'strerror'):
        if exc.filename:
            error = prefix + "%s: %s" % (exc.filename, exc.strerror)
        else:
            # two-argument functions in posix module don't
            # include the filename in the exception object!
            error = prefix + "%s" % exc.strerror
    else:
        error = prefix + str(exc[-1])

    return error

# Needed by 'split_quoted()'
_wordchars_re = _squote_re = _dquote_re = None

def _init_regex():
    global _wordchars_re, _squote_re, _dquote_re
    _wordchars_re = re.compile(r'[^\\\'\"%s ]*' % string.whitespace)
    _squote_re = re.compile(r"'(?:[^'\\]|\\.)*'")
    _dquote_re = re.compile(r'"(?:[^"\\]|\\.)*"')

def split_quoted(s):
    """Split a string up according to Unix shell-like rules for quotes and
    backslashes.

    In short: words are delimited by spaces, as long as those
    spaces are not escaped by a backslash, or inside a quoted string.
    Single and double quotes are equivalent, and the quote characters can
    be backslash-escaped.  The backslash is stripped from any two-character
    escape sequence, leaving only the escaped character.  The quote
    characters are stripped from any quoted string.  Returns a list of
    words.
    """
    # This is a nice algorithm for splitting up a single string, since it
    # doesn't require character-by-character examination.  It was a little
    # bit of a brain-bender to get it working right, though...
    if _wordchars_re is None: _init_regex()

    s = s.strip()
    words = []
    pos = 0

    while s:
        m = _wordchars_re.match(s, pos)
        end = m.end()
        if end == len(s):
            words.append(s[:end])
            break

        if s[end] in string.whitespace: # unescaped, unquoted whitespace: now
            words.append(s[:end])       # we definitely have a word delimiter
            s = s[end:].lstrip()
            pos = 0

        elif s[end] == '\\':            # preserve whatever is being escaped;
                                        # will become part of the current word
            s = s[:end] + s[end+1:]
            pos = end+1

        else:
            if s[end] == "'":           # slurp singly-quoted string
                m = _squote_re.match(s, end)
            elif s[end] == '"':         # slurp doubly-quoted string
                m = _dquote_re.match(s, end)
            else:
                raise RuntimeError("this can't happen "
                                   "(bad char '%c')" % s[end])

            if m is None:
                raise ValueError("bad string (mismatched %s quotes?)" % s[end])

            (beg, end) = m.span()
            s = s[:beg] + s[beg+1:end-1] + s[end:]
            pos = m.end() - 2

        if pos >= len(s):
            words.append(s)
            break

    return words


def execute(func, args, msg=None, verbose=0, dry_run=0):
    """Perform some action that affects the outside world.

    eg. by writing to the filesystem).  Such actions are special because
    they are disabled by the 'dry_run' flag.  This method takes care of all
    that bureaucracy for you; all you have to do is supply the
    function to call and an argument tuple for it (to embody the
    "external action" being performed), and an optional message to
    print.
    """
    if msg is None:
        msg = "%s%r" % (func.__name__, args)
        if msg[-2:] == ',)':        # correct for singleton tuple
            msg = msg[0:-2] + ')'

    log.info(msg)
    if not dry_run:
        func(*args)


def strtobool(val):
    """Convert a string representation of truth to true (1) or false (0).

    True values are 'y', 'yes', 't', 'true', 'on', and '1'; false values
    are 'n', 'no', 'f', 'false', 'off', and '0'.  Raises ValueError if
    'val' is anything else.
    """
    val = val.lower()
    if val in ('y', 'yes', 't', 'true', 'on', '1'):
        return 1
    elif val in ('n', 'no', 'f', 'false', 'off', '0'):
        return 0
    else:
        raise ValueError, "invalid truth value %r" % (val,)


def byte_compile(py_files, optimize=0, force=0, prefix=None, base_dir=None,
                  verbose=1, dry_run=0, direct=None):
    """Byte-compile a collection of Python source files to either .pyc
    or .pyo files in the same directory.

    'py_files' is a list of files to compile; any files that don't end in
    ".py" are silently skipped. 'optimize' must be one of the following:
      0 - don't optimize (generate .pyc)
      1 - normal optimization (like "python -O")
      2 - extra optimization (like "python -OO")
    If 'force' is true, all files are recompiled regardless of
    timestamps.

    The source filename encoded in each bytecode file defaults to the
    filenames listed in 'py_files'; you can modify these with 'prefix' and
    'basedir'.  'prefix' is a string that will be stripped off of each
    source filename, and 'base_dir' is a directory name that will be
    prepended (after 'prefix' is stripped).  You can supply either or both
    (or neither) of 'prefix' and 'base_dir', as you wish.

    If 'dry_run' is true, doesn't actually do anything that would
    affect the filesystem.

    Byte-compilation is either done directly in this interpreter process
    with the standard py_compile module, or indirectly by writing a
    temporary script and executing it.  Normally, you should let
    'byte_compile()' figure out to use direct compilation or not (see
    the source for details).  The 'direct' flag is used by the script
    generated in indirect mode; unless you know what you're doing, leave
    it set to None.
    """
    # nothing is done if sys.dont_write_bytecode is True
    if sys.dont_write_bytecode:
        raise DistutilsByteCompileError('byte-compiling is disabled.')

    # First, if the caller didn't force us into direct or indirect mode,
    # figure out which mode we should be in.  We take a conservative
    # approach: choose direct mode *only* if the current interpreter is
    # in debug mode and optimize is 0.  If we're not in debug mode (-O
    # or -OO), we don't know which level of optimization this
    # interpreter is running with, so we can't do direct
    # byte-compilation and be certain that it's the right thing.  Thus,
    # always compile indirectly if the current interpreter is in either
    # optimize mode, or if either optimization level was requested by
    # the caller.
    if direct is None:
        direct = (__debug__ and optimize == 0)

    # "Indirect" byte-compilation: write a temporary script and then
    # run it with the appropriate flags.
    if not direct:
        try:
            from tempfile import mkstemp
            (script_fd, script_name) = mkstemp(".py")
        except ImportError:
            from tempfile import mktemp
            (script_fd, script_name) = None, mktemp(".py")
        log.info("writing byte-compilation script '%s'", script_name)
        if not dry_run:
            if script_fd is not None:
                script = os.fdopen(script_fd, "w")
            else:
                script = open(script_name, "w")

            script.write("""\
from distutils.util import byte_compile
files = [
""")

            # XXX would be nice to write absolute filenames, just for
            # safety's sake (script should be more robust in the face of
            # chdir'ing before running it).  But this requires abspath'ing
            # 'prefix' as well, and that breaks the hack in build_lib's
            # 'byte_compile()' method that carefully tacks on a trailing
            # slash (os.sep really) to make sure the prefix here is "just
            # right".  This whole prefix business is rather delicate -- the
            # problem is that it's really a directory, but I'm treating it
            # as a dumb string, so trailing slashes and so forth matter.

            #py_files = map(os.path.abspath, py_files)
            #if prefix:
            #    prefix = os.path.abspath(prefix)

            script.write(",\n".join(map(repr, py_files)) + "]\n")
            script.write("""
byte_compile(files, optimize=%r, force=%r,
             prefix=%r, base_dir=%r,
             verbose=%r, dry_run=0,
             direct=1)
""" % (optimize, force, prefix, base_dir, verbose))

            script.close()

        cmd = [sys.executable, script_name]
        if optimize == 1:
            cmd.insert(1, "-O")
        elif optimize == 2:
            cmd.insert(1, "-OO")
        spawn(cmd, dry_run=dry_run)
        execute(os.remove, (script_name,), "removing %s" % script_name,
                dry_run=dry_run)

    # "Direct" byte-compilation: use the py_compile module to compile
    # right here, right now.  Note that the script generated in indirect
    # mode simply calls 'byte_compile()' in direct mode, a weird sort of
    # cross-process recursion.  Hey, it works!
    else:
        from py_compile import compile

        for file in py_files:
            if file[-3:] != ".py":
                # This lets us be lazy and not filter filenames in
                # the "install_lib" command.
                continue

            # Terminology from the py_compile module:
            #   cfile - byte-compiled file
            #   dfile - purported source filename (same as 'file' by default)
            cfile = file + (__debug__ and "c" or "o")
            dfile = file
            if prefix:
                if file[:len(prefix)] != prefix:
                    raise ValueError("invalid prefix: filename %r doesn't "
                                     "start with %r" % (file, prefix))
                dfile = dfile[len(prefix):]
            if base_dir:
                dfile = os.path.join(base_dir, dfile)

            cfile_base = os.path.basename(cfile)
            if direct:
                if force or newer(file, cfile):
                    log.info("byte-compiling %s to %s", file, cfile_base)
                    if not dry_run:
                        compile(file, cfile, dfile)
                else:
                    log.debug("skipping byte-compilation of %s to %s",
                              file, cfile_base)


def rfc822_escape(header):
    """Return a version of the string escaped for inclusion in an
    RFC-822 header, by ensuring there are 8 spaces space after each newline.
    """
    lines = header.split('\n')
    sep = '\n' + 8 * ' '
    return sep.join(lines)

_RE_VERSION = re.compile('(\d+\.\d+(\.\d+)*)')
_MAC_OS_X_LD_VERSION = re.compile('^@\(#\)PROGRAM:ld  PROJECT:ld64-((\d+)(\.\d+)*)')

def _find_ld_version():
    """Finds the ld version. The version scheme differs under Mac OSX."""
    if sys.platform == 'darwin':
        return _find_exe_version('ld -v', _MAC_OS_X_LD_VERSION)
    else:
        return _find_exe_version('ld -v')

def _find_exe_version(cmd, pattern=_RE_VERSION):
    """Find the version of an executable by running `cmd` in the shell.

    `pattern` is a compiled regular expression. If not provided, default
    to _RE_VERSION. If the command is not found, or the output does not
    match the mattern, returns None.
    """
    from subprocess import Popen, PIPE
    executable = cmd.split()[0]
    if find_executable(executable) is None:
        return None
    pipe = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    try:
        stdout, stderr = pipe.stdout.read(), pipe.stderr.read()
    finally:
        pipe.stdout.close()
        pipe.stderr.close()
    # some commands like ld under MacOS X, will give the
    # output in the stderr, rather than stdout.
    if stdout != '':
        out_string = stdout
    else:
        out_string = stderr

    result = pattern.search(out_string)
    if result is None:
        return None
    return LooseVersion(result.group(1))

def get_compiler_versions():
    """Returns a tuple providing the versions of gcc, ld and dllwrap

    For each command, if a command is not found, None is returned.
    Otherwise a LooseVersion instance is returned.
    """
    gcc = _find_exe_version('gcc -dumpversion')
    ld = _find_ld_version()
    dllwrap = _find_exe_version('dllwrap --version')
    return gcc, ld, dllwrap
