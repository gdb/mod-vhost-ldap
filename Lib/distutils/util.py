"""distutils.util

Miscellaneous utility functions -- anything that doesn't fit into
one of the other *util.py modules."""

# created 1999/03/08, Greg Ward

__revision__ = "$Id$"

import sys, os, string, re, shutil
from distutils.errors import *
from distutils.spawn import spawn

# for backwards compatibility:
from distutils.file_util import *
from distutils.dir_util import *
from distutils.dep_util import *
from distutils.archive_util import *


# More backwards compatibility hacks
def extend (list, new_list):
    """Appends the list 'new_list' to 'list', just like the 'extend()'
       list method does in Python 1.5.2 -- but this works on earlier
       versions of Python too."""

    if hasattr (list, 'extend'):
        list.extend (new_list)
    else:
        list[len(list):] = new_list

# extend ()


def get_platform ():
    """Return a string (suitable for tacking onto directory names) that
    identifies the current platform.  Currently, this is just
    'sys.platform'.
    """
    return sys.platform


def convert_path (pathname):
    """Return 'pathname' as a name that will work on the native
       filesystem, i.e. split it on '/' and put it back together again
       using the current directory separator.  Needed because filenames in
       the setup script are always supplied in Unix style, and have to be
       converted to the local convention before we can actually use them in
       the filesystem.  Raises ValueError if 'pathname' is
       absolute (starts with '/') or contains local directory separators
       (unless the local separator is '/', of course)."""

    if pathname[0] == '/':
        raise ValueError, "path '%s' cannot be absolute" % pathname
    if pathname[-1] == '/':
        raise ValueError, "path '%s' cannot end with '/'" % pathname
    if os.sep != '/':
        paths = string.split (pathname, '/')
        return apply (os.path.join, paths)
    else:
        return pathname

# convert_path ()


def change_root (new_root, pathname):
    """Return 'pathname' with 'new_root' prepended.  If 'pathname' is
    relative, this is equivalent to "os.path.join(new_root,pathname)".
    Otherwise, it requires making 'pathname' relative and then joining the
    two, which is tricky on DOS/Windows and Mac OS.
    """
    if os.name == 'posix':
        if not os.path.isabs (pathname):
            return os.path.join (new_root, pathname)
        else:
            return os.path.join (new_root, pathname[1:])

    elif os.name == 'nt':
        (drive, path) = os.path.splitdrive (pathname)
        if path[0] == '\\':
            path = path[1:]
        return os.path.join (new_root, path)

    elif os.name == 'mac':
        raise RuntimeError, "no clue how to do this on Mac OS"

    else:
        raise DistutilsPlatformError, \
              "nothing known about platform '%s'" % os.name


_environ_checked = 0
def check_environ ():
    """Ensure that 'os.environ' has all the environment variables we
       guarantee that users can use in config files, command-line
       options, etc.  Currently this includes:
         HOME - user's home directory (Unix only)
         PLAT - description of the current platform, including hardware
                and OS (see 'get_platform()')
    """

    global _environ_checked
    if _environ_checked:
        return

    if os.name == 'posix' and not os.environ.has_key('HOME'):
        import pwd
        os.environ['HOME'] = pwd.getpwuid (os.getuid())[5]

    if not os.environ.has_key('PLAT'):
        os.environ['PLAT'] = get_platform ()

    _environ_checked = 1


def subst_vars (str, local_vars):
    """Perform shell/Perl-style variable substitution on 'string'.
       Every occurrence of '$' followed by a name, or a name enclosed in
       braces, is considered a variable.  Every variable is substituted by
       the value found in the 'local_vars' dictionary, or in 'os.environ'
       if it's not in 'local_vars'.  'os.environ' is first checked/
       augmented to guarantee that it contains certain values: see
       '_check_environ()'.  Raise ValueError for any variables not found in
       either 'local_vars' or 'os.environ'."""

    check_environ ()
    def _subst (match, local_vars=local_vars):
        var_name = match.group(1)
        if local_vars.has_key (var_name):
            return str (local_vars[var_name])
        else:
            return os.environ[var_name]

    return re.sub (r'\$([a-zA-Z_][a-zA-Z_0-9]*)', _subst, str)

# subst_vars ()


def grok_environment_error (exc, prefix="error: "):
    """Generate a useful error message from an EnvironmentError (IOError or
    OSError) exception object.  Handles Python 1.5.1 and 1.5.2 styles, and
    does what it can to deal with exception objects that don't have a
    filename (which happens when the error is due to a two-file operation,
    such as 'rename()' or 'link()'.  Returns the error message as a string
    prefixed with 'prefix'.
    """
    # check for Python 1.5.2-style {IO,OS}Error exception objects
    if hasattr (exc, 'filename') and hasattr (exc, 'strerror'):
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
_wordchars_re = re.compile(r'[^\\\'\"\ ]*')
_squote_re = re.compile(r"'(?:[^'\\]|\\.)*'")
_dquote_re = re.compile(r'"(?:[^"\\]|\\.)*"')

def split_quoted (s):
    """Split a string up according to Unix shell-like rules for quotes and
    backslashes.  In short: words are delimited by spaces, as long as those
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

    s = string.strip(s)
    words = []
    pos = 0

    while s:
        m = _wordchars_re.match(s, pos)
        end = m.end()
        if end == len(s):
            words.append(s[:end])
            break

        if s[end] == ' ':               # unescaped, unquoted space: now
            words.append(s[:end])       # we definitely have a word delimiter
            s = string.lstrip(s[end:])
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
                raise RuntimeError, \
                      "this can't happen (bad char '%c')" % s[end]

            if m is None:
                raise ValueError, \
                      "bad string (mismatched %s quotes?)" % s[end]

            (beg, end) = m.span()
            s = s[:beg] + s[beg+1:end-1] + s[end:]
            pos = m.end() - 2

        if pos >= len(s):
            words.append(s)
            break

    return words

# split_quoted ()
