"""Utility functions for copying files and directory trees.

XXX The functions here don't copy the resource fork or other metadata on Mac.

"""

import os
import sys
import stat
import exceptions
from os.path import abspath

__all__ = ["copyfileobj","copyfile","copymode","copystat","copy","copy2",
           "copytree","move","rmtree","Error"]

class Error(exceptions.EnvironmentError):
    pass

def copyfileobj(fsrc, fdst, length=16*1024):
    """copy data from file-like object fsrc to file-like object fdst"""
    while 1:
        buf = fsrc.read(length)
        if not buf:
            break
        fdst.write(buf)

def _samefile(src, dst):
    # Macintosh, Unix.
    if hasattr(os.path,'samefile'):
        try:
            return os.path.samefile(src, dst)
        except OSError:
            return False

    # All other platforms: check for same pathname.
    return (os.path.normcase(os.path.abspath(src)) ==
            os.path.normcase(os.path.abspath(dst)))

def copyfile(src, dst):
    """Copy data from src to dst"""
    if _samefile(src, dst):
        raise Error, "`%s` and `%s` are the same file" % (src, dst)

    fsrc = None
    fdst = None
    try:
        fsrc = open(src, 'rb')
        fdst = open(dst, 'wb')
        copyfileobj(fsrc, fdst)
    finally:
        if fdst:
            fdst.close()
        if fsrc:
            fsrc.close()

def copymode(src, dst):
    """Copy mode bits from src to dst"""
    if hasattr(os, 'chmod'):
        st = os.stat(src)
        mode = stat.S_IMODE(st.st_mode)
        os.chmod(dst, mode)

def copystat(src, dst):
    """Copy all stat info (mode bits, atime and mtime) from src to dst"""
    st = os.stat(src)
    mode = stat.S_IMODE(st.st_mode)
    if hasattr(os, 'utime'):
        os.utime(dst, (st.st_atime, st.st_mtime))
    if hasattr(os, 'chmod'):
        os.chmod(dst, mode)


def copy(src, dst):
    """Copy data and mode bits ("cp src dst").

    The destination may be a directory.

    """
    if os.path.isdir(dst):
        dst = os.path.join(dst, os.path.basename(src))
    copyfile(src, dst)
    copymode(src, dst)

def copy2(src, dst):
    """Copy data and all stat info ("cp -p src dst").

    The destination may be a directory.

    """
    if os.path.isdir(dst):
        dst = os.path.join(dst, os.path.basename(src))
    copyfile(src, dst)
    copystat(src, dst)


def copytree(src, dst, symlinks=False):
    """Recursively copy a directory tree using copy2().

    The destination directory must not already exist.
    If exception(s) occur, an Error is raised with a list of reasons.

    If the optional symlinks flag is true, symbolic links in the
    source tree result in symbolic links in the destination tree; if
    it is false, the contents of the files pointed to by symbolic
    links are copied.

    XXX Consider this example code rather than the ultimate tool.

    """
    names = os.listdir(src)
    os.mkdir(dst)
    errors = []
    for name in names:
        srcname = os.path.join(src, name)
        dstname = os.path.join(dst, name)
        try:
            if symlinks and os.path.islink(srcname):
                linkto = os.readlink(srcname)
                os.symlink(linkto, dstname)
            elif os.path.isdir(srcname):
                copytree(srcname, dstname, symlinks)
            else:
                copy2(srcname, dstname)
            # XXX What about devices, sockets etc.?
        except (IOError, os.error), why:
            errors.append((srcname, dstname, why))
    if errors:
        raise Error, errors

def _raise_err(err):
    raise err

def rmtree(path, ignore_errors=False, onerror=None):
    """Recursively delete a directory tree.

    If ignore_errors is set, errors are ignored; otherwise, if
    onerror is set, it is called to handle the error; otherwise, an
    exception is raised.
    """
    # This strange way of calling functions is necessary to keep the onerror
    # argument working. Maybe sys._getframe hackery would work as well, but
    # this is simple.
    func = os.listdir
    arg = path
    try:
        for (dirpath, dirnames, filenames) in os.walk(path, topdown=False,
                                                      onerror=_raise_err):
            for filename in filenames:
                func = os.remove
                arg = os.path.join(dirpath, filename)
                func(arg)
            func = os.rmdir
            arg = dirpath
            func(arg)
    except OSError:
        exc = sys.exc_info()
        if ignore_errors:
            pass
        elif onerror is not None:
            onerror(func, arg, exc)
        else:
            raise exc[0], (exc[1][0], exc[1][1] + ' removing '+arg)

def move(src, dst):
    """Recursively move a file or directory to another location.

    If the destination is on our current filesystem, then simply use
    rename.  Otherwise, copy src to the dst and then remove src.
    A lot more could be done here...  A look at a mv.c shows a lot of
    the issues this implementation glosses over.

    """

    try:
        os.rename(src, dst)
    except OSError:
        if os.path.isdir(src):
            if destinsrc(src, dst):
                raise Error, "Cannot move a directory '%s' into itself '%s'." % (src, dst)
            copytree(src, dst, symlinks=True)
            rmtree(src)
        else:
            copy2(src,dst)
            os.unlink(src)

def destinsrc(src, dst):
    return abspath(dst).startswith(abspath(src))
