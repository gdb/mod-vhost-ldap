"""distutils.util

General-purpose utility functions used throughout the Distutils
(especially in command classes).  Mostly filesystem manipulation, but
not limited to that.  The functions in this module generally raise
DistutilsFileError when they have problems with the filesystem, because
os.error in pre-1.5.2 Python only gives the error message and not the
file causing it."""

# created 1999/03/08, Greg Ward

__rcsid__ = "$Id$"

import os
from distutils.errors import *


# I don't use os.makedirs because a) it's new to Python 1.5.2, and
# b) it blows up if the directory already exists (I want to silently
# succeed in that case).
def mkpath (name, mode=0777, verbose=0):
    """Create a directory and any missing ancestor directories.  If the
       directory already exists, return silently.  Raise
       DistutilsFileError if unable to create some directory along the
       way (eg. some sub-path exists, but is a file rather than a
       directory).  If 'verbose' is true, print a one-line summary of
       each mkdir to stdout."""

    # XXX what's the better way to handle verbosity? print as we create
    # each directory in the path (the current behaviour), or only announce
    # the creation of the whole path, and force verbose=0 on all sub-calls?

    if os.path.isdir (name):
        return

    (head, tail) = os.path.split (name)
    tails = [tail]                      # stack of lone dirs to create
    
    while head and tail and not os.path.isdir (head):
        #print "splitting '%s': " % head,
        (head, tail) = os.path.split (head)
        #print "to ('%s','%s')" % (head, tail)
        tails.insert (0, tail)          # push next higher dir onto stack

    #print "stack of tails:", tails

    # now 'head' contains the highest directory that already exists
    for d in tails:
        #print "head = %s, d = %s: " % (head, d),
        head = os.path.join (head, d)
        if verbose:
            print "creating", head
        try:
            os.mkdir (head)
        except os.error, (errno, errstr):
            raise DistutilsFileError, "%s: %s" % (head, errstr)

# mkpath ()


def newer (file1, file2):
    """Return true if file1 exists and is more recently modified than
       file2, or if file1 exists and file2 doesn't.  Return false if both
       exist and file2 is the same age or younger than file1.  Raises
       DistutilsFileError if file1 does not exist."""

    if not os.path.exists (file1):
        raise DistutilsFileError, "file '%s' does not exist" % file1
    if not os.path.exists (file2):
        return 1

    from stat import *
    mtime1 = os.stat(file1)[ST_MTIME]
    mtime2 = os.stat(file2)[ST_MTIME]

    return mtime1 > mtime2

# newer ()


def make_file (src, dst, func, args,
               verbose=0, update_message=None, noupdate_message=None):
    """Makes 'dst' from 'src' (both filenames) by calling 'func' with
       'args', but only if it needs to: i.e. if 'dst' does not exist or
       'src' is newer than 'dst'."""

    if newer (src, dst):
        if verbose and update_message:
            print update_message
        apply (func, args)
    else:
        if verbose and noupdate_message:
            print noupdate_message

# make_file ()


def _copy_file_contents (src, dst, buffer_size=16*1024):
    """Copy the file 'src' to 'dst'; both must be filenames.  Any error
       opening either file, reading from 'src', or writing to 'dst',
       raises DistutilsFileError.  Data is read/written in chunks of
       'buffer_size' bytes (default 16k).  No attempt is made to handle
       anything apart from regular files."""

    # Stolen from shutil module in the standard library, but with
    # custom error-handling added.

    fsrc = None
    fdst = None
    try:
        try:
            fsrc = open(src, 'rb')
        except os.error, (errno, errstr):
            raise DistutilsFileError, "could not open %s: %s" % (src, errstr)
        
        try:
            fdst = open(dst, 'wb')
        except os.error, (errno, errstr):
            raise DistutilsFileError, "could not create %s: %s" % (dst, errstr)
        
        while 1:
            try:
                buf = fsrc.read (buffer_size)
            except os.error, (errno, errstr):
                raise DistutilsFileError, \
                      "could not read from %s: %s" % (src, errstr)
            
            if not buf:
                break

            try:
                fdst.write(buf)
            except os.error, (errno, errstr):
                raise DistutilsFileError, \
                      "could not write to %s: %s" % (dst, errstr)
            
    finally:
        if fdst:
            fdst.close()
        if fsrc:
            fsrc.close()

# _copy_file_contents()


def copy_file (src, dst,
               preserve_mode=1,
               preserve_times=1,
               update=0,
               verbose=0):

    """Copy a file 'src' to 'dst'.  If 'dst' is a directory, then 'src'
       is copied there with the same name; otherwise, it must be a
       filename.  (If the file exists, it will be ruthlessly clobbered.)
       If 'preserve_mode' is true (the default), the file's mode (type
       and permission bits, or whatever is analogous on the current
       platform) is copied.  If 'preserve_times' is true (the default),
       the last-modified and last-access times are copied as well.  If
       'update' is true, 'src' will only be copied if 'dst' does not
       exist, or if 'dst' does exist but is older than 'src'.  If
       'verbose' is true, then a one-line summary of the copy will be
       printed to stdout."""

    # XXX doesn't copy Mac-specific metadata
       
    from shutil import copyfile
    from stat import *

    if not os.path.isfile (src):
        raise DistutilsFileError, \
              "can't copy %s:not a regular file" % src

    if os.path.isdir (dst):
        dir = dst
        dst = os.path.join (dst, os.path.basename (src))
    else:
        dir = os.path.dirname (dst)

    if update and not newer (src, dst):
        return

    if verbose:
        print "copying %s -> %s" % (src, dir)

    copyfile (src, dst)
    if preserve_mode or preserve_times:
        st = os.stat (src)
        if preserve_mode:
            os.chmod (dst, S_IMODE (st[ST_MODE]))
        if preserve_times:
            os.utime (dst, (st[ST_ATIME], st[ST_MTIME]))

# copy_file ()


def copy_tree (src, dst,
               preserve_mode=1,
               preserve_times=1,
               preserve_symlinks=0,
               update=0,
               verbose=0):               

    """Copy an entire directory tree 'src' to a new location 'dst'.  Both
       'src' and 'dst' must be directory names.  If 'src' is not a
       directory, raise DistutilsFileError.  If 'dst' does not exist, it
       is created with 'mkpath'.  The endresult of the copy is that
       every file in 'src' is copied to 'dst', and directories under
       'src' are recursively copied to 'dst'.

       'preserve_mode' and 'preserve_times' are the same as for
       'copy_file'; note that they only apply to regular files, not to
       directories.  If 'preserve_symlinks' is true, symlinks will be
       copied as symlinks (on platforms that support them!); otherwise
       (the default), the destination of the symlink will be copied.
       'update' and 'verbose' are the same as for 'copy_file'."""

    if not os.path.isdir (src):
        raise DistutilsFileError, \
              "cannot copy tree %s: not a directory" % src    
    try:
        names = os.listdir (src)
    except os.error, (errno, errstr):
        raise DistutilsFileError, \
              "error listing files in %s: %s" % (src, errstr)

        
    mkpath (dst, verbose=verbose)

    for n in names:
        src_name = os.path.join (src, n)
        dst_name = os.path.join (dst, n)

        if preserve_symlinks and os.path.islink (src_name):
            link_dest = os.readlink (src_name)
            os.symlink (link_dest, dst_name)
        elif os.path.isdir (src_name):
            copy_tree (src_name, dst_name,
                       preserve_mode, preserve_times, preserve_symlinks,
                       update, verbose)
        else:
            copy_file (src_name, dst_name,
                       preserve_mode, preserve_times,
                       update, verbose)

# copy_tree ()
